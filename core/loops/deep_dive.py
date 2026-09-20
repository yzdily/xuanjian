"""Phase 2.7 — LOOP 深挖编排钩子（E3-1：让 depth_chain 在真实扫描里跑起来）。

背景
----
`core/loops/loop_matrix.yaml` 声明了 11 条 trigger / 34 个 step，`LoopController.execute()`
也早就写好了，但**生产链路从未调用过它**（此前只有 tests 注入过 step_handler）。
本模块是「引擎 + 矩阵」与「真实扫描流程」之间的那根钩子线。

接入点
------
`core/parallel/_orch_phases/_report_phase.py` 的 `session.phase = "report"` 之前
（即 Phase 2.6 危害验证之后、`finish_scan()` 之前）。选这里的原因：

- 此处**所有已确认漏洞（VULNERABLE/CONFIRMED）都已汇总在 sitemap 里**，是天然的触发点；
- 深挖产出的 finding 写回 sitemap 后，**紧跟着的 `upsert_vuln` 循环与报告渲染会自动带上**，
  不需要另外改动报告链路。

开关（默认安全）
----------------
| 环境变量 | 默认 | 说明 |
|---|---|---|
| `XJ_LOOP_ENABLED` | `1` | 总开关；`0` 时本阶段完全静默跳过 |
| `XJ_LOOP_TRIGGERS` | `actuator_exposure` | 逗号分隔的启用 trigger；**E3-1 只开 actuator**（shiro 链 E3-2 已接线，需显式 `shiro_remmeberme_active` 才启用）|
| `XJ_LOOP_MAX_TRIGGERS` | `5` | 单次扫描最多执行几条链（防爆）|
| `XJ_LOOP_AUTO_EXPLOIT` | `0` | **利用类（C 类）步骤硬开关**；默认 false → 矩阵 `auto: false` 的步骤只产出 `awaiting_manual` 三问节点，绝不自动执行 |

设计要点
--------
1. **矩阵驱动**：trigger 名与 depth_chain 全部来自 yaml，本模块不硬编码链内容。
2. **未注册 step 显式留痕**：`dispatch()` 会把没 handler 的 step 记进 `ctx["_loop_missing_handlers"]`，
   这里汇总后写进事件与落盘文件 —— 不允许"什么都不做还不吭声"。
3. **链数据落盘** `data/tasks/{task_id}-loops.json`，供 `GET /api/loops/{task_id}` 与
   前端 ChainTimeline 读取（前端视图属阶段 1 剩余项）。
4. **单链失败不阻断扫描**：整段 try/except + 单链超时，深挖是增强项而非必需项。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any, AsyncGenerator
from urllib.parse import urlparse

from core.log import get_logger
from core.loops.loop_controller import LoopController
from core.loops.step_handlers import dispatch
from core.sitemap.models import CheckItem, CheckResult

log = get_logger("core.loops.deep_dive")

DEFAULT_TRIGGERS = ("actuator_exposure",)
CHAIN_TIMEOUT = 600.0            # 单链总时长上限（含 heapdump 下载）
_CONFIRMED = ("VULNERABLE", "CONFIRMED")


# ================================================================
# 开关
# ================================================================
def _enabled_triggers() -> tuple[str, ...] | None:
    """返回启用的 trigger 集合。

    - `None`  → 总开关关闭（调用方应完全静默返回）
    - `("*",)` → 放开全部（`XJ_LOOP_TRIGGERS=all`，E3-3 之后才有意义）
    """
    if os.getenv("XJ_LOOP_ENABLED", "1").strip() == "0":
        return None
    raw = os.getenv("XJ_LOOP_TRIGGERS", "").strip()
    if not raw:
        return DEFAULT_TRIGGERS
    wanted = {t.strip() for t in raw.split(",") if t.strip()}
    if "all" in wanted:
        return ("*",)
    return tuple(sorted(wanted))


def _max_triggers() -> int:
    try:
        return max(1, int(os.getenv("XJ_LOOP_MAX_TRIGGERS", "5")))
    except Exception:
        return 5


# ================================================================
# 工具
# ================================================================
def _origin(url: str) -> str:
    """取 scheme://host:port（深挖从站点根开始，不走具体接口路径）。"""
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    try:
        p = urlparse(url)
    except Exception:
        return ""
    if not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def match_trigger(controller: LoopController, vuln_type: str) -> str | None:
    """已确认漏洞的 vuln_type → 矩阵 trigger。

    规则（从严到宽）：
    1. 精确同名（`actuator_exposure` == `actuator_exposure`）
    2. 矩阵 `match` 关键词命中（留给后续把别名写进 yaml，无需改代码）
    3. **token 全包含**：trigger 名的所有 token 都出现在 vuln_type 里
       （`spring_boot_actuator_exposure` ⊇ {actuator, exposure} → 命中 `actuator_exposure`）

    ⚠️ 刻意**不做**朴素的双向子串包含 —— 那会让 `SQLi` 误命中 `sqli_possible`
    （一个是"已确认 SQLi"，另一个是"可能存在 SQLi"的触发条件，语义不同）。
    """
    vt = (vuln_type or "").strip().lower()
    if not vt:
        return None
    if controller.has_trigger(vt):
        return vt
    for name, entry in controller.matrix.items():
        for kw in (entry.get("match") or []):
            if str(kw).lower() in vt:
                return name
    vt_tokens = _tokens(vt)
    for name in controller.matrix:
        nt = _tokens(name)
        if nt and nt <= vt_tokens:
            return name
    return None


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t}


def _chain_steps(controller: LoopController, trigger: str) -> list[dict[str, Any]]:
    """把 VulnChainMemory 里记录的链路径整理成可序列化结构（供前端/落盘）。

    状态取值：`finding`（有产出）/ `ok`（执行了无产出）/ `no_finding` /
    `handler_error` / **`awaiting_manual`**（C 类步骤，停下等人工确认）。
    `awaiting_manual` 时 detail 里带三问（why / ready / actions），前端 ChainTimeline
    据此渲染人工确认节点，因此**不能**被折叠成 "no_finding"。
    """
    steps: list[dict[str, Any]] = []
    for cs in controller.chain.get_chain(trigger):
        detail = dict(cs.detail or {})
        status = detail.get("status") or ("finding" if detail.get("finding_id") else "ok")
        steps.append({
            "step": cs.step,
            "status": status,
            "finding_id": cs.finding_id,
            "awaiting_manual": status == "awaiting_manual",
            "detail": detail,
            "ts": cs.ts,
        })
    return steps


# ================================================================
# 写回 sitemap（供 upsert_vuln / 报告渲染自动带上）
# ================================================================
def _write_back(fp, findings: list, trigger: str, source_vuln_type: str = "") -> int:
    """把深挖产出的 finding 追加为原功能点的已确认 check。

    选"追加到原 fp"而不是新建功能点：深挖结果是**同一目标的纵深**，
    挂回原 fp 才能让报告里"功能点 → 漏洞"的归属保持清晰。

    ⚠️ 必须跳过"表层发现本身"：链的第 1 步产出的 finding（如 `actuator_exposure`）
    就是触发这条链的那个已确认漏洞，重复写回会让报告出现两条同名漏洞。
    """
    added = 0
    for f in findings:
        if f.vuln_type == trigger or (source_vuln_type and f.vuln_type == source_vuln_type):
            continue
        try:
            fp.checklist.append(CheckItem(
                vuln_type=f.vuln_type,
                result=CheckResult.VULNERABLE,
                # ★ 报告要明文（0919 用户确认）；仅 XJ_EVIDENCE_REDACT=1 时 step_handlers 才会脱敏
                detail=json.dumps(f.detail or {}, ensure_ascii=False)[:2000],
                severity=(f.severity or "high").lower(),
                source="loop_deep_dive",
                tested_at=time.time(),
            ))
            added += 1
        except Exception as exc:
            log.warning("[loop] 写回 sitemap 失败 trigger=%s: %s", trigger, exc)
    return added


def _persist(task_id: str, records: list[dict[str, Any]]) -> str:
    path = Path("data/tasks") / f"{task_id}-loops.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"task_id": task_id, "updated_at": time.time(), "chains": records}
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        tmp.replace(path)
        return str(path)
    except Exception as exc:
        log.warning("[loop] 链数据落盘失败 task=%s: %s", task_id, exc)
        return ""


# ================================================================
# 主流程
# ================================================================
async def run_deep_dive(session) -> AsyncGenerator[str, None]:
    """Phase 2.7 · LOOP 深挖。无候选或开关关闭时静默返回。"""
    triggers = _enabled_triggers()
    if triggers is None:
        return
    allow_all = "*" in triggers

    sitemap = getattr(session, "sitemap", None)
    if not sitemap:
        return

    try:
        controller = LoopController()
    except Exception as exc:
        log.warning("[loop] 矩阵加载失败，跳过深挖: %s", exc)
        return

    # ---- 收集候选：已确认漏洞 × 命中 trigger（按 trigger@origin 去重）----
    done: set[str] = getattr(session, "_loop_done", set())
    session._loop_done = done
    candidates: list[tuple[Any, Any, str, str]] = []
    seen: set[str] = set()
    for fp in sitemap.features.values():
        for c in fp.checklist:
            if not (c.result and c.result.name in _CONFIRMED):
                continue
            trigger = match_trigger(controller, c.vuln_type)
            if not trigger or not (allow_all or trigger in triggers):
                continue
            origin = _origin(sitemap.target) or _origin(
                fp.related_apis[0] if fp.related_apis else "")
            if not origin:
                continue
            key = f"{trigger}@{origin}"
            if key in done or key in seen:
                continue
            seen.add(key)
            candidates.append((fp, c, trigger, origin))

    if not candidates:
        return

    cap = _max_triggers()
    if len(candidates) > cap:
        yield session._event("system",
            f"🔎 LOOP 深挖候选 {len(candidates)} 条，本次只执行前 {cap} 条（XJ_LOOP_MAX_TRIGGERS）")
        candidates = candidates[:cap]

    yield session._event("system",
        f"🔎 Phase 2.7 LOOP 深挖：{len(candidates)} 条链待执行"
        f"（启用 trigger: {'全部' if allow_all else ', '.join(triggers)}）")

    records: list[dict[str, Any]] = []
    total_findings = 0

    for fp, check, trigger, origin in candidates:
        started = time.time()
        ctx: dict[str, Any] = {
            "base_url": origin,
            "target_url": origin,
            "trigger": trigger,
            "vuln_type": check.vuln_type,
            "feature_id": fp.id,
        }
        record: dict[str, Any] = {
            "trigger": trigger,
            "origin": origin,
            "feature_id": fp.id,
            "feature_name": fp.name,
            "triggered_by": check.vuln_type,
            "started_at": started,
        }
        try:
            findings = await asyncio.wait_for(
                controller.execute(trigger, ctx, step_handler=dispatch),
                timeout=CHAIN_TIMEOUT,
            )
            record["status"] = "completed"
        except asyncio.TimeoutError:
            findings = []
            record["status"] = "timeout"
            log.warning("[loop] 链超时 trigger=%s origin=%s", trigger, origin)
            yield session._event("system", f"⏱ LOOP 链超时：{trigger} @ {origin}（已跳过）")
        except Exception as exc:
            findings = []
            record["status"] = "error"
            record["error"] = f"{type(exc).__name__}: {exc}"[:300]
            log.warning("[loop] 链执行异常 trigger=%s: %s", trigger, exc, exc_info=True)

        steps = _chain_steps(controller, trigger)
        record["steps"] = steps
        # ★ E3-2：C 类步骤的人工确认节点（三问）—— 原样透出给前端/落盘
        record["awaiting_manual"] = list(ctx.get("_loop_awaiting_manual") or [])
        record["findings"] = [
            {"vuln_type": f.vuln_type, "severity": f.severity, "url": f.url, "detail": f.detail}
            for f in findings
        ]
        record["missing_handlers"] = list(dict.fromkeys(ctx.get("_loop_missing_handlers") or []))
        record["elapsed"] = round(time.time() - started, 2)

        added = _write_back(fp, findings, trigger, source_vuln_type=check.vuln_type) if findings else 0
        record["written_back"] = added
        total_findings += len(findings)
        records.append(record)
        done.add(f"{trigger}@{origin}")

        # ---- 事件：人类可读 + 结构化（前端 ChainTimeline 消费 "loop" 类型）----
        if findings:
            summary = "、".join(f"{f.vuln_type}({f.severity})" for f in findings)
            yield session._event("system",
                f"⛓ LOOP 深挖命中：{trigger} @ {origin}\n"
                f"  - 链步数 {len(steps)}，产出 {len(findings)} 条纵深发现：{summary}\n"
                f"  - 已写回功能点「{fp.name}」，将随报告一并输出")
        else:
            stop = steps[-1]["status"] if steps else "no_step"
            yield session._event("system",
                f"⛓ LOOP 深挖未命中：{trigger} @ {origin}（链步数 {len(steps)}，末步状态 {stop}）")

        # ★ E3-2：人工确认节点必须"有提示"（用户拍板：不要自动执行，至少有个提示）
        if record["awaiting_manual"]:
            first = record["awaiting_manual"][0]
            names = "、".join(e.get("step", "") for e in record["awaiting_manual"])
            yield session._event("system",
                f"⏸ LOOP 有 {len(record['awaiting_manual'])} 个步骤需人工确认（不自动执行利用）：{names}\n"
                f"  · 为什么停：{first.get('why', '')}\n"
                f"  · 已具备条件：{'；'.join(first.get('ready') or [])}\n"
                f"  · 你可以：{'、'.join(first.get('actions') or [])}")

        if record["missing_handlers"]:
            yield session._event("system",
                "⚠️ LOOP 存在未实现的 step（已留痕，未静默跳过）："
                + "、".join(record["missing_handlers"]))

        yield session._event("loop", {
            "version": 1,
            "task_id": getattr(sitemap, "task_id", ""),
            "trigger": trigger,
            "origin": origin,
            "status": record["status"],
            "steps": steps,
            "awaiting_manual": record["awaiting_manual"],
            "findings": record["findings"],
            "missing_handlers": record["missing_handlers"],
            "elapsed": record["elapsed"],
        })

    # ---- 汇总 + 落盘 ----
    if records:
        persisted = _persist(getattr(sitemap, "task_id", "default"), records)
        try:
            sitemap.save()
        except Exception as exc:
            log.warning("[loop] sitemap 保存失败: %s", exc)
        total_manual = sum(len(r.get("awaiting_manual") or []) for r in records)
        manual_note = f"，其中 {total_manual} 步需人工确认（awaiting_manual）" if total_manual else ""
        if total_findings:
            yield session._event("system",
                f"✅ Phase 2.7 完成：{len(records)} 条链产出 {total_findings} 条纵深发现{manual_note}"
                + (f"，链数据已落盘 {persisted}" if persisted else ""))
        else:
            yield session._event("system",
                f"ℹ️ Phase 2.7 完成：{len(records)} 条链均未命中纵深条件（末步终止）{manual_note}")


# ================================================================
# 与其他深挖路径的去重（F13 spawner ↔ E3-1 确定性链）
# ================================================================
def covered_triggers() -> set[str]:
    """当前开关下，确定性深挖链会覆盖的 trigger 集合。

    - `XJ_LOOP_ENABLED=0` → 空集（深挖完全关闭，全部漏洞都该由 F13 spawner 处理）
    - `XJ_LOOP_TRIGGERS=all` → 矩阵中全部 trigger
    - 其余 → 显式列出的 ∩ 矩阵实际存在的 trigger

    这是**单一事实来源** —— 判定"某个漏洞会不会被确定性链处理"只应从这里取，
    不要在调用方各自重复实现（否则开关语义会漂移）。
    """
    want = _enabled_triggers()
    if want is None:
        return set()
    try:
        controller = LoopController()
    except Exception as exc:                       # 矩阵坏了就当没有覆盖，交给 F13 兜底
        log.warning("[loop] 矩阵加载失败，覆盖集视为空: %s", exc)
        return set()
    if "*" in want:
        return set(controller.matrix)
    return {t for t in want if t in controller.matrix}


def filter_covered_by_loops(vulns: list[dict[str, Any]]) -> tuple[list[dict], list[dict]]:
    """把已确认漏洞分成 `(会被确定性深挖链覆盖, 不会被覆盖)`。

    用途：F13 假设链 spawner 与 E3-1 深挖都在做"已确认漏洞 → 下游"，若不做去重，
    同一个漏洞会被两条路径各处理一次（一份是任务描述建议、一份是实际执行的链）。
    分工约定：**矩阵覆盖的交给 E3-1（Phase 2.7 执行），其余才交给 F13 出建议。**

    注意时序：F13 钩子在 Phase 2.7 之前运行，所以这里是**预判**（will cover），
    不是"已执行"。措辞上不要写成"已完成"。
    """
    items = [v for v in (vulns or []) if isinstance(v, dict)]
    covered_set = covered_triggers()
    if not covered_set:
        return [], items
    try:
        controller = LoopController()
    except Exception:
        return [], items
    covered: list[dict] = []
    rest: list[dict] = []
    for v in items:
        vuln_type = str(v.get("vuln_type") or "")
        trigger = match_trigger(controller, vuln_type) if vuln_type else None
        (covered if (trigger and trigger in covered_set) else rest).append(v)
    return covered, rest


__all__ = [
    "run_deep_dive", "match_trigger",
    "covered_triggers", "filter_covered_by_loops",
]
