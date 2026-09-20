"""
业务对账模块 (Phase 2.5) — 在所有漏洞 Agent 跑完后,LLM 总监对账:
- 看业务理解里的 promises 哪些被测、哪些没测
- 看已发现漏洞是否提示同类业务点有问题
- 列出 Top 缺口(最多 5 条) + 起补齐任务

设计:
- 2 轮硬上限(可配置)
- 每轮最多 5 个补齐任务
- 失败/超时降级: 不阻断报告生成
- 补齐任务复用 Phase 2 的子 Agent 调度入口(转 checklist 格式)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from core.llm import LLMClient
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)

PROMPT_PATH = Path(__file__).parent / "prompts" / "business_reconcile.md"

# 硬上限(防御性)
MAX_ROUNDS = 2
MAX_NEW_TASKS_PER_ROUND = 5


# ============================================================
# Context 拼装
# ============================================================
def build_reconcile_context(
    sitemap: "Sitemap",
    bu_result: dict,
    already_executed_task_ids: Optional[set[str]] = None,
) -> str:
    """拼装对账上下文: 业务理解 + 已完成 checklist + 已发现漏洞 + 已执行的补齐任务。"""
    already_executed_task_ids = already_executed_task_ids or set()
    parts: list[str] = []

    # === 业务理解(精简版,只取 promises / attack_hypotheses / top_3) ===
    u = (bu_result or {}).get("understanding") or {}
    parts.append("# 业务理解(精简版)")
    parts.append("")

    domain = u.get("domain") or {}
    if domain:
        d_lbl = domain.get("label", "") if isinstance(domain, dict) else str(domain)
        parts.append(f"- **领域**: {d_lbl}")

    promises = u.get("promises") or []
    if promises:
        parts.append(f"- **系统承诺** ({len(promises)} 条):")
        for i, p in enumerate(promises[:30], 1):
            if not isinstance(p, dict):
                continue
            pid = p.get("id", f"P-{i:03d}")
            prio = p.get("priority", "P1").upper()
            stmt = (p.get("statement", "") or p.get("promise", "") or "")[:200]
            parts.append(f"  - [{prio}] {pid}: {stmt}")

    hypotheses = u.get("attack_hypotheses") or []
    if hypotheses:
        parts.append(f"- **业务理解推导的攻击假设** ({len(hypotheses)} 条):")
        for i, h in enumerate(hypotheses[:20], 1):
            if not isinstance(h, dict):
                continue
            ep = h.get("test_endpoint", "") or h.get("target_url", "")
            param = h.get("param_to_modify", "") or h.get("param", "")
            vt = h.get("vulnerability_type", "")
            parts.append(f"  - AH-{i:03d}: {vt} on `{ep}` ({param})")

    top3 = u.get("top_3_directions") or []
    if top3:
        parts.append(f"- **Top 3 深挖方向**:")
        for i, t in enumerate(top3[:5], 1):
            title = t.get("direction", "") if isinstance(t, dict) else str(t)
            parts.append(f"  - {i}. {title}")
    parts.append("")

    # === 已完成的 checklist ===
    parts.append("# 已完成的测试 (checklist 项)")
    parts.append("")
    completed_items = []
    for fp in (getattr(sitemap, "features", None) or {}).values():
        fp_name = getattr(fp, "name", "")
        fp_module = getattr(fp, "module", "")
        for c in (getattr(fp, "checklist", []) or []):
            result = getattr(c, "result", None)
            if result is None:
                continue
            # 兼容枚举/字符串
            result_str = getattr(result, "value", str(result))
            if result_str in ("pending", "not_tested", "skipped"):
                continue
            completed_items.append({
                "feature": fp_name,
                "module": fp_module,
                "item": getattr(c, "item", "") or getattr(c, "description", ""),
                "result": result_str,
                "vuln_type": getattr(c, "vuln_type", "") or getattr(c, "check_type", ""),
            })
    parts.append(f"- 共完成 {len(completed_items)} 项 checklist")
    # 按模块分组,简要列出
    from collections import defaultdict
    grouped: dict[str, list] = defaultdict(list)
    for ci in completed_items[:200]:
        grouped[ci["module"] or "其他"].append(ci)
    for mod, items in list(grouped.items())[:15]:
        parts.append(f"  - **{mod}** ({len(items)} 项):")
        for it in items[:8]:
            mark = "🔴" if it["result"] == "vulnerable" else "✅"
            parts.append(f"    - {mark} [{it['vuln_type']}] {it['item'][:120]}")
        if len(items) > 8:
            parts.append(f"    - ... 还有 {len(items) - 8} 项")
    parts.append("")

    # === 已发现的漏洞 ===
    vulns = []
    for fp in (getattr(sitemap, "features", None) or {}).values():
        for c in (getattr(fp, "checklist", []) or []):
            r = getattr(c, "result", None)
            r_str = getattr(r, "value", str(r)) if r else ""
            if r_str == "vulnerable":
                vulns.append({
                    "feature": getattr(fp, "name", ""),
                    "module": getattr(fp, "module", ""),
                    "item": getattr(c, "item", ""),
                    "vuln_type": getattr(c, "vuln_type", "") or getattr(c, "check_type", ""),
                    "severity": getattr(c, "severity", "") or "",
                    "evidence": (getattr(c, "evidence", "") or "")[:300],
                })

    # XSS findings
    xss_findings = getattr(sitemap, "xss_findings", []) or []
    confirmed_xss = [f for f in xss_findings if isinstance(f, dict) and f.get("status") == "confirmed"]

    parts.append(f"# 已发现的漏洞 ({len(vulns)} 个常规 + {len(confirmed_xss)} 个 XSS)")
    parts.append("")
    for v in vulns[:30]:
        parts.append(f"- 🔴 [{v['vuln_type']}] {v['feature']} - {v['module']}: {v['item'][:150]}")
    for xv in confirmed_xss[:15]:
        if isinstance(xv, dict):
            parts.append(f"- 🔴 [XSS:{xv.get('xss_type', '?')}] {xv.get('title', '')[:150]}")
    parts.append("")

    # === 已执行的补齐任务(避免重复) ===
    if already_executed_task_ids:
        parts.append("# 已执行过的补齐任务(请勿重复)")
        parts.append("")
        for tid in list(already_executed_task_ids)[:30]:
            parts.append(f"- {tid}")
        parts.append("")

    return "\n".join(parts)


# ============================================================
# 主入口: 单轮对账
# ============================================================
async def reconcile_once(
    sitemap: "Sitemap",
    bu_result: dict,
    llm: "LLMClient",
    already_executed_task_ids: Optional[set[str]] = None,
    timeout: float = 90.0,
) -> dict:
    """单轮对账。返回结构化结果。

    Returns:
        {
            "status": "ok" / "error" / "timeout",
            "reconcile_data": dict (LLM 解析的 JSON),
            "raw_response": str,
            "elapsed": float,
        }
    """
    started = time.time()
    if not PROMPT_PATH.exists():
        return {"status": "error", "error": f"提示词缺失: {PROMPT_PATH}"}
    if not bu_result or bu_result.get("status") != "ok":
        return {"status": "error",
                "error": "业务理解结果不可用,跳过对账"}

    try:
        system_prompt = PROMPT_PATH.read_text(encoding="utf-8")
        user_context = build_reconcile_context(sitemap, bu_result, already_executed_task_ids)
    except Exception as e:
        return {"status": "error", "error": f"上下文拼装失败: {e}"}

    from core.llm import Message
    messages = [
        Message(role="system", content=system_prompt),
        Message(role="user", content=user_context),
    ]
    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(llm.chat, messages, caller="business_reconcile"),
            timeout=timeout,
        )
        raw_text = response.content or ""
    except asyncio.TimeoutError:
        return {"status": "timeout",
                "error": f"对账 LLM 调用超过 {timeout}s",
                "elapsed": time.time() - started}
    except Exception as e:
        return {"status": "error",
                "error": f"对账 LLM 调用失败: {e}",
                "elapsed": time.time() - started}

    elapsed = time.time() - started
    rec_data = _extract_json(raw_text)
    if rec_data is None:
        return {"status": "error",
                "error": "无法解析对账 JSON",
                "raw_response": raw_text[:5000],
                "elapsed": elapsed}

    # 防御性: 截断 new_tasks
    if isinstance(rec_data.get("new_tasks"), list):
        rec_data["new_tasks"] = rec_data["new_tasks"][:MAX_NEW_TASKS_PER_ROUND]
        # 给每个任务补上唯一 id(如果没有)
        for i, t in enumerate(rec_data["new_tasks"]):
            if isinstance(t, dict) and not t.get("id"):
                t["id"] = f"GAP-R{int(time.time())}-{i:02d}"

    return {
        "status": "ok",
        "reconcile_data": rec_data,
        "raw_response": raw_text[:30000],
        "elapsed": elapsed,
    }


def _extract_json(raw_text: str) -> Optional[dict]:
    """从 LLM 响应中提取 JSON 对象。

    ★ P2-4: 增加字符串感知——JSON 值中包含 { } 字符时（如配置描述），
    原逻辑 depth 计数会被误导导致解析失败。
    """
    if not raw_text:
        return None
    # 1. ```json ... ```
    m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", raw_text)
    if m:
        try:
            return json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    # 2. 第一个 { 到匹配的 }（字符串感知版）
    start = raw_text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(raw_text)):
        ch = raw_text[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(raw_text[start:i + 1])
                except (json.JSONDecodeError, ValueError):
                    return None
    return None


# ============================================================
# 多轮调度入口
# ============================================================
async def reconcile_loop(
    sitemap: "Sitemap",
    bu_result: dict,
    llm: "LLMClient",
    *,
    execute_new_tasks: Optional[callable] = None,
    max_rounds: int = MAX_ROUNDS,
    on_event: Optional[callable] = None,
    timeout_per_round: float = 90.0,
) -> dict:
    """多轮对账主入口。

    Args:
        execute_new_tasks: async 回调,签名 async (new_tasks: list[dict]) -> list[dict]
                          收到 LLM 输出的补齐任务,实际执行后返回结果列表
                          (每个任务结果会被写回 task 项的 _executed_status / _executed_summary)
                          如果为 None,不执行补齐,只做对账输出
        max_rounds: 最大轮数(硬上限 2)
        on_event: 进度回调,签名 (msg: str) -> None
        timeout_per_round: 单轮超时

    Returns:
        {
            "status": "ok" / "error",
            "rounds": int (实际执行轮数),
            "reconcile_data": dict (最后一轮的对账数据,含合并所有轮的 new_tasks),
            "all_rounds_raw": list[dict],
            "elapsed": float,
        }
    """
    def _emit(msg: str):
        if on_event:
            try:
                on_event(msg)
            except Exception:
                pass

    started = time.time()
    max_rounds = min(max_rounds, MAX_ROUNDS)  # 强制不超过 2

    all_rounds: list[dict] = []
    all_new_tasks: list[dict] = []
    already_executed_ids: set[str] = set()
    final_rec_data: dict = {}

    for round_idx in range(1, max_rounds + 1):
        _emit(f"📋 对账第 {round_idx}/{max_rounds} 轮启动...")
        rec = await reconcile_once(
            sitemap=sitemap, bu_result=bu_result, llm=llm,
            already_executed_task_ids=already_executed_ids,
            timeout=timeout_per_round,
        )
        all_rounds.append(rec)
        if rec.get("status") != "ok":
            _emit(f"⚠️ 第 {round_idx} 轮对账失败: {rec.get('error', '')[:150]}")
            break

        rec_data = rec.get("reconcile_data") or {}
        cov = rec_data.get("coverage_summary", {}) or {}
        verdict = cov.get("verdict", "")
        new_tasks = rec_data.get("new_tasks", []) or []
        _emit(
            f"✅ 第 {round_idx} 轮对账完成: {len(new_tasks)} 个 Top 缺口, "
            f"verdict={verdict}"
        )

        # 累计 task
        for t in new_tasks:
            if isinstance(t, dict):
                all_new_tasks.append(t)

        # 最后一轮的 rec_data 作为整体输出
        final_rec_data = rec_data

        # 如无补齐任务或 verdict 为 covered_well, 结束
        if not new_tasks or verdict == "covered_well":
            _emit("📊 已无新缺口,对账结束")
            break

        # 执行补齐任务
        if execute_new_tasks:
            _emit(f"🔧 启动补齐任务执行 ({len(new_tasks)} 个)...")
            try:
                exec_results = await execute_new_tasks(new_tasks)
                # 回填执行结果到 task 项
                if exec_results and isinstance(exec_results, list):
                    for t, r in zip(new_tasks, exec_results):
                        if isinstance(t, dict) and isinstance(r, dict):
                            t["_executed_status"] = r.get("status", "已执行")
                            t["_executed_summary"] = r.get("summary", "")
                _emit(f"✅ 补齐任务执行完成")
            except Exception as e:
                _emit(f"⚠️ 补齐任务执行失败: {str(e)[:200]}")
            # 记录已执行的 id,防下一轮重复
            for t in new_tasks:
                if isinstance(t, dict):
                    tid = t.get("id", "")
                    if tid:
                        already_executed_ids.add(tid)
        else:
            # 不执行,但仍记录 id 避免下轮重复
            for t in new_tasks:
                if isinstance(t, dict):
                    tid = t.get("id", "")
                    if tid:
                        already_executed_ids.add(tid)
            _emit("ℹ️ 未配置补齐执行器,跳过实际执行,仅做缺口分析")

    # 合并所有轮的 new_tasks 到 final_rec_data
    if all_new_tasks:
        if not final_rec_data:
            final_rec_data = {}
        final_rec_data["new_tasks"] = all_new_tasks

    return {
        "status": "ok" if all_rounds and all_rounds[0].get("status") == "ok" else "error",
        "rounds": len(all_rounds),
        "reconcile_data": final_rec_data,
        "all_rounds_raw": all_rounds,
        "elapsed": time.time() - started,
    }
