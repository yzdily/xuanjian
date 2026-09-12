"""
scripts/backfill_replays.py — 把已经跑过的历史任务反向补录成"决策剧场"剧本

用途：
    决策剧场（core.replay）功能上线前已经跑完的任务，没有任何 worker.decision
    / harm.validated 事件被 emit，所以剧场里看不到。本脚本扫描历史产出文件，
    把它们重组为剧本帧，省去重新跑任务消耗 token。

数据源：
    1. data/tasks/<task_id>-chat.jsonl           → DECISION 帧（tool_call / phase / message）
    2. data/tasks/xss_findings-<task_id>.jsonl   → HARM_VALIDATED 帧（XSS 验证结论）

输出：
    data/replays/<task_id>/script.jsonl + meta.json

特点：
    - 严格复用 core.replay.save_frame，schema 跟主流程完全一致
    - 幂等：默认会先清空目标 run_id 旧剧本再写入（--keep 跳过已存在）
    - 干跑模式：--dry-run 只打印不落盘
    - 单 task：--task <task_id> 只处理一个

用法：
    # 在项目根目录执行
    python -m scripts.backfill_replays                   # 处理所有
    python -m scripts.backfill_replays --dry-run         # 预览
    python -m scripts.backfill_replays --task task_1780279239_74ed88
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Iterable

# 让脚本可以直接运行（python scripts/backfill_replays.py）
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.replay.frame import FrameKind, ReplayFrame, new_frame_id  # noqa: E402
from core.replay.store import REPLAY_ROOT, save_frame  # noqa: E402

TASKS_DIR = ROOT / "data" / "tasks"

# ============================================================
# Chat 解析：识别"决策性"事件
# ============================================================

# 哪些 tool_call 算作"渗透决策"（值得记入剧场）
# 设计原则：宁可多照、不可错杀
#   - LLM 选工具 = 决策，全部入剧
#   - 仅跳过纯"读取/查看/配置"类的噪音工具
_NOISE_TOOLS = {
    "sitemap_set_business", "sitemap_get_coverage", "checklist_view",
    "note_read", "note_summary", "target_get", "phase_complete",
    # "done" 作为里程碑保留（在下面单独处理）
}

# 明确列为"高价值决策"的工具（在剧场里着重高亮）
_HIGH_VALUE_TOOLS = {
    # HTTP 探测
    "proxy_send_request", "proxy_replay", "proxy_batch_send", "proxy_diff_responses",
    # 浏览器交互
    "browser_goto", "browser_click", "browser_fill", "browser_evaluate",
    "browser_screenshot", "browser_console",
    # 测试辅助
    "crypto_encrypt", "crypto_decrypt",
    "knowledge_load_skill", "knowledge_search",
    # 结论/报告
    "checklist_mark", "findings_add", "note_add",
    # XSS 专项
    "xss_scan", "xss_attack", "xss_payload",
    # 其他漏洞专项
    "sql_inject", "sqlmap_run", "ssti_test", "rce_chain", "exploit_run",
    # 站点发现
    "sitemap_add_feature", "sitemap_add_page", "sitemap_report_discovery",
    "sitemap_activate_deferred",
    # 经验
    "memory_recall", "memory_record", "lesson_record", "recall_lessons",
}

# 保留旧的设计（向后兼容）—— _DECISION_TOOLS 仅作为"默认必入剧"补充
DECISION_TOOLS = _HIGH_VALUE_TOOLS
_DECISION_TOOLS = _HIGH_VALUE_TOOLS  # 兼容旧名字

# 通过关键字模糊匹配漏洞类型
_VULN_TYPE_HINTS = [
    ("xss", "xss"),
    ("sql", "sqli"),
    ("ssti", "ssti"),
    ("ssrf", "ssrf"),
    ("rce", "rce"),
    ("cmd", "cmdi"),
    ("redirect", "open_redirect"),
    ("upload", "file_upload"),
    ("auth", "auth_bypass"),
    ("idor", "idor"),
    ("csrf", "csrf"),
]


def _guess_vuln_type(text: str) -> str:
    if not text:
        return ""
    low = text.lower()
    for kw, vt in _VULN_TYPE_HINTS:
        if kw in low:
            return vt
    return ""


def _parse_tool_call(data_str: str) -> tuple[str, str]:
    """从 'sitemap_set_business({"a":1})' 之类的字符串里提取 (tool_name, args_brief)"""
    if not data_str:
        return "", ""
    m = re.match(r"^([A-Za-z0-9_]+)\s*\(", data_str)
    name = m.group(1) if m else ""
    # 取括号里的参数概要（截断，避免 payload 噪音）
    args_brief = data_str[len(name) + 1: -1] if name else data_str
    return name, args_brief[:500]


def _iter_chat_lines(p: Path) -> Iterable[dict[str, Any]]:
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                yield json.loads(ln)
            except Exception:
                continue


def _build_decision_frames_from_chat(
    chat_path: Path,
    run_id: str,
    target_hint: str,
    base_ts: float,
) -> list[ReplayFrame]:
    """从 chat.jsonl 里抽取关键决策为 DECISION 帧。

    策略：
    - tool_call ∈ _DECISION_TOOLS 的算决策
    - phase / phase_complete 也作为里程碑帧（kind=DECISION，feature_name=Phase X）
    - reasoning 紧邻其后的 tool_call 时，作为 llm_summary 附在决策上
    - 时间戳：chat 行没原生时间戳，按 base_ts + 行序号 平摊
    """
    frames: list[ReplayFrame] = []
    pending_reason = ""
    pending_msg = ""
    idx = 0
    for row in _iter_chat_lines(chat_path):
        idx += 1
        t = row.get("type", "")
        d = row.get("data", "") or ""
        if not isinstance(d, str):
            d = json.dumps(d, ensure_ascii=False)

        if t == "reasoning":
            pending_reason = d[:1500]
            continue
        if t == "message":
            pending_msg = d[:500]
            continue

        if t == "phase":
            frames.append(ReplayFrame(
                frame_id=new_frame_id(),
                run_id=run_id,
                kind=FrameKind.DECISION,
                timestamp=base_ts + idx * 0.1,
                feature_name=d[:200],
                vuln_type="",
                skill_used="phase_marker",
                target_url=target_hint,
                llm_summary=pending_msg or pending_reason,
                extra={"source": "chat", "raw_type": "phase", "track": "system"},
            ))
            pending_reason = pending_msg = ""
            continue

        if t == "phase_complete":
            frames.append(ReplayFrame(
                frame_id=new_frame_id(),
                run_id=run_id,
                kind=FrameKind.DECISION,
                timestamp=base_ts + idx * 0.1,
                feature_name="✅ " + d[:200],
                skill_used="phase_complete",
                target_url=target_hint,
                llm_summary=d[:1500],
                extra={"source": "chat", "raw_type": "phase_complete", "track": "system"},
            ))
            pending_reason = pending_msg = ""
            continue

        if t == "tool_call":
            name, args = _parse_tool_call(d)
            if not name:
                continue
            # 跳过噪音工具
            if name in _NOISE_TOOLS:
                continue
            # checklist_mark 走 HARM_VALIDATED 帧（下面单独处理）——这里不发 DECISION
            if name == "checklist_mark":
                continue

            # 渗透决策帧：高价值工具或其他 LLM 选择的工具
            is_high_value = name in _HIGH_VALUE_TOOLS
            vuln_guess = _guess_vuln_type(name + " " + args)
            # 后续可能从 args 中抠 url 作为 target
            tool_target = target_hint
            try:
                # 粗略抽一下 URL（不要用 json.loads，因为 args 可能被截断了）
                m = re.search(r'"(?:url|base_url)"\s*:\s*"([^"]+)"', args)
                if m:
                    tool_target = m.group(1)
            except Exception:
                pass

            frames.append(ReplayFrame(
                frame_id=new_frame_id(),
                run_id=run_id,
                kind=FrameKind.DECISION,
                timestamp=base_ts + idx * 0.1,
                feature_name=f"🎯 {name}" if is_high_value else f"调用 {name}",
                vuln_type=vuln_guess,
                skill_used=name,
                payload=args,
                target_url=tool_target,
                llm_summary=(pending_msg + "\n" + pending_reason).strip()[:1500],
                extra={
                    "source": "chat",
                    "raw_type": "tool_call",
                    "track": "llm",
                    "high_value": is_high_value,
                },
            ))
            pending_reason = pending_msg = ""
            continue

        # ★ tool_result：worker checklist_mark 的结论 — 走 HARM_VALIDATED 帧
        # chat.jsonl 里 tool_call 后紧接着就是 tool_result，这是定型判定的关键点
        if t == "tool_result":
            # 仅处理什么：head 例如 "🔴 SQL注入: 发现..." / "✅ IDOR: 未发现" / "🟡 ..."
            # 这是 tool_executor 里给 checklist_mark 组装的返回文本
            if d.startswith("🔴 ") or d.startswith("✅ ") or d.startswith("🟡 "):
                conclusion = "vulnerable" if d.startswith("🔴 ") else \
                             "not_vuln" if d.startswith("✅ ") else "needs_review"
                # 提取 vuln_type + detail："<icon> <vuln_type>: <detail>\n剩余..."
                m = re.match(r"^[\U0001F300-\U0001FAFF\U00002600-\U000027BF\u2705\u26a0]+\s*(.+?):\s*(.+?)(?:\n|$)", d)
                vt = m.group(1).strip() if m else ""
                detail = m.group(2).strip() if m else d[:500]
                # 从 pending_msg / pending_reason 中抠完整详情
                summary = (pending_msg + "\n" + pending_reason).strip()[:1500] or detail[:1500]
                frames.append(ReplayFrame(
                    frame_id=new_frame_id(),
                    run_id=run_id,
                    kind=FrameKind.HARM_VALIDATED,
                    timestamp=base_ts + idx * 0.1,
                    feature_name=f"⚖️ 结论: {vt}" if vt else "⚖️ 结论",
                    vuln_type=_guess_vuln_type(vt),
                    skill_used="checklist_mark",
                    payload=detail[:1500],
                    target_url=target_hint,
                    conclusion=conclusion,
                    llm_summary=summary,
                    extra={
                        "source": "chat",
                        "raw_type": "checklist_mark",
                        "track": "llm",
                        "vuln_type_raw": vt,
                    },
                ))
                pending_reason = pending_msg = ""
                continue

    return frames


# ============================================================
# Findings 解析：HARM_VALIDATED 帧
# ============================================================

def _build_harm_frames_from_findings(
    findings_path: Path, run_id: str
) -> list[ReplayFrame]:
    """xss_findings-*.jsonl 每行一条结论 → HARM_VALIDATED 帧"""
    frames: list[ReplayFrame] = []
    for row in _iter_chat_lines(findings_path):
        status = row.get("status", "")  # confirmed / false_positive / needs_review
        conclusion = {
            "confirmed": "vulnerable",
            "false_positive": "not_vuln",
            "needs_review": "needs_review",
        }.get(status, status or "unknown")

        ts = float(row.get("judged_at") or row.get("scanned_at") or time.time())
        frames.append(ReplayFrame(
            frame_id=new_frame_id(),
            run_id=run_id,
            kind=FrameKind.HARM_VALIDATED,
            timestamp=ts,
            feature_id=row.get("feature_id", "") or row.get("id", ""),
            feature_name=row.get("title", "")[:200],
            vuln_type="xss",
            skill_used="xss_judge",
            payload=str(row.get("payload", ""))[:1500],
            target_url=row.get("url", ""),
            conclusion=conclusion,
            severity=row.get("severity", ""),
            llm_summary=str(row.get("judge_reasoning", ""))[:1500],
            extra={
                # ★ 区分剧情线：这是自动扫描器的结论，不是 LLM 决策
                "track": "scanner",
                "source": "xss_findings",
                "xss_type": row.get("xss_type", ""),
                "param": row.get("param", ""),
                "injection_point": row.get("injection_point", ""),
                "echo_count": row.get("echo_count", 0),
                "browser_triggered": row.get("browser_triggered", False),
                "judge_confidence": row.get("judge_confidence", 0),
                "fix_suggestion": str(row.get("fix_suggestion", ""))[:600],
            },
        ))
    return frames


# ============================================================
# Task 发现 / 元数据猜测
# ============================================================

def _discover_tasks() -> list[dict[str, Any]]:
    """扫 data/tasks/ 下所有 task_*-chat.jsonl，配对 xss_findings-*.jsonl 与 sitemap.json"""
    out: list[dict[str, Any]] = []
    if not TASKS_DIR.exists():
        return out
    for chat in sorted(TASKS_DIR.glob("task_*-chat.jsonl")):
        # 文件名形如：task_1780279239_74ed88-chat.jsonl
        m = re.match(r"^(task_[A-Za-z0-9_]+)-chat\.jsonl$", chat.name)
        if not m:
            continue
        task_id = m.group(1)
        out.append({
            "task_id": task_id,
            "chat": chat,
            "findings": TASKS_DIR / f"xss_findings-{task_id}.jsonl",
            "sitemap": TASKS_DIR / f"{task_id}-sitemap.json",
        })
    return out


def _read_target_from_chat(chat_path: Path) -> tuple[str, float]:
    """从 chat.jsonl 第一行 user 消息里嗅探目标地址 + 文件 mtime 作 base_ts"""
    target = ""
    base_ts = float(chat_path.stat().st_mtime) - 3600  # 兜底：以文件修改时间往前推 1h
    for row in _iter_chat_lines(chat_path):
        if row.get("type") == "user":
            txt = row.get("data", "") or ""
            m = re.search(r"目标地址[：:]\s*(\S+)", txt)
            if m:
                target = m.group(1)
            else:
                m2 = re.search(r"https?://\S+", txt)
                if m2:
                    target = m2.group(0).split()[0]
            break
    # 从 task_id 里抠时间戳更准（task_1780279239_xxx → 1780279239）
    m3 = re.search(r"task_(\d{10})", chat_path.name)
    if m3:
        try:
            base_ts = float(m3.group(1))
        except Exception:
            pass
    return target, base_ts


# ============================================================
# 主逻辑
# ============================================================

def backfill_one(
    task: dict[str, Any], dry_run: bool = False, keep: bool = False
) -> dict[str, Any]:
    task_id: str = task["task_id"]
    run_id = task_id  # 一个 task = 一个 run，简单清晰
    run_dir = REPLAY_ROOT / run_id

    if run_dir.exists():
        if keep:
            return {"task_id": task_id, "skipped": True, "reason": "exists"}
        if not dry_run:
            shutil.rmtree(run_dir)

    target, base_ts = _read_target_from_chat(task["chat"])

    decision_frames = _build_decision_frames_from_chat(
        task["chat"], run_id, target, base_ts
    )
    harm_frames = _build_harm_frames_from_findings(task["findings"], run_id)

    # 按 timestamp 排序
    all_frames = sorted(decision_frames + harm_frames, key=lambda f: f.timestamp)

    summary = {
        "task_id": task_id,
        "target": target,
        "decision_frames": len(decision_frames),
        "harm_frames": len(harm_frames),
        "total": len(all_frames),
        "dry_run": dry_run,
    }

    if dry_run:
        return summary

    meta_patch = {
        "task_id": task_id,
        "target": target,
        "notes": f"由 backfill_replays.py 离线补录于 "
                 f"{time.strftime('%Y-%m-%d %H:%M:%S')}",
    }
    for fr in all_frames:
        save_frame(fr, dict(meta_patch))

    summary["written_to"] = str(run_dir)
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="把历史任务反向补录为决策剧场剧本")
    ap.add_argument("--task", help="只处理指定 task_id", default=None)
    ap.add_argument("--dry-run", action="store_true", help="只预览，不写盘")
    ap.add_argument("--keep", action="store_true",
                    help="若目标 run 目录已存在，则跳过（默认会先清空覆盖写入）")
    args = ap.parse_args()

    tasks = _discover_tasks()
    if args.task:
        tasks = [t for t in tasks if t["task_id"] == args.task]
    if not tasks:
        print("⚠️  未发现可补录的任务（data/tasks/task_*-chat.jsonl 为空）")
        return 1

    print(f"🎬 发现 {len(tasks)} 个历史任务，开始补录"
          f"{'（dry-run）' if args.dry_run else ''}…\n")
    total_frames = 0
    for t in tasks:
        try:
            r = backfill_one(t, dry_run=args.dry_run, keep=args.keep)
        except Exception as e:
            print(f"  ❌ {t['task_id']} 失败: {e}")
            continue
        if r.get("skipped"):
            print(f"  ⏭️  {r['task_id']}  已存在，跳过")
            continue
        total_frames += r.get("total", 0)
        print(f"  ✅ {r['task_id']}")
        print(f"     target           = {r.get('target') or '(未识别)'}")
        print(f"     decision_frames  = {r['decision_frames']}")
        print(f"     harm_frames      = {r['harm_frames']}")
        print(f"     total            = {r['total']}"
              f"{'  (dry-run, 未落盘)' if args.dry_run else ''}")
        if not args.dry_run:
            print(f"     → {r.get('written_to')}")
        print()

    print(f"🎉 完成：{len(tasks)} 个任务，共 {total_frames} 帧"
          f"{'（dry-run，未实际写入）' if args.dry_run else ''}")
    if not args.dry_run:
        print(f"\n现在打开 http://127.0.0.1:7788/replay-theater 即可看到剧本列表 👀")
    return 0


if __name__ == "__main__":
    sys.exit(main())
