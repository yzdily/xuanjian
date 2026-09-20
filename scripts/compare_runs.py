#!/usr/bin/env python3
"""
A/B 模式对比脚本

用法:
    python3 scripts/compare_runs.py <task_id_批处理> <task_id_流式>

或者:
    python3 scripts/compare_runs.py --batch-dir 自动化渗透 --stream-dir 自动化渗透-streaming \\
        --batch-task task_xxx --stream-task task_yyy

输出对比表格(总耗时/首漏时间/漏洞数/API覆盖/Token消耗等)。

设计:
- 从两边的 data/tasks/{task_id}-sitemap.json + chat.jsonl 抓取指标
- 不依赖网络,纯本地数据分析
- 默认两个目录在同级:
    自动化渗透/data/tasks/{batch_task}
    自动化渗透-streaming/data/tasks/{stream_task}
"""
import argparse
import json
import sys
from pathlib import Path
from collections import Counter


def load_sitemap(base_dir: Path, task_id: str) -> dict:
    p = base_dir / "data/tasks" / f"{task_id}-sitemap.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def load_chat(base_dir: Path, task_id: str) -> list[dict]:
    p = base_dir / "data/tasks" / f"{task_id}-chat.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def extract_metrics(base_dir: Path, task_id: str, label: str) -> dict:
    sm = load_sitemap(base_dir, task_id)
    chat = load_chat(base_dir, task_id)

    if not sm and not chat:
        return {"label": label, "task_id": task_id, "_missing": True}

    # 时间相关
    timestamps = [c.get("ts", 0) for c in chat if c.get("ts")]
    start_ts = min(timestamps) if timestamps else 0
    end_ts = max(timestamps) if timestamps else 0
    total_secs = end_ts - start_ts if start_ts and end_ts else 0

    # 首个漏洞出现时间(支持多种来源)
    first_vuln_ts = None
    for c in chat:
        msg = (c.get("data") or "").lower()
        if not first_vuln_ts and (
            "vulnerable" in msg or "发现漏洞" in msg or "🌊 [内联] 发现" in c.get("data", "")
            or "已确认" in msg
        ):
            first_vuln_ts = c.get("ts")
    time_to_first_vuln = (first_vuln_ts - start_ts) if first_vuln_ts and start_ts else None

    # 漏洞统计 - sitemap features 里的 vulnerable
    vuln_count = 0
    for fp in (sm.get("features") or {}).values():
        for ci in (fp.get("checklist") or []):
            res = ci.get("result", "")
            if res == "vulnerable" or res == "VULNERABLE":
                vuln_count += 1

    # XSS 模块
    xss_findings = sm.get("xss_findings") or []
    xss_total = len(xss_findings)

    # 内联测试(只有流式版有)
    inline_findings = sm.get("inline_findings") or []
    inline_total = len(inline_findings)
    inline_high = sum(1 for f in inline_findings if f.get("confidence") == "high")
    inline_by_type = Counter(f.get("vuln_type", "?") for f in inline_findings)

    # 危害验证
    hv = sm.get("harm_validation") or {}
    hv_stats = hv.get("stats") or {}

    # API / 页面覆盖
    apis = sm.get("apis") or {}
    api_count = len(apis)
    pages = sm.get("pages") or {}
    page_count = len(pages)
    features_count = len(sm.get("features") or {})

    # 业务理解状态
    bu = sm.get("business_understanding") or {}
    bu_status = bu.get("status", "missing")
    bu_promises_count = 0
    bu_hypotheses_count = 0
    if bu_status == "ok":
        u = bu.get("understanding") or {}
        bu_promises_count = len(u.get("promises") or [])
        bu_hypotheses_count = len(u.get("attack_hypotheses") or [])

    # checklist 总数 + 完成数
    total_checks = 0
    done_checks = 0
    for fp in (sm.get("features") or {}).values():
        for ci in (fp.get("checklist") or []):
            total_checks += 1
            if ci.get("result") in ("not_vuln", "vulnerable", "skipped",
                                     "NOT_VULN", "VULNERABLE", "SKIPPED"):
                done_checks += 1

    return {
        "label": label,
        "task_id": task_id,
        "_missing": False,
        "total_secs": total_secs,
        "time_to_first_vuln": time_to_first_vuln,
        "vuln_count": vuln_count,
        "xss_total": xss_total,
        "inline_total": inline_total,
        "inline_high": inline_high,
        "inline_by_type": dict(inline_by_type),
        "hv_accepted": hv_stats.get("accepted", 0),
        "hv_borderline": hv_stats.get("borderline", 0),
        "hv_rejected": hv_stats.get("rejected", 0),
        "api_count": api_count,
        "page_count": page_count,
        "features_count": features_count,
        "total_checks": total_checks,
        "done_checks": done_checks,
        "bu_status": bu_status,
        "bu_promises": bu_promises_count,
        "bu_hypotheses": bu_hypotheses_count,
        "chat_events": len(chat),
    }


def fmt_secs(s):
    if s is None or s == 0:
        return "—"
    if s < 60:
        return f"{s:.0f}s"
    if s < 3600:
        return f"{s // 60:.0f}m{s % 60:.0f}s"
    return f"{s // 3600:.0f}h{(s % 3600) // 60:.0f}m"


def render_table(left: dict, right: dict) -> str:
    """渲染对比表格。"""
    rows = [
        ("批处理 vs 流式 — 任务对比", "—", "—"),
        ("任务 ID", left.get("task_id", "?")[:20], right.get("task_id", "?")[:20]),
        ("", "", ""),
        ("# 速度指标", "", ""),
        ("总耗时", fmt_secs(left.get("total_secs")), fmt_secs(right.get("total_secs"))),
        ("首漏时间", fmt_secs(left.get("time_to_first_vuln")),
         fmt_secs(right.get("time_to_first_vuln"))),
        ("事件总数", str(left.get("chat_events", 0)), str(right.get("chat_events", 0))),
        ("", "", ""),
        ("# 覆盖指标", "", ""),
        ("页面数", str(left.get("page_count", 0)), str(right.get("page_count", 0))),
        ("API 数", str(left.get("api_count", 0)), str(right.get("api_count", 0))),
        ("功能点数", str(left.get("features_count", 0)), str(right.get("features_count", 0))),
        ("checklist 完成率",
         f"{left.get('done_checks', 0)}/{left.get('total_checks', 0)}",
         f"{right.get('done_checks', 0)}/{right.get('total_checks', 0)}"),
        ("", "", ""),
        ("# 漏洞产出", "", ""),
        ("常规漏洞 (vulnerable)",
         str(left.get("vuln_count", 0)), str(right.get("vuln_count", 0))),
        ("XSS 模块发现",
         str(left.get("xss_total", 0)), str(right.get("xss_total", 0))),
        ("内联测试发现 (仅流式)",
         "—", str(right.get("inline_total", 0))),
        ("内联高置信发现 (仅流式)",
         "—", str(right.get("inline_high", 0))),
        ("", "", ""),
        ("# 危害验证 (SRC 标准)", "", ""),
        ("✅ 接受",
         str(left.get("hv_accepted", 0)), str(right.get("hv_accepted", 0))),
        ("⚠️ 边缘",
         str(left.get("hv_borderline", 0)), str(right.get("hv_borderline", 0))),
        ("❌ 拒收",
         str(left.get("hv_rejected", 0)), str(right.get("hv_rejected", 0))),
        ("", "", ""),
        ("# 业务理解", "", ""),
        ("状态", left.get("bu_status", "?"), right.get("bu_status", "?")),
        ("识别承诺数",
         str(left.get("bu_promises", 0)), str(right.get("bu_promises", 0))),
        ("生成攻击假设数",
         str(left.get("bu_hypotheses", 0)), str(right.get("bu_hypotheses", 0))),
    ]

    out = []
    out.append("| 指标 | 批处理版 | 流式版 |")
    out.append("|------|---------|--------|")
    for label, a, b in rows:
        if label.startswith("#"):
            out.append(f"| **{label}** | | |")
        elif not label and not a and not b:
            out.append("| | | |")
        else:
            out.append(f"| {label} | {a} | {b} |")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="A/B 模式对比工具")
    parser.add_argument("batch_task", nargs="?", help="批处理版 task_id")
    parser.add_argument("stream_task", nargs="?", help="流式版 task_id")
    parser.add_argument("--batch-dir", default=".",
                        help="批处理项目根目录")
    parser.add_argument("--stream-dir", default=".",
                        help="流式项目根目录")
    args = parser.parse_args()

    batch_dir = Path(args.batch_dir)
    stream_dir = Path(args.stream_dir)

    if not args.batch_task or not args.stream_task:
        # 自动找最新的
        for d, label in [(batch_dir, "批处理"), (stream_dir, "流式")]:
            tasks_dir = d / "data/tasks"
            if not tasks_dir.exists():
                print(f"⚠️ {label}: 数据目录不存在 {tasks_dir}")
                continue
            tasks = sorted(tasks_dir.glob("task_*-sitemap.json"),
                           key=lambda p: p.stat().st_mtime, reverse=True)
            if tasks:
                tid = tasks[0].name.replace("-sitemap.json", "")
                print(f"  {label} 最新 task: {tid}")
                if label == "批处理" and not args.batch_task:
                    args.batch_task = tid
                if label == "流式" and not args.stream_task:
                    args.stream_task = tid
            else:
                print(f"  {label}: 无任务数据")

    if not args.batch_task or not args.stream_task:
        print("❌ 找不到可对比的任务,请手动传 task_id")
        sys.exit(1)

    print()
    print(f"📊 对比任务:")
    print(f"  批处理版: {batch_dir} / {args.batch_task}")
    print(f"  流式版:   {stream_dir} / {args.stream_task}")
    print()

    left = extract_metrics(batch_dir, args.batch_task, "批处理")
    right = extract_metrics(stream_dir, args.stream_task, "流式")

    if left.get("_missing"):
        print(f"⚠️ 批处理任务 {args.batch_task} 数据缺失")
    if right.get("_missing"):
        print(f"⚠️ 流式任务 {args.stream_task} 数据缺失")

    print(render_table(left, right))
    print()
    print("# 关键观察点")
    print(f"  - 速度: 流式{'更快' if (right.get('time_to_first_vuln') or 999999) < (left.get('time_to_first_vuln') or 999999) else '更慢'} 出第一个漏洞")
    if right.get("inline_total", 0) > 0:
        print(f"  - 流式独有: {right['inline_total']} 个内联测试候选 ({right.get('inline_high', 0)} 高置信)")
    print(f"  - SRC 收录: 批处理 {left.get('hv_accepted', 0)} vs 流式 {right.get('hv_accepted', 0)}")


if __name__ == "__main__":
    main()
