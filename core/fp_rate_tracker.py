"""误报率统计反馈闭环（优化.md 建议9）。

记录「初判漏洞数 vs 核验后真实漏洞数」，按漏洞类型/阶段分维度累计，
持久化到 data/fp_rate_stats.json，反向优化 payload / 判定规则。

数据来源：harm_validation 的 stats（accepted/borderline/rejected）+ 初判总数。
参考：api-pentest-extension/skills/api-pentest-workflow/scripts/fp_rate_tracker.py
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from core.log import get_logger

log = get_logger("fp_rate_tracker")

_DEFAULT_PATH = Path("data/fp_rate_stats.json")


def _load(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning("加载误报率统计失败: %s", e)
    return {"records": [], "by_vuln_type": {}, "by_phase": {}, "updated_at": ""}


def _save(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        log.error("保存误报率统计失败: %s", e)


def record_scan(
    initial_count: int,
    stats: dict[str, int],
    *,
    vuln_type_breakdown: dict[str, dict[str, int]] | None = None,
    phase: str = "",
    scan_id: str = "",
    path: str | Path | None = None,
) -> dict:
    """记录一次扫描的误报率统计。

    Args:
        initial_count: 初判漏洞数（核验前）
        stats: {"accepted": int, "borderline": int, "rejected": int}
        vuln_type_breakdown: 按漏洞类型细分 {vuln_type: {accepted,borderline,rejected,initial}}
        phase: 漏洞阶段（recon/auth/authz/injection/...）
        scan_id: 扫描任务 id
        path: 统计文件路径，默认 data/fp_rate_stats.json

    Returns:
        本次记录的摘要 dict。
    """
    p = Path(path) if path else _DEFAULT_PATH
    data = _load(p)

    accepted = int(stats.get("accepted", 0))
    borderline = int(stats.get("borderline", 0))
    rejected = int(stats.get("rejected", 0))
    verified = accepted
    fp_count = rejected  # 明确拒收 = 误报
    # 误报率：误报 / 初判（初判为 0 时记 0）
    fp_rate = round(fp_count / initial_count, 4) if initial_count > 0 else 0.0
    confirm_rate = round(verified / initial_count, 4) if initial_count > 0 else 0.0

    record = {
        "scan_id": scan_id or datetime.now().strftime("%Y%m%d%H%M%S"),
        "timestamp": datetime.now().isoformat(),
        "phase": phase,
        "initial_count": initial_count,
        "verified_count": verified,
        "borderline_count": borderline,
        "rejected_count": rejected,
        "fp_rate": fp_rate,
        "confirm_rate": confirm_rate,
    }
    data["records"].append(record)
    # 仅保留最近 200 条，避免无限增长
    if len(data["records"]) > 200:
        data["records"] = data["records"][-200:]

    # 累计按漏洞类型
    if vuln_type_breakdown:
        for vt, br in vuln_type_breakdown.items():
            agg = data["by_vuln_type"].setdefault(vt, {
                "initial": 0, "verified": 0, "borderline": 0, "rejected": 0, "scans": 0})
            agg["initial"] += int(br.get("initial", 0))
            agg["verified"] += int(br.get("accepted", 0))
            agg["borderline"] += int(br.get("borderline", 0))
            agg["rejected"] += int(br.get("rejected", 0))
            agg["scans"] += 1
    if phase:
        agg = data["by_phase"].setdefault(phase, {
            "initial": 0, "verified": 0, "borderline": 0, "rejected": 0, "scans": 0})
        agg["initial"] += initial_count
        agg["verified"] += verified
        agg["borderline"] += borderline
        agg["rejected"] += rejected
        agg["scans"] += 1

    data["updated_at"] = datetime.now().isoformat()
    _save(p, data)
    log.info("误报率统计已记录: 初判=%d 核验通过=%d 误报=%d 误报率=%.1f%%",
             initial_count, verified, fp_count, fp_rate * 100)
    return record


def get_stats(path: str | Path | None = None) -> dict:
    """读取累计误报率统计。"""
    p = Path(path) if path else _DEFAULT_PATH
    data = _load(p)

    # 计算汇总
    records = data.get("records", [])
    total_initial = sum(r["initial_count"] for r in records)
    total_verified = sum(r["verified_count"] for r in records)
    total_rejected = sum(r["rejected_count"] for r in records)
    summary = {
        "scans": len(records),
        "total_initial": total_initial,
        "total_verified": total_verified,
        "total_rejected": total_rejected,
        "overall_fp_rate": round(total_rejected / total_initial, 4) if total_initial else 0.0,
        "overall_confirm_rate": round(total_verified / total_initial, 4) if total_initial else 0.0,
    }
    # 各漏洞类型误报率排序（高误报类型优先优化）
    vt_rates = []
    for vt, agg in data.get("by_vuln_type", {}).items():
        ini = agg.get("initial", 0)
        vt_rates.append({
            "vuln_type": vt,
            "initial": ini,
            "verified": agg.get("verified", 0),
            "rejected": agg.get("rejected", 0),
            "fp_rate": round(agg.get("rejected", 0) / ini, 4) if ini else 0.0,
            "scans": agg.get("scans", 0),
        })
    vt_rates.sort(key=lambda x: x["fp_rate"], reverse=True)
    return {
        "summary": summary,
        "by_vuln_type": vt_rates,
        "by_phase": data.get("by_phase", {}),
        "recent_records": records[-10:],
    }


def format_stats_text(path: str | Path | None = None) -> str:
    """格式化为可读文本（供 CLI / 报告引用）。"""
    s = get_stats(path)
    summ = s["summary"]
    lines = [
        "## 误报率统计反馈闭环",
        f"- 累计扫描: {summ['scans']} 次",
        f"- 初判漏洞总数: {summ['total_initial']}",
        f"- 核验通过(真实漏洞): {summ['total_verified']}",
        f"- 误报拒收: {summ['total_rejected']}",
        f"- 整体误报率: {summ['overall_fp_rate']*100:.1f}%",
        f"- 整体确认率: {summ['overall_confirm_rate']*100:.1f}%",
        "",
        "### 按漏洞类型（误报率从高到低，优先优化高误报类型）",
        "| 漏洞类型 | 初判 | 通过 | 误报 | 误报率 | 扫描次数 |",
        "|---|---|---|---|---|---|",
    ]
    for v in s["by_vuln_type"][:15]:
        lines.append(f"| {v['vuln_type']} | {v['initial']} | {v['verified']} | "
                     f"{v['rejected']} | {v['fp_rate']*100:.1f}% | {v['scans']} |")
    return "\n".join(lines)
