# -*- coding: utf-8 -*-
"""
文件名: chain_render.py
描述: 攻击链报告渲染 —— 把 match_all 产出的 ChainMatch 列表渲染为 markdown，
      落盘 data/scan_artifacts/attack_chain_report.md（方案 v4 §5.6）。
      落盘范式复用 matrix_render.write_matrix_report（mkdir + write_text utf-8，
      失败 log.warning 返回空串，不影响主报告）。
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

__all__ = ["render_attack_chains", "write_attack_chain_report"]

log = logging.getLogger("testflow.chain_render")

# 三态符号（对齐 matrix_render.CELL_SYMBOLS 五态格视觉语言）
_STATE_SYMBOLS: dict[str, str] = {
    "confirmed": "✓",
    "open_proof_gap": "⚠",
    "missing": "∅",
}

_LINK_LABELS: dict[str, str] = {
    "value_pool": "值池",
    "capability": "能力跃迁",
    "implicit": "隐式(降档)",
    "none": "入口",
}

# severity 列序（高 → 低，对齐 chain_engine._SEV_WEIGHT）
_SEV_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_key(cm: Any) -> tuple[int, float]:
    """排序键（§5.5）：severity 权重 × completeness——match_all 已排，此处兜底稳定序。"""
    return (_SEV_ORDER.get(str(getattr(cm, "severity", "")), 9), -float(getattr(cm, "completeness", 0.0)))


def _hop_line(idx: int, hop: Any) -> str:
    """单跳渲染：状态 + 衔接方式 + 命中 URL + 证据（flow_id 可回放，§3v3-3）。"""
    state = str(getattr(hop, "state", "missing"))
    sym = _STATE_SYMBOLS.get(state, "∅")
    link = _LINK_LABELS.get(str(getattr(hop, "link_kind", "none")), "入口")
    matched = getattr(hop, "matched", None)
    url = str(getattr(matched, "url", "") or "")[:80]
    vt = str(getattr(matched, "vuln_type", "") or "") or str(getattr(hop, "role", "") or "")
    parts = [f"{idx}. {sym} `{hop.id}`（{vt}）", f"衔接: {link}"]
    if url:
        parts.append(f"证据: {url}")
    flow_id = str(getattr(hop, "evidence_flow_id", "") or "") or (
        str(getattr(matched, "evidence_flow_id", "") or "") if matched else "")
    if flow_id:
        parts.append(f"[flow:{flow_id}]")
    if state == "open_proof_gap":
        parts.append("⚠ partial——证据不完整，需人工复核")
    if state == "missing":
        parts.append("∅ 未命中——整链不报成立，仅展示缺口")
    return " — ".join(parts)


def render_attack_chains(camps: list[Any], session: Any = None) -> str:
    """渲染攻击链 markdown（纯函数，不落盘）。

    camps: chain_engine.match_all 产出的 ChainMatch 列表（已按 severity×completeness 降序）。
    """
    lines: list[str] = []
    lines.append("## 攻击链分析（链式规则）\n")
    if not camps:
        lines.append("（未命中任何链模板——单点发现未构成 2 跳以上串联）\n")
        return "\n".join(lines)

    lines.append(f"共命中 **{len(camps)}** 条攻击链（按 severity × 完整度降序）。\n")

    for i, cm in enumerate(sorted(camps, key=_sort_key), 1):
        completeness = float(getattr(cm, "completeness", 0.0))
        partial = "⚠ partial" if completeness < 1.0 else "完整链"
        lines.append(f"### {i}. {getattr(cm, 'name', cm.chain_id)}（`{cm.chain_id}`）\n")
        lines.append(f"- **severity**: `{getattr(cm, 'severity', 'info')}`　"
                     f"**完整度**: {len(getattr(cm, 'hops', []))} 跳 × {completeness:.0%} → {partial}")
        lines.append("")
        for j, hop in enumerate(getattr(cm, "hops", []), 1):
            lines.append(_hop_line(j, hop))
        value_pool = list(getattr(cm, "value_pool", None) or [])
        if value_pool:
            fields = ", ".join(str(vp.get("field", "?")) for vp in value_pool[:6])
            lines.append(f"- **值池字段**: {fields}" + ("…" if len(value_pool) > 6 else ""))
        lines.append("")

    lines.append("---")
    lines.append("✓ confirmed  ⚠ open_proof_gap（证据不完整）  ∅ missing（未命中）")
    lines.append("\n> 反证铁律：任一跳命中 counter_evidence → 该跳判 ruled_out，链坍缩不报成立；")
    lines.append("> 只串同一 session / 同一 target 内的 finding（作用域隔离），跨域/幽灵端点不参与串联。")
    return "\n".join(lines)


def write_attack_chain_report(camps: list[Any], session: Any = None) -> str:
    """渲染并落盘 data/scan_artifacts/attack_chain_report.md，返回路径（失败返回空串）。"""
    try:
        content = render_attack_chains(camps, session)
        out_dir = Path("data/scan_artifacts")
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "attack_chain_report.md"
        path.write_text(content, encoding="utf-8")
        return str(path)
    except Exception as exc:
        log.warning("攻击链报告落盘失败: %s", exc)
        return ""
