"""testflow 稀疏矩阵渲染 — 漏洞域 × 接口五态格全图（v3 §〇 0.4 / Stage 5 G6）。

用户承诺③的落点：报告里每条漏洞归到具体接口与域，且**每个接口都有结论**——
矩阵全图遍历 FeaturePoint.risk_domains/domain_status 输出五态格表 +
域级结论 + 部分覆盖声明，落盘 data/scan_artifacts/matrix_report.md。
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

from core.sitemap.models import MatrixOutcome

__all__ = ["render_sparse_matrix", "write_matrix_report", "CELL_SYMBOLS"]

log = logging.getLogger("testflow.matrix_render")

# 五态格符号（对齐 v3 §〇 0.4 UI 视图）
CELL_SYMBOLS: dict[str, str] = {
    MatrixOutcome.REPORTED.value: "✓",
    MatrixOutcome.NEEDS_FOLLOW_UP.value: "⚠",
    MatrixOutcome.NO_ISSUE.value: "✗",
    MatrixOutcome.RULED_OUT.value: "∅",
    MatrixOutcome.NOT_APPLICABLE.value: "—",
}

# bug-legacy 8 域列序（PHASE_ORDER 减 precheck/recon）
DOMAIN_COLUMNS: tuple[str, ...] = (
    "authz", "csrf", "injection", "ssrf", "upload", "file", "business", "config",
)


def _domain_columns_of(fps: Iterable) -> list[str]:
    """实际出现的域按固定列序排（额外域追加在尾部，不丢列）。"""
    present: set[str] = set()
    for fp in fps:
        present.update(getattr(fp, "risk_domains", None) or [])
        present.update((getattr(fp, "domain_status", None) or {}).keys())
    ordered = [d for d in DOMAIN_COLUMNS if d in present]
    ordered += sorted(d for d in present if d.startswith("_") is False and d not in DOMAIN_COLUMNS)
    return ordered


def render_sparse_matrix(sitemap: Any, session: Any = None) -> str:
    """渲染五态格表 markdown（纯函数，不落盘）。

    只渲染"有归属或已定格"的行——纯静态/无归属端点由普查层给 _census 结论，
    不制造 408 格全 — 的噪音。
    """
    features = list(getattr(sitemap, "features", {}).values())
    rows = [fp for fp in features
            if (getattr(fp, "risk_domains", None) or (getattr(fp, "domain_status", None) or {}))]
    cols = _domain_columns_of(rows)

    lines: list[str] = []
    lines.append("## 稀疏矩阵：漏洞域 × 接口（五态格）\n")
    if not rows:
        lines.append("（无归属功能点——本次扫描未启用 testflow 或无可用资产）\n")
        lines.append("✓ verified  ⚠ pending/needs_follow_up  ✗ no_issue  ∅ ruled_out  — not_applicable")
        return "\n".join(lines)

    header = "| 接口 | " + " | ".join(cols) + " |"
    sep = "|---" * (len(cols) + 1) + "|"
    lines.append(header)
    lines.append(sep)
    for fp in rows:
        method, path = "", (getattr(fp, "page_url", "") or "")
        for api_str in (fp.related_apis or []):
            parts = api_str.split(" ", 1)
            if len(parts) == 2 and parts[0].isupper():
                method, path = parts[0], parts[1]
                break
            if len(parts) == 1 and parts[0]:
                method, path = "GET", parts[0]
                break
        status_map = getattr(fp, "domain_status", None) or {}
        cells = []
        for d in cols:
            outcome = status_map.get(d)
            cells.append(CELL_SYMBOLS.get(outcome, " ") if outcome else " ")
        label = f"{method} {path}".strip() or getattr(fp, "name", "?")
        lines.append(f"| {label[:60]} | " + " | ".join(cells) + " |")

    lines.append("")
    lines.append("✓ verified  ⚠ pending/needs_follow_up  ✗ no_issue  ∅ ruled_out  — not_applicable")

    # ---- 域级结论 ----
    lines.append("")
    lines.append("### 域级结论\n")
    for d in cols:
        covered = sum(1 for fp in rows
                      if (getattr(fp, "domain_status", None) or {}).get(d) not in (None, MatrixOutcome.NOT_APPLICABLE.value))
        reported = sum(1 for fp in rows
                       if (getattr(fp, "domain_status", None) or {}).get(d) == MatrixOutcome.REPORTED.value)
        pending = sum(1 for fp in rows
                      if (getattr(fp, "domain_status", None) or {}).get(d) == MatrixOutcome.NEEDS_FOLLOW_UP.value)
        lines.append(f"- **{d}**: 覆盖 {covered} 格 → 产出 {reported}（待跟进 {pending}）")

    # ---- 部分覆盖声明（G6 双数据源）----
    declarations: list[str] = []
    pending_cells = [
        (fp, d) for fp in rows
        for d, s in (getattr(fp, "domain_status", None) or {}).items()
        if s == MatrixOutcome.NEEDS_FOLLOW_UP.value
    ]
    if pending_cells:
        sample = "; ".join(f"{getattr(fp, 'name', fp.id)}×{d}" for fp, d in pending_cells[:5])
        declarations.append(f"LLM/执行者触顶或未闭环格 {len(pending_cells)} 个（需人工复核）：{sample}"
                            + ("…" if len(pending_cells) > 5 else ""))
    auth_surface = str(getattr(session, "auth_surface_mode", "") or "") if session is not None else ""
    if auth_surface == "unauth_only":
        declarations.append("登录面未测：无有效凭证，auth 相位整相位 not_applicable（报告须声明）")
    if getattr(session, "_testflow_waf_degrade", False) if session is not None else False:
        declarations.append("WAF 降级：注入类域在拦截率超阈后降权执行，结论可能保守")
    if declarations:
        lines.append("")
        lines.append("### 部分覆盖声明\n")
        for dcl in declarations:
            lines.append(f"- ⚠️ {dcl}")

    return "\n".join(lines)


def write_matrix_report(sitemap: Any, session: Any = None) -> str:
    """渲染并落盘 data/scan_artifacts/matrix_report.md，返回路径（失败返回空串）。"""
    try:
        content = render_sparse_matrix(sitemap, session)
        out_dir = Path("data/scan_artifacts")
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "matrix_report.md"
        path.write_text(content, encoding="utf-8")
        return str(path)
    except Exception as exc:
        log.warning("稀疏矩阵落盘失败: %s", exc)
        return ""
