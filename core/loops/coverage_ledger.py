"""G4 — 端点×漏洞类型覆盖账本 + 未覆盖门控（F14 钩入层）。

对标参考：H:\\api-pentest-extension\\skills\\api-pentest-workflow\\scripts\\coverage_ledger.py
  - 双账本对账（save 默认 coverage_audit.json）
  - detect_gaps 增 per_surface_expected / per_surface_missing
  - 报告"未覆盖声明"强制章节（GATE 风格）

职责：把 G1（风险域标签）+ G2（接口面）+ G3（期望漏洞类型）+ F14（CoverageEntry）
串成一张"期望 × 实测"对账表，输出：
  - 域级结论表（按风险域聚合 已测/缺失/未覆盖）
  - 未覆盖声明（High 类未覆盖即阻断——GATE 风格门控）
  - 每端点的 per_surface_missing

F14 的 CoverageEntry.outcome 语义：
  reported        — 实测有发现
  no_issue_found  — 实测无问题（干净）
  ruled_out       — 判定不适用（需 evidence）
  not_applicable  — 结构性不适用（需 evidence）
  needs_follow_up — 待跟进（需 evidence）
"负空间"= expected 中 outcome 为 None 的行（漏测）。
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from .coverage_tracker import CoverageEntry, validate_entries
from .coverage_derive import expected_coverage_matrix
from ..endpoint.surface_inventory import build_surface_inventory
from ..endpoint.risk_domain import DOMAIN_LABELS

# 视为"高风险"的漏洞类型——未覆盖即触发门控阻断（Security：High 未测不可放过）
HIGH_RISK_VULN_TYPES = frozenset({
    "sqli", "idor", "bola", "bfla", "ssrf", "rce", "ssti",
    "file_upload_unrestricted", "path_traversal", "broken_object_level_authorization",
})


def build_coverage_ledger(
    surfaces: list[dict[str, Any]],
    coverage_entries: list[CoverageEntry],
) -> dict[str, Any]:
    """构建 (surface × expected_vuln_type) × outcome 对账账本。

    Args:
        surfaces: build_surface_inventory 的 surfaces 字段（已打 G1 标签）。
        coverage_entries: F14 实测 coverage 行（CoverageEntry 列表）。

    Returns:
        dict 含：
          - matrix: 期望矩阵（expected_coverage_matrix 输出）
          - per_surface: 每端点的 expected / recorded / missing
          - by_risk_domain: 域级结论表 {域: {expected, recorded, missing, uncovered_high}}
          - uncovered_high: 高风险未覆盖列表（阻断门控用）
          - validation_errors: F14 条目校验错误（如有）
    """
    # 1) 校验 F14 条目（ruled_out/not_applicable/needs_follow_up 必须有 evidence）
    validation_errors = validate_entries(coverage_entries)

    # 2) 期望矩阵
    matrix = expected_coverage_matrix(surfaces)

    # 3) 实测索引：surface_key → {vuln_type: outcome}
    recorded: dict[str, dict[str, str]] = defaultdict(dict)
    for e in coverage_entries:
        recorded[e.surface][e.risk_area] = e.outcome

    # 4) 逐端点对账
    per_surface: list[dict[str, Any]] = []
    uncovered_high: list[dict[str, str]] = []
    for row in matrix:
        key = row["surface_key"]
        exp_vts = row["expected_vuln_types"]
        rec = recorded.get(key, {})
        missing = [vt for vt in exp_vts if vt not in rec]
        for vt in missing:
            if vt in HIGH_RISK_VULN_TYPES:
                uncovered_high.append({"surface": key, "vuln_type": vt})
        per_surface.append({
            "surface_key": key,
            "risk_domain": row["risk_domain"],
            "expected": exp_vts,
            "recorded": list(rec.keys()),
            "missing": missing,
        })

    # 5) 域级结论表
    by_domain: dict[str, dict[str, Any]] = {}
    for ps in per_surface:
        for dom in ps["risk_domain"]:
            d = by_domain.setdefault(dom, {
                "label": DOMAIN_LABELS.get(dom, dom),
                "expected": 0, "recorded": 0, "missing": 0, "uncovered_high": 0,
            })
            d["expected"] += len(ps["expected"])
            d["recorded"] += len(ps["recorded"])
            d["missing"] += len(ps["missing"])
            d["uncovered_high"] += sum(
                1 for m in ps["missing"] if m in HIGH_RISK_VULN_TYPES
            )

    return {
        "matrix": matrix,
        "per_surface": per_surface,
        "by_risk_domain": dict(sorted(
            by_domain.items(),
            key=lambda kv: -kv[1]["missing"],
        )),
        "uncovered_high": uncovered_high,
        "validation_errors": validation_errors,
    }


def gate_uncovered_high(ledger: dict[str, Any]) -> tuple[bool, str]:
    """G4 门控：高风险漏洞类型未覆盖即阻断（GATE 风格）。

    Returns:
        (passed, reason): passed=False 时 reason 列出阻断项；passed=True 时 reason 为通过语。
    """
    errs = ledger.get("validation_errors") or []
    if errs:
        return False, f"coverage 条目校验失败 {len(errs)} 条：{errs[0][:120]}"
    uh = ledger.get("uncovered_high") or []
    if uh:
        sample = "; ".join(f"{u['surface']}={u['vuln_type']}" for u in uh[:3])
        return False, f"阻断：{len(uh)} 个高风险漏洞类型未覆盖（示例：{sample}）"
    return True, "通过：高风险漏洞类型均已覆盖或已 ruled_out"


def domain_conclusion_table(ledger: dict[str, Any]) -> str:
    """生成域级结论表（Markdown，报告章节用）。"""
    by_dom = ledger.get("by_risk_domain") or {}
    if not by_dom:
        return "_(无端点数据)_"
    lines = [
        "| 风险域 | 期望 | 已测 | 缺失 | 高风险未覆盖 |",
        "|---|---|---|---|---|",
    ]
    for dom, d in by_dom.items():
        flag = "🔴" if d["uncovered_high"] else ("🟡" if d["missing"] else "🟢")
        lines.append(
            f"| {flag} {d['label']} | {d['expected']} | {d['recorded']} | "
            f"{d['missing']} | {d['uncovered_high']} |"
        )
    return "\n".join(lines)


def uncovered_statement(ledger: dict[str, Any]) -> str:
    """生成"未覆盖声明"章节（报告强制章节，对标 GATE-1.5 未覆盖声明）。"""
    per_surface = ledger.get("per_surface") or []
    missing_rows = [ps for ps in per_surface if ps["missing"]]
    if not missing_rows:
        return "**未覆盖声明**：所有端点的期望漏洞类型均已覆盖（reported / no_issue_found / ruled_out）。"
    lines = ["**未覆盖声明**（以下端点存在期望漏洞类型未实测，需补测或显式 ruled_out）："]
    for ps in missing_rows:
        doms = "/".join(ps["risk_domain"])
        lines.append(
            f"- `{ps['surface_key']}` [{doms}] 缺失：{', '.join(ps['missing'])}"
        )
    return "\n".join(lines)


__all__ = [
    "HIGH_RISK_VULN_TYPES",
    "build_coverage_ledger",
    "gate_uncovered_high",
    "domain_conclusion_table",
    "uncovered_statement",
]
