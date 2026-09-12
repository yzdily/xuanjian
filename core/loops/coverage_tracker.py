"""F14 — coverage 负空间 + skill_coverage_gaps 缺口检测（0827 E3 强化版）。

strix 核心②：测试范围可审计化。coverage 负空间 = (surface, risk_area, outcome, evidence)。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


VALID_OUTCOMES = frozenset({
    "reported",
    "no_issue_found",
    "ruled_out",
    "not_applicable",
    "needs_follow_up",
})

# outcome 为这些值时必须有 evidence
EVIDENCE_REQUIRED = frozenset({"ruled_out", "not_applicable", "needs_follow_up"})


@dataclass
class CoverageEntry:
    surface: str          # endpoint pattern
    risk_area: str        # vuln_class (e.g. "sqli", "idor")
    outcome: str          # one of VALID_OUTCOMES
    evidence: dict[str, Any] = field(default_factory=dict)
    depth_chain: list[str] = field(default_factory=list)


def validate_entry(entry: CoverageEntry) -> list[str]:
    """校验单条 coverage 条目，返回违规列表。"""
    errors: list[str] = []
    if entry.outcome not in VALID_OUTCOMES:
        errors.append(f"outcome={entry.outcome} 不在合法值 {VALID_OUTCOMES} 中")
    if entry.outcome in EVIDENCE_REQUIRED and not entry.evidence:
        errors.append(
            f"outcome={entry.outcome} 必须有 evidence（不能为空）"
        )
    if not entry.surface:
        errors.append("surface 不能为空")
    if not entry.risk_area:
        errors.append("risk_area 不能为空")
    return errors


def validate_entries(entries: list[CoverageEntry]) -> list[str]:
    """校验全部 coverage 条目。"""
    all_errors: list[str] = []
    for i, e in enumerate(entries):
        errs = validate_entry(e)
        for err in errs:
            all_errors.append(f"[entry {i}] {err}")
    return all_errors


SKILL_ALIASES: dict[str, list[str]] = {
    "sqli": ["sql injection", "sqli"],
    "idor": ["idor", "insecure direct object reference"],
    "xss": ["xss", "cross-site scripting"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "csrf": ["csrf", "cross-site request forgery"],
    "rce": ["rce", "remote code execution"],
    "xxe": ["xxe", "xml external entity"],
    "ssti": ["ssti", "server-side template injection"],
}


def skill_coverage_gaps(
    carried_skills: list[str],
    coverage_entries: list[CoverageEntry],
) -> list[str]:
    """检测 agent 携带的 skill 是否有对应 coverage 行。

    某 skill 无对应 coverage 行 → 标 unrecorded_risk_class（视为未测，非干净）。
    """
    gaps: list[str] = []
    for skill in carried_skills:
        aliases = SKILL_ALIASES.get(skill, [skill])
        has_record = any(
            any(alias in e.risk_area.lower() for alias in aliases)
            for e in coverage_entries
        )
        if not has_record:
            gaps.append(
                f"unrecorded_risk_class: skill={skill} "
                f"无任何 coverage 行（视为未测，非干净）"
            )
    return gaps


__all__ = [
    "CoverageEntry",
    "validate_entry",
    "validate_entries",
    "skill_coverage_gaps",
    "VALID_OUTCOMES",
    "EVIDENCE_REQUIRED",
    "SKILL_ALIASES",
]
