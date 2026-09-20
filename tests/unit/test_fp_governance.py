"""§2.6.6 误报治理闭环：规则过宽 + 高危不可自动抑制 + 抑制审计。"""
from __future__ import annotations

from core.loops.fp_governance import (
    evaluate_rule_breadth,
    decide_suppression,
    audit_suppression,
    DECISION_AUTO_SUPPRESS,
    DECISION_REQUIRE_CONFIRM,
    DECISION_BLOCK_SUPPRESS,
    HIGH_SEVERITY,
)


# ---- evaluate_rule_breadth ----

def test_rule_too_broad():
    """规则命中 ≥50% → 过宽告警。"""
    r = evaluate_rule_breadth(rule_hits=6, total_findings=10)
    assert r["too_broad"] is True
    assert r["ratio"] == 0.6


def test_rule_acceptable():
    """规则命中 <50% → 宽度可接受。"""
    r = evaluate_rule_breadth(rule_hits=3, total_findings=10)
    assert r["too_broad"] is False
    assert r["ratio"] == 0.3


def test_rule_breadth_no_findings():
    """无 finding → 无法评估。"""
    r = evaluate_rule_breadth(rule_hits=0, total_findings=0)
    assert r["too_broad"] is False


def test_rule_breadth_threshold_boundary():
    """恰好等于阈值 → 过宽（≥）。"""
    r = evaluate_rule_breadth(rule_hits=5, total_findings=10)
    assert r["too_broad"] is True


# ---- decide_suppression ----

def test_block_high_unconfirmed():
    """高危 finding 未确认 → 禁止抑制（防漏报）。"""
    finding = {"severity": "Critical", "cwe": "CWE-862"}
    r = decide_suppression(finding, fp_rule={"pattern": "x", "hit_count": 1})
    assert r["decision"] == DECISION_BLOCK_SUPPRESS


def test_block_high_unconfirmed_no_rule():
    """高危 finding 无规则 → 仍禁止抑制。"""
    finding = {"severity": "High"}
    r = decide_suppression(finding, fp_rule=None)
    assert r["decision"] == DECISION_BLOCK_SUPPRESS


def test_require_confirm_high_confirmed():
    """高危 finding 已确认 → 须复核（不直接 auto_suppress）。"""
    finding = {"severity": "High"}
    r = decide_suppression(finding, fp_rule={"pattern": "x", "hit_count": 1}, confirmed=True)
    assert r["decision"] == DECISION_REQUIRE_CONFIRM


def test_auto_suppress_low_precise_rule():
    """低危 + 规则精确 → 自动抑制。"""
    finding = {"severity": "Low"}
    r = decide_suppression(finding, fp_rule={"pattern": "x", "hit_count": 1})
    assert r["decision"] == DECISION_AUTO_SUPPRESS


def test_require_confirm_low_no_rule():
    """中低危 + 无规则 → 须确认。"""
    finding = {"severity": "Medium"}
    r = decide_suppression(finding, fp_rule=None)
    assert r["decision"] == DECISION_REQUIRE_CONFIRM


def test_require_confirm_low_broad_rule():
    """中低危 + 规则过宽（命中≥10）→ 须确认。"""
    finding = {"severity": "Low"}
    r = decide_suppression(finding, fp_rule={"pattern": "x", "hit_count": 15})
    assert r["decision"] == DECISION_REQUIRE_CONFIRM
    assert r["rule_too_broad"] is True


def test_auto_suppress_medium_precise():
    """中危 + 规则精确 → 自动抑制。"""
    finding = {"severity": "Medium"}
    r = decide_suppression(finding, fp_rule={"pattern": "x", "hit_count": 2})
    assert r["decision"] == DECISION_AUTO_SUPPRESS


def test_severity_case_insensitive():
    """严重度大小写不敏感。"""
    finding = {"severity": "critical"}
    r = decide_suppression(finding)
    assert r["decision"] == DECISION_BLOCK_SUPPRESS


def test_severity_from_level_field():
    """兼容 level 字段。"""
    finding = {"level": "high"}
    r = decide_suppression(finding)
    assert r["decision"] == DECISION_BLOCK_SUPPRESS


# ---- audit_suppression ----

def test_audit_no_fn_risk():
    """有拦截 + 无待确认 → 无漏报风险。"""
    findings = [
        {"decision": DECISION_AUTO_SUPPRESS},
        {"decision": DECISION_BLOCK_SUPPRESS},
    ]
    r = audit_suppression(findings, high_severity_blocked=1)
    assert r["fn_risk"] is False
    assert r["auto_suppressed"] == 1
    assert r["block_suppressed"] == 1


def test_audit_fn_risk_pending_confirm():
    """有待确认 + 无拦截 + 无高危拦截 → 漏报风险。"""
    findings = [
        {"decision": DECISION_AUTO_SUPPRESS},
        {"decision": DECISION_REQUIRE_CONFIRM},
    ]
    r = audit_suppression(findings, high_severity_blocked=0)
    assert r["fn_risk"] is True
    assert r["require_confirm"] == 1


def test_audit_no_fn_risk_when_blocked():
    """有待确认但有高危拦截 → 无漏报风险。"""
    findings = [
        {"decision": DECISION_REQUIRE_CONFIRM},
        {"decision": DECISION_BLOCK_SUPPRESS},
    ]
    r = audit_suppression(findings, high_severity_blocked=1)
    assert r["fn_risk"] is False


def test_audit_empty():
    """空列表 → 无漏报风险。"""
    r = audit_suppression([], 0)
    assert r["fn_risk"] is False
    assert r["auto_suppressed"] == 0
