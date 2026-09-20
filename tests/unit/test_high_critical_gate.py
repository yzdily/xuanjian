"""§3.5：High/Critical 6 条验收门（降级不删除）。"""
from __future__ import annotations

from core.loops.high_critical_gate import (
    HIGH_CRITICAL_RULES,
    apply_downgrade,
    evaluate_high_critical,
)


def test_upload_without_readback_demoted():
    ok, reason = evaluate_high_critical(
        {"severity": "high", "category": "upload", "readback": False}
    )
    assert ok is False and reason == HIGH_CRITICAL_RULES[0]


def test_xss_without_exec_confirmed_demoted():
    ok, reason = evaluate_high_critical(
        {"severity": "high", "category": "xss", "exec_confirmed": False}
    )
    assert ok is False and reason == HIGH_CRITICAL_RULES[1]


def test_upload_with_readback_passes():
    ok, _ = evaluate_high_critical(
        {"severity": "high", "category": "upload", "readback": True}
    )
    assert ok is True


def test_authz_without_three_identities_demoted():
    ok, reason = evaluate_high_critical(
        {"severity": "high", "category": "idor", "identities": ["noauth", "low"]}
    )
    assert ok is False and reason == HIGH_CRITICAL_RULES[2]


def test_authz_with_three_identities_passes():
    ok, _ = evaluate_high_critical(
        {"severity": "high", "category": "idor",
         "identities": ["noauth", "low", "high"]}
    )
    assert ok is True


def test_business_denied_status_demoted():
    ok, reason = evaluate_high_critical(
        {"severity": "high", "category": "other", "business_code": "401"}
    )
    assert ok is False and reason == HIGH_CRITICAL_RULES[3]


def test_chain_without_terminal_evidence_demoted():
    ok, reason = evaluate_high_critical(
        {"severity": "high", "is_chain": True, "terminal_evidence": None}
    )
    assert ok is False and reason == HIGH_CRITICAL_RULES[4]


def test_critical_requires_confidence_above_inferred():
    ok, reason = evaluate_high_critical(
        {"severity": "critical", "confidence": "inferred"}
    )
    assert ok is False and reason == HIGH_CRITICAL_RULES[5]


def test_critical_with_observed_passes():
    ok, _ = evaluate_high_critical(
        {"severity": "critical", "confidence": "observed"}
    )
    assert ok is True


def test_medium_never_demoted():
    ok, reason = evaluate_high_critical({"severity": "medium"})
    assert ok is True and reason == ""


def test_apply_downgrade_sets_preliminary():
    findings = [
        {"severity": "high", "category": "upload", "readback": False},
        {"severity": "high", "category": "upload", "readback": True},
        {"severity": "low"},
    ]
    out = apply_downgrade(findings)
    assert out[0]["severity"] == "preliminary"
    assert out[0]["downgraded"] is True
    assert out[1]["severity"] == "high"
    assert out[2]["severity"] == "low"


def test_apply_downgrade_skips_non_dict():
    assert apply_downgrade(["oops", None]) == []
