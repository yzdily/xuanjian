"""§3.1：覆盖率闸门 L6–L10 + L-NOVEL。"""
from __future__ import annotations

from core.loops.coverage_gate import (
    ERROR,
    WARNING,
    GateResult,
    gate_exit_code,
    run_coverage_gate,
)


def test_l6_error_when_expected_missing_in_actual():
    ledger = {"expected": [{"key": "a"}, {"key": "b"}], "matrix": [{"key": "a"}]}
    res = run_coverage_gate(ledger, [], [])
    l6 = [r for r in res if r.level == "L6"]
    assert l6 and l6[0].severity == ERROR and l6[0].passed is False


def test_l6_skipped_when_no_expected():
    assert not [r for r in run_coverage_gate({}, [], []) if r.level == "L6"]


def test_l7_error_when_payloads_lt_two():
    res = run_coverage_gate({}, [{"rule": "sqli", "payloads": ["p1"]}], [])
    l7 = [r for r in res if r.level == "L7"]
    assert l7 and l7[0].severity == ERROR


def test_l7_passes_with_two_payloads():
    res = run_coverage_gate({}, [{"rule": "sqli", "payloads": ["p1", "p2"]}], [])
    assert not [r for r in res if r.level == "L7"]


def test_l8_error_on_short_rationale():
    res = run_coverage_gate({}, [], [{"rationale": "N/A"}])
    l8 = [r for r in res if r.level == "L8"]
    assert l8 and l8[0].severity == ERROR


def test_l8_error_on_missing_rationale():
    res = run_coverage_gate({}, [], [{"method": "GET"}])
    assert [r for r in res if r.level == "L8"]


def test_l9_warning_post_without_body():
    res = run_coverage_gate(
        {}, [], [{"rationale": "x" * 25, "method": "POST", "body_params": None}]
    )
    l9 = [r for r in res if r.level == "L9"]
    assert l9 and l9[0].severity == WARNING


def test_l9_no_warning_post_with_body():
    res = run_coverage_gate(
        {}, [], [{"rationale": "x" * 25, "method": "POST", "body_params": {"a": 1}}]
    )
    assert not [r for r in res if r.level == "L9"]


def test_l10_warning_when_points_incomplete():
    res = run_coverage_gate(
        {}, [], [{"rationale": "x" * 25, "target_injection_points": ["body"]}]
    )
    l10 = [r for r in res if r.level == "L10"]
    assert l10 and l10[0].severity == WARNING


def test_l10_passes_when_all_points():
    res = run_coverage_gate(
        {}, [], [{"rationale": "x" * 25,
                  "target_injection_points": ["header", "path", "body"]}]
    )
    assert not [r for r in res if r.level == "L10"]


def test_l_novel_warning_for_array_param_business_flow():
    res = run_coverage_gate(
        {}, [], [{"rationale": "x" * 25, "has_array_param": True,
                  "is_business_flow": True}]
    )
    novel = [r for r in res if r.level == "L-NOVEL"]
    assert novel and novel[0].severity == WARNING


def test_exit_code_one_on_error():
    res = [GateResult("L6", ERROR, False)]
    assert gate_exit_code(res) == 1


def test_exit_code_zero_on_warning_only():
    res = [GateResult("L9", WARNING, False), GateResult("L10", WARNING, False)]
    assert gate_exit_code(res) == 0


def test_exit_code_zero_when_empty():
    assert gate_exit_code([]) == 0
    assert gate_exit_code(None) == 0
