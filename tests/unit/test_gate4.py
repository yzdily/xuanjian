"""§2.6.4 / GATE-4：报告硬校验（溯源 + 禁手写 + severity 一致 + 未覆盖声明）。"""
from __future__ import annotations

from core.report.gate4 import gate4_exit_code, gate4_validate


def _good_report():
    return {
        "verified_findings": [{"id": "f1"}],
        "findings": [{"id": "f1", "severity": "high", "source": "script:sqli"}],
        "severity_by_id": {"f1": "high"},
        "uncovered_declaration": {"未测端点": ["/a", "/b"]},
        "summary": {"total": 1},
    }


def test_valid_report_passes():
    res = gate4_validate(_good_report())
    assert not [r for r in res if r.severity == "ERROR"]
    assert gate4_exit_code(res) == 0


def test_missing_verified_findings_is_error():
    rep = _good_report()
    rep.pop("verified_findings")
    res = gate4_validate(rep)
    assert any(r.level == "G4-1" and r.severity == "ERROR" for r in res)
    assert gate4_exit_code(res) == 1


def test_finding_not_in_verified_is_error():
    rep = _good_report()
    rep["findings"].append({"id": "f2", "severity": "low"})
    res = gate4_validate(rep)
    assert any(r.level == "G4-1" for r in res)


def test_handwritten_entry_is_error():
    rep = _good_report()
    rep["findings"][0]["source"] = "handwritten"
    res = gate4_validate(rep)
    assert any(r.level == "G4-2" and r.severity == "ERROR" for r in res)


def test_severity_mismatch_is_error():
    rep = _good_report()
    rep["severity_by_id"]["f1"] = "medium"  # 门控降级后与报告不一致
    res = gate4_validate(rep)
    assert any(r.level == "G4-3" for r in res)


def test_empty_uncovered_declaration_is_error():
    rep = _good_report()
    rep["uncovered_declaration"] = {}
    res = gate4_validate(rep)
    assert any(r.level == "G4-4" and r.severity == "ERROR" for r in res)


def test_missing_uncovered_declaration_is_error():
    rep = _good_report()
    rep.pop("uncovered_declaration")
    res = gate4_validate(rep)
    assert any(r.level == "G4-4" for r in res)


def test_missing_summary_is_warning_only():
    rep = _good_report()
    rep.pop("summary")
    res = gate4_validate(rep)
    warn = [r for r in res if r.level == "G4-5"]
    assert warn and warn[0].severity == "WARNING"
    assert gate4_exit_code(res) == 0


def test_empty_report_returns_errors():
    assert gate4_exit_code(gate4_validate({})) == 1
    assert gate4_exit_code(gate4_validate(None)) == 1
