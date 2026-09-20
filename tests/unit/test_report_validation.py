"""F16 报告 11 字段 + CVSS 单元测试。"""
from __future__ import annotations

import pytest

from core.harm_validation.render import (
    validate_report, REQUIRED_REPORT_FIELDS,
    _calc_cvss_simple, _calc_cvss_score,
)


class TestRequiredReportFields:
    def test_field_count(self):
        assert len(REQUIRED_REPORT_FIELDS) == 11

    def test_critical_fields_present(self):
        assert "severity_vector" in REQUIRED_REPORT_FIELDS
        assert "poc_script_code" in REQUIRED_REPORT_FIELDS
        assert "remediation_steps" in REQUIRED_REPORT_FIELDS
        assert "evidence" in REQUIRED_REPORT_FIELDS


class TestValidateReport:
    def test_all_fields_present(self):
        report = {f: "value" for f in REQUIRED_REPORT_FIELDS}
        report["severity_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        errors = validate_report(report)
        assert errors == []

    def test_missing_field(self):
        report = {f: "value" for f in REQUIRED_REPORT_FIELDS if f != "title"}
        errors = validate_report(report)
        assert any("title" in e for e in errors)

    def test_missing_multiple_fields(self):
        report = {"title": "test"}
        errors = validate_report(report)
        assert len(errors) >= 10

    def test_cvss_vector_recalculated(self):
        report = {f: "value" for f in REQUIRED_REPORT_FIELDS}
        report["severity_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        validate_report(report)
        assert "severity_score" in report
        assert isinstance(report["severity_score"], (int, float))
        assert report["severity_score"] > 0


class TestCvssCalcSimple:
    def test_high_severity_vector(self):
        score = _calc_cvss_simple("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score >= 9.0  # Critical

    def test_low_severity_vector(self):
        score = _calc_cvss_simple("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L")
        assert score < 3.0  # Low

    def test_missing_av_raises(self):
        with pytest.raises(ValueError, match="AV"):
            _calc_cvss_simple("CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_scope_changed(self):
        score = _calc_cvss_simple("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score >= 9.0

    def test_zero_impact(self):
        score = _calc_cvss_simple("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0
