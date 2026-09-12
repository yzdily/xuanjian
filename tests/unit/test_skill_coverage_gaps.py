"""F14 coverage 负空间 + 缺口检测单元测试。"""
from __future__ import annotations

import pytest

from core.loops.coverage_tracker import (
    CoverageEntry, validate_entry, validate_entries,
    skill_coverage_gaps, VALID_OUTCOMES, EVIDENCE_REQUIRED,
)


class TestCoverageEntryValidation:
    def test_valid_reported_entry(self):
        entry = CoverageEntry(surface="/api/users", risk_area="idor", outcome="reported")
        assert validate_entry(entry) == []

    def test_valid_no_issue_found(self):
        entry = CoverageEntry(surface="/api/x", risk_area="xss", outcome="no_issue_found")
        assert validate_entry(entry) == []

    def test_ruled_out_requires_evidence(self):
        entry = CoverageEntry(surface="/api/x", risk_area="sqli", outcome="ruled_out")
        errors = validate_entry(entry)
        assert any("evidence" in e for e in errors)

    def test_ruled_out_with_evidence_passes(self):
        entry = CoverageEntry(
            surface="/api/x", risk_area="sqli", outcome="ruled_out",
            evidence={"reason": "parameterized queries confirmed"},
        )
        assert validate_entry(entry) == []

    def test_not_applicable_requires_evidence(self):
        entry = CoverageEntry(surface="/static/*", risk_area="sqli", outcome="not_applicable")
        errors = validate_entry(entry)
        assert any("evidence" in e for e in errors)

    def test_needs_follow_up_requires_evidence(self):
        entry = CoverageEntry(surface="/api/x", risk_area="idor", outcome="needs_follow_up")
        errors = validate_entry(entry)
        assert len(errors) >= 1

    def test_invalid_outcome(self):
        entry = CoverageEntry(surface="/api/x", risk_area="sqli", outcome="invalid")
        errors = validate_entry(entry)
        assert any("outcome" in e for e in errors)

    def test_empty_surface(self):
        entry = CoverageEntry(surface="", risk_area="sqli", outcome="reported")
        errors = validate_entry(entry)
        assert any("surface" in e for e in errors)


class TestSkillCoverageGaps:
    def test_no_gap_when_skill_has_coverage(self):
        entries = [
            CoverageEntry(surface="/api/users", risk_area="SQL Injection", outcome="reported"),
        ]
        gaps = skill_coverage_gaps(["sqli"], entries)
        assert gaps == []

    def test_gap_when_skill_missing(self):
        entries = [
            CoverageEntry(surface="/api/users", risk_area="idor", outcome="reported"),
        ]
        gaps = skill_coverage_gaps(["sqli"], entries)
        assert len(gaps) == 1
        assert "unrecorded_risk_class" in gaps[0]

    def test_multiple_skills_mixed(self):
        entries = [
            CoverageEntry(surface="/api/x", risk_area="sqli", outcome="reported"),
        ]
        gaps = skill_coverage_gaps(["sqli", "xss", "idor"], entries)
        assert len(gaps) == 2  # xss and idor have no coverage

    def test_alias_matching(self):
        entries = [
            CoverageEntry(surface="/api/x", risk_area="Cross-Site Scripting", outcome="reported"),
        ]
        gaps = skill_coverage_gaps(["xss"], entries)
        assert gaps == []

    def test_empty_entries_all_gaps(self):
        gaps = skill_coverage_gaps(["sqli", "idor"], [])
        assert len(gaps) == 2

    def test_unknown_skill_still_checked(self):
        entries = []
        gaps = skill_coverage_gaps(["custom_vuln"], entries)
        assert len(gaps) == 1
        assert "custom_vuln" in gaps[0]
