"""F15 反误报三态闭包单元测试。"""
from __future__ import annotations

import pytest

from core.harm_validation.validator import (
    Verdict, validate_ruled_out, three_state_verdict,
    INSUFFICIENT_RULED_OUT_PATTERNS,
)


class TestValidateRuledOut:
    def test_valid_reason(self):
        assert validate_ruled_out("confirmed input validation at all entry points")

    def test_empty_reason(self):
        assert not validate_ruled_out("")

    def test_generic_library_trust(self):
        assert not validate_ruled_out("uses generic_library_trust for safety")

    def test_control_on_other_path(self):
        assert not validate_ruled_out("control_on_other_path prevents it")

    def test_fail_open_present(self):
        assert not validate_ruled_out("fail_open_present in the flow")

    def test_safe_sibling_assumption(self):
        assert not validate_ruled_out("safe_sibling_assumption applies")

    def test_missing_information(self):
        assert not validate_ruled_out("missing_information about the target")

    def test_difficulty_only(self):
        assert not validate_ruled_out("difficulty_only prevents exploitation")

    def test_configurability_only(self):
        assert not validate_ruled_out("configurability_only means it can be disabled")

    def test_internal_only(self):
        assert not validate_ruled_out("internal_only network access")


class TestThreeStateVerdict:
    def test_accepted_to_confirmed(self):
        assert three_state_verdict("accepted") == Verdict.CONFIRMED

    def test_rejected_with_valid_reason(self):
        assert three_state_verdict("rejected", "input validation at sink") == Verdict.RULED_OUT

    def test_rejected_with_insufficient_reason(self):
        assert three_state_verdict("rejected", "generic_library_trust") == Verdict.OPEN_PROOF_GAP

    def test_borderline_to_open_proof_gap(self):
        assert three_state_verdict("borderline") == Verdict.OPEN_PROOF_GAP

    def test_empty_verdict_to_open_proof_gap(self):
        assert three_state_verdict("") == Verdict.OPEN_PROOF_GAP

    def test_all_insufficient_patterns(self):
        for pattern in INSUFFICIENT_RULED_OUT_PATTERNS:
            assert three_state_verdict("rejected", pattern) == Verdict.OPEN_PROOF_GAP, \
                f"pattern {pattern} should map to OPEN_PROOF_GAP"
