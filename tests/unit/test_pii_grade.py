"""§2.6.4：PII 字段分级（S1/S2/S3 + 脱敏降档 + 空值单列）。"""
from __future__ import annotations

from core.loops.pii_grade import grade_many, grade_pii, severity_for


def test_id_card_is_s1():
    assert grade_pii("11010519491231002X") == "S1"


def test_bank_card_is_s1():
    assert grade_pii("6222021234567890123") == "S1"


def test_credential_kv_is_s1():
    assert grade_pii('password: Secret123') == "S1"


def test_phone_is_s2():
    assert grade_pii("13812345678") == "S2"


def test_email_is_s2():
    assert grade_pii("a.b@example.com") == "S2"


def test_masked_downgrades():
    assert grade_pii("156****66") == "masked"
    assert severity_for("masked") == "info"


def test_empty_values():
    assert grade_pii("") == "empty"
    assert grade_pii(None) == "empty"
    assert grade_pii("   ") == "empty"
    assert severity_for("empty") == "info"


def test_plain_text_is_s3():
    assert grade_pii("some free text") == "S3"
    assert severity_for("S3") == "low"


def test_severity_mapping():
    assert severity_for("S1") == "high"
    assert severity_for("S2") == "medium"
    assert severity_for("S3") == "low"
    assert severity_for("unknown-grade") == "info"


def test_grade_many():
    out = grade_many(["13812345678", "156****66", ""])
    assert out["13812345678"] == "S2"
    assert out["156****66"] == "masked"
    assert out[""] == "empty"
