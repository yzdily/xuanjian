"""§4 Phase 2 item 6：report_phase 扩展单元测试。

验证 root_cause 同因合并 + PII 脱敏标记。
"""
from __future__ import annotations

from core.loops.report_phase_enhancements import (
    mark_pii_sanitized,
    merge_findings_by_root_cause,
    sanitize_pii,
)


# ============================================================
# root_cause 同因合并
# ============================================================
def test_merge_same_root_cause():
    findings = [
        {"vuln_type": "SQL注入", "url": "http://x/api/user?id=1",
         "detail": "参数 'id' 存在 SQL 注入", "evidence": "ev1"},
        {"vuln_type": "SQL注入", "url": "http://x/api/user?id=2",
         "detail": "参数 'id' 存在 SQL 注入", "evidence": "ev2"},
        {"vuln_type": "XSS", "url": "http://x/api/user",
         "detail": "参数 'name' 存在 XSS", "evidence": "ev3"},
    ]
    merged = merge_findings_by_root_cause(findings)
    # 同因 SQL 注入合并为 1 条，XSS 保持 1 条 → 共 2 条
    assert len(merged) == 2
    sql_finding = [f for f in merged if f["vuln_type"] == "SQL注入"][0]
    assert sql_finding.get("merged_count") == 2
    assert "ev1" in sql_finding["evidence"] and "ev2" in sql_finding["evidence"]


def test_merge_no_duplicates_unchanged():
    findings = [
        {"vuln_type": "XSS", "url": "http://x/a", "detail": "x", "evidence": "e1"},
        {"vuln_type": "SQL注入", "url": "http://x/b", "detail": "y", "evidence": "e2"},
    ]
    merged = merge_findings_by_root_cause(findings)
    assert len(merged) == 2
    assert all("merged_count" not in f for f in merged)


def test_merge_preserves_order():
    findings = [
        {"vuln_type": "A", "url": "http://x/p1", "detail": "d", "evidence": "1"},
        {"vuln_type": "B", "url": "http://x/p2", "detail": "d", "evidence": "2"},
        {"vuln_type": "A", "url": "http://x/p1", "detail": "d", "evidence": "3"},
    ]
    merged = merge_findings_by_root_cause(findings)
    assert [f["vuln_type"] for f in merged] == ["A", "B"]


# ============================================================
# PII 脱敏
# ============================================================
def test_sanitize_phone():
    text, types = sanitize_pii("phone: 13812345678")
    assert "138****5678" in text
    assert "PHONE" in types


def test_sanitize_id_card():
    text, types = sanitize_pii("id=110101199003078038")
    assert "110101********8038" in text
    assert "ID_CARD" in types


def test_sanitize_email():
    text, types = sanitize_pii("email: real.user@company.cn")
    assert "real.user" not in text
    assert "company.cn" in text
    assert "EMAIL" in types


def test_safe_email_domain_not_masked():
    text, types = sanitize_pii("email: user@example.com")
    assert text == "email: user@example.com"
    assert types == []


def test_sanitize_bank_card():
    text, types = sanitize_pii("card=4111111111111111")
    assert "4111" in text and "1111" in text
    assert "****" in text
    assert "BANK_CARD" in types


def test_sanitize_no_pii():
    text, types = sanitize_pii("no pii here")
    assert text == "no pii here"
    assert types == []


def test_sanitize_multiple_pii():
    text, types = sanitize_pii("phone=13812345678 email=a@b.com id=110101199003078038")
    assert "PHONE" in types and "EMAIL" in types and "ID_CARD" in types


# ============================================================
# mark_pii_sanitized
# ============================================================
def test_mark_pii_sanitized_adds_fields():
    findings = [
        {"vuln_type": "X", "evidence": "phone=13812345678", "detail": "d"},
        {"vuln_type": "Y", "evidence": "clean", "detail": "d"},
    ]
    out = mark_pii_sanitized(findings)
    assert out[0]["pii_sanitized"] is True
    assert out[0]["pii_types"] == ["PHONE"]
    assert "13812345678" not in out[0]["evidence"]
    assert out[1]["pii_sanitized"] is False
    assert out[1]["pii_types"] == []
