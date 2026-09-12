"""tests/unit/test_finding_schema.py — 中期 M2 验收。

按 XUANJIAN_ROADMAP_MID_TERM §3.3 5 断言：
1. 完整 finding → ok
2. 缺必填 → fail
3. 非法 severity → fail
4. CWE 映射正确（sqli ∈ A03）
5. CWE 映射错误（SSRF CWE 不在 A03）→ fail
6. LLM 守卫：未通过自动标 rejected
"""
from __future__ import annotations

from core.finding_schema import guard_llm_output, validate
from core.cwe_dict import OWASP_TO_CWE, validate_cwe


def _valid_finding() -> dict:
    return {
        "id": "F-1",
        "owasp_id": "A03",
        "cwe_id": "CWE-89",
        "severity": "high",
        "endpoint": "/api/users",
        "method": "GET",
        "verdict": "confirmed",
    }


def test_valid_finding_passes():
    ok, msg = validate(_valid_finding())
    assert ok is True, msg


def test_missing_required_field_fails():
    f = {"id": "F-2"}  # 缺其他必填
    ok, msg = validate(f)
    assert ok is False
    assert "owasp_id" in msg


def test_invalid_severity_fails():
    f = _valid_finding()
    f["severity"] = "super-critical"
    ok, msg = validate(f)
    assert ok is False
    assert "severity" in msg


def test_cwe_mapping_sqli_in_a03():
    """SQLi CWE-89 属于 OWASP A03 Injection。"""
    ok, msg = validate_cwe("A03", "CWE-89")
    assert ok is True


def test_cwe_mapping_wrong_pair_fails():
    """SSRF CWE-918 不在 A03。"""
    ok, msg = validate_cwe("A03", "CWE-918")
    assert ok is False
    assert "A03" in msg and "CWE-918" in msg


def test_guard_llm_marks_rejected():
    """LLM 产出 finding 缺 owasp_id → guard 自动标 rejected。"""
    bad = {"id": "F-9", "cwe_id": "CWE-89", "severity": "high",
           "endpoint": "/x", "method": "GET", "verdict": "confirmed"}
    out = guard_llm_output(bad)
    assert out["verdict"] == "rejected"
    assert "rejection_reasons" in out


def test_guard_llm_passes_through_valid():
    """合法 finding → guard 直接透传。"""
    f = _valid_finding()
    out = guard_llm_output(f)
    assert out["verdict"] == "confirmed"
    assert "rejection_reasons" not in out


def test_owasp_coverage_full():
    """A01–A10 全部有映射。"""
    for i in range(1, 11):
        key = f"A{i:02d}"
        assert key in OWASP_TO_CWE, f"缺 {key} 映射"
        assert len(OWASP_TO_CWE[key]) > 0, f"{key} 映射为空"
