"""§3.4：统一判定 schema + 三道门。"""
from __future__ import annotations

from core.verdict import (
    FindingVerdict,
    build_verdict,
    enforce_silent_zero,
    gate_business_code,
    gate_control,
    gate_has_data,
)

_ALWAYS_OK = lambda text: False      # 永不判业务拒绝
_ALWAYS_DENY = lambda text: True     # 永远判业务拒绝


def test_gate_business_code_ok_on_200():
    assert gate_business_code({"http_code": 200, "evidence": "hello"},
                              is_business_deny=_ALWAYS_OK) is True


def test_gate_business_code_false_on_deny_status():
    for code in (401, 403, 500):
        assert gate_business_code({"http_code": code, "evidence": "x"},
                                  is_business_deny=_ALWAYS_OK) is False


def test_gate_business_code_false_on_business_deny_text():
    assert gate_business_code({"http_code": 200, "evidence": "业务失败"},
                              is_business_deny=_ALWAYS_DENY) is False


def test_gate_has_data():
    assert gate_has_data({"data": {"a": 1}}) is True
    assert gate_has_data({"data": ["x"]}) is True
    assert gate_has_data({"data": ""}) is False
    assert gate_has_data({"data": None, "response_body": []}) is False
    assert gate_has_data({}) is False


def test_gate_control_baseline_denied_is_valid():
    # 低权限 baseline 被 401 拦截 → 对照组成立
    assert gate_control({"http_code": 200}, {"http_code": 401}) is True


def test_gate_control_baseline_not_denied_is_limitation():
    # baseline 也是 200 → 无法区分"鉴权失效"还是"接口本就公开"
    assert gate_control({"http_code": 200}, {"http_code": 200}) is False


def test_gate_control_no_baseline_passes():
    assert gate_control({"http_code": 200}, None) is True


def test_build_verdict_vulnerable():
    f = {"http_code": 200, "data": {"id": 1}, "confidence": "confirmed"}
    v = build_verdict(f, baseline={"http_code": 401}, is_business_deny=_ALWAYS_OK)
    assert isinstance(v, FindingVerdict)
    assert v.verdict == "vulnerable"
    assert v.has_data is True
    assert v.confidence == "confirmed"


def test_build_verdict_safe_when_denied():
    f = {"http_code": 403, "data": {}}
    v = build_verdict(f, is_business_deny=_ALWAYS_OK)
    assert v.verdict == "safe"


def test_build_verdict_needs_follow_up_when_no_data():
    f = {"http_code": 200, "data": {}}
    v = build_verdict(f, is_business_deny=_ALWAYS_OK)
    assert v.verdict == "needs_follow_up"


def test_build_verdict_default_confidence_inferred():
    v = build_verdict({"http_code": 200, "data": {"a": 1}},
                      is_business_deny=_ALWAYS_OK)
    assert v.confidence == "inferred"


def test_enforce_silent_zero_triggers():
    assert enforce_silent_zero([], error_rate=0.6) == 1


def test_enforce_silent_zero_no_trigger_low_error_rate():
    assert enforce_silent_zero([], error_rate=0.3) == 0


def test_enforce_silent_zero_no_trigger_with_findings():
    assert enforce_silent_zero([{"a": 1}], error_rate=0.9) == 0


def test_verdict_to_dict_roundtrip():
    v = FindingVerdict(business_code="0", has_data=True, identities=["noauth", "low"])
    d = v.to_dict()
    assert d["business_code"] == "0"
    assert d["identities"] == ["noauth", "low"]
