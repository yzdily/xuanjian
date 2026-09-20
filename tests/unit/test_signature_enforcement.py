"""§2.6.2 / G11：签名校验有效性（篡改 sign 比对）。"""
from __future__ import annotations

from core.loops.signature_enforcement import verify_signature


def test_tampered_rejected_means_enforced():
    ok = {"http_code": 200, "body": "data"}
    bad = {"http_code": 401, "body": "sign error"}
    r = verify_signature(ok, bad)
    assert r["enforced"] is True
    assert r["cwe"] is None


def test_tampered_identical_means_not_enforced():
    # 篡改 sign 后仍 200 且数据一致 → 签名形同虚设
    ok = {"http_code": 200, "body": '{"uid":1}'}
    bad = {"http_code": 200, "body": '{"uid":1}'}
    r = verify_signature(ok, bad)
    assert r["enforced"] is False
    assert r["cwe"] == "CWE-345/347"


def test_tampered_different_is_inconclusive():
    ok = {"http_code": 200, "body": "A"}
    bad = {"http_code": 200, "body": "B"}
    r = verify_signature(ok, bad)
    assert r["enforced"] is True  # 证据不足不判漏洞


def test_403_tampered_means_enforced():
    r = verify_signature({"http_code": 200, "body": "x"},
                         {"http_code": 403, "body": "forbidden"})
    assert r["enforced"] is True


def test_empty_original_body_not_flagged():
    # 原始就无数据时不做"一致"判定
    r = verify_signature({"http_code": 200, "body": ""},
                         {"http_code": 200, "body": ""})
    assert r["enforced"] is True


def test_non_dict_inputs_safe():
    r = verify_signature(None, None)
    assert r["enforced"] is True
