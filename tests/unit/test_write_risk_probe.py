"""§3.11.3 写接口复合风险：未授权写 + SSRF + 明文凭证 三态×多host。"""
from __future__ import annotations

from core.loops.write_risk_probe import (
    build_ssrf_hosts,
    evaluate_write_risk,
    CWE_MISSING_AUTHZ,
    CWE_SSRF,
    CWE_INFO_EXPOSURE,
)


def _cwes(findings):
    return [f["cwe"] for f in findings]


# ---- build_ssrf_hosts ----

def test_ssrf_hosts():
    """内网探测 host 列表含 5 个，覆盖 169.254.169.254。"""
    hosts = build_ssrf_hosts()
    assert len(hosts) == 5
    assert "169.254.169.254" in hosts
    assert "10.0.0.1" in hosts
    assert "127.0.0.1" in hosts


# ---- evaluate_write_risk ----

def test_write_unauthorized():
    """未授权写 200+数据 → finding CWE-862。"""
    write_resp = {"http_code": 200, "body": '{"id":99,"created":true}'}
    r = evaluate_write_risk(write_resp, [])
    assert r["write_unauthorized"] is True
    assert CWE_MISSING_AUTHZ in _cwes(r["findings"])


def test_write_unauthorized_by_success_hint():
    """未授权写 200+成功标志（无 body 数据）→ CWE-862。"""
    write_resp = {"http_code": 200, "body": "created"}
    r = evaluate_write_risk(write_resp, [])
    assert r["write_unauthorized"] is True
    assert CWE_MISSING_AUTHZ in _cwes(r["findings"])


def test_ssrf_detected():
    """SSRF 探测 200+数据 → finding CWE-918。"""
    write_resp = {"http_code": 403, "body": "forbidden"}
    ssrf_resps = [{"http_code": 200, "body": "internal_meta_data", "host": "10.0.0.1"}]
    r = evaluate_write_risk(write_resp, ssrf_resps)
    assert r["ssrf_detected"] is True
    assert r["write_unauthorized"] is False
    assert CWE_SSRF in _cwes(r["findings"])


def test_credential_leak():
    """SSRF 响应体含 password → finding CWE-200。"""
    write_resp = {"http_code": 403, "body": "forbidden"}
    ssrf_resps = [
        {"http_code": 200, "body": '{"db_password":"p@ss"}', "host": "169.254.169.254"},
    ]
    r = evaluate_write_risk(write_resp, ssrf_resps)
    assert r["credential_leak"] is True
    assert CWE_INFO_EXPOSURE in _cwes(r["findings"])


def test_credential_leak_other_hints():
    """SSRF 响应体含 token/secret → 同样命中 CWE-200。"""
    write_resp = {"http_code": 403, "body": "forbidden"}
    ssrf_resps = [
        {"http_code": 500, "body": "aws token leak", "host": "10.10.10.1"},
    ]
    r = evaluate_write_risk(write_resp, ssrf_resps)
    assert r["credential_leak"] is True
    assert r["ssrf_detected"] is False  # 500 非 SSRF 命中
    assert CWE_INFO_EXPOSURE in _cwes(r["findings"])


def test_write_risk_clean():
    """全部被拒 → 无 finding、三态全 False。"""
    write_resp = {"http_code": 403, "body": "forbidden"}
    ssrf_resps = [
        {"http_code": 403, "body": "blocked", "host": "10.0.0.1"},
        {"http_code": 401, "body": "unauthorized", "host": "169.254.169.254"},
    ]
    r = evaluate_write_risk(write_resp, ssrf_resps)
    assert r["findings"] == []
    assert r["write_unauthorized"] is False
    assert r["ssrf_detected"] is False
    assert r["credential_leak"] is False


def test_write_risk_compound():
    """三态同时命中：未授权写 + SSRF + 明文凭证。"""
    write_resp = {"http_code": 200, "body": '{"created":true}'}
    ssrf_resps = [
        {"http_code": 200, "body": "internal secret=password123", "host": "169.254.169.254"},
    ]
    r = evaluate_write_risk(write_resp, ssrf_resps)
    assert r["write_unauthorized"] is True
    assert r["ssrf_detected"] is True
    assert r["credential_leak"] is True
    cwes = _cwes(r["findings"])
    assert CWE_MISSING_AUTHZ in cwes
    assert CWE_SSRF in cwes
    assert CWE_INFO_EXPOSURE in cwes
