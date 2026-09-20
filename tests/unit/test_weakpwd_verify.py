"""§2.6.6 弱口令核验：登录三态 + 覆盖矩阵 + 凭证泄露。"""
from __future__ import annotations

from core.loops.weakpwd_verify import (
    classify_login_result,
    verify_weakpwd_coverage,
    detect_credential_leak,
    evaluate_weakpwd_chain,
    CWE_WEAK_PASSWORD,
    CWE_DEFAULT_CREDS,
    CWE_INFO_EXPOSURE,
    LOGIN_SUCCESS,
    LOGIN_REDIRECT_FAKE,
    LOGIN_BLOCKED,
    WEAKPWD_DEFAULT,
    WEAKPWD_EMPTY,
    WEAKPWD_COMMON,
)


def _cwes(findings):
    return [f["cwe"] for f in findings]


# ---- classify_login_result ----

def test_login_success_token():
    """200 + token → 真登录成功。"""
    resp = {"http_code": 200, "body": '{"token":"abc123"}'}
    r = classify_login_result(resp)
    assert r["result"] == LOGIN_SUCCESS
    assert r["cwe"] == CWE_WEAK_PASSWORD


def test_login_success_code0():
    """200 + "code":0 → 真登录成功。"""
    resp = {"http_code": 200, "body": '{"code":0,"msg":"ok"}'}
    r = classify_login_result(resp)
    assert r["result"] == LOGIN_SUCCESS


def test_login_success_chinese():
    """200 + 登录成功 → 真登录成功。"""
    resp = {"http_code": 200, "body": "登录成功"}
    r = classify_login_result(resp)
    assert r["result"] == LOGIN_SUCCESS


def test_login_redirect_fake():
    """302 重定向 → 假成功（非真登录）。"""
    resp = {"http_code": 302, "body": "redirect to /home"}
    r = classify_login_result(resp)
    assert r["result"] == LOGIN_REDIRECT_FAKE
    assert r["cwe"] is None


def test_login_blocked_401():
    """401 → 被拒。"""
    resp = {"http_code": 401, "body": "unauthorized"}
    r = classify_login_result(resp)
    assert r["result"] == LOGIN_BLOCKED


def test_login_blocked_403():
    """403 → 被拒。"""
    resp = {"http_code": 403, "body": "forbidden"}
    r = classify_login_result(resp)
    assert r["result"] == LOGIN_BLOCKED


def test_login_blocked_200_failure_signal():
    """200 但含失败标志 → 被拒。"""
    resp = {"http_code": 200, "body": '{"error":"password wrong"}'}
    r = classify_login_result(resp)
    assert r["result"] == LOGIN_BLOCKED


def test_login_blocked_200_no_signal():
    """200 无成功/失败标志 → 保守判 blocked（防误报）。"""
    resp = {"http_code": 200, "body": "some random content"}
    r = classify_login_result(resp)
    assert r["result"] == LOGIN_BLOCKED


# ---- verify_weakpwd_coverage ----

def test_coverage_pass_all_three():
    """三类全测 → 覆盖率 100% → pass。"""
    tested = {WEAKPWD_DEFAULT, WEAKPWD_EMPTY, WEAKPWD_COMMON}
    r = verify_weakpwd_coverage(tested)
    assert r["pass"] is True
    assert r["coverage"] == 1.0
    assert r["missing"] == []


def test_coverage_pass_two_thirds():
    """测 2/3 类 → 覆盖率 67% → pass（≥0.6）。"""
    tested = {WEAKPWD_DEFAULT, WEAKPWD_COMMON}
    r = verify_weakpwd_coverage(tested)
    assert r["pass"] is True
    assert r["coverage"] > 0.6
    assert WEAKPWD_EMPTY in r["missing"]


def test_coverage_fail_one_third():
    """只测 1/3 类 → 覆盖率 33% → fail。"""
    tested = {WEAKPWD_DEFAULT}
    r = verify_weakpwd_coverage(tested)
    assert r["pass"] is False
    assert r["coverage"] < 0.6


def test_coverage_fail_empty():
    """未测任何类 → 覆盖率 0% → fail。"""
    r = verify_weakpwd_coverage(set())
    assert r["pass"] is False
    assert r["coverage"] == 0.0
    assert len(r["missing"]) == 3


# ---- detect_credential_leak ----

def test_credential_leak_password():
    """响应含 password → 泄露。"""
    resp = {"http_code": 200, "body": '{"password":"p@ss"}'}
    r = detect_credential_leak(resp)
    assert r["leaked"] is True
    assert r["cwe"] == CWE_INFO_EXPOSURE


def test_credential_leak_secret():
    """响应含 secret → 泄露。"""
    resp = {"http_code": 200, "body": "api_secret=xxx"}
    r = detect_credential_leak(resp)
    assert r["leaked"] is True


def test_credential_no_leak():
    """响应无凭证指纹 → 不泄露。"""
    resp = {"http_code": 200, "body": '{"token":"abc"}'}
    r = detect_credential_leak(resp)
    assert r["leaked"] is False


# ---- evaluate_weakpwd_chain ----

def test_chain_success_no_leak():
    """登录成功 + 无泄露 → 仅弱口令 finding。"""
    resp = {"http_code": 200, "body": '{"token":"abc"}'}
    r = evaluate_weakpwd_chain(resp, WEAKPWD_DEFAULT)
    assert r["result"] == LOGIN_SUCCESS
    assert r["leaked"] is False
    assert len(r["findings"]) == 1
    assert _cwes(r["findings"]) == [CWE_DEFAULT_CREDS]


def test_chain_success_with_leak():
    """登录成功 + 凭证泄露 → 弱口令 + 凭证泄露 两个 finding。"""
    resp = {"http_code": 200, "body": '{"token":"abc","password":"p@ss"}'}
    r = evaluate_weakpwd_chain(resp, WEAKPWD_COMMON)
    assert r["result"] == LOGIN_SUCCESS
    assert r["leaked"] is True
    assert len(r["findings"]) == 2
    cwes = _cwes(r["findings"])
    assert CWE_WEAK_PASSWORD in cwes
    assert CWE_INFO_EXPOSURE in cwes


def test_chain_blocked_no_finding():
    """登录被拒 → 无 finding。"""
    resp = {"http_code": 401, "body": "unauthorized"}
    r = evaluate_weakpwd_chain(resp, WEAKPWD_DEFAULT)
    assert r["result"] == LOGIN_BLOCKED
    assert r["findings"] == []


def test_chain_redirect_no_finding():
    """重定向假成功 → 无 finding（防误报）。"""
    resp = {"http_code": 302, "body": "redirect"}
    r = evaluate_weakpwd_chain(resp, WEAKPWD_DEFAULT)
    assert r["result"] == LOGIN_REDIRECT_FAKE
    assert r["findings"] == []
