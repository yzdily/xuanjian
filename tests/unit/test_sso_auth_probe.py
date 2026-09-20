"""§2.5 SSO 专项：Token↔主体绑定 + 主因子推导（技术方案 3.10.1）。"""
from __future__ import annotations

import pytest

from core.loops.sso_auth_probe import (
    evaluate_token_userid_binding,
    derive_primary_credential,
    detect_token_expiry,
    PRIMARY_TOKEN,
    PRIMARY_COOKIE,
    PRIMARY_BOTH,
    PRIMARY_UNKNOWN,
)


# ---- evaluate_token_userid_binding ----

def test_token_userid_binding_bypass_detected():
    """同 token 替换 userid 遍历 victim 返回 200+数据 → 认证绕过。"""
    self_resp = {"http_code": 200, "body": '{"uid":1,"name":"me"}'}
    victim_resps = [
        {"http_code": 200, "body": '{"uid":2,"name":"victim_a"}'},
        {"http_code": 200, "body": '{"uid":3,"name":"victim_b"}'},
    ]
    findings = evaluate_token_userid_binding(self_resp, victim_resps)
    assert len(findings) == 2
    assert findings[0]["cwe"] == "CWE-287+CWE-639"
    assert findings[0]["severity"] == "High"


def test_token_userid_binding_no_bypass_when_denied():
    """victim 请求被拒（401）→ 不报绕过。"""
    self_resp = {"http_code": 200, "body": '{"uid":1}'}
    victim_resps = [{"http_code": 401, "body": "unauthorized"}]
    findings = evaluate_token_userid_binding(self_resp, victim_resps)
    assert len(findings) == 0


def test_token_userid_binding_no_bypass_when_empty():
    """victim 请求 200 但无数据 → 不报绕过。"""
    self_resp = {"http_code": 200, "body": '{"uid":1}'}
    victim_resps = [{"http_code": 200, "body": ""}]
    findings = evaluate_token_userid_binding(self_resp, victim_resps)
    assert len(findings) == 0


def test_token_userid_binding_self_failed_no_findings():
    """自身请求没成功 → 无法判定，不产 finding。"""
    self_resp = {"http_code": 401, "body": ""}
    victim_resps = [{"http_code": 200, "body": "data"}]
    findings = evaluate_token_userid_binding(self_resp, victim_resps)
    assert len(findings) == 0


# ---- derive_primary_credential ----

def test_primary_credential_token_only():
    """token_only=ACCESS & cookie_only=DENIED → 主因子=Token（不报绕过）。"""
    assert derive_primary_credential("ACCESS", "DENIED") == PRIMARY_TOKEN


def test_primary_credential_cookie_only():
    """token_only=DENIED & cookie_only=ACCESS → 主因子=Cookie。"""
    assert derive_primary_credential("DENIED", "ACCESS") == PRIMARY_COOKIE


def test_primary_credential_both():
    assert derive_primary_credential("ACCESS", "ACCESS") == PRIMARY_BOTH


def test_primary_credential_unknown():
    assert derive_primary_credential("DENIED", "DENIED") == PRIMARY_UNKNOWN


def test_primary_credential_case_insensitive():
    assert derive_primary_credential("access", "denied") == PRIMARY_TOKEN


# ---- detect_token_expiry ----

def test_token_expiry_by_business_code():
    assert detect_token_expiry({"code": -100}) is True


def test_token_expiry_by_http_status():
    assert detect_token_expiry({"http_code": 401}) is True
    assert detect_token_expiry({"http_code": 419}) is True


def test_token_expiry_not_expired():
    assert detect_token_expiry({"http_code": 200, "code": 0}) is False
    assert detect_token_expiry({}) is False
