"""§2.5 IDOR / 越权专项：跨租户 BOLA + 垂直三角色 + 参数忽略 + 量化（技术方案 3.10.4）。"""
from __future__ import annotations

from core.loops.idor_probe import (
    evaluate_cross_tenant,
    quantify_authz,
    evaluate_vertical_3role,
    evaluate_param_ignored,
    evaluate_idor_manipulation,
    ID_MANIPULATION_TECHNIQUES,
)


# ---- evaluate_cross_tenant (G10 BOLA) ----

def test_cross_tenant_bola_detected():
    """tenant-A 登录态读 tenant-B 资源返回 200+数据 → BOLA。"""
    a_resp = {"http_code": 200, "body": '{"uid":2,"tenant":"B"}'}
    b_resp = {"http_code": 200, "body": '{"uid":2,"tenant":"B"}'}
    r = evaluate_cross_tenant(a_resp, b_resp)
    assert r["vulnerable"] is True
    assert r["cwe"] == "CWE-862"
    assert r["severity"] == "High"


def test_cross_tenant_denied_no_bola():
    """tenant-A 被 401 拒绝 → 不报 BOLA。"""
    a_resp = {"http_code": 401, "body": "unauthorized"}
    b_resp = {"http_code": 200, "body": '{"uid":2}'}
    r = evaluate_cross_tenant(a_resp, b_resp)
    assert r["vulnerable"] is False


def test_cross_tenant_empty_data_no_bola():
    """tenant-A 200 但无数据 → 不报 BOLA。"""
    a_resp = {"http_code": 200, "body": ""}
    b_resp = {"http_code": 200, "body": '{"uid":2}'}
    r = evaluate_cross_tenant(a_resp, b_resp)
    assert r["vulnerable"] is False


# ---- quantify_authz (G2 diff_rate) ----

def test_quantify_authz_no_isolation():
    """diff_rate=0 → 无隔离（CWE-862）。"""
    assert quantify_authz(100, 100) == 0.0


def test_quantify_authz_full_isolation():
    """diff_rate=1 → 完全隔离。"""
    assert quantify_authz(100, 0) == 1.0


def test_quantify_authz_partial():
    assert 0 < quantify_authz(100, 50) < 1.0


def test_quantify_authz_zero_safe():
    """两个都 0 不崩。"""
    assert quantify_authz(0, 0) == 0.0


# ---- evaluate_vertical_3role (L48) ----

def test_vertical_3role_low_bypass():
    """low 角色访问 admin 端点返回 200 → 垂直越权（High）。"""
    admin = {"http_code": 200, "body": "admin_data"}
    user = {"http_code": 403, "body": "forbidden"}
    low = {"http_code": 200, "body": "low_sees_admin"}
    r = evaluate_vertical_3role(admin, user, low)
    assert r["vulnerable"] is True
    assert r["severity"] == "High"


def test_vertical_3role_user_bypass():
    """user 角色访问 admin 端点返回 200 → 垂直越权（Medium）。"""
    admin = {"http_code": 200, "body": "admin_data"}
    user = {"http_code": 200, "body": "user_sees_admin"}
    low = {"http_code": 403, "body": "forbidden"}
    r = evaluate_vertical_3role(admin, user, low)
    assert r["vulnerable"] is True
    assert r["severity"] == "Medium"


def test_vertical_3role_properly_blocked():
    """低权限角色被正确拦截 → 不报越权。"""
    admin = {"http_code": 200, "body": "admin_data"}
    user = {"http_code": 403, "body": "forbidden"}
    low = {"http_code": 403, "body": "forbidden"}
    r = evaluate_vertical_3role(admin, user, low)
    assert r["vulnerable"] is False


# ---- evaluate_param_ignored (G7) ----

def test_param_ignored_detected():
    """伪造租户标识返回相同数据 → 参数被忽略。"""
    real = {"http_code": 200, "body": '{"items":[1,2,3]}'}
    fake = {"http_code": 200, "body": '{"items":[1,2,3]}'}
    r = evaluate_param_ignored(real, fake)
    assert r["vulnerable"] is True
    assert r["cwe"] == "CWE-639"


def test_param_ignored_not_detected_different_data():
    """伪造租户返回不同数据 → 参数未被忽略。"""
    real = {"http_code": 200, "body": '{"items":[1,2,3]}'}
    fake = {"http_code": 200, "body": '{"items":[4,5,6]}'}
    r = evaluate_param_ignored(real, fake)
    assert r["vulnerable"] is False


def test_param_ignored_fake_denied():
    """伪造租户被拒 → 参数有效。"""
    real = {"http_code": 200, "body": '{"items":[1,2,3]}'}
    fake = {"http_code": 403, "body": "forbidden"}
    r = evaluate_param_ignored(real, fake)
    assert r["vulnerable"] is False


# ---- evaluate_idor_manipulation (I1) ----

def test_idor_manipulation_detected():
    """替换 userid 后 victim 返回 200+数据 → IDOR。"""
    self_resp = {"http_code": 200, "body": '{"uid":1}'}
    victim_resp = {"http_code": 200, "body": '{"uid":2}'}
    r = evaluate_idor_manipulation(self_resp, victim_resp)
    assert r["vulnerable"] is True
    assert r["cwe"] == "CWE-639"


def test_idor_manipulation_denied():
    self_resp = {"http_code": 200, "body": '{"uid":1}'}
    victim_resp = {"http_code": 403, "body": "forbidden"}
    r = evaluate_idor_manipulation(self_resp, victim_resp)
    assert r["vulnerable"] is False


def test_idor_techniques_complete():
    """ID 操纵技术清单完整性。"""
    assert len(ID_MANIPULATION_TECHNIQUES) >= 9
    assert "direct_replace" in ID_MANIPULATION_TECHNIQUES
    assert "hpp" in ID_MANIPULATION_TECHNIQUES
