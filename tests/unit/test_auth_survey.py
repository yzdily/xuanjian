"""§2.6.6 鉴权面普查 + 覆盖率门禁：三态分类 + 覆盖率 + 未测识别。"""
from __future__ import annotations

from core.loops.auth_survey import (
    classify_auth_surface,
    survey_coverage,
    identify_untested,
    CWE_MISSING_AUTHZ,
    SURFACE_NO_AUTH,
    SURFACE_AUTH_REQUIRED,
    SURFACE_AUTH_MISSING,
)


# ---- classify_auth_surface ----

def test_surface_no_auth_public():
    """公开接口(/login) → 无需鉴权。"""
    r = classify_auth_surface("/api/login", {"http_code": 200, "body": "login page"})
    assert r["surface"] == SURFACE_NO_AUTH
    assert r["cwe"] is None


def test_surface_no_auth_health():
    """/health → 无需鉴权。"""
    r = classify_auth_surface("/health", {"http_code": 200, "body": "ok"})
    assert r["surface"] == SURFACE_NO_AUTH


def test_surface_auth_required_401():
    """无 token 401 → 鉴权生效。"""
    r = classify_auth_surface("/api/users", {"http_code": 401, "body": "unauthorized"})
    assert r["surface"] == SURFACE_AUTH_REQUIRED


def test_surface_auth_required_403():
    """无 token 403 → 鉴权生效。"""
    r = classify_auth_surface("/api/admin", {"http_code": 403, "body": "forbidden"})
    assert r["surface"] == SURFACE_AUTH_REQUIRED


def test_surface_auth_missing_200_data():
    """无 token 200+数据 → 未授权可访问（漏洞）。"""
    r = classify_auth_surface("/api/users/list", {"http_code": 200, "body": '{"users":[]}'})
    assert r["surface"] == SURFACE_AUTH_MISSING
    assert r["cwe"] == CWE_MISSING_AUTHZ


def test_surface_auth_required_other_status():
    """无 token 404/500 → 视为需鉴权（保守）。"""
    r = classify_auth_surface("/api/data", {"http_code": 404, "body": "not found"})
    assert r["surface"] == SURFACE_AUTH_REQUIRED


def test_surface_auth_missing_with_data_field():
    """data 字段（非 body）含数据 → auth_missing。"""
    r = classify_auth_surface("/api/orders", {"http_code": 200, "data": {"id": 1}})
    assert r["surface"] == SURFACE_AUTH_MISSING


# ---- survey_coverage ----

def test_coverage_pass():
    """应测 5 已测 4 → 覆盖率 80% → pass。"""
    endpoints = [
        {"url": "/api/users", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/orders", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/admin", "surface": SURFACE_AUTH_MISSING},
        {"url": "/api/data", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/config", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/login", "surface": SURFACE_NO_AUTH},  # 不计入应测
    ]
    tested = {"/api/users", "/api/orders", "/api/admin", "/api/data"}
    r = survey_coverage(endpoints, tested)
    assert r["pass"] is True
    assert r["should_test"] == 5
    assert r["tested"] == 4
    assert r["coverage"] == 0.8


def test_coverage_fail():
    """应测 5 已测 2 → 覆盖率 40% → fail。"""
    endpoints = [
        {"url": "/api/users", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/orders", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/admin", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/data", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/config", "surface": SURFACE_AUTH_REQUIRED},
    ]
    tested = {"/api/users", "/api/orders"}
    r = survey_coverage(endpoints, tested)
    assert r["pass"] is False
    assert r["coverage"] == 0.4


def test_coverage_all_public():
    """全部公开接口 → 无需测试 → pass。"""
    endpoints = [
        {"url": "/login", "surface": SURFACE_NO_AUTH},
        {"url": "/health", "surface": SURFACE_NO_AUTH},
    ]
    r = survey_coverage(endpoints, set())
    assert r["pass"] is True
    assert r["should_test"] == 0
    assert r["coverage"] == 1.0


def test_coverage_full():
    """全部应测已测 → 覆盖率 100% → pass。"""
    endpoints = [
        {"url": "/api/users", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/admin", "surface": SURFACE_AUTH_MISSING},
    ]
    tested = {"/api/users", "/api/admin"}
    r = survey_coverage(endpoints, tested)
    assert r["pass"] is True
    assert r["coverage"] == 1.0


# ---- identify_untested ----

def test_untested_identified():
    """应测未测接口被识别。"""
    endpoints = [
        {"url": "/api/users", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/admin", "surface": SURFACE_AUTH_MISSING, "cwe": CWE_MISSING_AUTHZ},
        {"url": "/login", "surface": SURFACE_NO_AUTH},
    ]
    tested = {"/api/users"}
    untested = identify_untested(endpoints, tested)
    assert len(untested) == 1
    assert untested[0]["url"] == "/api/admin"
    assert untested[0]["cwe"] == CWE_MISSING_AUTHZ


def test_untested_empty_when_all_tested():
    """全部应测已测 → 无未测。"""
    endpoints = [
        {"url": "/api/users", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/login", "surface": SURFACE_NO_AUTH},
    ]
    tested = {"/api/users"}
    untested = identify_untested(endpoints, tested)
    assert untested == []


def test_untested_all_when_none_tested():
    """无已测 → 全部应测接口未测。"""
    endpoints = [
        {"url": "/api/users", "surface": SURFACE_AUTH_REQUIRED},
        {"url": "/api/admin", "surface": SURFACE_AUTH_MISSING},
    ]
    untested = identify_untested(endpoints, set())
    assert len(untested) == 2
