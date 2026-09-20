"""§1.3 补测：扫描前授权 SOFT 门（web/api/auth_gate.py）。

F17 硬合规门：目标必须在书面授权白名单内才允许扫描。
覆盖 verify_authorization / load_scope_file / AuthScopeError 的
正/反路径（无 scope、未签名、不在范围、过期、非法 JSON）。
"""
from __future__ import annotations

import json

import pytest

from web.api.auth_gate import AuthScopeError, load_scope_file, verify_authorization


def _write_scope(tmp_path, **overrides):
    scope = {
        "signed": True,
        "domains": ["https://target.example.com", "https://*.example.com"],
        "expires_at": "2099-12-31T23:59:59",
        "signed_by": "John Doe",
    }
    scope.update(overrides)
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(scope), encoding="utf-8")
    return p


def test_load_scope_file_ok(tmp_path):
    p = _write_scope(tmp_path)
    scope = load_scope_file(p)
    assert scope["signed"] is True


def test_load_scope_file_missing(tmp_path):
    with pytest.raises(AuthScopeError, match="不存在"):
        load_scope_file(tmp_path / "nope.json")


def test_load_scope_file_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(AuthScopeError, match="解析失败"):
        load_scope_file(p)


def test_verify_no_scope_file_raises():
    """SOFT 门关闭时（无 --scope-file）必须拒绝，不允许扫描。"""
    with pytest.raises(AuthScopeError, match="未提供 scope 文件"):
        verify_authorization("https://target.example.com", None)


def test_verify_unsigned_scope_raises(tmp_path):
    p = _write_scope(tmp_path, signed=False)
    with pytest.raises(AuthScopeError, match="未签名"):
        verify_authorization("https://target.example.com", p)


def test_verify_exact_domain_match(tmp_path):
    p = _write_scope(tmp_path)
    assert verify_authorization("https://target.example.com/", p) is True


def test_verify_wildcard_subdomain_match(tmp_path):
    p = _write_scope(tmp_path)
    assert verify_authorization("https://app.example.com/admin", p) is True


def test_verify_out_of_scope_raises(tmp_path):
    p = _write_scope(tmp_path)
    with pytest.raises(AuthScopeError, match="不在授权范围"):
        verify_authorization("https://evil.example.org", p)


def test_verify_scheme_mismatch_raises(tmp_path):
    """http 访问 https 授权域 → 拒绝（方案约束 scheme 一致）。"""
    p = _write_scope(tmp_path, domains=["https://target.example.com"])
    with pytest.raises(AuthScopeError, match="不在授权范围"):
        verify_authorization("http://target.example.com", p)


def test_verify_expired_raises(tmp_path):
    p = _write_scope(tmp_path, expires_at="2000-01-01T00:00:00")
    with pytest.raises(AuthScopeError, match="已过期"):
        verify_authorization("https://target.example.com", p)


def test_verify_invalid_expires_at_raises(tmp_path):
    p = _write_scope(tmp_path, expires_at="not-a-date")
    with pytest.raises(AuthScopeError, match="expires_at"):
        verify_authorization("https://target.example.com", p)
