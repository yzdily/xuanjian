"""F17 root 工具裁剪 + 授权门单元测试。"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from core.tools import ROOT_TOOLS_WHITELIST
from web.api.auth_gate import verify_authorization, load_scope_file, AuthScopeError, _match_host


class TestRootToolsWhitelist:
    def test_orchestration_tools_included(self):
        assert "spawn_agent" in ROOT_TOOLS_WHITELIST
        assert "finish_scan" in ROOT_TOOLS_WHITELIST
        assert "record_coverage" in ROOT_TOOLS_WHITELIST

    def test_scanner_tools_excluded(self):
        assert "proxy_send_request" not in ROOT_TOOLS_WHITELIST
        assert "browser_goto" not in ROOT_TOOLS_WHITELIST

    def test_shell_tools_excluded(self):
        assert "exec_command" not in ROOT_TOOLS_WHITELIST
        assert "shell_exec" not in ROOT_TOOLS_WHITELIST


class TestMatchHost:
    def test_exact_match(self):
        assert _match_host("target.com", "target.com")

    def test_no_match(self):
        assert not _match_host("target.com", "other.com")

    def test_wildcard_match(self):
        assert _match_host("api.target.com", "*.target.com")

    def test_wildcard_no_match(self):
        assert not _match_host("api.other.com", "*.target.com")


class TestVerifyAuthorization:
    def test_valid_scope_passes(self, tmp_path):
        scope = {
            "signed": True,
            "domains": ["https://target.example.com"],
        }
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps(scope))
        assert verify_authorization("https://target.example.com/api", scope_file)

    def test_unsigned_scope_raises(self, tmp_path):
        scope = {"signed": False, "domains": ["https://target.example.com"]}
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps(scope))
        with pytest.raises(AuthScopeError, match="未签名"):
            verify_authorization("https://target.example.com/api", scope_file)

    def test_out_of_scope_raises(self, tmp_path):
        scope = {"signed": True, "domains": ["https://target.example.com"]}
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps(scope))
        with pytest.raises(AuthScopeError, match="不在授权范围"):
            verify_authorization("https://other.com/api", scope_file)

    def test_expired_scope_raises(self, tmp_path):
        scope = {
            "signed": True,
            "domains": ["https://target.example.com"],
            "expires_at": "2020-01-01T00:00:00",
        }
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps(scope))
        with pytest.raises(AuthScopeError, match="过期"):
            verify_authorization("https://target.example.com/api", scope_file)

    def test_no_scope_file_raises(self):
        with pytest.raises(AuthScopeError, match="未提供"):
            verify_authorization("https://target.example.com/api", None)

    def test_wildcard_domain(self, tmp_path):
        scope = {"signed": True, "domains": ["*.example.com"]}
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps(scope))
        assert verify_authorization("https://api.example.com/api", scope_file)

    def test_nonexistent_file_raises(self):
        with pytest.raises(AuthScopeError, match="不存在"):
            verify_authorization("https://t.com", "/nonexistent/scope.json")
