"""F2 认证探活单元测试。"""
from __future__ import annotations

import pytest

from core.auth_probe import verify_auth_validity, is_auth_blocked, AuthInvalidError


class TestIsAuthBlocked:
    def test_token_expired(self):
        assert is_auth_blocked("token失效")

    def test_state_false(self):
        assert is_auth_blocked('{"state":false}')

    def test_unauthorized(self):
        assert is_auth_blocked("Unauthorized")

    def test_normal_response(self):
        assert not is_auth_blocked('{"data":"hello world"}')

    def test_empty_body(self):
        assert not is_auth_blocked("")

    def test_chinese_markers(self):
        assert is_auth_blocked("请先登录")
        assert is_auth_blocked("未登录")


class TestVerifyAuthValidity:
    def test_401_raises(self):
        class MockResp:
            status = 401
            body = ""
        with pytest.raises(AuthInvalidError, match="HTTP 401"):
            verify_auth_validity({"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp())

    def test_403_raises(self):
        class MockResp:
            status = 403
            body = ""
        with pytest.raises(AuthInvalidError, match="HTTP 403"):
            verify_auth_validity({"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp())

    def test_blocked_body_raises(self):
        class MockResp:
            status = 200
            body = '{"state":false,"msg":"token失效"}'
        with pytest.raises(AuthInvalidError, match="认证拦截"):
            verify_auth_validity({"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp())

    def test_empty_body_raises(self):
        class MockResp:
            status = 200
            body = ""
        with pytest.raises(AuthInvalidError, match="响应体为空"):
            verify_auth_validity({"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp())

    def test_normal_passes(self):
        class MockResp:
            status = 200
            body = '{"data":"hello world response"}'
        assert verify_auth_validity(
            {"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp(),
        ) is True

    def test_no_request_fn_passes(self):
        assert verify_auth_validity({"url": "http://t/api"}, {}) is True
