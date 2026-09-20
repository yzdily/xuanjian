"""F3 登录判定三重校验单元测试。"""
from __future__ import annotations

from core.login_judge import attempt_login, LoginJudgeResult


class TestAttemptLogin:
    """F3: 登录判定三重校验。"""

    def test_success_all_conditions_pass(self):
        result = attempt_login(
            {"final_url": "http://target/dashboard", "set_cookies": ["SESSIONID"], "body": "welcome"},
            fail_url_pattern="error=true",
            required_cookies={"SESSIONID"},
            success_hints=["welcome", "dashboard"],
        )
        assert result.success is True

    def test_fail_url_contains_error(self):
        result = attempt_login(
            {"final_url": "http://target/login?error=true", "set_cookies": ["SESSIONID"], "body": ""},
            fail_url_pattern="error=true",
        )
        assert result.success is False
        assert "URL" in result.reason

    def test_fail_url_contains_login(self):
        result = attempt_login(
            {"final_url": "http://target/login", "set_cookies": [], "body": ""},
        )
        # login in URL but no error → still passes condition 1
        # But without required_cookies and success_hints, it passes
        assert result.success is True

    def test_fail_missing_cookie(self):
        result = attempt_login(
            {"final_url": "http://target/home", "set_cookies": ["JSESSIONID"], "body": "welcome"},
            required_cookies={"SESSIONID", "AUTH_TOKEN"},
        )
        assert result.success is False
        assert "Cookie" in result.reason

    def test_fail_no_success_hint(self):
        result = attempt_login(
            {"final_url": "http://target/home", "set_cookies": ["SESSIONID"], "body": "error page"},
            success_hints=["welcome", "success"],
        )
        assert result.success is False
        assert "成功关键词" in result.reason

    def test_fail_cookie_only_is_insufficient(self):
        """zhinenjqr 误报根因：失败响应也下发 SESSION cookie"""
        result = attempt_login(
            {
                "final_url": "http://target/login?error=true",
                "set_cookies": ["SESSIONID"],  # 失败响应也有 cookie
                "body": "密码错误",
            },
            fail_url_pattern="error=true",
            required_cookies={"SESSIONID"},
            success_hints=["welcome"],
        )
        assert result.success is False

    def test_required_cookies_case_insensitive(self):
        result = attempt_login(
            {"final_url": "http://target/home", "set_cookies": ["sessionid"], "body": "welcome"},
            required_cookies={"SESSIONID"},
            success_hints=["welcome"],
        )
        assert result.success is True

    def test_empty_result(self):
        result = attempt_login({})
        assert result.success is True  # No conditions specified → passes
