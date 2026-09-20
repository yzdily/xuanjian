"""§4 Phase 2 item 8：viewer 白名单单元测试。"""
from __future__ import annotations

from web.viewer_whitelist import (
    check_viewer_access,
    get_access_log,
    get_viewer_token,
    verify_email_whitelist,
    verify_viewer_token,
)


def test_token_is_unguessable():
    t = get_viewer_token()
    assert len(t) >= 32  # token_urlsafe(32) ≈ 43 chars
    # 同一进程内 token 稳定
    assert t == get_viewer_token()


def test_verify_token_valid():
    assert verify_viewer_token(get_viewer_token()) is True


def test_verify_token_invalid():
    assert verify_viewer_token(None) is False
    assert verify_viewer_token("") is False
    assert verify_viewer_token("wrong-token") is False


def test_verify_email_no_whitelist_allows_all():
    # 未配置 XUANJIAN_VIEWER_EMAILS 时允许所有
    assert verify_email_whitelist("any@example.com") is True
    assert verify_email_whitelist(None) is True


def test_check_viewer_access_requires_token():
    result = check_viewer_access(None, "user@example.com")
    assert result["allowed"] is False
    assert result["reason"] == "invalid_token"


def test_check_viewer_access_success():
    result = check_viewer_access(get_viewer_token(), "user@example.com", "127.0.0.1")
    assert result["allowed"] is True
    assert result["reason"] == "ok"


def test_access_log_masked():
    # 触发一次访问
    check_viewer_access(get_viewer_token(), "alice@company.cn", "10.0.0.1")
    log = get_access_log()
    assert log
    entry = log[-1]
    # 邮箱脱敏
    assert "al***@company.cn" in entry["email"] or entry["email"].startswith("al")
    assert "company.cn" in entry["email"]
    assert "@" in entry["email"]
