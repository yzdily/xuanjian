"""§1.3 补测：F3 三身份 required_cookies Cookie 集判定（core/login_judge.py）。

方案 §2.4 F3：登录判定必须校验「完整 Cookie 集」，避免弱口令误报——
zhinenjqr 1176 个弱口令误报根因即失败响应也下发 SESSION cookie。
"""
from __future__ import annotations

from core.login_judge import attempt_login


def test_no_required_cookies_skips_condition2():
    """未传 required_cookies 时保持原行为（仅 URL 干净即通过）。"""
    res = attempt_login({"final_url": "http://x/dashboard", "set_cookies": [], "body": ""})
    assert res.success is True


def test_all_required_cookies_present():
    """全部必需 Cookie 命中 → 成功。"""
    res = attempt_login(
        {
            "final_url": "http://x/dashboard",
            "set_cookies": ["SESSION", "UID"],
            "body": "welcome",
        },
        required_cookies={"SESSION", "UID"},
    )
    assert res.success is True
    assert "cookies_complete" in res.matched_conditions


def test_missing_required_cookie_fails():
    """缺少任一必需 Cookie → 失败（弱口令误报根因场景）。"""
    res = attempt_login(
        {
            "final_url": "http://x/dashboard",
            "set_cookies": ["SESSION"],  # 缺 UID
            "body": "welcome",
        },
        required_cookies={"SESSION", "UID"},
    )
    assert res.success is False
    assert "UID" in res.reason or "uid" in res.reason


def test_required_cookies_case_insensitive():
    """Cookie 名大小写不敏感。"""
    res = attempt_login(
        {
            "final_url": "http://x/dashboard",
            "set_cookies": ["session", "uid"],
            "body": "welcome",
        },
        required_cookies={"SESSION", "UID"},
    )
    assert res.success is True


def test_fail_url_pattern_takes_priority():
    """URL 含失败标志优先失败（即使 Cookie 全命中）。"""
    res = attempt_login(
        {
            "final_url": "http://x/login?error=1",
            "set_cookies": ["SESSION"],
            "body": "",
        },
        fail_url_pattern=r"error",
        required_cookies={"SESSION"},
    )
    assert res.success is False
    assert "error" in res.reason.lower()


def test_success_hints_required():
    """传入 success_hints 时 body 必须命中。"""
    res = attempt_login(
        {
            "final_url": "http://x/dashboard",
            "set_cookies": ["SESSION"],
            "body": "plain page",
        },
        required_cookies={"SESSION"},
        success_hints=["welcome", "你好"],
    )
    assert res.success is False
    assert "成功关键词" in res.reason
