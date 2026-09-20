"""§1.3 补测：用户枚举 + 频控缺失（core/fast_scanner/_checks_auth.py `_check_user_enum`）。

CWE-204：存在/不存在用户响应可区分 → 用户枚举。
CWE-307：并发 5 次无 429/Retry-After → 频控缺失（红线：仅检测不轰炸）。
遵循 monkeypatch `_request` 模式。
"""
from __future__ import annotations

import httpx
import pytest

from core.fast_scanner import FastScanner, ScanTarget


def _scanner(fake):
    s = FastScanner(max_workers=1)
    s._request = fake
    return s


def _resp(status: int = 200, text: str = "", **headers) -> httpx.Response:
    return httpx.Response(status, text=text, headers=headers)


@pytest.mark.asyncio
async def test_user_enum_skips_non_auth_endpoint():
    """非登录/注册类端点 → 直接跳过，不发请求。"""
    calls = []

    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        calls.append(url)
        return _resp(200, "ok")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/orders", method="GET")
    assert await s._check_user_enum(target) == []
    assert calls == []  # 未发任何请求


@pytest.mark.asyncio
async def test_user_enum_positive_distinct_responses():
    """存在用户 vs 不存在用户状态码不同 → 用户枚举。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if "admin" in payload_tag:
            return _resp(200, '{"code":0,"msg":"密码错误"}')
        return _resp(404, '{"code":1,"msg":"用户不存在"}')

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/login", method="POST")
    findings = await s._check_user_enum(target)
    assert any(f.vuln_type == "用户枚举" for f in findings)


@pytest.mark.asyncio
async def test_user_enum_negative_same_response():
    """两用户响应不可区分 → 不报枚举。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"code":0,"msg":"用户名或密码错误"}')

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/login", method="POST")
    findings = await s._check_user_enum(target)
    assert not any(f.vuln_type == "用户枚举" for f in findings)


@pytest.mark.asyncio
async def test_rate_limit_missing_detected():
    """并发 5 次全 200 无 429 → 频控缺失。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"code":0,"msg":"用户名或密码错误"}')

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/login", method="POST")
    findings = await s._check_user_enum(target)
    assert any(f.vuln_type == "频控缺失" for f in findings)


@pytest.mark.asyncio
async def test_rate_limit_present_not_detected():
    """并发请求返回 429 → 不报频控缺失。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "rate_check":
            return _resp(429, "too many requests")
        return _resp(200, '{"code":0,"msg":"用户名或密码错误"}')

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/login", method="POST")
    findings = await s._check_user_enum(target)
    assert not any(f.vuln_type == "频控缺失" for f in findings)
