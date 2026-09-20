"""§1.3 补测：Host 头注入（core/fast_scanner/_checks_server.py `_check_host_header`）。

CWE-20/644：Host 头替换为外部域名/内网地址，检测响应体回显 / Location 头反射。
红线：仅检测，不实际构造恶意链接。
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
async def test_host_header_positive_body_reflection():
    """Host 反射到响应体且基线不含 → 报 medium。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        host = (headers or {}).get("Host", "")
        if payload_tag == "baseline" or not rule_tag:
            return _resp(200, "welcome page")  # 基线无 evil.com
        if "evil.com" in host:
            return _resp(200, '<a href="//evil.com/reset">重置密码</a>')
        return _resp(200, "welcome page")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/reset", method="GET")
    findings = await s._check_host_header(target)
    assert findings
    assert findings[0].vuln_type == "Host头注入"
    assert findings[0].severity == "medium"
    assert findings[0].rule_tag == "HostHdr"


@pytest.mark.asyncio
async def test_host_header_positive_location_reflection():
    """Location 头指向注入 Host → 报 high。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        host = (headers or {}).get("Host", "")
        if payload_tag == "baseline" or not rule_tag:
            return _resp(200, "welcome")
        if "evil.com" in host:
            return _resp(302, "redirecting to login", Location="http://evil.com/login")
        return _resp(200, "welcome")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/reset", method="GET")
    findings = await s._check_host_header(target)
    assert findings
    assert findings[0].severity == "high"


@pytest.mark.asyncio
async def test_host_header_negative_no_reflection():
    """Host 未回显 → 不报。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "static page")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/reset", method="GET")
    assert await s._check_host_header(target) == []


@pytest.mark.asyncio
async def test_host_header_negative_waf_blocked():
    """变体被 WAF 拦截 → 不报。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline" or not rule_tag:
            return _resp(200, "welcome")
        return _resp(403, "waf blocked")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/reset", method="GET")
    assert await s._check_host_header(target) == []


@pytest.mark.asyncio
async def test_host_header_no_baseline_returns_empty():
    """基线请求失败 → 直接返回空。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return None

    s = _scanner(fake)
    target = ScanTarget(url="http://x/reset", method="GET")
    assert await s._check_host_header(target) == []
