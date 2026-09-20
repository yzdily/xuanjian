"""§1.3 补测：NoSQL 注入检查（core/fast_scanner/_checks_injection.py `_check_nosql_injection`）。

CWE-943：$ne / $gt / $regex 操作符注入，基线业务拒绝 + 注入后出真实数据 → 报。
遵循 test_checks_supplement.py 的 monkeypatch `_request` 模式，不发起真实请求。
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
async def test_nosql_positive_get_operator_bypass():
    """基线业务拒绝，$ne 注入后出真实数据 → NoSQL 注入。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(200, '{"code":-1,"msg":"未登录"}')
        if rule_tag == "NoSQLi":
            return _resp(200, '{"code":0,"data":[{"name":"admin","id":1}]}')
        return None

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/user", method="GET", params={"id": "1"})
    findings = await s._check_nosql_injection(target)
    assert findings
    assert findings[0].vuln_type == "NoSQL注入"
    assert findings[0].rule_tag == "NoSQLi"
    assert findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_nosql_positive_post_json_body():
    """POST JSON body 字段注入。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(200, '{"code":-1,"msg":"未登录"}')
        if rule_tag == "NoSQLi" and method == "POST":
            return _resp(200, '{"code":0,"data":[{"x":1}]}')
        return None

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/query", method="POST",
                        body='{"username":"a"}')
    findings = await s._check_nosql_injection(target)
    assert findings
    assert findings[0].method == "POST"


@pytest.mark.asyncio
async def test_nosql_negative_no_bypass():
    """注入后仍业务拒绝 → 不报（防误报）。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"code":-1,"msg":"未登录"}')

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/user", method="GET", params={"id": "1"})
    findings = await s._check_nosql_injection(target)
    assert not findings


@pytest.mark.asyncio
async def test_nosql_negative_waf_block():
    """注入响应被 WAF 拦截 → 不报。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(200, '{"code":-1,"msg":"未登录"}')
        return _resp(403, "waf blocked")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/user", method="GET", params={"id": "1"})
    findings = await s._check_nosql_injection(target)
    assert not findings


@pytest.mark.asyncio
async def test_nosql_no_baseline_returns_empty():
    """基线请求失败 → 直接返回空。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return None

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/user", method="GET", params={"id": "1"})
    assert await s._check_nosql_injection(target) == []
