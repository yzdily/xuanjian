"""§1.3 补测：403 绕过检查（core/fast_scanner/_checks_auth.py `_check_403_bypass`）。

CWE-425/CWE-284：基线 401/403 → 探测变体（大小写/..;/%2e/转发头）→ 200+业务数据。
遵循 test_checks_supplement.py 的 monkeypatch `_request` 模式。
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
async def test_403_bypass_positive_sensitive_data():
    """基线 403，变体返回 200 且含敏感数据 → 报 high。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(403, "forbidden")
        if rule_tag == "403Bypass" and url.endswith("/ADMIN"):
            return _resp(200, '{"users":[{"name":"admin","phone":"13800138000"}]}')
        return _resp(403, "forbidden")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/admin", method="GET")
    findings = await s._check_403_bypass(target)
    assert findings
    assert findings[0].vuln_type == "403绕过"
    assert findings[0].severity == "high"
    assert findings[0].rule_tag == "403Bypass"


@pytest.mark.asyncio
async def test_403_bypass_positive_header_only():
    """变体 200 但响应体非公开壳（JSON 业务内容）→ medium（header_only，需二次确认）。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(403, "forbidden")
        if rule_tag == "403Bypass" and url.endswith("/ADMIN"):
            return _resp(200, "internal admin panel", **{"content-type": "application/json"})
        return _resp(403, "forbidden")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/admin", method="GET")
    findings = await s._check_403_bypass(target)
    assert findings
    assert findings[0].severity == "medium"
    assert findings[0].evidence_quality == "header_only"


@pytest.mark.asyncio
async def test_403_bypass_negative_baseline_not_forbidden():
    """基线非 401/403 → 跳过（防误报：本就可访问无需绕过）。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "public page")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/admin", method="GET")
    assert await s._check_403_bypass(target) == []


@pytest.mark.asyncio
async def test_403_bypass_negative_waf_blocked_variant():
    """变体被 WAF 拦截/返回业务拒绝 → 不报（防假阳性）。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(403, "forbidden")
        return _resp(403, "waf blocked")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/admin", method="GET")
    assert await s._check_403_bypass(target) == []


def test_build_403_variants_includes_techniques():
    """变体构造：大小写/..;/%2e/转发头齐全。"""
    s = FastScanner(max_workers=1)
    target = ScanTarget(url="http://x/admin", method="GET")
    variants = s._build_403_variants(target)
    techniques = {v["technique"] for v in variants}
    assert "大小写" in techniques
    assert "..;/" in techniques
    assert "%2e" in techniques
    assert "X-Original-URL" in techniques
    assert "X-Forwarded-For" in techniques
