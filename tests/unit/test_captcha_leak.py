"""§1.3 补测：验证码答案泄露（core/fast_scanner/_checks_auth.py `_check_captcha_leak`）。

CWE-804/200：验证码接口响应直接泄露答案字段 → 报。
红线：只检测响应是否泄露答案，不做识别/绕过。
★ 防误报：{"code":0} 等成功标记不得被判为答案。
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
async def test_captcha_leak_skips_non_captcha_endpoint():
    """非验证码端点 → 直接跳过，不发请求。"""
    calls = []

    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        calls.append(url)
        return _resp(200, "ok")

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/user", method="GET")
    assert await s._check_captcha_leak(target) == []
    assert calls == []


@pytest.mark.asyncio
async def test_captcha_leak_positive_json_answer():
    """JSON 响应泄露 answer 字段 → 报 high。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"captcha_id":"a1b2","answer":"K3f9","img":"/c/1.png"}')

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/captcha", method="GET")
    findings = await s._check_captcha_leak(target)
    assert findings
    assert findings[0].vuln_type == "验证码答案泄露"
    assert findings[0].severity == "high"
    assert "K3f9" in findings[0].payload


@pytest.mark.asyncio
async def test_captcha_leak_negative_no_answer():
    """响应无答案字段 → 不报。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"captcha_id":"a1b2","img":"/c/1.png","expire":300}')

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/captcha", method="GET")
    assert await s._check_captcha_leak(target) == []


@pytest.mark.asyncio
async def test_captcha_leak_negative_status_code():
    """非 200 → 不报。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(500, '{"answer":"K3f9"}')

    s = _scanner(fake)
    target = ScanTarget(url="http://x/api/captcha", method="GET")
    assert await s._check_captcha_leak(target) == []


def test_extract_captcha_answer_fields_no_fp_on_success_code():
    """防误报：{"code":0} 成功标记不是验证码答案。"""
    s = FastScanner(max_workers=1)
    assert s._extract_captcha_answer_fields('{"code":0,"msg":"ok"}') == []


def test_extract_captcha_answer_fields_detects_short_answer():
    """短值答案字段被识别；长值/通用字段排除。"""
    s = FastScanner(max_workers=1)
    found = s._extract_captcha_answer_fields(
        '{"answer":"Ab12","solution":"Xy9","result":"success","msg":"some long value"}')
    assert "answer=Ab12" in found
    assert "solution=Xy9" in found
    assert not any(x.startswith("result=") for x in found)  # 成功标记排除
