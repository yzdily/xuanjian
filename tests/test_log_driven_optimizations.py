import asyncio

import httpx

from core.business_understanding import analyze_business
from core.fast_scanner import FastScanner
from core.intent import jwt_headers_to_local_storage
from core.sitemap import CheckItem, CheckResult, FeaturePoint, Priority, Sitemap
from core.sitemap.coverage import _normalize_vuln_key


class BrokenLLM:
    chat = None


def test_bearer_auth_header_injects_common_storage_keys():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature"

    items = jwt_headers_to_local_storage({"Authorization": f"Bearer {token}"})

    assert items["Authorization"] == token
    assert items["token"] == token
    assert items["access_token"] == token
    assert items["authToken"] == token


def test_custom_token_header_injects_storage_keys():
    token = "abcDEF_1234567890abcDEF_1234567890"

    items = jwt_headers_to_local_storage({"c-token": token})

    assert items["c-token"] == token
    assert items["token"] == token
    assert items["jwt"] == token


def test_secret_leak_findings_share_root_cause_key():
    fp = FeaturePoint(
        id="fp_secret",
        name="[敏感]api_key",
        related_apis=["GET https://example.com/static/js/app.js"],
        priority=Priority.HIGH,
        checklist=[
            CheckItem(
                "信息泄露",
                result=CheckResult.VULNERABLE,
                detail="APPKEY=xxx APPSECRET=yyy",
            ),
            CheckItem(
                "JS代码审计(硬编码密钥/绕过逻辑/敏感信息)",
                result=CheckResult.VULNERABLE,
                detail="前端硬编码 APPSECRET",
            ),
        ],
    )

    key1 = _normalize_vuln_key(fp, fp.checklist[0].vuln_type)
    key2 = _normalize_vuln_key(fp, fp.checklist[1].vuln_type)

    assert key1 == key2
    assert "客户端硬编码密钥泄露" in key1


def test_business_understanding_degrades_when_llm_unavailable():
    sitemap = Sitemap("https://admin.example.com")
    sitemap.add_page("https://admin.example.com/dashboard", title="管理后台")

    result = asyncio.run(analyze_business(sitemap, BrokenLLM()))

    assert result["status"] == "degraded"
    assert "LLM 未配置" in result["error"]
    assert result["understanding"]


def test_fast_scanner_response_log_sampling_suppresses_noise():
    scanner = FastScanner()
    resp = httpx.Response(500, content=b"x" * 8675, request=httpx.Request("GET", "https://example.com/a/b"))

    for i in range(12):
        scanner._record_scan_response_log("InfoLeak", "GET", "https://example.com/a/b", "/.env", resp)

    assert scanner._response_log_counts
    assert scanner._response_log_suppressed > 0
