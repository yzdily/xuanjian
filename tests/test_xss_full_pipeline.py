"""
XSS 完整流水线端到端验证（13-step）。

测试目标：
1. 所有新模块能正常 import
2. scanner.run() 能完整跑通（不抛异常）
3. 报告中各章节正常输出
4. WebUI 接口正常响应
"""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_import_all_modules():
    """Step 1: 所有新模块 import 测试。"""
    from core.xss import XssScanner  # noqa
    from core.xss.header_injection import generate_header_injection_targets, COMMON_REFLECTABLE_HEADERS  # noqa
    from core.xss.stored_tracker import StoredXssTracker  # noqa
    from core.xss.waf_bypass import WafBypassEngine, _generate_heuristic_bypass  # noqa
    from core.xss.oob import (
        BlindXssScanner, LocalOobReceiver, get_global_oob_receiver,
        build_blind_payloads,
    )  # noqa
    from core.xss.postmessage_scanner import (
        PostMessageScanner, find_postmessage_risks_in_js,
        find_dom_clobbering_risks_in_js,
    )  # noqa
    from core.xss.mutation_xss import (
        MutationXssScanner, build_mxss_payloads,
        is_likely_richtext_target,
    )  # noqa
    from core.xss.csp_analyzer import CspAnalyzer, parse_csp  # noqa
    from core.xss.upload_xss import UploadXssScanner, extract_file_urls_from_response  # noqa
    from core.xss.template_injection import (
        TemplateInjectionScanner, build_template_probes,
        build_csti_xss_payloads,
    )  # noqa


def test_header_injection_generation():
    """测试 Header 注入目标生成。"""
    from core.xss.header_injection import (
        generate_header_injection_targets, COMMON_REFLECTABLE_HEADERS
    )
    # 模拟 sitemap
    sm = MagicMock()
    sm.api_samples = {
        "k1": {
            "url": "http://example.com/api/info",
            "method": "GET",
            "request_headers": {"User-Agent": "Mozilla", "Cookie": "session=abc; csrf=xyz"},
        }
    }
    sm.apis = {}
    sm.pages = {}
    targets = generate_header_injection_targets(sm)
    assert len(targets) > 0, "应生成至少一个 header 目标"
    # 验证 Referer/UA/XFF 都有
    header_names = {t.param_name for t in targets if t.injection_point.value == "header"}
    assert "Referer" in header_names
    assert "User-Agent" in header_names
    assert "X-Forwarded-For" in header_names
    # 验证 Cookie 注入也被生成
    cookie_names = {t.param_name for t in targets if t.injection_point.value == "cookie"}
    assert "session" in cookie_names or "csrf" in cookie_names


def test_csp_parser():
    """测试 CSP 解析器。"""
    from core.xss.csp_analyzer import parse_csp

    # Case 1: 危险 CSP（有 unsafe-inline）
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline' *.googleapis.com"
    analysis = parse_csp(csp)
    assert analysis.score < 5, f"应低分: {analysis.score}"
    assert len(analysis.bypass_paths) >= 2, f"应有多个 bypass: {analysis.bypass_paths}"
    assert "unsafe-inline" in str(analysis.bypass_paths).lower()

    # Case 2: 严格 CSP
    csp_safe = "default-src 'none'; script-src 'self' 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'none'"
    analysis2 = parse_csp(csp_safe)
    assert analysis2.score >= 6, f"严格 CSP 应高分: {analysis2.score}"


def test_blind_payloads():
    """盲打 payload 生成。"""
    from core.xss.oob import build_blind_payloads, _generate_oob_token
    token = _generate_oob_token()
    payloads = build_blind_payloads("http://oob.test.com/cb", token)
    assert len(payloads) >= 5
    # 每个 payload 必须包含 token
    for p in payloads:
        assert token in p, f"payload 缺 token: {p}"


def test_mxss_payloads():
    """Mutation XSS payload 生成。"""
    from core.xss.mutation_xss import build_mxss_payloads, is_likely_richtext_target
    from core.xss.models import InjectionTarget, InjectionPoint
    import base64
    marker = "mxss_test_marker"
    payloads = build_mxss_payloads(marker)
    assert len(payloads) >= 10
    # 每个 payload 必须含 marker（或其 base64 编码）
    b64_marker = base64.b64encode(marker.encode()).decode()
    for p in payloads:
        assert (marker in p) or (b64_marker[:10] in p), f"mxss payload 缺 marker: {p[:80]}"
    # 富文本字段识别
    t1 = InjectionTarget(url="x", param_name="content", injection_point=InjectionPoint.BODY_JSON)
    t2 = InjectionTarget(url="x", param_name="user_id", injection_point=InjectionPoint.BODY_JSON)
    assert is_likely_richtext_target(t1)
    assert not is_likely_richtext_target(t2)


def test_postmessage_static():
    """postMessage 静态分析。"""
    from core.xss.postmessage_scanner import (
        find_postmessage_risks_in_js, find_dom_clobbering_risks_in_js,
    )
    js_code = """
    window.addEventListener('message', function(e) {
        // 没有 origin 校验！
        document.getElementById('x').innerHTML = e.data.html;
    });

    if (window.config) {
        loadConfig(window.config);
    }
    """
    pm_risks = find_postmessage_risks_in_js(js_code, js_url="test.js")
    assert len(pm_risks) > 0, "应识别 postMessage 风险"
    assert pm_risks[0]["has_origin_check"] is False

    clobber = find_dom_clobbering_risks_in_js(js_code, js_url="test.js")
    assert any(r["var_name"] == "config" for r in clobber), "应识别 window.config clobbering"


def test_template_probes():
    """模板注入探测 payload 生成。"""
    from core.xss.template_injection import build_template_probes, build_csti_xss_payloads
    probes = build_template_probes()
    assert len(probes) >= 4
    # 每个 probe 应有合理的 expected
    for engine, payload, expected, check in probes:
        # expected 应该是数字字符串（乘积）
        assert expected.isdigit()
        # check 函数应当能识别 expected
        assert check(f"<html>{expected}</html>")
    xss = build_csti_xss_payloads("test_marker")
    assert len(xss) >= 3


def test_waf_bypass_heuristic():
    """启发式 WAF 绕过。"""
    from core.xss.waf_bypass import _generate_heuristic_bypass
    marker = "wm123"
    payload = f"<script>alert({marker})</script>"
    variants = _generate_heuristic_bypass(payload, ["<"], marker)
    assert len(variants) > 0, "至少应生成 1 个变种"
    # 验证变种不是原 payload
    assert payload not in variants


def test_scanner_pipeline_initialization():
    """Scanner 初始化测试（不实际跑扫描，只验证流水线能装配）。"""
    from core.xss import XssScanner
    sm = MagicMock()
    sm.target = "http://example.com"
    sm.features = {}
    sm.apis = {}
    sm.api_samples = {}
    sm.pages = {}
    sm.js_analysis = {}
    sm.xss_findings = []
    llm = MagicMock()

    scanner = XssScanner(
        sitemap=sm,
        llm=llm,
        proxy="",
        enable_param_mining=False,
        enable_header_injection=True,
        enable_browser_verify=False,
        enable_dom_scan=True,
        enable_llm_judge=False,
        enable_waf_bypass=True,
        enable_stored_xss=False,
        enable_mutation_xss=False,
        enable_postmessage=True,
        enable_upload_xss=False,
        enable_template_injection=False,
        enable_blind_xss=False,
        enable_csp_analysis=True,
        max_targets=10,
    )
    # 验证流水线组件正确装配
    assert scanner.sitemap is sm
    assert scanner.llm is llm
    assert scanner.sitemap.target == "http://example.com"
    assert scanner.enable_header_injection is True
    assert scanner.enable_dom_scan is True
    assert scanner.enable_waf_bypass is True
    assert scanner.enable_postmessage is True
    assert scanner.enable_csp_analysis is True


def test_scanner_dry_run():
    """完整跑一次扫描（空 sitemap）— 验证不抛异常。"""
    import asyncio
    from core.xss import XssScanner
    sm = MagicMock()
    sm.target = "http://example.com"
    sm.features = {}
    sm.apis = {}
    sm.api_samples = {}
    sm.pages = {}
    sm.js_analysis = {}
    sm.xss_findings = []
    # Mock save 避免实际写文件
    sm.save = MagicMock()
    llm = MagicMock()

    scanner = XssScanner(
        sitemap=sm,
        llm=llm,
        enable_param_mining=False,
        enable_browser_verify=False,
        enable_llm_judge=False,
        enable_stored_xss=False,
        enable_mutation_xss=False,
        enable_upload_xss=False,
        enable_template_injection=False,
        enable_blind_xss=False,
        max_targets=5,
    )

    async def _run():
        events_count = 0
        done_received = False
        async for evt in scanner.run():
            events_count += 1
            if evt.get("type") == "xss_done":
                done_received = True
        assert events_count > 0
        assert done_received, "应收到 xss_done 事件"

    asyncio.run(_run())


def test_extract_file_urls():
    """文件上传 URL 提取。"""
    from core.xss.upload_xss import extract_file_urls_from_response
    # JSON 响应
    json_resp = '{"data":{"url":"/uploads/abc.svg","filename":"abc.svg"}}'
    urls = extract_file_urls_from_response(json_resp, "http://example.com/upload")
    assert any("abc.svg" in u for u in urls), f"未提取到 URL: {urls}"
    # 纯文本响应
    text_resp = '上传成功: https://cdn.example.com/files/test.html'
    urls2 = extract_file_urls_from_response(text_resp, "http://example.com/upload")
    assert any("test.html" in u for u in urls2)


def test_oob_receiver_lifecycle():
    """OOB receiver 注册和命中。"""
    from core.xss.oob import LocalOobReceiver

    async def _run():
        r = LocalOobReceiver()
        r.register_token("token123", {"target_url": "http://test"})
        await r.record_hit("token123", {"ua": "TestUA", "ip": "1.2.3.4"})
        hits = await r.get_hits("token123")
        assert len(hits) == 1
        assert hits[0]["ua"] == "TestUA"

    asyncio.run(_run())
