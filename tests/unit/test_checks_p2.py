"""§2.8 P2 净新增 13 类检查单元测试（技术方案 §4 / 产品方案 §2.8.1）。

13 类：XSLT/CSV公式/CRLF/原型链/HTTP2/HPP/点击劫持/CSP/缓存投毒/
       WebSocket/SAML/子域接管/依赖混淆

所有测试通过 monkeypatch 实例 _request 模拟响应，不发起真实网络请求。
"""
import httpx
import pytest

from core.fast_scanner import FastScanner, ScanTarget

_RULES_13 = [
    "xslt_injection", "csv_formula_injection", "crlf_injection",
    "prototype_pollution", "http2_abuse", "hpp", "clickjacking",
    "csp_bypass", "web_cache_poisoning", "websocket_security",
    "saml_assertion", "subdomain_takeover", "dependency_confusion",
]


def _scanner(fake):
    s = FastScanner(max_workers=1)
    s._request = fake
    return s


def _resp(status=200, text="", **headers):
    return httpx.Response(status, text=text, headers=headers)


# ============================================================
# 接线：13 个方法均能被 FastScanner 解析
# ============================================================
def test_all_13_check_methods_bound():
    s = FastScanner(max_workers=1)
    for rule in _RULES_13:
        handler = getattr(s, f"_check_{rule}", None)
        assert handler is not None, f"_check_{rule} 未注册到 FastScanner"
        assert callable(handler)


# ============================================================
# 1. XSLT 注入
# ============================================================
@pytest.mark.asyncio
async def test_xslt_positive():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "result <?xml-stylesheet ...> transformed")
    s = _scanner(fake)
    t = ScanTarget(url="http://x/transform", method="POST", body="<xml/>")
    f = await s._check_xslt_injection(t)
    assert f and f[0].vuln_type == "XSLT注入"


@pytest.mark.asyncio
async def test_xslt_negative_not_post():
    s = _scanner(None)
    t = ScanTarget(url="http://x/", method="GET")
    f = await s._check_xslt_injection(t)
    assert not f


# ============================================================
# 2. CSV 公式注入
# ============================================================
@pytest.mark.asyncio
async def test_csv_formula_positive():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "name,=cmd|' /C calc'!A0\n",
                     **{"content-type": "text/csv"})
    s = _scanner(fake)
    t = ScanTarget(url="http://x/export", method="GET", params={"name": "x"})
    f = await s._check_csv_formula_injection(t)
    assert f and f[0].vuln_type == "CSV公式注入"


@pytest.mark.asyncio
async def test_csv_formula_negative_not_csv():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "=cmd|' /C calc'!A0", **{"content-type": "text/html"})
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET", params={"q": "x"})
    f = await s._check_csv_formula_injection(t)
    assert not f


# ============================================================
# 3. CRLF
# ============================================================
@pytest.mark.asyncio
async def test_crlf_positive():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "ok", **{"X-Injected": "true"})
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET", params={"q": "x"})
    f = await s._check_crlf_injection(t)
    assert f and f[0].vuln_type == "CRLF响应头注入"


# ============================================================
# 4. 原型链污染
# ============================================================
@pytest.mark.asyncio
async def test_proto_pollution_positive():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"isAdmin":true}')
    s = _scanner(fake)
    t = ScanTarget(url="http://x/api", method="POST", body='{"a":1}')
    f = await s._check_prototype_pollution(t)
    assert f and f[0].vuln_type == "原型链污染"


@pytest.mark.asyncio
async def test_proto_pollution_negative_not_json():
    s = _scanner(None)
    t = ScanTarget(url="http://x/api", method="POST", body="not json")
    f = await s._check_prototype_pollution(t)
    assert not f


# ============================================================
# 5. HTTP2
# ============================================================
@pytest.mark.asyncio
async def test_http2_positive_h2c_upgrade():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(101, "", **{"Upgrade": "h2c"})
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET")
    f = await s._check_http2_abuse(t)
    assert f and f[0].vuln_type == "HTTP/2降级漏洞"


@pytest.mark.asyncio
async def test_http2_negative_no_upgrade():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "ok")
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET")
    f = await s._check_http2_abuse(t)
    assert not f


# ============================================================
# 6. HPP
# ============================================================
@pytest.mark.asyncio
async def test_hpp_positive():
    calls = {"n": 0}

    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        calls["n"] += 1
        if payload_tag == "baseline":
            return _resp(200, '{"data":null}')
        return _resp(403, '{"code":-1}')  # 不同状态码
    s = _scanner(fake)
    t = ScanTarget(url="http://x/api", method="GET", params={"id": "1"})
    f = await s._check_hpp(t)
    assert f and f[0].vuln_type == "HPP参数污染"


# ============================================================
# 7. 点击劫持
# ============================================================
@pytest.mark.asyncio
async def test_clickjacking_positive():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "<html>")
    s = _scanner(fake)
    t = ScanTarget(url="http://x/login", method="GET")
    f = await s._check_clickjacking(t)
    assert f and f[0].vuln_type == "点击劫持"


@pytest.mark.asyncio
async def test_clickjacking_negative_xfo_present():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "<html>", **{"X-Frame-Options": "DENY"})
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET")
    f = await s._check_clickjacking(t)
    assert not f


# ============================================================
# 8. CSP
# ============================================================
@pytest.mark.asyncio
async def test_csp_missing():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "<html>")
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET")
    f = await s._check_csp_bypass(t)
    assert f and f[0].vuln_type == "CSP缺失"


@pytest.mark.asyncio
async def test_csp_unsafe_inline():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "<html>",
                     **{"Content-Security-Policy": "script-src 'unsafe-inline'"})
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET")
    f = await s._check_csp_bypass(t)
    assert f and f[0].vuln_type == "CSP配置缺陷"


@pytest.mark.asyncio
async def test_csp_strict_negative():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "<html>",
                     **{"Content-Security-Policy":
                        "default-src 'self'; script-src 'nonce-abc'"})
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET")
    f = await s._check_csp_bypass(t)
    assert not f


# ============================================================
# 9. 缓存投毒
# ============================================================
@pytest.mark.asyncio
async def test_cache_poisoning_positive():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "host: evil-cache.com page")
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET")
    f = await s._check_web_cache_poisoning(t)
    assert f and f[0].vuln_type == "Web缓存投毒"


# ============================================================
# 10. WebSocket
# ============================================================
@pytest.mark.asyncio
async def test_websocket_plaintext():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(404, "")
    s = _scanner(fake)
    t = ScanTarget(url="ws://x/ws", method="GET")
    f = await s._check_websocket_security(t)
    assert any(x.vuln_type == "WebSocket明文传输" for x in f)


@pytest.mark.asyncio
async def test_websocket_origin_bypass():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(101, "", **{"Sec-WebSocket-Accept": "s3pP..."})
    s = _scanner(fake)
    t = ScanTarget(url="http://x/ws", method="GET")
    f = await s._check_websocket_security(t)
    assert any(x.vuln_type == "WebSocket跨域" for x in f)


# ============================================================
# 11. SAML
# ============================================================
@pytest.mark.asyncio
async def test_saml_positive():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '<samlp:Response><saml:Assertion>...</saml:Assertion>')
    s = _scanner(fake)
    t = ScanTarget(url="http://x/sso/SAMLResponse", method="GET")
    f = await s._check_saml_assertion(t)
    assert f and f[0].vuln_type == "SAML断言篡改风险"


@pytest.mark.asyncio
async def test_saml_negative_no_saml_url():
    s = _scanner(None)
    t = ScanTarget(url="http://x/api", method="GET")
    f = await s._check_saml_assertion(t)
    assert not f


# ============================================================
# 12. 子域接管
# ============================================================
@pytest.mark.asyncio
async def test_subdomain_takeover_positive():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "There is no app configured at that hostname.")
    s = _scanner(fake)
    t = ScanTarget(url="http://sub.x/", method="GET")
    f = await s._check_subdomain_takeover(t)
    assert f and f[0].vuln_type == "子域接管"


@pytest.mark.asyncio
async def test_subdomain_takeover_negative():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "normal page")
    s = _scanner(fake)
    t = ScanTarget(url="http://x/", method="GET")
    f = await s._check_subdomain_takeover(t)
    assert not f


# ============================================================
# 13. 依赖混淆
# ============================================================
@pytest.mark.asyncio
async def test_dep_confusion_positive():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"dependencies":{"internal-utils":"1.0.0"}}')
    s = _scanner(fake)
    t = ScanTarget(url="http://x/package.json", method="GET")
    f = await s._check_dependency_confusion(t)
    assert f and f[0].vuln_type == "依赖混淆风险"
