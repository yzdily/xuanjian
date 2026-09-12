"""fast_scanner sitemap 集成 mixin（从原 fast_scanner.py 机械拆分，方法体逐字保留）。"""

from __future__ import annotations

import asyncio
from urllib.parse import urlencode, urlparse

from core.log import get_logger

from ._models import VulnFinding, ScanTarget

log = get_logger("fast_scanner")


class _SitemapIntegration:
    """sitemap 集成与被动分析方法（功能点扫描 / JS 被动分析 / source map 推导）。"""

    async def scan_sitemap_features(
        self,
        features: list,
        session_info: dict | None = None,
        sitemap=None,
    ) -> list[VulnFinding]:
        """扫描 sitemap 中的功能点（供 orchestrator 调用）。

        Args:
            features: FeaturePoint 列表（来自 sitemap）
            session_info: 包含 headers 等信息的 dict
            sitemap: Sitemap 实例（可选），用于补充未覆盖的 API
        """
        findings: list[VulnFinding] = []
        auth_headers = (session_info or {}).get("headers", {})

        # 收集所有已扫描的 API key（"METHOD url" 格式），用于去重
        scanned_api_keys: set[str] = set()
        targets: list[ScanTarget] = []

        # ---- 1. 从功能点的 related_apis 生成扫描目标 ----
        # related_apis 格式: ["GET /api/users", "POST /api/login", ...]
        for fp in features:
            for api in getattr(fp, "related_apis", []):
                if isinstance(api, str):
                    # "METHOD url" 格式
                    parts = api.split(" ", 1)
                    if len(parts) == 2:
                        method, api_url = parts
                    else:
                        method, api_url = "GET", api
                elif isinstance(api, dict):
                    method = api.get("method", "GET")
                    api_url = api.get("url", "")
                else:
                    continue

                if not api_url:
                    continue

                # 跳过非 HTTP URL（如 mailto:, javascript:）
                if api_url.startswith(("mailto:", "javascript:", "tel:", "#")):
                    continue

                api_key = f"{method} {api_url}"
                if api_key in scanned_api_keys:
                    continue
                scanned_api_keys.add(api_key)

                # 从 sitemap.api_samples 提取请求样本（body/params）
                body = ""
                params = {}
                if sitemap:
                    body, params = self._extract_sample_from_sitemap(
                        sitemap, method, api_url, auth_headers
                    )

                targets.append(ScanTarget(
                    url=api_url,
                    method=method,
                    params=params,
                    body=body,
                    auth_headers=auth_headers,
                    # ★ Fix4：从功能点优先级透传（FeaturePoint.priority 为 Priority 枚举，str() 取 "critical"/"high"/...）
                    priority=str(getattr(fp, "priority", "")) or "medium",
                ))

            # 如果功能点没有 related_apis，用 page_url 兜底
            if not getattr(fp, "related_apis", []):
                fp_url = getattr(fp, "page_url", "") or getattr(fp, "url", "")
                if fp_url and fp_url.startswith("http"):
                    targets.append(ScanTarget(url=fp_url, auth_headers=auth_headers))

        # ---- 2. 从 sitemap.apis 补充未被功能点覆盖的 API ----
        if sitemap and hasattr(sitemap, "apis"):
            for api_key, api_endpoint in sitemap.apis.items():
                if api_key in scanned_api_keys:
                    continue
                scanned_api_keys.add(api_key)

                api_url = getattr(api_endpoint, "url", "")
                method = getattr(api_endpoint, "method", "GET")
                if not api_url:
                    continue

                # 从 api_samples 提取请求样本
                body = getattr(api_endpoint, "request_body_sample", "") or ""
                params = {}
                param_names = getattr(api_endpoint, "params", [])
                if param_names and isinstance(param_names, list):
                    params = {p: "" for p in param_names}

                body2, params2 = self._extract_sample_from_sitemap(
                    sitemap, method, api_url, auth_headers
                )
                if body2:
                    body = body2
                if params2:
                    params = params2

                targets.append(ScanTarget(
                    url=api_url,
                    method=method,
                    params=params,
                    body=body,
                    auth_headers=auth_headers,
                    # sitemap.apis 补充的目标暂无功能点优先级，默认 medium
                    priority=getattr(api_endpoint, "priority", "medium"),
                ))

        if not targets:
            log.warning("FastScanner: 无可扫描目标（功能点和 sitemap.apis 均为空）")
            return []

        log.info("FastScanner: 扫描 %d 个目标 (功能点 %d + sitemap.apis 补充)",
                 len(targets), len(features))

        # ★ SEC-8: 扫描启动时输出当前 WAF/超时状态，便于追溯跨目标持久化状态
        # project_memory: WAF 状态跨目标持久化，启动日志应显示 clean/blocked(继承)
        _sec8_waf = "blocked" if getattr(self, "_waf_blocked", False) else "clean"
        _sec8_timeout = "blocked" if getattr(self, "_timeout_blocked", False) else "clean"
        _sec8_global_to = getattr(self, "_global_timeout_count", 0)
        _sec8_global_slow = "on" if getattr(self, "_global_timeout_slowdown", False) else "off"
        log.info("🛡️ WAF 状态: %s | 超时熔断: %s | 全局超时累计: %d (降速 %s)",
                 _sec8_waf, _sec8_timeout, _sec8_global_to, _sec8_global_slow)

        # 批量扫描
        results = await self.scan_targets(targets)

        # 收集发现
        for result in results:
            findings.extend(result.findings)

        # ★ SEC-4: FastScanner 命中诊断日志 — 0 命中时输出候选/过滤统计
        # 定位是规则未匹配还是被过滤（zhenduan 诊断：业务理解提到 JSONP/硬编码 key
        # 但 FastScanner 0 命中，需明确告知是规则缺失还是过滤过严）
        if not findings:
            _sec4_total = len(targets)
            _sec4_no_resp = sum(1 for r in results if not getattr(r, "response", None))
            _sec4_blocked = sum(1 for r in results if getattr(r, "blocked", False))
            log.warning(
                "FastScanner 0 命中诊断: 目标 %d 个, 无响应 %d, 被拦截 %d — "
                "若业务理解提到敏感接口但此处 0 命中，请检查 rules/*.yaml 规则覆盖度",
                _sec4_total, _sec4_no_resp, _sec4_blocked,
            )

        # ★ Source Map 动态推导探测：对爬取到的每个 JS URL 追加 .map 检测
        #   原 SENSITIVE_PATHS 只硬编码 /app.js.map 等 4 个路径，无法覆盖 hash 文件名
        #   （如 chunk-2cd2c088.a68ccc9c.js.map）。这里从 sitemap.js_file_urls 动态推导。
        if sitemap and getattr(sitemap, "js_file_urls", None):
            sm_findings = await self._check_js_source_maps(
                sitemap.js_file_urls, auth_headers
            )
            findings.extend(sm_findings)

        # ★ WAF 封禁后被动模式：主动扫描被 WAF 全局封禁，但已获取的 JS 源码仍可分析
        #   红队原则：WAF 封禁不等于放弃，立即切换被动分析——
        #   从 JS 源码中提取硬编码密钥、内网域名、调试接口等
        if getattr(self, "_waf_blocked", False) and sitemap:
            passive_findings = await self._passive_js_analysis(sitemap, auth_headers)
            findings.extend(passive_findings)

        return findings

    async def _passive_js_analysis(
        self, sitemap, auth_headers: dict
    ) -> list[VulnFinding]:
        """WAF 封禁后被动模式：分析已缓存的 JS 源码

        无需向目标发送请求（已被 WAF 封禁），从 sitemap 已持久化的 JS 分析结果中提取：
        1. 调试接口（/debug /test /dev 等隐藏路径，来自 js_routes / js_api_calls）
        2. source map 已知可访问 URL（来自爬取阶段检测结果）

        注：硬编码密钥等敏感信息在爬取阶段已由 js_analyzer 检测并生成功能点，
        这里只补充被动分析阶段能产出的额外发现。
        """
        findings: list[VulnFinding] = []
        try:
            # 1. 检查 js_routes / js_api_calls 中的调试接口
            debug_keywords = ("/debug", "/test", "/dev", "/mock", "/demo",
                              "/api-docs", "/swagger", "/actuator",
                              "/console", "/admin/debug")
            seen_paths = set()
            for route in getattr(sitemap, "js_routes", []):
                path = (route.get("path") or "") if isinstance(route, dict) else ""
                if not path or path in seen_paths:
                    continue
                if any(kw in path.lower() for kw in debug_keywords):
                    seen_paths.add(path)
                    full_url = path if path.startswith("http") else sitemap.target.rstrip("/") + path
                    findings.append(VulnFinding(
                        vuln_type="信息泄露",
                        severity="low",
                        url=full_url,
                        method="GET",
                        detail=f"JS 路由中发现调试接口: {path}（WAF 封禁后被动分析发现）",
                        evidence=f"路由来源: {route.get('source_file', '') if isinstance(route, dict) else ''}",
                        payload="",
                        fix_suggestion="生产环境移除调试接口或添加访问控制",
                        evidence_quality="header_only",
                        rule_tag="InfoLeak",
                    ))
            for api_call in getattr(sitemap, "js_api_calls", []):
                path = (api_call.get("path") or "") if isinstance(api_call, dict) else ""
                if not path or path in seen_paths:
                    continue
                if any(kw in path.lower() for kw in debug_keywords):
                    seen_paths.add(path)
                    full_url = path if path.startswith("http") else sitemap.target.rstrip("/") + path
                    findings.append(VulnFinding(
                        vuln_type="信息泄露",
                        severity="low",
                        url=full_url,
                        method="GET",
                        detail=f"JS API 调用中发现调试接口: {path}（WAF 封禁后被动分析发现）",
                        evidence=f"来源: {api_call.get('source_file', '') if isinstance(api_call, dict) else ''}",
                        payload="",
                        fix_suggestion="生产环境移除调试接口或添加访问控制",
                        evidence_quality="header_only",
                        rule_tag="InfoLeak",
                    ))

            # 2. 尝试从 JS 缓存中提取敏感信息（如果缓存未被清理）
            try:
                from core.js_analyzer import _js_source_cache, _normalize_target_key, analyze_js
                target_key = _normalize_target_key(sitemap.target)
                bucket = _js_source_cache.get(target_key, {})
                if bucket:
                    log.info("[PASSIVE] WAF 封禁被动模式: 分析 %d 个缓存 JS 文件", len(bucket))
                    js_contents = list(bucket.items())
                    result = analyze_js(js_contents, sitemap.target)
                    for info in result.sensitive_info:
                        sev = "high" if info.info_type in ("api_key", "secret", "password") else "medium"
                        findings.append(VulnFinding(
                            vuln_type="客户端硬编码密钥泄露" if info.info_type in ("api_key", "secret", "password") else "信息泄露",
                            severity=sev,
                            url=info.source_file or sitemap.target,
                            method="GET",
                            detail=(f"JS 源码中发现{info.info_type}: {info.value[:80]}"
                                    f"（WAF 封禁后被动分析发现）"),
                            evidence=f"文件: {info.source_file}\n上下文: {info.context[:300]}",
                            payload="",
                            fix_suggestion=("将密钥迁移到服务端环境变量，前端只通过接口获取临时 token；"
                                            "已泄露的密钥立即轮换"),
                            evidence_quality="content_match",
                            rule_tag="InfoLeak",
                        ))
            except ImportError:
                pass

            log.info("[PASSIVE] WAF 封禁被动模式完成: 发现 %d 个泄露", len(findings))
        except Exception as e:
            log.warning("[PASSIVE] 被动分析失败: %s", e)

        return findings


    async def _check_js_source_maps(
        self, js_urls: list[str], auth_headers: dict
    ) -> list[VulnFinding]:
        """Source Map 动态推导探测

        对每个 JS URL 追加 .map 后缀探测（如 main.js → main.js.map），
        覆盖 hash 文件名场景（SENSITIVE_PATHS 硬编码路径无法覆盖）。

        判定逻辑（多因素）：
        1. .map 返回 200 + Content-Type 为 JSON/JS
        2. 响应体含 source map 特征字段（version / sources / mappings / sourcesContent）
        """
        if not js_urls:
            return []

        findings: list[VulnFinding] = []
        # 去重 + 限制数量避免请求爆炸
        unique_urls: list[str] = []
        seen = set()
        for u in js_urls:
            if u not in seen and u.startswith("http"):
                seen.add(u)
                unique_urls.append(u)
        unique_urls = unique_urls[:30]  # 最多探测 30 个

        async def check_one(js_url: str) -> VulnFinding | None:
            # 构造 .map URL
            if js_url.endswith(".js"):
                map_url = js_url + ".map"
            elif js_url.endswith(".mjs"):
                map_url = js_url + ".map"
            else:
                return None
            # 跳过已知的第三方 CDN（如 cdnjs/jquery.com）——它们的 .map 无安全价值
            from urllib.parse import urlparse as _up
            host = _up(map_url).netloc.lower()
            if any(h in host for h in ("cdnjs.", "jquery.com", "unpkg.com",
                                        "cdn.jsdelivr.net", "ajax.googleapis.com")):
                return None

            resp = await self._request(
                "GET", map_url, headers=auth_headers,
                rule_tag="InfoLeak", payload_tag=".map"
            )
            if not resp or resp.status_code != 200:
                return None
            # 多因素验证：响应体必须含 source map 特征字段
            text = resp.text or ""
            sm_features = ["\"version\"", "\"sources\"", "\"mappings\"",
                           "\"sourcesContent\"", "version:1", "sourceRoot"]
            matched = sum(1 for f in sm_features if f in text)
            if matched < 2:
                return None
            # sourcesContent 泄露最严重（包含完整源码）
            has_sources_content = "\"sourcesContent\"" in text
            severity = "high" if has_sources_content else "medium"
            quality = "content_match" if matched >= 3 else "body_confirmed"
            return VulnFinding(
                vuln_type="信息泄露",
                severity=severity,
                url=map_url,
                method="GET",
                detail=(f"Source Map 文件可访问: {map_url}（"
                        f"{'含 sourcesContent，泄露完整源码' if has_sources_content else '含 sources/mappings，可还原源码结构'}）"),
                evidence=f"HTTP {resp.status_code}, Content-Length: {len(text)}\n"
                         f"特征匹配: {matched}/6\n响应体片段: {text[:300]}",
                payload="",
                fix_suggestion=("生产环境关闭 Source Map 生成，或部署后删除 .map 文件；"
                                "至少移除 sourcesContent 字段（它包含完整源码）"),
                evidence_quality=quality,
                rule_tag="InfoLeak",
            )

        tasks = [check_one(u) for u in unique_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, VulnFinding):
                findings.append(r)

        if findings:
            log.info("[SCAN] Source Map 动态推导: 探测 %d 个 JS，发现 %d 个 .map 可访问",
                     len(unique_urls), len(findings))
        return findings


    @staticmethod
    def _extract_sample_from_sitemap(
        sitemap, method: str, api_url: str, auth_headers: dict
    ) -> tuple[str, dict]:
        """从 sitemap.api_samples 提取请求样本，返回 (body, params)。"""
        body = ""
        params = {}

        if not hasattr(sitemap, "api_samples"):
            return body, params

        # api_samples 的 key 格式: "METHOD host/path|param_fingerprint"
        from urllib.parse import urlparse
        parsed = urlparse(api_url)
        path = parsed.path or api_url

        for skey, sample in sitemap.api_samples.items():
            if not isinstance(sample, dict):
                continue
            # 匹配 method + path
            s_parts = skey.split(" ", 1)
            s_method = s_parts[0] if len(s_parts) == 2 else ""
            s_url_part = s_parts[1] if len(s_parts) == 2 else skey
            s_base = s_url_part.split("|")[0]

            if s_method.upper() != method.upper():
                continue
            # 路径匹配（s_base 可能是 host/path 或 /path）
            if path not in s_base and s_base not in path:
                continue

            # 提取 body
            req_body = sample.get("request_body") or sample.get("body") or ""
            if req_body:
                body = req_body
            # 提取 params
            req_params = sample.get("params") or sample.get("query_params") or {}
            if isinstance(req_params, dict):
                params = req_params
            break

        return body, params

    # ============================================================
    # 辅助方法
    # ============================================================

    @staticmethod
    def _build_url(base_url: str, params: dict) -> str:
        """构造带参数的 URL"""
        if not params:
            return base_url
        sep = "&" if "?" in base_url else "?"
        return base_url + sep + urlencode(params)
