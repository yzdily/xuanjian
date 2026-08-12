"""
ExplorePhaseMixin — Phase 0 爬虫相关辅助方法。

方法：
- _extract_api_samples_from_traffic: 从 proxy_get_traffic 返回提取 API 样本
- _sync_all_flows_to_sitemap: 全量同步 FlowStore → sitemap
- _llm_filter_domains: LLM 域名清洗
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import AsyncGenerator

from core.log import get_logger

log = get_logger("session.explore")


class ExplorePhaseMixin:
    """Phase 0 爬虫相关辅助方法。"""

    async def _probe_target_reachable(self, url: str, max_retries: int = 3) -> bool:
        """目标可达性预检：重试 max_retries 次，每次间隔递增。

        Returns:
            True 如果目标可达，False 如果全部重试失败。
        """
        import asyncio
        import httpx
        from core.log import get_logger
        _log = get_logger("session.explore")

        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(10.0),
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(url)
                    if resp.status_code >= 500:
                        # 5xx 服务端错误（502/503/504）视为服务不可用，继续重试
                        _log.warning("目标返回 %d（服务端错误），视为不可达（第 %d/%d 次）: %s",
                                     resp.status_code, attempt + 1, max_retries, url)
                    else:
                        # 2xx/3xx/4xx 都说明目标可达（服务在线，可能需认证或路径不存在）
                        _log.info("目标可达性预检（第 %d 次）: %s => %d",
                                  attempt + 1, url, resp.status_code)
                        return True
            except httpx.ConnectError as e:
                _log.warning("目标不可达（第 %d/%d 次）: %s",
                             attempt + 1, max_retries, str(e)[:150])
            except httpx.TimeoutException:
                _log.warning("目标超时（第 %d/%d 次）", attempt + 1, max_retries)
            except Exception as e:
                _log.warning("目标预检异常（第 %d/%d 次）: %s",
                             attempt + 1, max_retries, str(e)[:150])
            # 递增等待：2s, 4s, 6s
            if attempt < max_retries - 1:
                await asyncio.sleep(2 * (attempt + 1))
        return False

    async def _passive_recon(self, url: str) -> list:
        """被动侦察：目标不可达时做信息收集 + dirsearch 风格目录爆破。

        流程：
        1. 轻量元信息探测（robots.txt / sitemap.xml / security.txt）
        2. 目录/文件爆破（core.dir_scanner.DirectoryScanner）：
           - 主机连接级不可达时自动跳过，不浪费字典请求
           - 命中路径回写 sitemap（add_page / add_api），供下游 FastScanner 测试
           - 敏感路径产出 info_disclosure 发现
        """
        import httpx
        from urllib.parse import urljoin
        from core.log import get_logger
        _log = get_logger("session.explore")

        findings: list[dict] = []

        # 1. 轻量元信息探测（robots.txt / sitemap.xml / security.txt）
        common_files = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(8.0), follow_redirects=True, verify=False,
        ) as client:
            for path in common_files:
                try:
                    target_url = urljoin(url, path)
                    resp = await client.get(target_url)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        findings.append({
                            "type": "info_disclosure",
                            "url": target_url,
                            "detail": f"发现 {path}: {resp.text[:200]}",
                        })
                        if self.sitemap:
                            self.sitemap.add_page(target_url, title=path)
                except Exception:
                    pass

        # 2. dirsearch 风格目录/文件爆破（核心增强）
        dir_summary: dict = {
            "host_unreachable": False,
            "wildcard_detected": False,
            "discovered": [],
            "sensitive": [],
            "total_requests": 0,
            "elapsed": 0.0,
        }
        try:
            from core.dir_scanner import DirectoryScanner

            # 认证头：目标不可达时通常无有效会话，best-effort 从已有属性提取
            auth_headers = getattr(self, "auth_headers", None) or {}

            def _on_progress(msg: str):
                _log.info("[DirScan] %s", msg)

            scanner = DirectoryScanner(
                max_workers=20, timeout=8.0,
                recursive=True, max_depth=2,
            )
            dir_result = await scanner.scan(
                url, auth_headers=auth_headers, on_progress=_on_progress,
            )

            dir_summary["host_unreachable"] = dir_result.host_unreachable
            dir_summary["wildcard_detected"] = dir_result.wildcard_detected
            dir_summary["total_requests"] = dir_result.total_requests
            dir_summary["elapsed"] = round(dir_result.elapsed, 2)
            # ★ 诊断字段
            dir_summary["connect_errors"] = dir_result.connect_errors
            dir_summary["timeout_errors"] = dir_result.timeout_errors
            dir_summary["critical_path_fallback"] = dir_result.critical_path_fallback

            # 回写 sitemap + 转 finding
            already_seen = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}
            # ★ 复用 supplemental_test_agent 的非业务路径过滤，避免 DirScan 字典猜测路径
            # （/dashboard、/login 等）被添加为 sitemap page/API，导致 feature 爆炸
            try:
                from core.sitemap.filters import is_non_business_path as _is_non_business_path
            except Exception:
                _is_non_business_path = None

            for entry in dir_result.entries:
                if entry.path in already_seen:
                    continue
                is_non_biz = _is_non_business_path(entry.path) if _is_non_business_path else False
                dir_summary["discovered"].append({
                    "path": entry.path, "status": entry.status,
                    "length": entry.length, "title": entry.title,
                    "content_type": entry.content_type,
                    "skipped": is_non_biz,
                })
                # ★ 非业务路径（管理后台/认证猜测等）不写入 sitemap，仅记录在摘要中
                if self.sitemap and not is_non_biz:
                    self.sitemap.add_page(entry.url, title=entry.title or entry.path)
                    # API-like 路径补建为 API，供下游 FastScanner 测试
                    if self._is_api_like_path(entry.path, entry.content_type):
                        try:
                            self.sitemap.add_api("GET", entry.url, discovered_by="dir_scan")
                        except Exception:
                            pass
                findings.append({
                    "type": "accessible_path",
                    "url": entry.url,
                    "detail": f"目录扫描发现: {entry.path} (HTTP {entry.status}, "
                              f"{entry.length}B, {entry.content_type})"
                              + (" [非业务路径，已跳过功能创建]" if is_non_biz else ""),
                })

            for f in dir_result.findings:
                dir_summary["sensitive"].append({
                    "vuln_type": f.vuln_type, "severity": f.severity, "url": f.url,
                })
                findings.append({
                    "type": "info_disclosure",
                    "url": f.url,
                    "detail": f"{f.vuln_type}: {f.detail}",
                    "severity": f.severity,
                })
                # ★ 同步写入 sitemap 的 DirScan 漏洞列表，确保在 get_coverage 中上报
                if self.sitemap:
                    try:
                        self.sitemap._dirscan_sensitive_vulns.append({
                            "vuln_type": f.vuln_type,
                            "severity": f.severity or "high",
                            "url": f.url,
                            "detail": f.detail,
                            "source": "dirscan",
                        })
                    except Exception:
                        pass

            _log.info(
                "目录扫描完成: 发现 %d 个路径, %d 个敏感泄露 (请求 %d, 耗时 %.1fs, "
                "host_unreachable=%s, wildcard=%s)",
                dir_result.discovered_count, dir_result.sensitive_count,
                dir_result.total_requests, dir_result.elapsed,
                dir_result.host_unreachable, dir_result.wildcard_detected,
            )
        except Exception as e:
            _log.warning("目录扫描失败（非致命）: %s", e, exc_info=True)

        # 暴露摘要供 chat_loop 渲染
        self._dir_scan_summary = dir_summary

        if self.sitemap:
            try:
                self.sitemap.save()
            except Exception:
                pass

        _log.info("被动侦察完成: 发现 %d 条信息", len(findings))
        return findings

    @staticmethod
    def _is_api_like_path(path: str, content_type: str) -> bool:
        """判断目录扫描命中的路径是否像 API 端点（用于回写 sitemap.apis）。"""
        p = path.lower()
        ct = (content_type or "").lower()
        if "json" in ct or "xml" in ct:
            return True
        api_markers = (
            "/api", "swagger", "openapi", "graphql", "api-docs",
            "actuator", "/v1/", "/v2/", "/v3/",
        )
        return any(m in p for m in api_markers)

    def _extract_api_samples_from_traffic(self, traffic_text: str) -> None:
        """从 proxy_get_traffic 的返回文本中提取 flow_id，再从 FlowStore 获取完整请求样本。"""
        import re as _re

        # 1. 从文本中提取 flow_id 列表
        flow_ids = _re.findall(r'\[(flow_[a-f0-9]+)\]', traffic_text)
        if not flow_ids:
            return

        # 2. 从 FlowStore 获取完整请求信息
        try:
            from mcp_servers.proxy_mcp import _store, _load_new_flows
            _load_new_flows()

            for fid in flow_ids:
                flow = _store.get(fid)
                if not flow:
                    continue

                # 只处理业务 API（跳过静态资源、第三方请求）
                url = flow.url

                # 过滤 CONNECT 隧道请求（不是真正的 API）
                if flow.method.upper() == "CONNECT":
                    continue

                # 过滤静态资源
                static_exts = ('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff', '.ttf', '.map', '.gif')
                if any(url.split('?')[0].lower().endswith(ext) for ext in static_exts):
                    continue

                # 写入 sitemap
                self.sitemap.add_api(flow.method, url.split("?")[0],
                                     discovered_by="mitmproxy")
                self.sitemap.add_api_sample(
                    method=flow.method,
                    url=url,
                    headers=flow.request_headers,
                    body=flow.request_body,
                    status_code=flow.status_code,
                    discovered_by="mitmproxy",
                    response_body=flow.response_body,
                    response_headers=getattr(flow, 'response_headers', None) or {},
                    content_type=getattr(flow, 'content_type', '') or '',
                    flow_id=fid,
                    trigger_context={"tool": "proxy_get_traffic"},
                )
        except Exception as e:
            log.warning("提取 API 样本失败: %s", e)

    def _sync_all_flows_to_sitemap(self) -> dict:
        """全量同步 FlowStore 到 sitemap（Phase 1→2 过渡时调用）。

        确保 mitmproxy 抓到的所有目标站点流量 100% 进入 sitemap.apis 和 api_samples。
        add_api/add_api_sample 内部自带去重，重复调用不会产生冗余。

        Returns:
            {"total_flows": int, "new_apis": int, "new_samples": int}
        """
        if not self.sitemap:
            return {"total_flows": 0, "new_apis": 0, "new_samples": 0}

        from urllib.parse import urlparse

        # 提取目标域名
        target_host = ""
        if self.target_url:
            parsed = urlparse(self.target_url)
            target_host = parsed.netloc

        try:
            from mcp_servers.proxy_mcp import _store, _load_new_flows
            _load_new_flows()  # 确保读取最新流量

            # 记录同步前的数量
            apis_before = len(self.sitemap.apis)
            samples_before = len(self.sitemap.api_samples)
            total_flows = 0

            for flow_id in list(_store._order):
                flow = _store.get(flow_id)
                if not flow:
                    continue

                url = flow.url
                method = flow.method.upper()

                # 过滤非目标域名
                if target_host:
                    flow_host = urlparse(url).netloc
                    if flow_host != target_host:
                        continue

                # 过滤 CONNECT 隧道
                if method == "CONNECT":
                    continue

                # 过滤静态资源（add_api 内部也会过滤，这里提前跳过减少开销）
                path_lower = url.split('?')[0].lower()
                if any(path_lower.endswith(ext) for ext in
                       ('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.map')):
                    continue
                if any(seg in path_lower for seg in ('/assets/', '/static/', '/dist/')):
                    continue

                # ★ 过滤推测探测痕迹：GET 请求 + CRUD 动词路径 + 错误状态码
                # 这些是 Phase 0 推测验证时用 GET 探测 POST/PUT/DELETE 端点留下的流量
                _CRUD_SUFFIXES = ('/create', '/add', '/save', '/update', '/edit',
                                  '/modify', '/delete', '/remove', '/import',
                                  '/export', '/batch', '/upload')
                if method == "GET" and flow.status_code in (401, 403, 405, 500, 502):
                    if any(path_lower.rstrip("/").endswith(s) for s in _CRUD_SUFFIXES):
                        continue

                total_flows += 1

                # 写入 sitemap（add_api/add_api_sample 内部去重）
                self.sitemap.add_api(method, url.split("?")[0],
                                     discovered_by="mitmproxy_sync")
                self.sitemap.add_api_sample(
                    method=method,
                    url=url,
                    headers=flow.request_headers,
                    body=flow.request_body,
                    status_code=flow.status_code,
                    discovered_by="mitmproxy_sync",
                    response_body=flow.response_body,
                    response_headers=getattr(flow, 'response_headers', None) or {},
                    content_type=getattr(flow, 'content_type', '') or '',
                    flow_id=flow_id,
                    trigger_context={"tool": "flowstore_sync"},
                )

            new_apis = len(self.sitemap.apis) - apis_before
            new_samples = len(self.sitemap.api_samples) - samples_before

            # ★ API 文档自动发现：扫描流量中的 Swagger/Actuator/GraphQL 特征
            # 命中后自动提取端点并补全 sitemap
            api_doc_count = 0
            try:
                from core.api_doc_discovery import detect_and_extract

                # 收集认证头（从已有流量中提取）
                doc_auth_headers = {}
                for fid2 in list(_store._order):
                    f2 = _store.get(fid2)
                    if f2 and f2.request_headers:
                        for k in ("cookie", "Cookie", "authorization", "Authorization"):
                            if k in f2.request_headers and f2.request_headers[k]:
                                doc_auth_headers[k] = f2.request_headers[k]
                        if doc_auth_headers:
                            break

                async def _run_doc_discovery():
                    import httpx
                    total = 0
                    async with httpx.AsyncClient(verify=False, timeout=8, follow_redirects=True) as doc_client:
                        for fid2 in list(_store._order):
                            f2 = _store.get(fid2)
                            if not f2 or not f2.response_body:
                                continue
                            ct2 = (f2.content_type or "").lower()
                            if "html" not in ct2 and "json" not in ct2 and "javascript" not in ct2:
                                continue
                            doc_results = await detect_and_extract(
                                url=f2.url,
                                response_body=f2.response_body[:5000],
                                response_headers=getattr(f2, 'response_headers', None),
                                sitemap=self.sitemap,
                                http_client=doc_client,
                                auth_headers=doc_auth_headers,
                            )
                            if doc_results:
                                total += sum(len(r.get("endpoints", [])) for r in doc_results)
                    return total

                # ★ 安全运行协程：兼容已有事件循环的场景
                # _sync_all_flows_to_sitemap 可能从 async 上下文调用，
                # 此时 asyncio.run() 会因嵌套事件循环而失败，改用 loop.run_until_complete
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None

                if loop and loop.is_running():
                    # 已在事件循环中 → 用 nest_asyncio 允许嵌套，
                    # 或在新线程中运行以避免冲突
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        api_doc_count = pool.submit(
                            asyncio.run, _run_doc_discovery()
                        ).result()
                else:
                    api_doc_count = asyncio.run(_run_doc_discovery())

                if api_doc_count > 0:
                    log.info("API 文档自动发现: 提取了 %d 个端点", api_doc_count)
            except Exception as e:
                log.debug("API 文档自动发现失败（非致命）: %s", e)

            # 为新增的 API 补建功能点（如果还没有功能点关联这些 API）
            new_features = 0
            if new_apis > 0:
                existing_api_set = set()
                for fp in self.sitemap.features.values():
                    for api in fp.related_apis:
                        existing_api_set.add(api.split("?")[0].rstrip("/"))

                for api_key, api in self.sitemap.apis.items():
                    api_norm = api_key.split("?")[0].rstrip("/")
                    if api_norm not in existing_api_set:
                        # 为这个 API 创建功能点
                        vulns = self.sitemap._infer_vulns_from_api(api.method, api.url)
                        from urllib.parse import urlparse as _urlparse
                        path = _urlparse(api.url).path
                        path_parts = [p for p in path.split("/") if p and p not in ("api", "v1", "v2", "v3")]
                        method_label = {"GET": "查询", "POST": "新增", "PUT": "修改",
                                       "PATCH": "修改", "DELETE": "删除"}.get(api.method, api.method)
                        path_name = "/".join(path_parts[-2:]) if len(path_parts) >= 2 else (
                            path_parts[-1] if path_parts else "root")
                        name = f"{path_name}({method_label})"
                        desc = f"API 端点 {api.method} {api.url}（流量全量同步补建）"

                        fp = self.sitemap._create_atomic_feature(
                            name, desc, api.url, api_key, vulns)
                        if fp:
                            new_features += 1

            result = {
                "total_flows": total_flows,
                "new_apis": new_apis,
                "new_samples": new_samples,
                "new_features": new_features,
            }
            log.info("全量流量同步: %s", result)
            return result

        except Exception as e:
            log.warning("全量流量同步失败: %s", e)
            return {"total_flows": 0, "new_apis": 0, "new_samples": 0, "error": str(e)}

    async def _llm_filter_domains(self, crawl_result: dict) -> int:
        """让 LLM 判断爬虫抓到的域名中，哪些是目标业务相关的、哪些是第三方。

        从 sitemap.apis 中提取所有域名 → LLM 分类 → 删除非业务域名的 API。
        返回被清除的 API 数量。
        """
        if not self.sitemap:
            return 0

        # ★ LLM 未配置或不可调用时跳过域名清洗（FAST 模式下 self.llm 为 None）
        if not callable(getattr(self.llm, "chat", None)):
            log.info("LLM 未配置，跳过域名清洗")
            return 0

        from urllib.parse import urlparse
        from collections import Counter
        from core.llm import Message
        import asyncio

        # 1. 统计所有域名及其 API 数量
        domain_counts: Counter = Counter()
        domain_apis: dict[str, list[str]] = {}  # domain → [api_keys]
        for key in list(self.sitemap.apis.keys()):
            parts = key.split(" ", 1)
            if len(parts) == 2 and parts[1].startswith("http"):
                host = urlparse(parts[1]).netloc.lower()
            elif len(parts) == 2:
                host = urlparse(self.sitemap.target).netloc.lower()
            else:
                continue
            domain_counts[host] += 1
            domain_apis.setdefault(host, []).append(key)

        # 只有 1 个域名或没有域名，不需要清洗
        if len(domain_counts) <= 1:
            return 0

        # 2. 构建 prompt 让 LLM 分类（附带 URL 样例，让 LLM 看到具体请求）
        target_url = self.sitemap.target

        # 每个域名附带最多 3 个 URL 样例
        domain_details = []
        for domain, count in domain_counts.most_common(50):
            examples = domain_apis.get(domain, [])[:3]
            example_str = "\n".join(f"    {ex[:120]}" for ex in examples)
            domain_details.append(f"- **{domain}** ({count} 个请求)\n{example_str}")
        domain_list = "\n".join(domain_details)

        prompt = (
            f"目标网站是: {target_url}\n\n"
            f"爬虫在访问该网站时抓到了以下域名的 HTTP 请求（含 URL 样例）：\n\n{domain_list}\n\n"
            "请判断哪些是**目标业务 API**，哪些应该**排除**。\n\n"
            "## 排除标准（满足任一即排除）\n"
            "1. **第三方域名**：广告（doubleclick/facebook pixel/bing ads）、分析（google analytics/segment/mixpanel）、"
            "监控（bugsnag/sentry/newrelic）、Cookie 合规（cookielaw/onetrust）、追踪像素（spotify/pinterest/reddit）\n"
            "2. **同域名下的非业务 URL**：即使域名是目标自有的，以下类型也要排除：\n"
            "   - GTM/Google Tag 埋点：URL 含 `/gtm/` `/g/collect` `/metrics/ddm/`\n"
            "   - 广告/营销追踪：URL 含 `/pixel` `/beacon` `/track` `/collect` `/activity`\n"
            "   - 纯静态资源加载、service worker、manifest\n"
            "3. **设备指纹/反欺诈**：如 intuit deviceintel、online-metrix、ThreatMetrix\n\n"
            "## 保留标准\n"
            "- 目标公司的业务 API（增删改查、用户操作、数据接口）\n"
            "- 前后端分离的 API 服务器（即使域名不同）\n"
            "- SSO/登录服务（如 login.xxx.com）\n"
            "- 不确定的**保留**，不要误删\n\n"
            "严格返回 JSON：\n"
            '{"business_domains": ["domain1.com"], '
            '"third_party_domains": ["ads.example.com"], '
            '"third_party_url_patterns": ["/gtm/", "/g/collect", "/metrics/ddm/"]}\n\n'
            "third_party_url_patterns 是**同域名下**也要排除的 URL 路径关键词。"
        )

        try:
            messages = [
                Message(role="system", content="你是安全测试助手，负责判断域名是否属于目标业务。"),
                Message(role="user", content=prompt),
            ]
            response = await asyncio.to_thread(self.llm.chat, messages, caller="domain_filter")
            text = response.content or ""

            # 解析 JSON
            json_match = re.search(r'\{[\s\S]*\}', text)
            if not json_match:
                log.warning("域名清洗: LLM 未返回有效 JSON，跳过清洗")
                return 0

            result = json.loads(json_match.group())
            third_party = set(d.lower() for d in result.get("third_party_domains", []))
            url_patterns = [p.lower() for p in result.get("third_party_url_patterns", []) if isinstance(p, str)]

            if not third_party and not url_patterns:
                return 0

            # 3. 从 sitemap 中删除
            removed = 0
            keys_to_remove = []

            for key in list(self.sitemap.apis.keys()):
                parts = key.split(" ", 1)
                url = parts[1] if len(parts) == 2 else ""
                url_lower = url.lower()

                # 规则 A：第三方域名整体删除
                from urllib.parse import urlparse as _up2
                req_host = _up2(url).netloc.lower() if url.startswith("http") else ""
                if req_host and req_host in third_party:
                    keys_to_remove.append(key)
                    continue

                # 规则 B：同域名下的追踪 URL 模式删除
                if url_patterns and any(pat in url_lower for pat in url_patterns):
                    keys_to_remove.append(key)
                    continue

            for key in keys_to_remove:
                self.sitemap.apis.pop(key, None)
                removed += 1

            # api_samples 的 key 格式是 "METHOD host/path|param_fingerprint"，与 apis 的 key 格式不同
            # 需要根据域名/URL 模式单独匹配删除
            sample_keys_to_remove = []
            for skey in list(self.sitemap.api_samples.keys()):
                s_parts = skey.split(" ", 1)
                s_url_part = s_parts[1] if len(s_parts) == 2 else ""
                # key 中 host/path 在 | 之前
                s_base = s_url_part.split("|")[0]  # host/path 部分
                s_url_lower = s_base.lower()

                # 规则 A：第三方域名
                if not s_base.startswith("/"):
                    # 含 host 的 key，提取 host
                    s_host = s_base.split("/")[0].lower() if "/" in s_base else s_base.lower()
                    if s_host in third_party:
                        sample_keys_to_remove.append(skey)
                        continue

                # 规则 B：URL 模式匹配
                if url_patterns and any(pat in s_url_lower for pat in url_patterns):
                    sample_keys_to_remove.append(skey)
                    continue

            for skey in sample_keys_to_remove:
                self.sitemap.api_samples.pop(skey, None)
                removed += 1

            if removed:
                log.info("域名清洗: 清除 %d 个非业务 API（%d 个第三方域名 + URL 模式匹配）",
                         removed, len(third_party))
            return removed

        except Exception as e:
            log.warning("域名清洗失败: %s，跳过", e)
            return 0
