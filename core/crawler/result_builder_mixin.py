"""
ResultBuilderMixin — 爬取结果构建与对比。

从 crawler_core.py 拆分出来的独立 mixin，负责：
- _extract_js_endpoints: 从页面 JS 文件中提取 API 端点
- _compare_rounds: 对比不同角色的爬取结果
- _build_final_result: 构建最终完整爬取结果（含指纹推测验证）
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlparse, urljoin
from typing import Any

from .models import FORM_FILL_RULES
from core.realtime_protocols import classify_realtime_flow, dedupe_realtime_channels


# 菜单 API 关键词（从 crawler_core.py 导入，避免重复定义）
# 注意：这里不重复定义，而是在运行时通过 self 或模块级引用获取
# 实际使用时从 crawler_core 模块级常量 MENU_API_KEYWORDS 获取


class ResultBuilderMixin:
    """爬取结果构建与对比能力（Mixin，需配合 AutoCrawler 使用）。"""

    def _build_menu_contexts_for_result(self, items: list[dict], login_status: dict | None = None) -> dict:
        """按角色汇总菜单树响应上下文。"""
        contexts: dict[str, dict] = {}
        login_status = login_status or {}
        for item in items or []:
            if not isinstance(item, dict):
                continue
            auth_ctx = item.get("auth_context", {}) if isinstance(item.get("auth_context"), dict) else {}
            role = str(item.get("role") or auth_ctx.get("role") or "anonymous")
            ctx = contexts.setdefault(role, {
                "role": role,
                "account": item.get("account") or auth_ctx.get("account") or "",
                "credential_id": item.get("credential_id") or auth_ctx.get("credential_id") or role,
                "login_success": bool(login_status.get(role, role == "anonymous")),
                "menu_api_urls": [],
                "sources": [],
                "menu_response_count": 0,
            })
            url = item.get("url", "")
            source = item.get("source", "")
            if url and url not in ctx["menu_api_urls"]:
                ctx["menu_api_urls"].append(url)
            if source and source not in ctx["sources"]:
                ctx["sources"].append(source)
            ctx["menu_response_count"] += 1
        return contexts

    async def _extract_js_endpoints(self, page) -> list[str]:
        """从页面加载的 JS 文件中提取 API 端点。"""
        endpoints = set()
        try:
            js_urls = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
            }""")

            for js_url in js_urls[:10]:  # 最多分析 10 个 JS
                try:
                    resp = await page.goto(js_url, timeout=5000)
                    if resp and resp.status == 200:
                        text = await resp.text()
                        # 提取 API 路径
                        patterns = re.findall(r'["\'](/api/[^"\'?#]+)["\']', text)
                        patterns += re.findall(r'["\'](/v[12]/[^"\'?#]+)["\']', text)
                        patterns += re.findall(r'["\'](/admin/[^"\'?#]+)["\']', text)
                        patterns += re.findall(r'["\'](/user/[^"\'?#]+)["\']', text)
                        endpoints.update(patterns)
                except Exception:
                    continue

            # 回到目标
            await page.goto(self.target, wait_until="domcontentloaded", timeout=10000)
        except Exception:
            pass

        return list(endpoints)

    def _compare_rounds(self) -> dict[str, Any]:
        """对比不同角色的爬取结果（含 anon 对比 + 登录角色两两对比）。"""
        if len(self.rounds) < 2:
            return {"compared": False, "reason": "只有一轮爬取，无法对比"}

        anon = self.rounds[0]
        comparison = {"compared": True, "roles": [], "diff": [], "pairwise_diff": []}

        for r in self.rounds:
            comparison["roles"].append({
                "role": r.role,
                "pages": len(r.pages),
                "apis": len(r.api_endpoints),
                "js_endpoints": len(r.js_endpoints),
            })

        # 对比每轮与未登录轮的差异
        anon_apis = set(anon.api_endpoints.keys())
        anon_pages = set(anon.pages.keys())

        for r in self.rounds[1:]:
            new_pages = set(r.pages.keys()) - anon_pages
            new_apis = set(r.api_endpoints.keys()) - anon_apis

            if new_pages or new_apis:
                comparison["diff"].append({
                    "role": r.role,
                    "new_pages": list(new_pages)[:20],
                    "new_apis": list(new_apis)[:30],
                    "note": f"{r.role} 登录后多出 {len(new_pages)} 个页面, {len(new_apis)} 个 API",
                })

        # ★ 登录角色两两对比（找出"角色 A 独有"vs"角色 B 独有"的差异）
        login_rounds = [r for r in self.rounds[1:]]  # 排除 anon
        for i in range(len(login_rounds)):
            for j in range(i + 1, len(login_rounds)):
                a, b = login_rounds[i], login_rounds[j]
                a_apis = set(a.api_endpoints.keys())
                b_apis = set(b.api_endpoints.keys())
                a_pages = set(a.pages.keys())
                b_pages = set(b.pages.keys())

                a_only_apis = a_apis - b_apis - anon_apis
                b_only_apis = b_apis - a_apis - anon_apis
                a_only_pages = a_pages - b_pages - anon_pages
                b_only_pages = b_pages - a_pages - anon_pages

                if a_only_apis or b_only_apis or a_only_pages or b_only_pages:
                    comparison["pairwise_diff"].append({
                        "role_a": a.role,
                        "role_b": b.role,
                        "a_only_apis": list(a_only_apis)[:20],
                        "b_only_apis": list(b_only_apis)[:20],
                        "a_only_pages": list(a_only_pages)[:10],
                        "b_only_pages": list(b_only_pages)[:10],
                        "note": (
                            f"{a.role} 独有: {len(a_only_pages)} 页面/{len(a_only_apis)} API; "
                            f"{b.role} 独有: {len(b_only_pages)} 页面/{len(b_only_apis)} API "
                            f"→ 可用于横向越权测试"
                        ),
                    })

        return comparison

    async def _build_final_result(self, comparison: dict) -> dict[str, Any]:
        """构建最终的完整爬取结果。"""
        # 导入模块级常量（避免循环导入）
        from .crawler_core import MENU_API_KEYWORDS

        # 合并所有轮次的 API
        all_apis: dict[str, dict] = {}
        all_pages: dict[str, dict] = {}
        all_forms: list[dict] = []
        all_js_endpoints: set[str] = set()
        all_realtime_channels: list[dict] = []

        for r in self.rounds:
            for key, api in r.api_endpoints.items():
                if key not in all_apis:
                    api_item = {**api, "discovered_by": r.role}
                    trigger_ctx = dict(api_item.get("trigger_context", {}) or {})
                    trigger_ctx.setdefault("role", r.role)
                    api_item["trigger_context"] = trigger_ctx
                    all_apis[key] = api_item
            for url, page in r.pages.items():
                if url not in all_pages:
                    all_pages[url] = {
                        "title": page.title,
                        "forms_count": len(page.forms),
                        "clickable_elements": len(page.elements),
                        "links_count": len(page.links),
                        "discovered_by": r.role,
                    }
                for f in page.forms:
                    all_forms.append({
                        "page": url, "action": f.action, "method": f.method,
                        "fields": [i.get("name") for i in f.inputs if i.get("name")],
                        "submitted": f.submitted,
                        "requests_triggered": len(f.submit_requests),
                    })
            for channel in r.realtime_channels:
                if isinstance(channel, dict):
                    item = dict(channel)
                    item.setdefault("role", r.role)
                    all_realtime_channels.append(item)
            all_js_endpoints.update(r.js_endpoints)

        total_elements = sum(len(p.elements) for r in self.rounds for p in r.pages.values())

        # ---- 路径推测 + 指纹对比验证 ----
        self._report("推测并验证 CRUD 变体 API...")

        inferred_candidates: list[tuple[str, str]] = []  # (method, url)
        crud_suffixes = [
            ("list", "GET"), ("detail", "GET"), ("info", "GET"),
            ("create", "POST"), ("add", "POST"), ("save", "POST"),
            ("update", "PUT"), ("edit", "PUT"), ("modify", "PATCH"),
            ("delete", "DELETE"), ("remove", "DELETE"),
            ("export", "GET"), ("import", "POST"), ("batch", "POST"),
        ]
        seen_paths = {urlparse(a["url"]).path.rstrip("/") for a in all_apis.values()}
        for api in list(all_apis.values()):
            parsed = urlparse(api["url"])
            path_parts = [p for p in parsed.path.rstrip("/").split("/") if p]
            if len(path_parts) < 2:
                continue
            base_prefix = "/".join(path_parts[:-1])
            base_url_prefix = f"{parsed.scheme}://{parsed.netloc}/{base_prefix}"
            for suffix, method in crud_suffixes:
                inferred_path = f"/{base_prefix}/{suffix}"
                if inferred_path not in seen_paths:
                    inferred_url = f"{base_url_prefix}/{suffix}"
                    key = f"{method} {inferred_url}"
                    if key not in all_apis:
                        inferred_candidates.append((method, inferred_url))
                        seen_paths.add(inferred_path)

        # ★ 路径前缀字典 fuzz
        target_parsed = urlparse(self.target)
        target_host_root = f"{target_parsed.scheme}://{target_parsed.netloc}"

        # 已发现 API 的"通用前缀"
        common_prefixes: set[str] = set()
        for api_data in all_apis.values():
            ap = urlparse(api_data["url"]).path
            parts = [p for p in ap.strip("/").split("/") if p]
            if len(parts) >= 1:
                common_prefixes.add("/" + parts[0])
            if len(parts) >= 2:
                common_prefixes.add("/" + parts[0] + "/" + parts[1])
            if len(parts) >= 3:
                common_prefixes.add("/" + parts[0] + "/" + parts[1] + "/" + parts[2])

        # 兜底：如果没发现任何 API（冷启动），用一组常见前缀
        if not common_prefixes:
            common_prefixes = {
                "/api", "/api/v1", "/api/v2", "/api/admin", "/api/system",
                "/api/auth", "/api/user", "/api/sys",
            }

        # 常见模块名（中后台高频）
        common_modules = [
            "user", "users", "role", "roles", "permission", "permissions",
            "menu", "menus", "dept", "department", "org", "organization",
            "config", "setting", "settings", "log", "logs", "audit",
            "file", "files", "upload", "download", "export", "import",
            "dict", "dictionary", "notice", "notification", "message",
            "task", "job", "schedule", "cron", "monitor", "metrics",
            "system", "sys", "admin", "auth", "login", "logout", "captcha",
            "info", "profile", "account", "password", "reset",
        ]

        # 每个前缀 × 模块名 × CRUD 后缀 → 候选
        fuzz_added = 0
        max_fuzz = 800  # 全局上限避免太多请求
        for prefix in list(common_prefixes):
            if fuzz_added >= max_fuzz:
                break
            is_api_prefix = "/api" in prefix
            for module in common_modules:
                if fuzz_added >= max_fuzz:
                    break
                # 一级模块路径：/api/system/user
                base = f"{prefix}/{module}"
                if base not in seen_paths:
                    inferred_url = f"{target_host_root}{base}"
                    key = f"GET {inferred_url}"
                    if key not in all_apis:
                        inferred_candidates.append(("GET", inferred_url))
                        seen_paths.add(base)
                        fuzz_added += 1
                # 模块 + CRUD 后缀（仅 /api 前缀）
                if is_api_prefix:
                    for suffix, method in crud_suffixes:
                        if fuzz_added >= max_fuzz:
                            break
                        full = f"{base}/{suffix}"
                        if full not in seen_paths:
                            inferred_url = f"{target_host_root}{full}"
                            key = f"{method} {inferred_url}"
                            if key not in all_apis:
                                inferred_candidates.append((method, inferred_url))
                                seen_paths.add(full)
                                fuzz_added += 1

        if fuzz_added:
            self._report(f"  路径前缀 fuzz: 新增 {fuzz_added} 个候选（基于 {len(common_prefixes)} 个前缀 × {len(common_modules)} 个模块名）")

        verified_count = 0
        if inferred_candidates:
            # 获取认证 headers（从已有真实请求中提取 Cookie/Token）
            auth_headers: dict[str, str] = {}
            for api_data in all_apis.values():
                h = api_data.get("headers", {})
                for key_name in ("cookie", "Cookie"):
                    if h.get(key_name):
                        auth_headers["Cookie"] = h[key_name]
                for key_name in ("authorization", "Authorization"):
                    if h.get(key_name):
                        auth_headers["Authorization"] = h[key_name]
                if auth_headers:
                    break

            import httpx

            # Step 1: 获取"不存在"的基准响应指纹
            base_host = f"{urlparse(self.target).scheme}://{urlparse(self.target).netloc}"
            not_exist_paths = [
                f"{base_host}/api/_pentest_not_exist_8f3a2b",
                f"{base_host}/_pentest_404_check_c7e9d1",
            ]
            # 也在每个已知 API 前缀下探测
            prefix_set: set[str] = set()
            for api_data in list(all_apis.values())[:20]:
                parsed = urlparse(api_data["url"])
                parts = [p for p in parsed.path.rstrip("/").split("/") if p]
                if len(parts) >= 2:
                    prefix = "/".join(parts[:-1])
                    if prefix not in prefix_set:
                        prefix_set.add(prefix)
                        not_exist_paths.append(
                            f"{parsed.scheme}://{parsed.netloc}/{prefix}/_not_exist_z9x8w7"
                        )

            self._report(f"  Step 1: 采集 {len(not_exist_paths)} 个不存在路径的基准响应指纹...")

            def _make_fingerprint(status: int, body: str) -> tuple[int, int, str]:
                """生成响应指纹：状态码 + 长度桶（±50字符算同一桶）+ 内容hash前8位。"""
                import hashlib
                length_bucket = len(body) // 50  # 每 50 字符一个桶
                body_hash = hashlib.md5(body.encode(errors="ignore")).hexdigest()[:8]
                return (status, length_bucket, body_hash)

            baseline_fingerprints: set[tuple[int, int, str]] = set()
            baseline_has_biz_error = False

            try:
                async with httpx.AsyncClient(
                    timeout=5, verify=False, follow_redirects=True,
                    headers=auth_headers,
                ) as client:
                    # 采集基准指纹
                    for ne_url in not_exist_paths:
                        try:
                            resp = await client.get(ne_url)
                            body = resp.text[:2000]
                            fp = _make_fingerprint(resp.status_code, body)
                            baseline_fingerprints.add(fp)
                            # 检测基准响应是否就是"业务层通用错误"
                            if resp.status_code == 200:
                                try:
                                    j = json.loads(body)
                                    biz_code = j.get("code", 0)
                                    msg = (j.get("msg", "") or j.get("message", "")).lower()
                                    if biz_code in (500, 501, 502, 503) or any(kw in msg for kw in (
                                        "系统异常", "系统繁忙", "服务异常", "internal error",
                                        "server error", "not implemented", "method not allowed",
                                        "不支持", "未实现",
                                    )):
                                        baseline_has_biz_error = True
                                except (json.JSONDecodeError, AttributeError):
                                    pass
                        except Exception:
                            pass

                    if not baseline_fingerprints:
                        self._report("  ⚠️ 无法获取基准指纹，跳过推测验证")
                    else:
                        self._report(
                            f"  基准指纹 {len(baseline_fingerprints)} 个 "
                            f"(框架统一兜底={baseline_has_biz_error}): "
                            f"{', '.join(f'{s}:{l}:{h}' for s, l, h in baseline_fingerprints)}"
                        )

                        # Step 2: 并发验证推测 API
                        self._report(f"  Step 2: 验证 {len(inferred_candidates)} 个推测 API...")
                        semaphore = asyncio.Semaphore(10)

                        async def verify_one(method: str, url: str) -> dict | None:
                            async with semaphore:
                                try:
                                    resp = await client.get(url)
                                    body = resp.text[:2000]
                                    fp = _make_fingerprint(resp.status_code, body)

                                    # 指纹与 404 基准相同 = 不存在，跳过
                                    if fp in baseline_fingerprints:
                                        return None

                                    # 二级过滤：Spring Boot 等框架通配路由识别
                                    if resp.status_code == 200:
                                        try:
                                            j = json.loads(body)
                                            biz_code = j.get("code", 0)
                                            msg = (j.get("msg", "") or j.get("message", "")).lower()
                                            if biz_code == 404 or "not found" in msg or "no handler" in msg:
                                                return None
                                            if baseline_has_biz_error and (
                                                biz_code in (500, 501, 502, 503) or any(kw in msg for kw in (
                                                    "系统异常", "系统繁忙", "服务异常", "internal error",
                                                    "server error", "not implemented", "method not allowed",
                                                    "不支持", "未实现",
                                                ))
                                            ):
                                                return None
                                        except (json.JSONDecodeError, AttributeError):
                                            pass

                                    # HTTP 404 = 路径不存在
                                    if resp.status_code == 404:
                                        return None
                                    # HTTP 405 = 路径存在但方法不对，保留
                                    if resp.status_code == 405:
                                        return {
                                            "method": method, "url": url,
                                            "resource_type": "inferred_verified",
                                            "post_data": "",
                                            "headers": dict(auth_headers),
                                            "discovered_by": "path_inference_verified",
                                            "verify_status": resp.status_code,
                                        }

                                    # 指纹不同于 404 基准，视为真实存在
                                    return {
                                        "method": method, "url": url,
                                        "resource_type": "inferred_verified",
                                        "post_data": "",
                                        "headers": dict(auth_headers),
                                        "discovered_by": "path_inference_verified",
                                        "verify_status": resp.status_code,
                                    }
                                except Exception:
                                    return None

                        tasks = [verify_one(m, u) for m, u in inferred_candidates]
                        results = await asyncio.gather(*tasks)

                        # 对验证通过的 API，从 JS 缓存中定位调用代码
                        from core.js_analyzer import locate_api_in_js
                        import time as _t

                        # 防 CPU 雪崩：累计 30s 后剩余的 result 不再 locate
                        LOCATE_TOTAL_BUDGET_S = 30.0
                        locate_t0 = _t.monotonic()
                        locate_calls = 0
                        locate_skipped_budget = 0

                        for _i, result in enumerate(results):
                            if result:
                                key = f"{result['method']} {result['url']}"
                                # 时间预算未耗尽才 locate
                                if _t.monotonic() - locate_t0 < LOCATE_TOTAL_BUDGET_S:
                                    try:
                                        js_context = locate_api_in_js(result['url'], target=self.target)
                                        if js_context:
                                            result["js_context"] = js_context
                                    except Exception:
                                        pass
                                    locate_calls += 1
                                else:
                                    locate_skipped_budget += 1
                                all_apis[key] = result
                                verified_count += 1
                            # 让出事件循环
                            if _i % 50 == 49:
                                await asyncio.sleep(0)

                        if locate_skipped_budget:
                            self._report(
                                f"  JS 上下文定位: {locate_calls} 次 / 跳过 {locate_skipped_budget} 次"
                                f"（已达 {LOCATE_TOTAL_BUDGET_S:.0f}s 预算上限）"
                            )

            except Exception as e:
                self._report(f"  ⚠️ 验证出错: {e}")

            self._report(
                f"  推测 {len(inferred_candidates)} 个 → "
                f"指纹对比验证通过 {verified_count} 个真实存在的 API"
            )

        from core.js_analyzer import js_result_to_crawl_data, JSAnalysisResult
        merged_js_data = {
            "js_api_calls": [], "js_routes": [], "js_auth_patterns": [],
            "js_sensitive_info": [], "js_source_maps": [],
            "js_stats": {"files_analyzed": 0, "total_size_kb": 0, "api_calls": 0, "routes": 0},
        }
        base_url = f"{urlparse(self.target).scheme}://{urlparse(self.target).netloc}"
        for r in self.rounds:
            if r.js_analysis:
                rd = js_result_to_crawl_data(r.js_analysis, base_url)
                merged_js_data["js_api_calls"].extend(rd.get("js_api_calls", []))
                merged_js_data["js_routes"].extend(rd.get("js_routes", []))
                merged_js_data["js_auth_patterns"].extend(rd.get("js_auth_patterns", []))
                merged_js_data["js_sensitive_info"].extend(rd.get("js_sensitive_info", []))
                merged_js_data["js_source_maps"].extend(rd.get("js_source_maps", []))
                stats = rd.get("js_stats", {})
                merged_js_data["js_stats"]["files_analyzed"] += stats.get("files_analyzed", 0)
                merged_js_data["js_stats"]["total_size_kb"] += stats.get("total_size_kb", 0)
                merged_js_data["js_stats"]["api_calls"] += stats.get("api_calls", 0)
                merged_js_data["js_stats"]["routes"] += stats.get("routes", 0)

        # 去重 JS API
        seen_js_apis: set[str] = set()
        unique_js_apis = []
        for api in merged_js_data["js_api_calls"]:
            key = f"{api['method']} {api['path']}"
            if key not in seen_js_apis:
                seen_js_apis.add(key)
                unique_js_apis.append(api)
                all_js_endpoints.add(api["path"])
        merged_js_data["js_api_calls"] = unique_js_apis

        # JS 发现的 API 也加入全局 API 列表（不重复）
        for api in unique_js_apis:
            method = api["method"] if api["method"] != "UNKNOWN" else "GET"
            key = f"{method} {api['path'].split('?')[0]}"
            if key not in all_apis:
                all_apis[key] = {
                    "method": method, "url": api.get("url", api["path"]),
                    "resource_type": "js_discovered", "post_data": "",
                    "headers": {}, "discovered_by": "js_analysis",
                }

        # ---- 构建菜单覆盖报告 ----
        menu_coverage: list[dict] = []
        for r in self.rounds:
            for page_url, page in r.pages.items():
                for elem in page.elements:
                    triggered_api_count = len([
                        req for req in elem.triggered_requests
                        if req.get("resource_type") in ("xhr", "fetch")
                        or "/api/" in req.get("url", "")
                    ])
                    menu_coverage.append({
                        "page": page_url[:80],
                        "text": elem.text[:30],
                        "apis_triggered": triggered_api_count,
                        "total_requests": len(elem.triggered_requests),
                    })

        # 统计
        with_api = sum(1 for m in menu_coverage if m["apis_triggered"] > 0)
        without_api = sum(1 for m in menu_coverage if m["apis_triggered"] == 0)

        # ---- 从 mitmproxy FlowStore 读取完整流量 ----
        proxy_flow_count = 0
        try:
            from mcp_servers.proxy_mcp import _store, _load_new_flows
            _load_new_flows()
            target_host = self.target_domain

            for flow_id in list(_store._order):
                flow = _store.get(flow_id)
                if not flow:
                    continue
                if target_host not in flow.url:
                    continue
                url_path = urlparse(flow.url).path.lower()
                if any(url_path.endswith(ext) for ext in
                       ('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff', '.ttf', '.map', '.gif')):
                    continue

                key = f"{flow.method} {flow.url.split('?')[0]}"
                flow_url_lower = flow.url.lower()
                is_menu_flow = any(kw.lower() in flow_url_lower for kw in MENU_API_KEYWORDS)
                resp_body_limit = 50000 if is_menu_flow else 2000
                all_apis[key] = {
                    "method": flow.method,
                    "url": flow.url,
                    "resource_type": "proxy_captured",
                    "post_data": flow.request_body[:2000] if flow.request_body else "",
                    "headers": flow.request_headers,
                    "discovered_by": "mitmproxy",
                    "status_code": flow.status_code,
                    "response_body": flow.response_body[:resp_body_limit] if flow.response_body else "",
                }
                all_realtime_channels.extend(classify_realtime_flow(
                    method=flow.method,
                    url=flow.url,
                    request_headers=flow.request_headers,
                    request_body=flow.request_body or "",
                    response_headers=getattr(flow, "response_headers", {}) or {},
                    response_body=flow.response_body or "",
                    status_code=flow.status_code,
                    discovered_by="mitmproxy",
                ))
                proxy_flow_count += 1

            self._report(f"  从 mitmproxy 读取了 {proxy_flow_count} 条完整流量记录")
        except Exception as e:
            self._report(f"  ⚠️ 读取 mitmproxy 流量失败: {e}（可能代理未启动）")

        return {
            "target": self.target,
            "crawl_rounds": len(self.rounds),
            "roles_crawled": [r.role for r in self.rounds],
            "login_status": {r.role: r.login_success for r in self.rounds if r.role != "anonymous"},
            "pages_total": len(all_pages),
            "apis_total": len(all_apis),
            "apis_inferred_verified": verified_count,
            "forms_total": len(all_forms),
            "forms_submitted": sum(1 for f in all_forms if f["submitted"]),
            "js_endpoints_found": len(all_js_endpoints),
            "total_clickable_elements": total_elements,
            "menu_clicked": len(menu_coverage),
            "menu_with_api": with_api,
            "menu_without_api": without_api,
            "menu_coverage": menu_coverage,
            "pages": all_pages,
            "api_endpoints": [
                {"method": a["method"], "url": a["url"], "has_body": bool(a.get("post_data")),
                 "post_data": a.get("post_data", ""),
                 "headers": a.get("headers", {}),
                 "discovered_by": a.get("discovered_by", ""),
                 "status_code": a.get("status_code", 0) or a.get("verify_status", 0),
                 "response_body": a.get("response_body", ""),
                 "response_headers": a.get("response_headers", {}),
                 "content_type": a.get("content_type", ""),
                 "flow_id": a.get("flow_id", ""),
                 "trigger_context": a.get("trigger_context", {}),
                 "js_context": a.get("js_context", "")}
                for a in all_apis.values()
            ],
            "realtime_channels": dedupe_realtime_channels(all_realtime_channels),
            "realtime_channels_total": len(dedupe_realtime_channels(all_realtime_channels)),
            "forms": all_forms,
            "js_endpoints": list(all_js_endpoints),
            "api_doc_hits": getattr(self, "_api_doc_hits", []),
            "menu_tree_responses": self._menu_tree_responses,
            "menu_contexts": self._build_menu_contexts_for_result(
                self._menu_tree_responses,
                {r.role: r.login_success for r in self.rounds if r.role != "anonymous"},
            ),
            "role_comparison": comparison,
            "crawled_elements": [
                {
                    "page_url": el.page_url,
                    "tag": el.tag,
                    "text": el.text,
                    "selector": el.selector,
                    "is_menu": ("data-menu-idx" in (el.selector or "")),
                    "triggered_apis": len([
                        req for req in (el.triggered_requests or [])
                        if req.get("resource_type") in ("xhr", "fetch")
                        or "/api/" in req.get("url", "")
                    ]),
                }
                for r in self.rounds
                for page in r.pages.values()
                for el in page.elements
                if el.text and el.text.strip()
            ],
            **merged_js_data,
            "extra_scope": list(self.extra_scope),
        }
