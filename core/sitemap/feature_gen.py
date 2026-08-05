"""Sitemap — 功能点生成 + 动态发现 Mixin。"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse, parse_qs

from core.sitemap.models import FeaturePoint, CheckItem, Priority, TestStatus
from core.config import (
    FEATURE_VULN_MAPPING, UNIVERSAL_CHECKS, BROWSER_REQUIRED_VULNS,
    VULN_TO_SKILL, VULN_DETAIL_HINTS, VULN_SYNONYMS,
    MAX_CHECKLIST_PER_FP, VULN_PRIORITY, VULN_PRIORITY_DEFAULT,
)
from core.sitemap.constants import GENERIC_NAMES, STATIC_EXTS

log = logging.getLogger("pentest_agent.sitemap")


class FeatureGenMixin:
    """功能点生成（原子级 + LLM 添加）+ 动态发现/合并。"""

    # 幽灵端点黑名单路径段（路径段全为数字/常见静态名称时不生成独立功能点）
    PHANTOM_PATH_SEGMENTS = {
        "assets", "static", "dist", "build", "public", "images", "img",
        "css", "js", "fonts", "uploads", "files", "docs", "api-docs",
        "swagger", "v1", "v2", "v3",
    }
    """功能点生成（原子级 + LLM 添加）+ 动态发现/合并。"""

    # ---- 动态发现 ----

    def report_discovery(self, api_or_url: str, description: str = "",
                         source_feature: str = "") -> dict:
        """Phase 2 测试中上报新发现的 API/功能。

        不直接创建功能点，而是存入 pending_discoveries 待 Phase 2 结束后统一合并。
        """
        api_or_url = api_or_url.strip()
        if not api_or_url:
            return {"action": "ignored", "reason": "空输入"}

        parsed = urlparse(api_or_url.split(" ")[-1])
        new_path = parsed.path.rstrip("/").lower()

        # 快速去重：已在 pending 列表中
        for d in self.pending_discoveries:
            if d["api_or_url"] == api_or_url:
                return {"action": "already_known", "feature": "待合并列表"}

        # 快速去重：已被现有功能点的 related_apis 覆盖
        for fp in self.features.values():
            if api_or_url in fp.related_apis:
                return {"action": "already_known", "feature": fp.name}
            if new_path:
                for api in fp.related_apis:
                    api_path = urlparse(api.split(" ")[-1]).path.rstrip("/").lower()
                    if new_path == api_path:
                        return {"action": "already_known", "feature": fp.name}

        # 存入待合并列表
        self.pending_discoveries.append({
            "api_or_url": api_or_url,
            "description": description,
            "source_feature": source_feature,
        })
        self.save()
        return {"action": "queued",
                "message": f"已记录到待合并列表（当前 {len(self.pending_discoveries)} 个），Phase 2 结束后统一整合"}

    def merge_discoveries(self) -> dict:
        """Phase 2 结束后调用：将 pending_discoveries 与已有功能清单去重合并。"""
        if not self.pending_discoveries:
            return {"merged": 0, "new": 0, "discarded": 0, "details": []}

        merged = 0
        new_count = 0
        discarded = 0
        details = []

        for disc in self.pending_discoveries:
            api_or_url = disc["api_or_url"]
            description = disc.get("description", "")
            parsed = urlparse(api_or_url.split(" ")[-1])
            new_path = parsed.path.rstrip("/").lower()
            new_path_parts = [p for p in new_path.split("/")
                              if p and p not in ("api", "v1", "v2", "v3", "admin")]

            matched_fp = None

            for fp in self.features.values():
                # 1. 精确匹配 related_apis
                if api_or_url in fp.related_apis:
                    matched_fp = fp
                    break

                # 2. URL 路径匹配
                if new_path:
                    for api in fp.related_apis:
                        api_path = urlparse(api.split(" ")[-1]).path.rstrip("/").lower()
                        if new_path == api_path or new_path in api_path or api_path in new_path:
                            matched_fp = fp
                            break
                    if matched_fp:
                        break

                # 3. page_url 路径重叠
                if fp.page_url:
                    fp_path = urlparse(fp.page_url).path.rstrip("/").lower()
                    fp_parts = [p for p in fp_path.split("/")
                                if p and p not in ("api", "v1", "v2", "v3", "admin")]
                    if fp_parts and new_path_parts:
                        overlap = set(fp_parts) & set(new_path_parts)
                        if overlap and len(overlap) >= len(min(fp_parts, new_path_parts, key=len)):
                            matched_fp = fp
                            break

                # 4. 功能点名称 vs URL 路径关键词
                fp_name_lower = f"{fp.name} {fp.description}".lower()
                for part in new_path_parts:
                    clean_part = part.replace("-", "").replace("_", "")
                    if (len(part) > 2 and part in fp_name_lower) or \
                       (len(clean_part) > 3 and clean_part in fp_name_lower.replace("-", "").replace("_", "")):
                        matched_fp = fp
                        break
                if matched_fp:
                    break

            if matched_fp:
                if api_or_url not in matched_fp.related_apis:
                    matched_fp.related_apis.append(api_or_url)
                merged += 1
                details.append(f"归并: {api_or_url} → {matched_fp.name}")
            else:
                path_parts = [p for p in parsed.path.split("/")
                              if p and p not in ("api", "v1", "v2", "v3")]
                auto_name = "/".join(path_parts[-2:]) if len(path_parts) >= 2 else \
                           (path_parts[-1] if path_parts else "未知接口")
                auto_desc = description or f"Phase 2 动态发现: {api_or_url}"

                fp = self.add_feature(
                    name=auto_name,
                    description=auto_desc,
                    page_url=api_or_url.split(" ")[-1],
                    priority=Priority.HIGH,
                    related_apis=[api_or_url],
                )
                if fp:
                    new_count += 1
                    details.append(f"新增: {fp.name} ({len(fp.checklist)} 项 checklist) ← {api_or_url}")
                else:
                    discarded += 1
                    details.append(f"丢弃: {api_or_url}")

        # 清空待合并列表
        self.pending_discoveries.clear()
        self.save()

        return {"merged": merged, "new": new_count, "discarded": discarded, "details": details}

    def check_api_coverage(self) -> dict:
        """检查所有已知 API 是否被功能点覆盖。"""
        covered_apis: set[str] = set()
        for fp in self.features.values():
            for api in fp.related_apis:
                covered_apis.add(api)
                parsed = urlparse(api.split(" ")[-1])
                covered_apis.add(parsed.path.rstrip("/"))

        uncovered = []
        for key, api in self.apis.items():
            path = api.url.split("?")[0].rstrip("/")
            if any(path.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".map")):
                continue
            if key not in covered_apis and path not in covered_apis:
                uncovered.append({"method": api.method, "url": api.url})

        return {
            "total_apis": len(self.apis),
            "covered": len(self.apis) - len(uncovered),
            "uncovered": uncovered,
            "coverage_pct": round((1 - len(uncovered) / max(len(self.apis), 1)) * 100, 1),
        }

    # ---- 原子操作级功能点自动生成 ----

    def generate_atomic_features(self, crawl_result: dict) -> list[FeaturePoint]:
        """从爬取结果自动生成原子操作级功能点。"""
        import re
        from core.config import METHOD_VULN_MAP, PATH_VULN_PATTERNS, ELEMENT_VULN_MAP

        created: list[FeaturePoint] = []
        seen_apis: set[str] = set()

        # ★ 持久化多角色/菜单上下文
        if hasattr(self, "sync_role_context_from_crawl"):
            self.sync_role_context_from_crawl(crawl_result)

        # ★ 持久化 JS 分析结果
        self.js_routes = crawl_result.get("js_routes", [])
        self.js_api_calls = crawl_result.get("js_api_calls", [])
        if self.js_routes or self.js_api_calls:
            log.info("保存 JS 分析结果: %d 个路由, %d 个 API 调用",
                     len(self.js_routes), len(self.js_api_calls))

        pages = crawl_result.get("pages", {})

        for page_url, page_data in pages.items():
            page_title = page_data.get("title", "")

            # ---- 从页面加载时的请求生成 ----
            for req in page_data.get("requests_during_load", []):
                api_key = f"{req.get('method', 'GET')} {req.get('url', '').split('?')[0]}"
                if api_key in seen_apis:
                    continue
                if self._is_static_resource(req.get("url", "")):
                    continue
                seen_apis.add(api_key)
                self.add_api(
                    req.get("method", "GET"),
                    req.get("url", "").split("?")[0],
                    discovered_by=req.get("discovered_by", "crawler"),
                    resource_type=req.get("resource_type", ""),
                )

            # ---- 从可点击元素 + 触发的请求生成 ----
            for elem in page_data.get("elements", []):
                elem_text = elem.get("text", "").strip()
                triggered = elem.get("triggered_requests", [])
                if not triggered and not elem_text:
                    continue

                for req in triggered:
                    url = req.get("url", "")
                    method = req.get("method", "GET")
                    api_path = url.split("?")[0]
                    query_sig = self._get_query_signature(url)
                    api_key = f"{method} {api_path}" + (f"?{query_sig}" if query_sig else "")
                    if api_key in seen_apis:
                        continue
                    if self._is_static_resource(url):
                        continue
                    seen_apis.add(api_key)
                    self.add_api(
                        method,
                        api_path,
                        discovered_by=req.get("discovered_by", "crawler"),
                        resource_type=req.get("resource_type", ""),
                    )

                    name = self._make_atomic_name(page_title, elem_text, method, api_path)
                    desc = f"按钮「{elem_text}」触发 {method} {api_path}"
                    vulns = self._infer_vulns_from_api(method, url)

                    fp = self._create_atomic_feature(name, desc, page_url, api_key, vulns)
                    if fp:
                        created.append(fp)

                # 按钮没触发 API 但有文本
                if not triggered and elem_text and len(elem_text) > 1:
                    name = f"{page_title[:10]}/{elem_text[:15]}"
                    desc = f"页面「{page_title}」上的按钮「{elem_text}」（未捕获到 API 请求，可能是前端交互）"
                    fp = self._create_atomic_feature(
                        name, desc, page_url, "", ["XSS", "CSRF"],
                        priority=Priority.LOW,
                    )
                    if fp:
                        created.append(fp)

            # ---- 从表单生成 ----
            for form in page_data.get("forms", []):
                form_action = form.get("action", page_url)
                form_method = form.get("method", "POST").upper()
                inputs = form.get("inputs", [])
                input_names = [inp.get("name", "") for inp in inputs if inp.get("name")]
                submitted_reqs = form.get("submit_requests", [])

                api_key = f"{form_method} {form_action.split('?')[0]}"
                if api_key in seen_apis:
                    continue
                seen_apis.add(api_key)

                input_desc = ", ".join(input_names[:5])
                name = f"{page_title[:10]}/表单({input_desc[:20]})"
                desc = f"表单提交 {form_method} {form_action}，字段: {input_desc}"

                vulns = self._infer_vulns_from_api(form_method, form_action)
                for inp in inputs:
                    inp_type = inp.get("type", "text").lower()
                    inp_name = inp.get("name", "").lower()
                    if inp_type == "file":
                        vulns.append("文件上传绕过")
                    if inp_type in ("text", "search") or "search" in inp_name or "query" in inp_name:
                        for v in ["SQL注入", "XSS"]:
                            if v not in vulns:
                                vulns.append(v)
                    if inp_type == "password":
                        for v in ["弱密码/默认密码"]:
                            if v not in vulns:
                                vulns.append(v)

                fp = self._create_atomic_feature(name, desc, page_url, api_key, vulns)
                if fp:
                    created.append(fp)

        # ---- 从全局 API 列表补漏 ----
        # ★ 命名优化：之前直接用 path 段拼接（如 doLogin/config(查询)），完全无业务语义，
        # 导致 worker 跑完 359 项却像在机械跑 URL。现在：
        # 1. 用 PATH_SEG_CN_MAP 把常见英文路径段映射为中文业务词
        # 2. 优先取业务理解里的领域标签作为前缀（如「旅行社ERP/用户管理(查询)」）
        # 3. 无映射时回退原逻辑，保证不丢功能点
        for api_key_str, api in self.apis.items():
            if api_key_str in seen_apis:
                continue
            if self._is_static_resource(api.url):
                continue
            seen_apis.add(api_key_str)

            path = urlparse(api.url).path
            path_parts = [p for p in path.split("/") if p and p not in ("api", "v1", "v2", "v3")]
            method_label = {"GET": "查询", "POST": "新增", "PUT": "修改",
                           "PATCH": "修改", "DELETE": "删除"}.get(api.method, api.method)

            # ★ 语义化路径段：英文 → 中文业务词
            cn_parts = [self._path_seg_to_cn(p) for p in path_parts]
            # 去掉映射失败的纯英文段（保留中文段），最多取最后 2 段
            cn_segments = [p for p in cn_parts if p]
            if cn_segments:
                path_name = "/".join(cn_segments[-2:])
            else:
                # 无中文映射时回退原逻辑（保留英文路径段，不丢功能点）
                path_name = "/".join(path_parts[-2:]) if len(path_parts) >= 2 else (path_parts[-1] if path_parts else "root")

            # ★ 业务领域前缀：从 business_understanding 取领域标签
            domain_prefix = self._get_domain_prefix()
            if domain_prefix and not path_name.startswith(domain_prefix):
                name = f"{domain_prefix}/{path_name}({method_label})"[:50]
            else:
                name = f"{path_name}({method_label})"[:50]
            desc = f"API 端点 {api.method} {api.url}"

            vulns = self._infer_vulns_from_api(api.method, api.url)
            fp = self._create_atomic_feature(name, desc, api.url, api_key_str, vulns)
            if fp:
                created.append(fp)

        # ---- 从 JS 路由表生成功能点 ----
        router_mode_global = ""
        for route in crawl_result.get("js_routes", []):
            rm = route.get("router_mode", "")
            if rm:
                router_mode_global = rm
                break

        for route in crawl_result.get("js_routes", []):
            route_path = route.get("path", "")
            if not route_path or route_path == "/":
                continue

            # 优先用 js_analyzer 拼好的 url
            route_url = route.get("url", "") or ""
            if not route_url:
                base = urlparse(next(iter(pages.keys()), self.target))
                origin = f"{base.scheme}://{base.netloc}"
                app_base = (origin + (base.path or "").rstrip("/")).rstrip("/")
                mode = route.get("router_mode") or router_mode_global or "hash"
                if mode == "history":
                    route_url = f"{app_base}{route_path}"
                else:
                    route_url = f"{app_base}/#{route_path}"

            route_key = f"GET {route_url}"
            if route_key in seen_apis:
                continue
            seen_apis.add(route_key)

            component = route.get("component", "")
            meta = route.get("meta", "")
            name = f"[路由]{route_path[-30:]}"
            desc = f"JS 路由: {route_path}"
            if component:
                desc += f" (组件: {component})"
            if meta:
                desc += f" (meta: {meta[:50]})"

            priority = Priority.HIGH if any(
                kw in route_path.lower() for kw in ("admin", "manage", "dashboard", "setting", "config")
            ) else Priority.MEDIUM

            vulns = ["未授权访问", "垂直越权"]
            if "admin" in route_path.lower():
                vulns.append("信息泄露")

            fp = self._create_atomic_feature(name, desc, route_url, route_key, vulns, priority=priority)
            if fp:
                created.append(fp)

        # ---- 从 JS 敏感信息生成功能点 ----
        for info in crawl_result.get("js_sensitive_info", []):
            info_type = info.get("type", "")
            value = info.get("value", "")
            if not info_type or not value:
                continue
            name = f"[敏感]{info_type[:20]}"
            desc = f"JS 中发现 {info_type}: {value[:30]}... (来源: {info.get('context', '')[:60]})"
            vulns = ["信息泄露", "JS代码审计(硬编码密钥/绕过逻辑/敏感信息)"]
            fp = self._create_atomic_feature(name, desc, "", "", vulns, priority=Priority.HIGH)
            if fp:
                created.append(fp)

        self.save()
        return created

    def _create_atomic_feature(self, name: str, desc: str, page_url: str,
                                api_key: str, vulns: list[str],
                                priority: Priority | None = None) -> FeaturePoint | None:
        """创建一个原子级功能点。"""
        name = name.strip()[:50]
        if len(name) < 2 or len(desc) < 4:
            return None

        # ★ 过滤纯 CRUD/通用操作名
        name_for_check = name.lower()
        if name_for_check.startswith(("get ", "post ", "put ", "delete ", "patch ")):
            name_for_check = name_for_check.split(" ", 1)[-1].strip()
        if "→" in name_for_check or "->" in name_for_check:
            parts = name_for_check.replace("->", "→").split("→")
            after_arrow = parts[-1].strip()
            if after_arrow.startswith(("get ", "post ", "put ", "delete ", "patch ")):
                after_arrow = after_arrow.split(" ", 1)[-1].strip()
            if after_arrow in GENERIC_NAMES:
                return None
        if name_for_check in GENERIC_NAMES:
            return None

        # 已存在同名功能点？
        for fp in self.features.values():
            if fp.name == name:
                if api_key and api_key not in fp.related_apis:
                    fp.related_apis.append(api_key)
                return None

        # 自动推导优先级
        if priority is None:
            priority = self._infer_priority(vulns, api_key)

        # ★ API 测试计数检查
        api_base = self._normalize_api_key(api_key) if api_key else ""
        if api_base:
            current_count = self._api_test_count.get(api_base, 0)
            if current_count >= self.MAX_API_TEST_OWNERS:
                self._feature_counter += 1
                fp = FeaturePoint(
                    id=f"fp_{self._feature_counter}",
                    name=name,
                    description=desc + f"（API 已被 {current_count} 个功能点覆盖，跳过重复测试）",
                    page_url=page_url,
                    related_apis=[api_key] if api_key else [],
                    priority=Priority.LOW,
                    checklist=[],
                )
                fp.test_status = TestStatus.TESTED
                self.features[fp.id] = fp
                return fp

        # 去重漏洞列表
        unique_vulns = []
        for v in vulns:
            canonical = VULN_SYNONYMS.get(v, v)
            if canonical not in unique_vulns:
                unique_vulns.append(canonical)

        # ★ 上下文感知过滤：根据 API 特征排除明显不适用的检查项
        unique_vulns = self._context_filter_tests(unique_vulns,
                                                    [api_key] if api_key else None,
                                                    desc)

        self._feature_counter += 1
        has_page = self._has_frontend_page(page_url)
        checklist = [CheckItem(
            vuln_type=v,
            needs_browser=(v in BROWSER_REQUIRED_VULNS),
        ) for v in unique_vulns]

        if api_base:
            self._api_test_count[api_base] = self._api_test_count.get(api_base, 0) + 1

        fp = FeaturePoint(
            id=f"fp_{self._feature_counter}",
            name=name,
            description=desc,
            page_url=page_url,
            related_apis=[api_key] if api_key else [],
            priority=priority,
            checklist=checklist,
        )
        self.features[fp.id] = fp
        return fp

    @staticmethod
    def _infer_vulns_from_api(method: str, url: str) -> list[str]:
        """根据 HTTP 方法 + URL 路径特征推导应测漏洞。"""
        import re
        from core.config import METHOD_VULN_MAP, PATH_VULN_PATTERNS

        vulns = list(METHOD_VULN_MAP.get(method.upper(), ["未授权访问"]))

        url_lower = url.lower()
        for patterns, vuln_types in PATH_VULN_PATTERNS:
            for pat in patterns:
                if pat.startswith(r"/"):
                    if re.search(pat, url_lower):
                        for v in vuln_types:
                            if v not in vulns:
                                vulns.append(v)
                        break
                elif pat in url_lower:
                    for v in vuln_types:
                        if v not in vulns:
                            vulns.append(v)
                    break

        return vulns

    @staticmethod
    def _infer_priority(vulns: list[str], api_key: str) -> Priority:
        """根据漏洞类型和 API 路径推导优先级。"""
        critical_vulns = {"金额篡改", "垂直越权", "文件上传绕过"}
        high_vulns = {"IDOR越权", "SQL注入", "密码重置逻辑"}
        if any(v in critical_vulns for v in vulns):
            return Priority.CRITICAL
        if any(v in high_vulns for v in vulns):
            return Priority.HIGH
        api_lower = api_key.lower()
        if any(kw in api_lower for kw in ("admin", "pay", "order", "password", "delete")):
            return Priority.HIGH
        return Priority.MEDIUM

    @staticmethod
    def _make_atomic_name(page_title: str, elem_text: str, method: str, api_path: str) -> str:
        """生成原子操作名称 — 优先中文语义，URL 路径作辅助。"""
        import re as _re

        path = urlparse(api_path).path
        path_parts = [p for p in path.split("/") if p
                      and p.lower() not in ("api", "v1", "v2", "v3", "admin", "system")]
        path_tail = "/".join(path_parts[-2:]) if path_parts else ""

        title = (page_title or "").strip()
        for suffix in ("- 管理系统", "管理平台", "系统", "后台", "平台"):
            if title.endswith(suffix) and len(title) > len(suffix) + 2:
                title = title[:-len(suffix)].strip()
        title = title[:12]

        btn = (elem_text or "").strip()[:15]

        has_cn_title = bool(_re.search(r'[\u4e00-\u9fff]', title))
        has_cn_btn = bool(_re.search(r'[\u4e00-\u9fff]', btn))

        method_tag = {"GET": "查询", "POST": "新增", "PUT": "修改",
                      "PATCH": "修改", "DELETE": "删除"}.get(method.upper(), method)

        if btn and title and (has_cn_btn or has_cn_title):
            return f"{title}/{btn}({method_tag})"[:50]
        elif btn and has_cn_btn:
            return f"{btn}({method_tag})"[:50]
        elif btn:
            if path_tail:
                return f"{btn}→{method} {path_tail}"[:50]
            return f"{btn}({method_tag})"[:50]
        elif title and has_cn_title and path_tail:
            return f"{title}/{path_tail}({method_tag})"[:50]
        elif path_tail:
            return f"{method} {path_tail}"[:50]
        return f"{method} {path}"[:50]

    @staticmethod
    def _normalize_api_key(api_key: str) -> str:
        """统一化 API key 格式为 'METHOD /path'。"""
        if not api_key:
            return ""
        parts = api_key.split(" ", 1)
        if len(parts) != 2:
            return api_key.split("?")[0].split("|")[0].rstrip("/")
        method, url = parts
        url = url.split("|")[0]
        url = url.split("?")[0].rstrip("/")
        if url.startswith("http://") or url.startswith("https://"):
            url = urlparse(url).path.rstrip("/")
        elif not url.startswith("/"):
            url = urlparse("https://" + url).path.rstrip("/")
        return f"{method} {url}"

    @staticmethod
    def _has_frontend_page(page_url: str) -> bool:
        """判断 page_url 是否是真实的前端页面。"""
        if not page_url:
            return False
        url_lower = page_url.lower()
        if "#/" in url_lower:
            return True
        if "/api/" in url_lower or "/api?" in url_lower:
            return False
        _API_SEGMENTS = ("/list", "/detail", "/info", "/create", "/add", "/save",
                         "/update", "/edit", "/modify", "/delete", "/remove",
                         "/export", "/import", "/batch", "/upload", "/download",
                         "/page", "/search", "/query", "/tree", "/login", "/me")
        path = url_lower.split("?")[0].rstrip("/")
        if any(path.endswith(seg) for seg in _API_SEGMENTS):
            return False
        return True

    @staticmethod
    def _is_static_resource(url: str) -> bool:
        """判断 URL 是否是静态资源。"""
        path = url.split("?")[0].lower()
        return any(path.endswith(ext) for ext in STATIC_EXTS)

    @staticmethod
    def _get_query_signature(url: str) -> str:
        """提取 URL 查询参数名作为签名（忽略值）。"""
        parsed = urlparse(url)
        if not parsed.query:
            return ""
        params = sorted(parse_qs(parsed.query).keys())
        security_params = [p for p in params if p.lower() not in ("page", "pagesize", "size", "limit", "offset", "sort", "order")]
        return ",".join(security_params) if security_params else ""

    # ---- 功能点（LLM 添加）----

    def _auto_associate_apis(self, name: str, description: str,
                            page_url: str, module: str) -> list[str]:
        """当 LLM 添加功能点没传 related_apis 时，自动从已有数据中关联。"""
        matched_apis: list[str] = []
        MAX_APIS = 15
        norm_page = (page_url or "").rstrip("/").split("?")[0]

        # ========== 策略 1：page_url 相同的已有功能点 ==========
        if norm_page:
            for fp in self.features.values():
                fp_page = (fp.page_url or "").rstrip("/").split("?")[0]
                if fp_page and fp_page == norm_page and fp.related_apis:
                    for api in fp.related_apis:
                        if api not in matched_apis:
                            matched_apis.append(api)
            if matched_apis:
                return matched_apis[:MAX_APIS]

        # ========== 策略 2：JS 路由 → 源文件 → API 调用 ==========
        if self.js_routes and self.js_api_calls and norm_page:
            route_path = ""
            if "#" in norm_page:
                route_path = norm_page.split("#")[-1]
            else:
                route_path = urlparse(norm_page).path

            if route_path:
                matched_sources = set()
                for jr in self.js_routes:
                    jr_path = jr.get("path", "")
                    if jr_path and (jr_path == route_path or
                                   route_path.startswith(jr_path + "/") or
                                   jr_path.startswith(route_path)):
                        src = jr.get("source", "")
                        if src:
                            matched_sources.add(src)
                        comp = jr.get("component", "")
                        if comp:
                            for jc in self.js_api_calls:
                                if comp.lower() in (jc.get("context", "") or "").lower():
                                    api_url = jc.get("url", "")
                                    method = jc.get("method", "GET")
                                    if api_url:
                                        api_ref = f"{method} {api_url}"
                                        if api_ref not in matched_apis:
                                            matched_apis.append(api_ref)

                if matched_sources:
                    for jc in self.js_api_calls:
                        if len(matched_apis) >= MAX_APIS:
                            break
                        if jc.get("source", "") in matched_sources:
                            api_url = jc.get("url", "")
                            method = jc.get("method", "GET")
                            if api_url and not self._is_static_resource(api_url):
                                api_ref = f"{method} {api_url}"
                                if api_ref not in matched_apis:
                                    matched_apis.append(api_ref)

                if matched_apis:
                    log.info("功能点 '%s' 通过 JS 路由分析关联了 %d 个 API（源文件: %s）",
                             name, len(matched_apis),
                             ", ".join(s.split("/")[-1] for s in matched_sources)[:100])
                    return matched_apis[:MAX_APIS]

        # ========== 策略 3：page_url 路径段匹配 API 样本 ==========
        page_segments = set()
        if norm_page:
            path_part = norm_page.split("#")[-1] if "#" in norm_page else norm_page
            for seg in path_part.split("/"):
                seg = seg.strip().lower()
                if seg and seg not in ("", "admin", "http:", "https:") and len(seg) >= 3:
                    page_segments.add(seg)

        if page_segments:
            for key, sample in self.api_samples.items():
                if len(matched_apis) >= MAX_APIS:
                    break
                path = sample.get("path", "").lower()
                if any(path.startswith(p) for p in ("/assets/", "/static/", "/favicon")):
                    continue
                for kw in page_segments:
                    if f"/{kw}" in path:
                        method = sample.get("method", "GET")
                        api_ref = f"{method} {sample.get('url', '')}"
                        if api_ref not in matched_apis:
                            matched_apis.append(api_ref)
                        break

        return matched_apis[:MAX_APIS]

    @classmethod
    def _auto_suggest_tests(cls, name: str, description: str, priority: Priority,
                            related_apis: list[str] | None = None) -> list[str]:
        """根据功能点名称/描述/关联API，自动匹配映射表+API特征推断漏洞类型列表。"""
        searchable = f"{name} {description}".lower()
        matched: list[str] = []

        for keywords, vuln_types in FEATURE_VULN_MAPPING:
            for kw in keywords:
                if kw.lower() in searchable:
                    for vt in vuln_types:
                        if vt not in matched:
                            matched.append(vt)
                    break

        if related_apis:
            has_post = has_put = has_delete = has_get_with_id = has_get_with_keyword = False
            has_upload_api = has_export_api = False

            for api_ref in related_apis:
                parts = api_ref.strip().split(" ", 1)
                method = parts[0].upper() if len(parts) >= 2 and parts[0].isupper() else "GET"
                url_part = parts[1] if len(parts) >= 2 else parts[0]
                path_lower = url_part.lower()

                if method == "POST":
                    has_post = True
                elif method in ("PUT", "PATCH"):
                    has_put = True
                elif method == "DELETE":
                    has_delete = True

                if method == "GET":
                    try:
                        parsed = urlparse(url_part)
                        params = parse_qs(parsed.query)
                        param_names = {k.lower() for k in params}
                        if param_names & {"id", "user_id", "uid", "order_id", "record_id"}:
                            has_get_with_id = True
                        if param_names & {"keyword", "search", "q", "query", "name", "filter",
                                          "page", "pagenum", "pagesize", "current", "size",
                                          "sort", "order", "orderby", "sortby", "offset", "limit"}:
                            has_get_with_keyword = True
                    except Exception:
                        pass
                    path_segs = url_part.rstrip("/").split("/")
                    if any(seg.isdigit() for seg in path_segs):
                        has_get_with_id = True

                if any(kw in path_lower for kw in ("upload", "import", "attach")):
                    has_upload_api = True
                if any(kw in path_lower for kw in ("export", "download")):
                    has_export_api = True
                if method == "GET" and any(kw in path_lower for kw in
                        ("list", "page", "records", "items", "all", "datalist")):
                    has_get_with_keyword = True

            def _add(vt: str):
                if vt not in matched:
                    matched.append(vt)

            if has_post:
                _add("SQL注入"); _add("CSRF"); _add("未授权访问")
            if has_put:
                _add("IDOR越权"); _add("SQL注入"); _add("CSRF"); _add("未授权访问")
            if has_delete:
                _add("IDOR越权"); _add("CSRF"); _add("未授权访问")
            if has_get_with_id:
                _add("IDOR越权"); _add("信息泄露")
            if has_get_with_keyword:
                _add("SQL注入"); _add("XSS")
            if has_upload_api:
                _add("文件上传绕过")
            if has_export_api:
                _add("越权导出"); _add("信息泄露")

        if priority in (Priority.CRITICAL, Priority.HIGH):
            for uc in UNIVERSAL_CHECKS:
                if uc not in matched:
                    matched.append(uc)

        # ★ 保险丝：checklist 项数上限（防止多层规则并集爆炸）
        # 超出 MAX_CHECKLIST_PER_FP 时，按 VULN_PRIORITY 从高到低保留。
        # 同优先级下保持原顺序（stable sort）——这样 UNIVERSAL_CHECKS 走到后面，
        # 而 FEATURE_VULN_MAPPING 首轮命中的项会被优先保留。
        if len(matched) > MAX_CHECKLIST_PER_FP:
            indexed = list(enumerate(matched))
            indexed.sort(key=lambda x: (
                VULN_PRIORITY.get(x[1], VULN_PRIORITY_DEFAULT),
                x[0],  # 同优先级按原顺序
            ))
            kept = sorted(indexed[:MAX_CHECKLIST_PER_FP], key=lambda x: x[0])
            log.info(
                "checklist 裁剪：%d 项 → %d 项（优先级裁剪）name='%s'",
                len(matched), MAX_CHECKLIST_PER_FP, name,
            )
            matched = [vt for _, vt in kept]

        return matched

    @classmethod
    def _context_filter_tests(cls, tests: list[str], related_apis: list[str] | None = None,
                               description: str = "") -> list[str]:
        """根据 API 实际特征，排除明显不适用的检查项（减少鸡肋 checklist）。

        过滤规则：
        1. 纯 JSON API（无 multipart/upload 路径）→ 排除文件上传类
        2. 纯 GET/只读接口 → 排除写操作类（金额篡改、状态篡改、CSRF）
        3. 非认证接口 → 排除弱密码、密码重置
        4. 语义去重：越权查看 ≈ IDOR越权，保留 IDOR
        5. 列表/查询类 POST → 排除文件上传、XXE、金额篡改等
        """
        if not tests:
            return tests

        # 分析 API 特征
        has_upload_path = False      # 路径含 upload/import/attach
        has_xml_path = False         # 路径含 xml/soap/wsdl
        has_payment_path = False     # 路径含 pay/order/checkout/price/amount
        has_auth_path = False        # 路径含 login/signin/password/auth
        has_delete_method = False    # DELETE 方法
        has_write_method = False     # POST/PUT/PATCH 方法（非查询类）
        is_readonly = True           # 只有 GET 方法
        is_list_query_api = False    # 列表/查询类 POST（POST 但语义是查询）

        # ★ 当 related_apis 为空时，从 description 中提取 API 信息
        #    典型格式："自动发现的功能型 API：POST /api/xxx" 或 "导入接口 POST /api/xxx"
        if not related_apis and description:
            api_match = re.search(r'\b(GET|POST|PUT|PATCH|DELETE)\s+(/?\S+)', description, re.IGNORECASE)
            if api_match:
                related_apis = [f"{api_match.group(1).upper()} {api_match.group(2)}"]

        if related_apis:
            for api_ref in related_apis:
                parts = api_ref.strip().split(" ", 1)
                method = parts[0].upper() if len(parts) >= 2 and parts[0].isupper() else "GET"
                url_part = parts[1] if len(parts) >= 2 else parts[0]
                path_lower = url_part.lower()

                if method in ("POST", "PUT", "PATCH"):
                    has_write_method = True
                    is_readonly = False
                    # ★ 列表/查询类 POST：路径含 list/page/query/get/search/find
                    # 或路径模式为 /Api.xxxList / /api/xxx/list
                    if any(kw in path_lower for kw in ("list", "page", "query", "search",
                                                         "find", "get", "fetch", "records",
                                                         "items", "datalist")):
                        is_list_query_api = True
                        has_write_method = False  # 查询类 POST 不是真正的写操作
                if method == "DELETE":
                    has_delete_method = True
                    is_readonly = False

                if any(kw in path_lower for kw in ("upload", "import", "attach", "avatar", "file")):
                    has_upload_path = True
                if any(kw in path_lower for kw in ("xml", "soap", "wsdl", "docx", "xlsx")):
                    has_xml_path = True
                if any(kw in path_lower for kw in ("pay", "order", "checkout", "price", "amount",
                                                     "recharge", "wallet", "balance", "coupon",
                                                     "discount", "redeem")):
                    has_payment_path = True
                if any(kw in path_lower for kw in ("login", "signin", "password", "passwd",
                                                     "auth", "sso", "oauth")):
                    has_auth_path = True

        # 也检查 description 中的特征
        desc_lower = description.lower()
        if not has_payment_path and any(kw in desc_lower for kw in ("金额", "价格", "支付", "订单", "购买")):
            has_payment_path = True
        if not has_auth_path and any(kw in desc_lower for kw in ("登录", "认证", "密码", "注册")):
            has_auth_path = True
        if not has_upload_path and any(kw in desc_lower for kw in ("上传", "附件")):
            has_upload_path = True
        # ★ description 中含"查询"/"列表"/"搜索"等词 → 更可能是查询类
        if not is_list_query_api and any(kw in desc_lower for kw in ("查询", "列表", "搜索", "获取", "筛选")):
            is_list_query_api = True
            has_write_method = False

        # 过滤规则
        filtered = []
        for t in tests:
            # 规则 1：无上传路径 → 排除文件上传类（description 中"导入"可能是语义误匹配）
            if not has_upload_path and t in ("文件上传绕过", "文件上传", "任意文件上传", "Webshell上传"):
                continue
            # 规则 1b：无 XML 路径且无上传路径 → 排除 XXE
            if not has_xml_path and not has_upload_path and t == "XXE":
                continue
            # 规则 2：纯只读接口 或 列表查询接口 → 排除写操作类
            if (is_readonly or is_list_query_api) and t in (
                "金额篡改", "数量篡改", "状态篡改", "竞态条件",
                "订单替换", "支付回调伪造", "重复使用", "并发领取"
            ):
                continue
            # 规则 2b：无支付路径 → 排除金额篡改类
            if not has_payment_path and t in ("金额篡改", "数量篡改", "订单替换",
                                               "支付回调伪造", "竞态条件", "重复使用", "并发领取"):
                continue
            # 规则 2c：状态篡改需要接口有状态相关路径/描述
            if t == "状态篡改":
                has_status_context = (
                    any(kw in (desc_lower or "") for kw in ("状态", "审批", "审核", "approve", "status", "state"))
                    or (related_apis and any(
                        any(kw in (api.lower() if isinstance(api, str) else str(api).lower())
                            for kw in ("status", "state", "approve", "review", "audit"))
                        for api in related_apis))
                )
                if not has_status_context:
                    continue
            # 规则 3：非认证接口 → 排除弱密码、密码重置
            if not has_auth_path and t in ("弱密码/默认密码", "密码重置逻辑", "短信轰炸", "验证码绕过"):
                continue
            # 规则 4：语义去重 — 越权查看 ≈ IDOR越权，只保留 IDOR
            if t == "越权查看" and "IDOR越权" in tests:
                continue
            # 规则 5：列表查询接口 → 排除 CSRF（查询类 POST 通常不需要 CSRF 防护）
            if is_list_query_api and t == "CSRF":
                continue

            filtered.append(t)

        # 去重（防止 synonym 映射后出现重复）
        seen = set()
        result = []
        for t in filtered:
            if t not in seen:
                seen.add(t)
                result.append(t)

        return result

    def add_feature(self, name: str, description: str = "", page_url: str = "",
                    priority: Priority = Priority.MEDIUM,
                    suggested_tests: list[str] | None = None,
                    related_apis: list[str] | None = None,
                    requires_auth: bool = False,
                    deferred: bool = False,
                    module: str = "") -> FeaturePoint | None:
        # 名称校验
        name = name.strip()
        description = (description or "").strip()
        if len(name) < 2 or len(description) < 4:
            return None
        if name.lower() in ("test", "a", "ab", "abc", "abcd", "1", "123", "xxx"):
            return None

        # 过滤纯 CRUD/通用操作名
        name_for_check = name.lower()
        if name_for_check.startswith(("get ", "post ", "put ", "delete ", "patch ")):
            name_for_check = name_for_check.split(" ", 1)[-1].strip()
        if "→" in name_for_check or "->" in name_for_check:
            parts = name_for_check.replace("->", "→").split("→")
            after_arrow = parts[-1].strip()
            if after_arrow.startswith(("get ", "post ", "put ", "delete ", "patch ")):
                after_arrow = after_arrow.split(" ", 1)[-1].strip()
            if after_arrow in GENERIC_NAMES:
                return None
        if name_for_check in GENERIC_NAMES:
            return None

        # ★ 去重
        def _api_key(a: str) -> str:
            return a.strip().split("?")[0].rstrip("/")

        incoming_apis = {_api_key(a) for a in (related_apis or []) if a}
        norm_page = (page_url or "").rstrip("/").split("?")[0]

        for existing in self.features.values():
            existing_apis = {_api_key(a) for a in existing.related_apis if a}
            existing_page = (existing.page_url or "").rstrip("/").split("?")[0]

            same_name = existing.name == name
            page_match = bool(norm_page) and norm_page == existing_page
            name_overlap = (name in existing.name) or (existing.name in name)
            apis_overlap = bool(incoming_apis) and bool(existing_apis) and incoming_apis == existing_apis

            if same_name or (page_match and name_overlap) or apis_overlap:
                merged_apis = list(existing.related_apis)
                for a in (related_apis or []):
                    if a and a not in merged_apis:
                        merged_apis.append(a)
                existing.related_apis = merged_apis
                if (not existing.description) and description:
                    existing.description = description
                if not existing.deferred and suggested_tests:
                    # ★ 过滤后再合并（防止 LLM 建议不适用项）
                    filtered_suggested = self._context_filter_tests(
                        list(suggested_tests), merged_apis, existing.description or description
                    )
                    existing_vulns = {c.vuln_type for c in existing.checklist}
                    for t in filtered_suggested:
                        canonical = VULN_SYNONYMS.get(t, t)
                        if canonical not in existing_vulns and t not in existing_vulns:
                            merge_has_page = self._has_frontend_page(existing.page_url or page_url)
                            existing.checklist.append(CheckItem(
                                vuln_type=canonical,
                                needs_browser=(canonical in BROWSER_REQUIRED_VULNS),
                            ))
                if (not existing.module) and module:
                    existing.module = module
                _PRIO_ORDER = {Priority.LOW: 0, Priority.MEDIUM: 1, Priority.HIGH: 2, Priority.CRITICAL: 3}
                if _PRIO_ORDER.get(priority, 1) > _PRIO_ORDER.get(existing.priority, 1):
                    existing.priority = priority
                try:
                    existing._was_merged = True
                except Exception:
                    pass
                return existing

        self._feature_counter += 1

        # ★ 自动关联
        if not related_apis:
            related_apis = self._auto_associate_apis(name, description, page_url, module)
            if related_apis:
                log.info("功能点 '%s' 自动关联了 %d 个 API（从已有原子功能点匹配）",
                         name, len(related_apis))

        if deferred:
            checklist = [CheckItem(vuln_type="未授权访问", needs_browser=False)]
        else:
            auto_tests = self._auto_suggest_tests(name, description, priority, related_apis)
            # ★ 上下文感知过滤：根据 API 特征排除明显不适用的检查项
            auto_tests = self._context_filter_tests(auto_tests, related_apis, description)
            all_tests = list(auto_tests)
            for t in (suggested_tests or []):
                canonical = VULN_SYNONYMS.get(t, t)
                if canonical not in all_tests and t not in all_tests:
                    all_tests.append(canonical)

            # ★ 二次过滤：LLM suggested_tests 合并后再过滤一遍（LLM 也可能建议不适用项）
            all_tests = self._context_filter_tests(all_tests, related_apis, description)

            all_apis_saturated = False
            if related_apis:
                saturated_count = 0
                for api in related_apis:
                    api_base = self._normalize_api_key(api)
                    if self._api_test_count.get(api_base, 0) >= self.MAX_API_TEST_OWNERS:
                        saturated_count += 1
                if saturated_count == len(related_apis):
                    all_apis_saturated = True

            if all_apis_saturated:
                checklist = []
                log.info("功能点 '%s' 的所有 API 已被 >=%d 个功能点覆盖，跳过 checklist",
                         name, self.MAX_API_TEST_OWNERS)
            else:
                has_page = self._has_frontend_page(page_url)
                checklist = [CheckItem(
                    vuln_type=t,
                    needs_browser=(t in BROWSER_REQUIRED_VULNS)
                ) for t in all_tests]
                for api in (related_apis or []):
                    api_base = self._normalize_api_key(api)
                    if api_base:
                        self._api_test_count[api_base] = self._api_test_count.get(api_base, 0) + 1

        fp = FeaturePoint(
            id=f"fp_{self._feature_counter}",
            name=name,
            description=description,
            page_url=page_url,
            related_apis=related_apis or [],
            priority=priority,
            checklist=checklist,
            requires_auth=requires_auth,
            deferred=deferred,
            module=module or self._infer_module(page_url, name),
        )

        if not checklist and not deferred:
            fp.test_status = TestStatus.TESTED

        if not fp.related_apis and self.apis:
            fp.related_apis = self._infer_related_apis(fp)

        self.features[fp.id] = fp
        return fp

    def _infer_related_apis(self, fp: "FeaturePoint") -> list[str]:
        """从已知 API 列表中，根据功能点名称/描述/page_url 自动匹配关联的 API。"""
        import re
        matched: list[str] = []
        keywords: set[str] = set()

        for word in fp.name.lower().replace("/", " ").replace("-", " ").replace("_", " ").split():
            if len(word) > 1:
                keywords.add(word)

        if fp.page_url:
            path = urlparse(fp.page_url).path.lower()
            for seg in path.split("/"):
                seg = seg.strip().replace("-", "").replace("_", "")
                if len(seg) > 2 and seg not in ("api", "admin", "src", "views"):
                    keywords.add(seg)

        for word in re.findall(r'[a-zA-Z]{3,}', fp.description.lower()):
            if word not in ("the", "and", "for", "with", "from", "this", "that", "http", "https"):
                keywords.add(word)

        if not keywords:
            return []

        for api_key in self.apis:
            api_lower = api_key.lower().replace("-", "").replace("_", "")
            for kw in keywords:
                clean_kw = kw.replace("-", "").replace("_", "")
                if clean_kw in api_lower:
                    matched.append(api_key)
                    break

        return matched[:10]

    def _infer_module(self, page_url: str, name: str) -> str:
        """从 URL 路径或功能点名称自动推断所属模块层级。"""
        if page_url:
            path = urlparse(page_url).path.strip("/")
            parts = [p for p in path.split("/") if p and p not in ("api", "v1", "v2", "v3", "index", "home", "#")]
            if parts:
                meaningful = [p.replace("-", " ").replace("_", " ").title() for p in parts if not p.isdigit()]
                if len(meaningful) >= 2:
                    return "/".join(meaningful[:3])
                elif meaningful:
                    return meaningful[0]

        if "/" in name:
            return name.rsplit("/", 1)[0].strip()

        return "其他"

    # ★ 功能点命名辅助：英文路径段 → 中文业务词
    # 覆盖常见 CRUD/业务模块词，让功能点名有业务语义而非纯 URL 拼接。
    # 未命中的段返回空字符串，由调用方决定是否回退英文。
    _PATH_SEG_CN_MAP = {
        # 认证
        "login": "登录", "dologin": "登录", "logout": "登出", "signin": "登录",
        "signup": "注册", "register": "注册", "forgot": "忘记密码",
        "password": "密码", "reset": "重置", "captcha": "验证码",
        "auth": "认证", "sso": "单点登录", "oauth": "OAuth授权",
        # 用户/权限
        "user": "用户", "users": "用户", "account": "账户", "profile": "个人信息",
        "member": "会员", "role": "角色", "roles": "角色", "permission": "权限",
        "menu": "菜单", "dept": "部门", "department": "部门", "organization": "组织",
        "org": "组织", "post": "岗位",
        # 业务模块
        "order": "订单", "orders": "订单", "product": "产品", "goods": "商品",
        "customer": "客户", "client": "客户", "supplier": "供应商", "distributor": "分销商",
        "finance": "财务", "payment": "支付", "pay": "支付", "invoice": "发票",
        "contract": "合同", "project": "项目", "task": "任务", "schedule": "日程",
        "message": "消息", "notice": "通知", "notification": "通知", "mail": "邮件",
        "log": "日志", "logs": "日志", "audit": "审计", "monitor": "监控",
        # 配置/系统
        "config": "配置", "setting": "设置", "settings": "设置", "system": "系统",
        "sys": "系统", "dict": "字典", "dictionary": "字典", "param": "参数",
        "env": "环境", "metrics": "指标", "health": "健康检查", "info": "信息",
        "version": "版本", "stat": "统计", "stats": "统计", "report": "报表",
        # 数据操作
        "list": "列表", "page": "分页", "detail": "详情", "info": "信息",
        "create": "新增", "add": "新增", "save": "保存", "update": "修改",
        "edit": "编辑", "modify": "修改", "delete": "删除", "remove": "删除",
        "export": "导出", "import": "导入", "upload": "上传", "download": "下载",
        "search": "搜索", "query": "查询", "find": "查找", "get": "获取",
        "tree": "树形", "batch": "批量", "cron": "定时任务",
    }

    def _path_seg_to_cn(self, seg: str) -> str:
        """将单个 URL 路径段映射为中文业务词，未命中返回空串。"""
        if not seg:
            return ""
        # 去掉 query/fragment
        seg = seg.split("?")[0].split("#")[0]
        # 已是中文段直接返回
        if re.search(r'[\u4e00-\u9fff]', seg):
            return seg
        # 规范化：去连字符/下划线，转小写
        key = seg.lower().replace("-", "").replace("_", "")
        return self._PATH_SEG_CN_MAP.get(key, "")

    def _get_domain_prefix(self) -> str:
        """从 business_understanding 提取业务领域标签作为命名前缀。

        返回简短的业务标签（如「旅行社ERP」「用户管理」），无则返回空串。
        用于让功能点名带业务上下文，而非纯 URL 拼接。
        """
        bu = getattr(self, "business_understanding", None) or {}
        if bu.get("status") != "ok":
            return ""
        u = bu.get("understanding") or {}
        # 优先 domain.label，其次 summary 前 10 字
        domain = u.get("domain") or {}
        if isinstance(domain, dict):
            label = (domain.get("label") or "").strip()
            if label:
                # 截断到 10 字，避免前缀过长
                return label[:10]
        summary = (u.get("summary") or "").strip()
        if summary:
            # 取前 8 字作为兜底前缀
            return summary[:8]
        return ""

    # ---- API 存活检测与幽灵端点过滤 ----

    # catch-all 路由常见特征：登录页/SPA fallback/验证码生成器
    _CATCH_ALL_HTML_PATTERNS = [
        "<title>登录", "<title>login", "<title>登入",
        'id="app"', 'id="root"', 'id="__next"',
        "<form.*password", "<form.*登录", "<form.*login",
    ]
    _CATCH_ALL_MIN_HTML_LEN = 500  # HTML 壳最小长度

    @staticmethod
    def _is_catch_all_response(status: int, body: str, content_type: str = "") -> bool:
        """检测响应是否为 catch-all 路由的兜底响应（登录页/SPA fallback/验证码生成器）。

        判定条件（满足任一）：
        1. 200 + HTML + 含登录页/SPA 入口特征
        2. 200 + JSON + 含验证码生成器特征（errcode + array + small）
        3. 200 + HTML + 长度与已知登录页壳相近且含 form/login 关键词
        """
        import re as _re

        if status != 200:
            return False

        body_stripped = body.strip()
        if not body_stripped:
            return False

        ct = (content_type or "").lower()

        # JSON 验证码生成器检测：响应含 errcode + array + small = 验证码 catch-all
        if "json" in ct or body_stripped.startswith("{"):
            try:
                import json as _json
                j = _json.loads(body_stripped[:2000])
                if isinstance(j, dict):
                    keys = set(j.keys())
                    # 验证码生成器特征：errcode + (array 或 y) + small/normal/img
                    if "errcode" in keys and (
                        "array" in keys or "y" in keys
                    ) and any(k in keys for k in ("small", "normal", "img", "imgx")):
                        return True
            except (ValueError, TypeError):
                pass
            return False

        # HTML catch-all 检测
        if "html" in ct or body_stripped[0] in "<!" or "<html" in body_stripped[:500].lower():
            if len(body_stripped) < FeatureGenMixin._CATCH_ALL_MIN_HTML_LEN:
                return False
            body_lower = body_stripped[:3000].lower()
            # 登录页特征
            for pattern in FeatureGenMixin._CATCH_ALL_HTML_PATTERNS:
                if _re.search(pattern, body_lower, _re.IGNORECASE):
                    return True
            # SPA fallback 特征：<div id="app"> + <script> 且无业务数据
            if ('id="app"' in body_lower or 'id="root"' in body_lower) and "<script" in body_lower:
                return True

        return False

    @staticmethod
    async def api_liveness_check(url: str, timeout: float = 5.0) -> bool:
        """通过 HEAD/GET 请求验证 API 端点是否存活。

        返回 True 表示端点可访问（非 404/非连接拒绝/非 catch-all 兜底），False 表示幽灵端点。
        """
        import httpx as _httpx

        if not url or url.startswith("data:"):
            return False
        clean_url = url.split(" ")[-1].split("|")[0].split("?")[0]
        if not clean_url.startswith("http"):
            return True  # 无法判断的相对路径视为存活
        try:
            async with _httpx.AsyncClient(verify=False, timeout=timeout) as client:
                resp = await client.head(clean_url, follow_redirects=True)
                if resp.status_code == 404:
                    return False
                if resp.status_code < 400 or resp.status_code == 405:
                    # 200/302/405 需进一步检查是否为 catch-all 兜底
                    if resp.status_code == 200:
                        # HEAD 无 body，需 GET 确认
                        resp = await client.get(clean_url, follow_redirects=True)
                        if resp.status_code == 404:
                            return False
                        body = resp.text[:3000]
                        ct = resp.headers.get("content-type", "")
                        if FeatureGenMixin._is_catch_all_response(resp.status_code, body, ct):
                            return False
                    return True
                if resp.status_code >= 500:
                    resp = await client.get(clean_url, follow_redirects=True)
                    if resp.status_code == 404:
                        return False
                    return True
                return True
        except (_httpx.HTTPError, _httpx.TimeoutException, OSError):
            return True  # 网络异常时保守存活

    async def filter_phantom_features(self, max_workers: int = 10) -> dict:
        """批量检测所有功能点关联 API 的存活状态，将 404 幽灵端点和 catch-all 兜底端点标记为 ghost。

        Returns:
            {"checked": int, "ghost_found": int, "ghost_details": list[str]}
        """
        import asyncio

        targets = [(fp, list(dict.fromkeys(
            api.split(" ", 1)[-1] for api in (fp.related_apis or [])
        ))) for fp in self.features.values() if fp.related_apis]

        sem = asyncio.Semaphore(max_workers)
        checked = 0
        ghost_count = 0
        ghost_details = []

        async def _check_fp(fp, urls) -> bool:
            nonlocal checked
            for url in urls:
                if not url.startswith("http"):
                    continue
                async with sem:
                    alive = await self.api_liveness_check(url)
                    checked += 1
                    if not alive:
                        return False
            return True

        tasks = [asyncio.ensure_future(_check_fp(fp, urls)) for fp, urls in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (fp, _), alive in zip(targets, results):
            if isinstance(alive, Exception):
                continue
            if not alive:
                ghost_count += 1
                fp.description = (fp.description or "") + " [GHOST-ENDPOINT]"
                fp.test_status = TestStatus.SKIPPED
                ghost_details.append(f"{fp.name} ({', '.join(fp.related_apis[:2])})")

        if ghost_count > 0:
            log.info("幽灵端点过滤: 检测 %d 个 API, 发现 %d 个幽灵端点/catch-all兜底 (%s)",
                     checked, ghost_count, "; ".join(ghost_details[:10]))
            self.save()

        return {"checked": checked, "ghost_found": ghost_count, "ghost_details": ghost_details[:50]}
