"""SPA Mixin — SPA 单页应用检测 + 手动浏览降级模式。

当爬虫遇到 SPA（Vue/React/Angular）时，传统 href 链接提取和 BFS 遍历
可能只发现 1-2 个页面，无法发现后端 API 路由。此 Mixin 提供：

1. **增强 SPA 检测**：框架指纹（Vue/React/Angular）、低链接率判定、
   hash 路由检测、动态内容比例判定
2. **SPA 降级决策**：BFS 结束后若页面数 < 阈值且检测到 SPA → 自动切换
   手动浏览模式
3. **手动浏览 + 流量录制**：在有头浏览器中提示用户手动操作，同时
   通过 page.on("request") / page.on("response") 录制所有 API 请求
4. **认证态自动提取**：手动登录/浏览完成后，自动提取 Cookie、
   localStorage、sessionStorage 中的认证信息，供后续轮次复用
5. **流量 API 提取**：从录制的网络流量中过滤出业务 API 端点

兼容性：作为独立 Mixin 注入 AutoCrawler 继承链，不修改现有方法签名。
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse, urljoin

from core.log import get_logger

log = get_logger("crawler.spa")


# ============================================================
# 常量
# ============================================================

# SPA 降级阈值：BFS 结束后发现的页面数少于此值 + 检测到 SPA 框架 → 触发降级
SPA_FALLBACK_PAGE_THRESHOLD = 3

# 手动浏览默认超时（秒）
MANUAL_BROWSE_TIMEOUT = 300

# 手动浏览期间，API 请求去重的 key 模板
_API_DEDUP_KEY = "{method} {url}"

# 业务 API 路径前缀白名单（用于从录制的流量中过滤出业务 API）
_BUSINESS_API_PREFIXES = (
    "/api/", "/apis/", "/v1/", "/v2/", "/v3/",
    "/backend/", "/admin/", "/sys/", "/system/",
    "/service/", "/services/", "/graphql", "/rest/",
    "/biz/", "/manage/", "/portal/", "/open/",
    "/gateway/", "/proxy/", "/invoke/", "/call/",
    "/operation/", "/operations/",
)

# 非业务请求的路径特征（排除静态资源、第三方 SDK 等）
_NON_BUSINESS_PATH_KEYWORDS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".mp4", ".mp3", ".webp", ".avif",
    "favicon", "robots.txt", "sitemap",
    "google", "facebook", "twitter", "analytics",
    "recaptcha", "cloudflare", "sentry",
)


class SPAMixin:
    """SPA 检测与手动浏览降级模式。

    设计原则：
    - 所有方法都是可选的——不调用则不影响原有流程
    - 手动浏览模式只在有头浏览器中启用
    - 录制的流量与 BFS 阶段的 captured 列表合并，不创建独立数据结构
    """

    async def _detect_spa_enhanced(self, page) -> dict[str, Any]:
        """增强 SPA 检测：框架指纹 + 路由模式 + 内容动态性。

        在页面加载后调用，返回检测结果字典：
        {
            "is_spa": bool,
            "framework": "vue3" | "vue2" | "react" | "angular" | "",
            "router_mode": "hash" | "history" | "",
            "route_count": int,          # 从框架 router 提取到的路由数
            "spa_routes": list[str],     # 路由路径列表
            "dynamic_content_ratio": float,  # 动态内容占比（0-1）
            "link_count": int,           # 页面 a[href] 链接数
        }
        """
        info: dict[str, Any] = {
            "is_spa": self._is_spa,  # 继承已有的初始判定
            "framework": "",
            "router_mode": "",
            "route_count": 0,
            "spa_routes": [],
            "dynamic_content_ratio": 0.0,
            "link_count": 0,
        }

        try:
            raw = await page.evaluate("""() => {
                const result = {
                    framework: '',
                    routes: [],
                    mode: '',
                    linkCount: 0,
                    dynamicRatio: 0,
                };
                try {
                    // ---- Vue 3 ----
                    const app = document.querySelector('#app');
                    if (app && app.__vue_app__) {
                        result.framework = 'vue3';
                        const router = app.__vue_app__.config.globalProperties.$router;
                        if (router) {
                            try {
                                result.routes = router.getRoutes()
                                    .map(r => r.path)
                                    .filter(p => p && p !== '/');
                            } catch(e) {
                                // Vue Router 可能没有 getRoutes
                            }
                            const opt = router.options || {};
                            if (opt.history) {
                                result.mode = location.hash && location.hash.startsWith('#/')
                                    ? 'hash' : 'history';
                            }
                        }
                    }
                    // ---- Vue 2 ----
                    if (!result.framework && app && app.__vue__) {
                        result.framework = 'vue2';
                        const router = app.__vue__.$router;
                        if (router) {
                            try {
                                result.routes = (router.options.routes || [])
                                    .map(r => r.path)
                                    .filter(p => p && p !== '/');
                            } catch(e) {}
                            result.mode = router.mode ||
                                (location.hash.startsWith('#/') ? 'hash' : 'history');
                        }
                    }
                    // ---- React ----
                    if (!result.framework) {
                        // React 18+ createRoot
                        const rootEl = document.getElementById('root') || document.getElementById('app');
                        if (rootEl && rootEl._reactRootContainer) {
                            result.framework = 'react';
                        }
                        // React 18 fiber
                        if (!result.framework) {
                            const fiberKey = Object.keys(rootEl || {}).find(k =>
                                k.startsWith('__reactFiber'));
                            if (fiberKey) result.framework = 'react';
                        }
                        // 检测 React Router
                        if (result.framework === 'react') {
                            // 从 DOM 中的 <a> 标签提取 React Router 路径
                            const reactLinks = Array.from(document.querySelectorAll('a[href]'))
                                .map(a => a.getAttribute('href'))
                                .filter(h => h && (h.startsWith('/') || h.startsWith('#/')))
                                .filter(h => !h.startsWith('//'));
                            // 去重
                            result.routes = [...new Set(reactLinks)].slice(0, 100);
                            result.mode = location.hash && location.hash.startsWith('#/')
                                ? 'hash' : 'history';
                        }
                    }
                    // ---- Angular ----
                    if (!result.framework) {
                        if (window.ng || document.querySelector('[ng-version]')) {
                            result.framework = 'angular';
                            result.mode = location.hash && location.hash.startsWith('#/')
                                ? 'hash' : 'history';
                            // Angular 路由从 Router 实例获取
                            try {
                                if (window.ng && window.ng.getRouter) {
                                    const router = window.ng.getRouter();
                                    if (router) {
                                        result.routes = router.config
                                            .map(r => r.path)
                                            .filter(p => p && p !== '**' && p !== '');
                                    }
                                }
                            } catch(e) {}
                        }
                    }

                    // ---- 通用检测 ----
                    // 链接数
                    result.linkCount = document.querySelectorAll('a[href]').length;
                    // 动态内容比例：body 中非文本节点的占比
                    const body = document.body;
                    if (body) {
                        const totalNodes = body.querySelectorAll('*').length;
                        const textNodes = body.querySelectorAll('p, span, h1, h2, h3, h4, h5, h6, label, a, td, li').length;
                        result.dynamicRatio = totalNodes > 0
                            ? 1 - (textNodes / totalNodes) : 0;
                    }
                    // 兜底路由模式
                    if (!result.mode) {
                        result.mode = location.hash && location.hash.startsWith('#/')
                            ? 'hash' : 'history';
                    }
                } catch(e) {}
                return result;
            }""")
        except Exception as e:
            log.debug("SPA 增强检测失败: %s", e)
            return info

        if not raw or not isinstance(raw, dict):
            return info

        info["framework"] = raw.get("framework", "")
        info["spa_routes"] = raw.get("routes", []) or []
        info["route_count"] = len(info["spa_routes"])
        info["router_mode"] = raw.get("mode", "")
        info["link_count"] = raw.get("linkCount", 0)
        info["dynamic_content_ratio"] = raw.get("dynamicRatio", 0.0)

        # 综合判定 is_spa
        # 条件1：检测到前端框架
        # 条件2：URL 含 hash 路由（原有逻辑）
        # 条件3：链接数极少（< 5）但有大量 DOM 节点（动态渲染）
        has_framework = bool(info["framework"])
        has_hash_route = self._is_spa  # 原有 __init__ 中的判定
        low_links_high_dynamic = (
            info["link_count"] < 5
            and info["dynamic_content_ratio"] > 0.6
        )
        info["is_spa"] = has_framework or has_hash_route or low_links_high_dynamic

        # 如果检测到 history 模式且有路由，修正 _is_spa
        if info["spa_routes"] and info["router_mode"] == "history":
            # history 模式的 SPA 不拼 #/，但仍然是 SPA
            # 不修改 self._is_spa（保持原有行为：不拼 #/）
            pass

        return info

    def _should_fallback_to_manual(
        self,
        page_count: int,
        spa_info: dict[str, Any],
        captured_api_count: int,
    ) -> bool:
        """判断是否应该降级到手动浏览模式。

        降级条件（满足任一）：
        1. BFS 发现页面数 < 3 且检测到 SPA 框架
        2. BFS 发现页面数 < 5 且 0 个 API 端点 且检测到 SPA
        3. 用户显式请求手动模式（通过环境变量）
        """
        import os
        # 用户显式请求
        if os.getenv("PENTEST_MANUAL_BROWSE", "").lower() in ("1", "true", "yes"):
            return True

        is_spa = spa_info.get("is_spa", False)
        has_framework = bool(spa_info.get("framework"))
        route_count = spa_info.get("route_count", 0)

        # 条件1：SPA + 页面太少
        if is_spa and page_count < SPA_FALLBACK_PAGE_THRESHOLD:
            log.info("SPA 降级触发: 页面数 %d < %d, SPA=%s",
                     page_count, SPA_FALLBACK_PAGE_THRESHOLD, is_spa)
            return True

        # 条件2：SPA + 页面少 + 无 API
        if is_spa and page_count < 5 and captured_api_count == 0:
            log.info("SPA 降级触发: 页面数 %d < 5, API=0, SPA=%s",
                     page_count, is_spa)
            return True

        # 条件3：检测到框架但路由提取为 0（可能是 React/Angular，运行时提取失败）
        if has_framework and route_count == 0 and page_count < 3:
            log.info("SPA 降级触发: 框架=%s 但路由提取为 0, 页面数 %d",
                     spa_info.get("framework"), page_count)
            return True

        return False

    async def _manual_browse_session(
        self,
        page,
        captured: list[dict],
        timeout: int = MANUAL_BROWSE_TIMEOUT,
    ) -> dict[str, Any]:
        """手动浏览模式：用户操作浏览器，爬虫录制所有网络请求。

        流程：
        1. 在有头浏览器中显示提示信息（覆盖层）
        2. 注册 page.on("request") / page.on("response") 监听器
        3. 等待用户操作（超时或用户点击"完成"按钮）
        4. 从录制的流量中提取 API 端点
        5. 自动提取认证态（Cookie/localStorage）

        Args:
            page: Playwright Page 对象
            captured: 已有的流量捕获列表（追加，不覆盖）
            timeout: 超时秒数

        Returns:
            {
                "apis": list[dict],           # 提取的 API 端点
                "auth_state": dict,           # 认证态（cookies/localStorage/headers）
                "pages_visited": int,         # 用户访问的页面数
                "duration": float,            # 实际浏览时长（秒）
            }
        """
        import time as _time
        loop = asyncio.get_event_loop()
        start = loop.time()

        # 录制期间的请求/响应
        manual_requests: list[dict] = []
        manual_responses: list[dict] = []
        pages_visited: set[str] = set()

        # 注入提示覆盖层
        try:
            await page.evaluate("""(timeout) => {
                const overlay = document.createElement('div');
                overlay.id = '__pentest_manual_overlay';
                overlay.style.cssText = `
                    position: fixed; top: 0; left: 0; right: 0; z-index: 999999;
                    background: #1a1a2e; color: #e0e0e0; padding: 12px 20px;
                    font-family: -apple-system, sans-serif; font-size: 14px;
                    border-bottom: 2px solid #e94560; display: flex;
                    justify-content: space-between; align-items: center;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.3);
                `;
                overlay.innerHTML = `
                    <div>
                        <span style="color: #e94560; font-weight: bold;">🔍 玄鉴爬虫</span>
                        &nbsp;手动浏览模式已启动 — 请在页面中正常操作（点击菜单、填写表单、翻页等），
                        爬虫正在录制所有 API 请求
                    </div>
                    <div>
                        <span id="__pentest_timer" style="color: #aaa; font-size: 12px;"></span>
                        <button id="__pentest_finish_btn" style="
                            margin-left: 12px; padding: 4px 16px; background: #e94560;
                            color: white; border: none; border-radius: 4px; cursor: pointer;
                            font-size: 13px;">完成浏览</button>
                    </div>
                `;
                document.body.appendChild(overlay);
                // 倒计时
                const timerEl = document.getElementById('__pentest_timer');
                const startTime = Date.now();
                const interval = setInterval(() => {
                    const elapsed = Math.floor((Date.now() - startTime) / 1000);
                    const remaining = timeout - elapsed;
                    if (remaining <= 0) {
                        clearInterval(interval);
                        return;
                    }
                    const min = Math.floor(remaining / 60);
                    const sec = remaining % 60;
                    timerEl.textContent = `剩余 ${min}:${sec.toString().padStart(2, '0')}`;
                }, 1000);
                // 完成按钮
                const btn = document.getElementById('__pentest_finish_btn');
                btn.onclick = () => {
                    window.__pentest_manual_done = true;
                    overlay.remove();
                };
            }""", timeout)
        except Exception as e:
            log.debug("注入手动浏览提示失败: %s", e)

        # 注册请求/响应监听器
        def _on_request(req):
            try:
                # 过滤静态资源
                url = req.url
                path = urlparse(url).path.lower()
                if any(kw in path for kw in _NON_BUSINESS_PATH_KEYWORDS):
                    return
                manual_requests.append({
                    "method": req.method,
                    "url": url,
                    "headers": dict(req.headers),
                    "post_data": req.post_data or "",
                })
                pages_visited.add(url.split("?")[0].split("#")[0])
            except Exception:
                pass

        async def _on_response(resp):
            try:
                url = resp.url
                path = urlparse(url).path.lower()
                if any(kw in path for kw in _NON_BUSINESS_PATH_KEYWORDS):
                    return
                # 只录制业务 API 响应
                is_api = (
                    any(prefix in url for prefix in _BUSINESS_API_PREFIXES)
                    or resp.request.resource_type in ("xhr", "fetch")
                )
                if not is_api:
                    return
                body_preview = ""
                try:
                    body_preview = await resp.text()
                    if len(body_preview) > 2000:
                        body_preview = body_preview[:2000]
                except Exception:
                    pass
                manual_responses.append({
                    "method": resp.request.method,
                    "url": url,
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body_preview,
                    "content_type": resp.headers.get("content-type", ""),
                })
            except Exception:
                pass

        page.on("request", _on_request)
        page.on("response", _on_response)

        # 推送事件到前端
        self._emit_event("manual_browse_start", {"timeout": timeout})

        # 等待用户操作或超时
        try:
            while loop.time() - start < timeout:
                await asyncio.sleep(2)
                # 检查用户是否点击了"完成"按钮
                try:
                    done = await page.evaluate("() => window.__pentest_manual_done === true")
                    if done:
                        self._report("  👤 用户已手动完成浏览")
                        break
                except Exception:
                    pass
                # 每 30 秒推送一次进度
                elapsed = loop.time() - start
                if int(elapsed) % 30 == 0 and int(elapsed) > 0:
                    self._emit_event("manual_browse_progress", {
                        "elapsed": int(elapsed),
                        "requests_captured": len(manual_requests),
                        "apis_captured": len(manual_responses),
                    })
        except Exception as e:
            log.warning("手动浏览等待异常: %s", e)

        # 清理监听器
        try:
            page.remove_listener("request", _on_request)
            page.remove_listener("response", _on_response)
        except Exception:
            pass

        # 移除覆盖层
        try:
            await page.evaluate("""() => {
                const el = document.getElementById('__pentest_manual_overlay');
                if (el) el.remove();
            }""")
        except Exception:
            pass

        duration = loop.time() - start
        self._emit_event("manual_browse_done", {
            "duration": int(duration),
            "requests_captured": len(manual_requests),
            "apis_captured": len(manual_responses),
        })

        # 从录制的流量中提取 API 端点
        apis = self._extract_apis_from_manual_traffic(
            manual_requests, manual_responses, self.target
        )

        # 追加到 captured 列表（与 BFS 阶段的流量合并）
        captured.extend(manual_requests)

        # 自动提取认证态
        auth_state = await self._auto_extract_auth_state(page)

        self._report(
            f"  📼 手动浏览完成: 录制 {len(manual_requests)} 个请求, "
            f"提取 {len(apis)} 个 API, {len(pages_visited)} 个页面"
        )

        return {
            "apis": apis,
            "auth_state": auth_state,
            "pages_visited": len(pages_visited),
            "duration": duration,
        }

    def _extract_apis_from_manual_traffic(
        self,
        requests: list[dict],
        responses: list[dict],
        base_url: str,
    ) -> list[dict]:
        """从手动浏览录制的流量中提取业务 API 端点。

        过滤规则：
        1. 排除静态资源（.js/.css/.png 等）
        2. 排除第三方域名（非目标域且非关联域）
        3. 优先保留有响应的请求（status code 可用）
        4. 按 (method, url_path) 去重
        """
        base_domain = urlparse(base_url).netloc.lower()
        seen: set[str] = set()
        apis: list[dict] = []

        # 构建 URL → response 映射
        resp_map: dict[str, dict] = {}
        for r in responses:
            key = f"{r.get('method', 'GET')} {r.get('url', '')}"
            resp_map[key] = r

        for req in requests:
            method = req.get("method", "GET")
            url = req.get("url", "")
            if not url:
                continue

            # 域名过滤
            req_domain = urlparse(url).netloc.lower()
            if req_domain and req_domain != base_domain:
                # 非目标域 → 检查是否在 extra_scope 中
                if not hasattr(self, "extra_scope") or req_domain not in self.extra_scope:
                    continue

            # 路径过滤
            path = urlparse(url).path.lower()
            if any(kw in path for kw in _NON_BUSINESS_PATH_KEYWORDS):
                continue

            # 去重（按 method + path，忽略 query string）
            url_no_query = url.split("?")[0].split("#")[0]
            dedup_key = _API_DEDUP_KEY.format(method=method, url=url_no_query)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # 合并请求和响应信息
            resp_key = f"{method} {url}"
            resp = resp_map.get(resp_key, {})
            post_data = req.get("post_data", "")
            # 截断过长的 post_data
            if len(post_data) > 1000:
                post_data = post_data[:1000]

            api_entry = {
                "method": method,
                "url": url_no_query,
                "status_code": resp.get("status", 0),
                "request_headers": req.get("headers", {}),
                "response_headers": resp.get("headers", {}),
                "post_data": post_data,
                "response_body": resp.get("body", ""),
                "content_type": resp.get("content_type", ""),
                "discovered_by": "manual_browse",
                "trigger_context": "手动浏览录制",
            }
            apis.append(api_entry)

        return apis

    async def _auto_extract_auth_state(self, page) -> dict[str, Any]:
        """从当前浏览器页面自动提取认证态。

        提取内容：
        1. 所有 Cookie（通过 page.context.cookies()）
        2. localStorage 中的 token/auth 相关 key
        3. sessionStorage 中的 token/auth 相关 key
        4. 请求头中的 Authorization（从最近的 XHR 请求中提取）

        Returns:
            {
                "cookies": list[dict],       # Playwright cookie 格式
                "local_storage": dict,       # {key: value}
                "session_storage": dict,     # {key: value}
                "auth_header": str,          # Authorization header 值
                "extra_headers": dict,       # 其他认证相关 header
            }
        """
        auth_state: dict[str, Any] = {
            "cookies": [],
            "local_storage": {},
            "session_storage": {},
            "auth_header": "",
            "extra_headers": {},
        }

        # 1. Cookie
        try:
            cookies = await page.context.cookies()
            auth_state["cookies"] = cookies
            # 提取认证相关 cookie 名称
            auth_cookie_names = [
                c["name"] for c in cookies
                if any(kw in c["name"].lower()
                       for kw in ("session", "token", "auth", "uid", "sid", "jwt"))
            ]
            if auth_cookie_names:
                self._report(f"  🍪 提取到认证 Cookie: {', '.join(auth_cookie_names[:5])}")
        except Exception as e:
            log.debug("Cookie 提取失败: %s", e)

        # 2. localStorage + sessionStorage
        try:
            storage_data = await page.evaluate("""() => {
                const result = {localStorage: {}, sessionStorage: {}};
                const authKeys = [
                    'token', 'access_token', 'accessToken', 'auth_token', 'authToken',
                    'jwt', 'id_token', 'idToken', 'Authorization', 'user_token',
                    'refresh_token', 'refreshToken', 'Bearer',
                    'Sc-Id-Token', 'c-token', 'x-token', 'X-Token',
                    'userInfo', 'user_info', 'permissions', 'roles',
                ];
                // localStorage
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    if (authKeys.some(ak => k.toLowerCase().includes(ak.toLowerCase()))) {
                        const v = localStorage.getItem(k);
                        if (v && v.length > 5) {
                            result.localStorage[k] = v;
                        }
                    }
                }
                // sessionStorage
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i);
                    if (authKeys.some(ak => k.toLowerCase().includes(ak.toLowerCase()))) {
                        const v = sessionStorage.getItem(k);
                        if (v && v.length > 5) {
                            result.sessionStorage[k] = v;
                        }
                    }
                }
                return result;
            }""")
            if storage_data:
                auth_state["local_storage"] = storage_data.get("localStorage", {})
                auth_state["session_storage"] = storage_data.get("sessionStorage", {})
                ls_count = len(auth_state["local_storage"])
                ss_count = len(auth_state["session_storage"])
                if ls_count + ss_count > 0:
                    self._report(f"  🔑 提取到认证 Storage: localStorage {ls_count} 项, sessionStorage {ss_count} 项")
        except Exception as e:
            log.debug("Storage 提取失败: %s", e)

        # 3. 从 localStorage 中推断 auth_header
        for key, value in auth_state["local_storage"].items():
            if value.startswith("Bearer ") or (len(value) > 50 and value.count(".") == 2):
                auth_state["auth_header"] = value if value.startswith("Bearer ") else f"Bearer {value}"
                break

        return auth_state

    def _apply_auth_state_to_context(self, ctx, auth_state: dict[str, Any]) -> None:
        """将提取的认证态应用到新的 BrowserContext（异步方法）。

        用于多轮爬取中，将手动浏览阶段提取的认证态注入到后续轮次。
        """
        # 这个方法需要在 async 上下文中调用
        # 在 _crawl_round 的 ctx 创建后调用
        pass

    async def _apply_auth_state_async(self, ctx, auth_state: dict[str, Any], target: str) -> bool:
        """异步应用认证态到 BrowserContext。

        Args:
            ctx: Playwright BrowserContext
            auth_state: _auto_extract_auth_state() 的返回值
            target: 目标 URL（用于计算 cookie domain）

        Returns:
            True 如果注入了任何认证信息
        """
        injected = False

        # 1. Cookie 注入
        cookies = auth_state.get("cookies", [])
        if cookies:
            try:
                # 过滤出目标域的 cookie
                target_domain = urlparse(target).netloc.lower()
                relevant_cookies = [
                    c for c in cookies
                    if target_domain.endswith(c.get("domain", "").lstrip(".").lower())
                    or c.get("domain", "").lstrip(".").lower() in target_domain
                ]
                if relevant_cookies:
                    await ctx.add_cookies(relevant_cookies)
                    injected = True
                    log.info("认证态复用: 注入 %d 个 Cookie", len(relevant_cookies))
            except Exception as e:
                log.warning("Cookie 复用注入失败: %s", e)

        # 2. Header 注入
        auth_header = auth_state.get("auth_header", "")
        extra_headers = auth_state.get("extra_headers", {})
        if auth_header:
            extra_headers = dict(extra_headers)
            extra_headers.setdefault("Authorization", auth_header)
        if extra_headers:
            try:
                await ctx.set_extra_http_headers(extra_headers)
                injected = True
                log.info("认证态复用: 注入 %d 个 Header", len(extra_headers))
            except Exception as e:
                log.warning("Header 复用注入失败: %s", e)

        # 3. localStorage 注入（通过 init_script）
        ls_data = auth_state.get("local_storage", {})
        if ls_data:
            try:
                import json as _json
                ls_json = _json.dumps(ls_data, ensure_ascii=False)
                await ctx.add_init_script(f"""
                    (() => {{
                        try {{
                            const items = JSON.parse({ls_json!r});
                            for (const [k, v] of Object.entries(items)) {{
                                localStorage.setItem(k, v);
                            }}
                        }} catch(e) {{}}
                    }})();
                """)
                injected = True
                log.info("认证态复用: 注入 %d 个 localStorage 项", len(ls_data))
            except Exception as e:
                log.warning("localStorage 复用注入失败: %s", e)

        return injected
