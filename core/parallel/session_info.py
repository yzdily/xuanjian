"""
session_info — 从浏览器获取当前 Session 信息（Cookie / Token / 自定义 Header）
"""

from __future__ import annotations

import json
import os

from core.log import get_logger

log = get_logger("parallel.session_info")


async def get_session_info() -> dict:
    """从浏览器获取当前 Session 信息（完整 Cookie），分发给子 Agent。

    返回 ``{"headers": {...}}`` 结构，包含：
    - 浏览器的全部 Cookie（拼成 Cookie 头）
    - localStorage 中的 token（拼成 Authorization 头）
    - 用户预导入的自定义 header（PENTEST_INJECT_HEADERS，如 X-Sign/X-Timestamp 等）

    自定义 header **优先级最低**，被浏览器实际拿到的 Cookie / Authorization 覆盖。
    """
    headers: dict = {}

    # 1) 用户预导入的自定义 header（先注入，后续 Cookie/Auth 可覆盖）
    inject_headers_json = os.getenv("PENTEST_INJECT_HEADERS", "")
    if inject_headers_json:
        try:
            inject_headers = json.loads(inject_headers_json)
            if isinstance(inject_headers, dict):
                # 同样剔除标准头（cookie / authorization 应由浏览器实时态提供）
                _drop = {"content-type", "content-length", "accept", "accept-encoding",
                         "accept-language", "connection", "host", "origin", "referer",
                         "user-agent", "cookie"}
                for k, v in inject_headers.items():
                    if isinstance(k, str) and k.lower() not in _drop and isinstance(v, (str, int, float)):
                        headers[k] = str(v)
        except (ValueError, TypeError):
            pass

    try:
        # 直接调用 Playwright API 获取完整 Cookie（不经过 browser_get_cookies 的截断）
        from core.mcp_bridge import _ensure_browser
        actual = getattr(_ensure_browser, "fn", _ensure_browser)
        page = await actual()
        cookies = await page.context.cookies()
        cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)

        # 同时提取 localStorage 中的 token（SPA 常用 JWT）
        try:
            local_token = await page.evaluate("""() => {
                const keys = ['token', 'access_token', 'accessToken', 'auth_token',
                              'jwt', 'Authorization', 'user_token', 'Token'];
                for (const key of keys) {
                    const val = localStorage.getItem(key);
                    if (val && val.length > 10) return {key, value: val};
                }
                return null;
            }""")
        except Exception:
            log.debug("从 localStorage 提取 token 失败", exc_info=True)
            local_token = None

        if cookie_str:
            headers["Cookie"] = cookie_str
        if local_token:
            # 常见格式：Bearer xxx 或直接 token
            token_val = local_token["value"]
            if not token_val.startswith("Bearer "):
                token_val = f"Bearer {token_val}"
            headers["Authorization"] = token_val

        return {"headers": headers} if headers else {}
    except Exception:
        # fallback: 旧的方式（浏览器没起来或失败）
        log.debug("从 Playwright 获取 Cookie 失败，尝试 fallback", exc_info=True)
        try:
            from mcp_servers import browser_mcp
            actual = getattr(browser_mcp.browser_get_cookies, "fn", browser_mcp.browser_get_cookies)
            cookies_json = await actual()
            cookies = json.loads(cookies_json)
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            if cookie_str:
                headers["Cookie"] = cookie_str
            # 用户预导入的 auth_header 兜底
            inject_auth = os.getenv("PENTEST_INJECT_AUTH", "")
            if inject_auth:
                headers.setdefault("Authorization", inject_auth)
            return {"headers": headers} if headers else {}
        except Exception:
            log.debug("fallback 获取 Cookie 也失败，返回已有 headers", exc_info=True)
            return {"headers": headers} if headers else {}
