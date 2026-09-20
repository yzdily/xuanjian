"""
session_info — 从浏览器获取当前 Session 信息（Cookie / Token / 自定义 Header）
"""

from __future__ import annotations

import json

from core.log import get_logger

log = get_logger("parallel.session_info")


#: 标准头剔除表（Cookie / Authorization 应由浏览器实时态提供，不接受用户预导入）
_DROP_HEADERS = {"content-type", "content-length", "accept", "accept-encoding",
                 "accept-language", "connection", "host", "origin", "referer",
                 "user-agent", "cookie"}


async def get_session_info(target_url: str = "") -> dict:
    """从浏览器获取当前 Session 信息（完整 Cookie），分发给子 Agent。

    返回 ``{"headers": {...}}`` 结构，包含：
    - 浏览器的 Cookie（拼成 Cookie 头）
    - localStorage 中的 token（拼成 Authorization 头）
    - 用户预导入的自定义 header（如 X-Sign/X-Timestamp 等）

    自定义 header **优先级最低**，被浏览器实际拿到的 Cookie / Authorization 覆盖。

    Args:
        target_url: **本会话的目标 URL**。传入时只取该目标域下的 Cookie（阶段 4-E1 · L2 修复）。

    为什么必须按目标过滤（实测证据见 ``_e1_repro_crosstalk.py``）：
        ``browser_mcp`` 的 ``_browser/_page`` 是模块级全局单例，全进程共享**一个** context。
        原先用不带 URL 的 ``page.context.cookies()`` → 会把**其它会话/目标**的 cookie
        一并拼进同一个 Cookie 头：

            Cookie: sid=SESSION_A_SECRET; token=TOKEN_B_SECRET     ← 跨目标混合

        而按域过滤时 cookie jar 是干净的（target-a 只有 sid / target-b 只有 token），
        说明污染源是「聚合读取方式」而非 cookie 本身串域 —— 故此处一行过滤即可修掉。

        未传 ``target_url`` 时依次回退到当前凭证作用域的 ``target_url``、再回退全量（兼容旧调用）。
    """
    from core.session.cred_scope import get_scope

    headers: dict = {}
    scope = get_scope()

    # 1) 用户预导入的自定义 header（先注入，后续 Cookie/Auth 可覆盖）
    for k, v in scope.headers.items():
        if isinstance(k, str) and k.lower() not in _DROP_HEADERS and isinstance(v, (str, int, float)):
            headers[k] = str(v)

    effective_target = target_url or scope.target_url

    try:
        # 直接调用 Playwright API 获取完整 Cookie（不经过 browser_get_cookies 的截断）
        from core.mcp_bridge import _ensure_browser
        actual = getattr(_ensure_browser, "fn", _ensure_browser)
        page = await actual()
        # ★ L2 修复：按目标域过滤，避免并行会话的 cookie 混入同一 Cookie 头
        cookies = await page.context.cookies(effective_target) if effective_target \
            else await page.context.cookies()
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
            # ★ L2 修复（fallback 路径）：此处的 browser_get_cookies 也返回全量，
            #   按目标 host 过滤，避免跨目标 cookie 混入同一 Cookie 头。
            if effective_target:
                from urllib.parse import urlparse
                _host = (urlparse(effective_target).hostname or "").lower()
                if _host:
                    def _domain_match(c: dict) -> bool:
                        d = str(c.get("domain", "")).lstrip(".").lower()
                        return bool(d) and (_host == d or _host.endswith("." + d))
                    cookies = [c for c in cookies if _domain_match(c)]
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            if cookie_str:
                headers["Cookie"] = cookie_str
            # 用户预导入的 auth 兜底（阶段 4-E1：改从凭证作用域取，未绑定时回退 env）
            if scope.auth:
                headers.setdefault("Authorization", scope.auth)
            return {"headers": headers} if headers else {}
        except Exception:
            log.debug("fallback 获取 Cookie 也失败，返回已有 headers", exc_info=True)
            return {"headers": headers} if headers else {}
