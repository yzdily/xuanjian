"""
Browser MCP — Playwright 浏览器操作服务

提供 Agent 操作浏览器的能力：访问、点击、填写、读取、截图。
所有流量经过 mitmproxy 代理，实现自动抓包。
"""

from __future__ import annotations

import os
import asyncio
from pathlib import Path
from mcp.server.fastmcp import FastMCP

from core.config import (
    MAX_JS_FILE_SIZE,
    HTTP_PROXY_CHECK_TIMEOUT,
    MAX_RESPONSE_BODY_SIZE,
)

mcp = FastMCP("browser")

# 全局 Playwright 实例
_browser = None
_page = None
_injection_fingerprint = ""


def _current_injection_fingerprint() -> str:
    keys = (
        "PENTEST_INJECT_COOKIES", "PENTEST_INJECT_AUTH", "PENTEST_INJECT_HEADERS",
        "PENTEST_INJECT_LOCAL_STORAGE", "PENTEST_TARGET_URL",
    )
    return "\n".join(f"{k}={os.getenv(k, '')}" for k in keys)


async def _refresh_session_injection_if_needed(page) -> None:
    """浏览器已存在时刷新 Header/Cookie/localStorage，避免 Phase 1 复用旧会话。"""
    global _injection_fingerprint

    fingerprint = _current_injection_fingerprint()
    if fingerprint == _injection_fingerprint:
        return

    try:
        import json as _json
        ctx = page.context
        inject_cookies = os.getenv("PENTEST_INJECT_COOKIES", "")
        inject_auth = os.getenv("PENTEST_INJECT_AUTH", "")
        inject_headers_json = os.getenv("PENTEST_INJECT_HEADERS", "")
        target_for_inject = os.getenv("PENTEST_TARGET_URL", "")

        if inject_cookies and target_for_inject:
            from core.intent import parse_cookie_string
            ck_list = parse_cookie_string(inject_cookies, target_for_inject)
            if ck_list:
                await ctx.add_cookies(ck_list)
                print(f"[browser] 🍪 已刷新 {len(ck_list)} 个 Cookie")

        headers_to_set: dict[str, str] = {}
        if inject_headers_json:
            try:
                headers_dict = _json.loads(inject_headers_json)
                skip = {"content-type", "content-length", "accept", "referer", "origin", "cookie"}
                for k, v in headers_dict.items():
                    if k.lower() not in skip:
                        headers_to_set[k] = v
            except Exception as je:
                print(f"[browser] ⚠️ INJECT_HEADERS JSON 解析失败: {je}")
        if inject_auth and "Authorization" not in headers_to_set:
            headers_to_set["Authorization"] = inject_auth
        await ctx.set_extra_http_headers(headers_to_set)
        if headers_to_set:
            print(f"[browser] 📦 已刷新 {len(headers_to_set)} 个自定义 Header: {', '.join(list(headers_to_set.keys())[:5])}")

        inject_local_storage_json = os.getenv("PENTEST_INJECT_LOCAL_STORAGE", "")
        if inject_local_storage_json:
            try:
                ls_items = _json.loads(inject_local_storage_json)
                if isinstance(ls_items, dict) and ls_items:
                    ls_json_escaped = _json.dumps(ls_items, ensure_ascii=False)
                    await ctx.add_init_script(f"""
                        (() => {{
                            try {{
                                const items = JSON.parse({ls_json_escaped!r});
                                for (const [k, v] of Object.entries(items)) {{
                                    localStorage.setItem(k, v);
                                }}
                            }} catch(e) {{}}
                        }})();
                    """)
                    try:
                        await page.evaluate("""items => {
                            try {
                                for (const [k, v] of Object.entries(items || {})) localStorage.setItem(k, v);
                            } catch(e) {}
                        }""", ls_items)
                    except Exception as e:
                        print(f"[browser] ⚠️ localStorage 注入到当前页面失败: {e}")
                    print(f"[browser] 🔑 已刷新 {len(ls_items)} 个 localStorage 项: {', '.join(list(ls_items.keys())[:5])}")
            except Exception as lse:
                print(f"[browser] ⚠️ INJECT_LOCAL_STORAGE 解析失败: {lse}")

        jwt_token = ""
        for _hk, _hv in headers_to_set.items():
            if isinstance(_hv, str) and _hv.startswith("eyJ") and len(_hv) > 20:
                jwt_token = _hv
                break
        if jwt_token:
            await ctx.add_init_script(f"""
                (() => {{
                    const TOKEN = {jwt_token!r};
                    let attempts = 0;
                    const timer = setInterval(() => {{
                        attempts++;
                        if (attempts > 30) {{ clearInterval(timer); return; }}
                        const el = document.querySelector('[data-v-app]') || document.querySelector('#app');
                        const vm = el && el.__vue__;
                        if (!vm || !vm.$store) return;
                        const state = vm.$store.state || {{}};
                        for (const key of ['user', 'auth', 'login', 'account']) {{
                            try {{ if (state[key] && typeof state[key] === 'object') state[key].token = TOKEN; }} catch(e) {{}}
                        }}
                        try {{ state.token = TOKEN; }} catch(e) {{}}
                        clearInterval(timer);
                    }}, 100);
                }})();
            """)
            print("[browser] 🏪 已刷新 Vuex Store token 注入脚本")

        _injection_fingerprint = fingerprint
    except Exception as e:
        print(f"[browser] ⚠️ 刷新会话凭证失败: {e}")


async def _check_proxy(proxy_url: str) -> bool:
    """检测代理是否可达。

    ★ #7: 不再依赖 httpbin.org（该域名常被墙/限速/宕机导致误判代理不可用），
    改用多个候选测试目标，任一可达即视为代理工作正常。
    """
    import httpx
    # 候选测试 URL（按可靠性排序）：
    # - example.com: IANA 维护，全球可达，几乎不会宕机
    # - www.baidu.com: 国内可达性最好，国外也能访问
    # - www.gstatic.com: Google 静态资源 CDN，国内偶发不可达但国外稳定
    test_urls = [
        "http://example.com/",
        "http://www.baidu.com/",
        "http://www.gstatic.com/generate_204",
    ]
    for url in test_urls:
        try:
            async with httpx.AsyncClient(proxy=proxy_url, timeout=HTTP_PROXY_CHECK_TIMEOUT) as c:
                resp = await c.get(url, follow_redirects=True)
                # 任何 HTTP 响应（包括 4xx/5xx）都说明代理能转发流量
                if resp.status_code > 0:
                    return True
        except Exception:
            continue
    return False


async def _ensure_browser():
    """★ #5: Playwright 缺失时抛出可读异常（带安装指引），而非 ImportError traceback。

    返回 None 表示浏览器不可用；调用方应捕获此异常并降级到无浏览器模式。
    """
    global _browser, _page, _injection_fingerprint
    # 检查现有实例是否还可用（Phase 0 爬虫关闭浏览器后 _page 对象已 closed 但不是 None）
    if _page is not None:
        try:
            await _page.title()  # 快速检测 page 是否还活着
            await _refresh_session_injection_if_needed(_page)
        except Exception:
            # page/browser 已关闭，需要重新创建
            _page = None
            _browser = None

    if _page is None:
        # ★ #5: 优雅降级 — Playwright 未安装时给出可读错误
        try:
            from playwright.async_api import async_playwright
        except ImportError as e:
            msg = (
                "Playwright 未安装，浏览器自动化功能不可用。\n"
                "请执行以下命令安装：\n"
                "  pip install playwright\n"
                "  python -m playwright install chromium\n"
                "（安装后重启服务即可恢复浏览器功能）"
            )
            print(f"[browser] ❌ {msg}")
            raise RuntimeError(msg) from e

        # ★ #5: chromium 内核未安装时（playwright 已装但浏览器二进制缺失）也要可读降级
        try:
            pw = await async_playwright().start()
        except Exception as e:
            err_lower = str(e).lower()
            if "executable" in err_lower or "browser" in err_lower or "chromium" in err_lower:
                msg = (
                    "Playwright 浏览器内核未安装，浏览器自动化功能不可用。\n"
                    "请执行以下命令安装 chromium 内核：\n"
                    "  python -m playwright install chromium\n"
                    "（安装后重启服务即可恢复浏览器功能）"
                )
                print(f"[browser] ❌ {msg}")
                raise RuntimeError(msg) from e
            raise

        headless = os.getenv("BROWSER_HEADLESS", "false").lower() == "true"
        proxy_url = os.getenv("BROWSER_PROXY", "http://127.0.0.1:18080")

        # 检测代理是否可用，不可用则直连
        launch_args = {"headless": headless, "args": ["--ignore-certificate-errors"]}
        use_proxy = await _check_proxy(proxy_url)
        if use_proxy:
            launch_args["proxy"] = {"server": proxy_url}
            print(f"[browser] 使用代理: {proxy_url}")
        else:
            print(f"[browser] 代理不可用，直连模式（流量抓包功能不可用）")

        # ★ 反检测：使用真实 UA，隐藏 Headless/Playwright 指纹
        # 解决 Akamai Bot Manager / Cloudflare / Incapsula 等 WAF 拦截问题
        _REAL_UA = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        launch_args["args"].extend([
            f"--user-agent={_REAL_UA}",
            "--disable-blink-features=AutomationControlled",  # 隐藏 navigator.webdriver
            "--disable-web-security",  # 禁用同源策略，解决 CDN 跨域资源 403/CORS 问题
            "--disable-features=IsolateOrigins,site-per-process",  # 配合 disable-web-security
        ])

        try:
            _browser = await pw.chromium.launch(**launch_args)
        except Exception as e:
            err_lower = str(e).lower()
            if "executable" in err_lower or "chromium" in err_lower or "browser" in err_lower:
                msg = (
                    "Playwright chromium 内核启动失败，浏览器自动化功能不可用。\n"
                    f"原始错误: {e}\n"
                    "请执行以下命令重新安装 chromium 内核：\n"
                    "  python -m playwright install chromium\n"
                )
                print(f"[browser] ❌ {msg}")
                raise RuntimeError(msg) from e
            raise
        ctx = await _browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800},
            user_agent=_REAL_UA,
        )

        # ★ 注入 stealth 脚本：覆盖 navigator.webdriver、plugins、languages 等
        await ctx.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en']});
            window.chrome = {runtime: {}};
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) =>
                parameters.name === 'notifications'
                    ? Promise.resolve({state: Notification.permission})
                    : originalQuery(parameters);
        """)

        # ★ 自动注入用户预设的会话凭证（环境变量由 session.py 设置）
        # PENTEST_INJECT_COOKIES = "name1=val1; name2=val2"
        # PENTEST_INJECT_AUTH    = "Bearer eyJxxx"
        # PENTEST_INJECT_HEADERS = '{"X-Sign":"xxx","X-Timestamp":"123",...}'   (JSON dict)
        # PENTEST_TARGET_URL     = "https://example.com"
        try:
            import json as _json
            inject_cookies = os.getenv("PENTEST_INJECT_COOKIES", "")
            inject_auth = os.getenv("PENTEST_INJECT_AUTH", "")
            inject_headers_json = os.getenv("PENTEST_INJECT_HEADERS", "")
            target_for_inject = os.getenv("PENTEST_TARGET_URL", "")

            # Cookie
            if inject_cookies and target_for_inject:
                from core.intent import parse_cookie_string
                ck_list = parse_cookie_string(inject_cookies, target_for_inject)
                if ck_list:
                    await ctx.add_cookies(ck_list)
                    print(f"[browser] 🍪 已注入 {len(ck_list)} 个 Cookie")

            # 完整 header dict（自定义 sign/key/timestamp 等）
            headers_to_set: dict[str, str] = {}
            if inject_headers_json:
                try:
                    headers_dict = _json.loads(inject_headers_json)
                    # 过滤掉不应注入的 header
                    SKIP = {"content-type", "content-length", "accept", "referer", "origin", "cookie"}
                    for k, v in headers_dict.items():
                        if k.lower() not in SKIP:
                            headers_to_set[k] = v
                except Exception as je:
                    print(f"[browser] ⚠️ INJECT_HEADERS JSON 解析失败: {je}")

            # Authorization（如果在 extra_headers 之外单独提供）
            if inject_auth and "Authorization" not in headers_to_set:
                headers_to_set["Authorization"] = inject_auth

            if headers_to_set:
                await ctx.set_extra_http_headers(headers_to_set)
                print(f"[browser] 📦 已注入 {len(headers_to_set)} 个自定义 Header: {', '.join(list(headers_to_set.keys())[:5])}{'...' if len(headers_to_set) > 5 else ''}")

            # ★ localStorage 注入（SPA/JWT 场景：token 存 localStorage 而非 Cookie）
            #   PENTEST_INJECT_LOCAL_STORAGE = '{"token":"eyJ...","refresh_token":"abc"}'
            #   通过 add_init_script 在每个页面的 JS 执行前注入，确保 SPA 读取时已存在
            inject_local_storage_json = os.getenv("PENTEST_INJECT_LOCAL_STORAGE", "")
            if inject_local_storage_json:
                try:
                    ls_items = _json.loads(inject_local_storage_json)
                    if isinstance(ls_items, dict) and ls_items:
                        ls_json_escaped = _json.dumps(ls_items, ensure_ascii=False)
                        await ctx.add_init_script(f"""
                            (() => {{
                                try {{
                                    const items = JSON.parse({ls_json_escaped!r});
                                    for (const [k, v] of Object.entries(items)) {{
                                        localStorage.setItem(k, v);
                                    }}
                                }} catch(e) {{}}
                            }})();
                        """)
                        print(f"[browser] 🔑 已注入 {len(ls_items)} 个 localStorage 项: {', '.join(list(ls_items.keys())[:5])}")
                except Exception as lse:
                    print(f"[browser] ⚠️ INJECT_LOCAL_STORAGE 解析失败: {lse}")

            # ★ ★ Vue/Vuex Store 拦截注入（解决 SPA 前端路由守卫问题）
            #   问题：set_extra_http_headers 让浏览器 HTTP 请求带上了认证头，
            #   但 SPA 前端路由守卫不读 HTTP 请求头，它从 Vuex store 读取 token。
            #   没走正常登录流程时 Vuex store 里没 token → 路由守卫判定未登录 → 跳 error/login 页。
            #
            #   方案：拦截 Vue.prototype.$store 的初始化，当 Vuex store 创建时，
            #   自动将 extra_headers 中的 JWT token 写入 store.state.user.token。
            #   这比拦截 XHR/fetch 更安全——不改变请求行为，只改变前端状态判断。
            #
            #   注意：不拦截 XHR/fetch 是因为：
            #   1. set_extra_http_headers 已经处理了请求头注入
            #   2. 拦截 XHR/fetch 可能触发 CORS 预检失败、反爬检测、请求重复注入
            #   3. 拦截器代码 bug 会导致整个页面请求挂掉
            if headers_to_set:
                # 提取 JWT 值用于注入 Vuex store
                jwt_token = ""
                for _hk, _hv in headers_to_set.items():
                    if isinstance(_hv, str) and _hv.startswith("eyJ") and len(_hv) > 20:
                        jwt_token = _hv
                        break
                if jwt_token:
                    await ctx.add_init_script(f"""
                        (() => {{
                            const TOKEN = {jwt_token!r};

                            // ★ 方式 1：拦截 Vue 实例创建，在 $store 就绪后注入 token
                            let _origVue = window.Vue;
                            if (_origVue) {{
                                const _origInit = _origVue.prototype._init;
                                if (_origInit) {{
                                    _origVue.prototype._init = function(options) {{
                                        _origInit.call(this, options);
                                        // Vue 实例创建后，store 已初始化
                                        _tryInjectStore(this);
                                    }};
                                }}
                            }}

                            function _tryInjectStore(vm) {{
                                if (!vm || !vm.$store) return;
                                const state = vm.$store.state;
                                // 尝试常见的 user 模块路径
                                const targets = [
                                    state.user,
                                    state.auth,
                                    state.login,
                                    state.account,
                                ];
                                for (const mod of targets) {{
                                    if (mod && typeof mod === 'object') {{
                                        if (!mod.token) {{
                                            try {{
                                                vm.$store.commit('SET_TOKEN', TOKEN);
                                            }} catch(e) {{}}
                                            // 直接修改 state（某些 Vuex 配置下 commit 不生效）
                                            try {{ mod.token = TOKEN; }} catch(e) {{}}
                                        }}
                                    }}
                                }}
                                // 也尝试全局 state
                                if (!state.token) {{
                                    try {{ state.token = TOKEN; }} catch(e) {{}}
                                }}
                            }}

                            // ★ 方式 2：延迟执行（Vue 可能还没加载）
                            let _attempts = 0;
                            const _interval = setInterval(() => {{
                                _attempts++;
                                if (_attempts > 30) {{ clearInterval(_interval); return; }}
                                // 查找页面上已挂载的 Vue 实例
                                const el = document.querySelector('[data-v-app]') || document.querySelector('#app');
                                if (el && el.__vue__) {{
                                    _tryInjectStore(el.__vue__);
                                    clearInterval(_interval);
                                }}
                            }}, 100);
                        }})();
                    """)
                    print(f"[browser] 🏪 已注入 Vuex Store 拦截器，自动写入 token 到 user/auth 模块")
        except Exception as e:
            print(f"[browser] ⚠️ 注入会话凭证失败: {e}")

        _page = await ctx.new_page()
        _injection_fingerprint = _current_injection_fingerprint()
    return _page


@mcp.tool()
async def browser_goto(url: str) -> str:
    """用浏览器访问指定 URL，返回页面标题和状态码。"""
    page = await _ensure_browser()
    resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
    title = await page.title()
    status = resp.status if resp else "unknown"
    return f"已访问 {url}\n标题: {title}\n状态码: {status}\nURL: {page.url}"


@mcp.tool()
async def browser_hover(selector: str) -> str:
    """悬停（hover）到页面元素上，触发 hover 才出现的子菜单、操作按钮、下拉面板等。

    典型场景：
    - 表格行 hover 后才出现的「编辑/删除」按钮
    - 导航菜单 hover 后展开的子菜单
    - tooltip / popover 触发

    hover 后建议紧接 browser_get_content() 查看新出现的元素，再 browser_click 操作。
    """
    page = await _ensure_browser()

    try:
        await page.hover(selector, timeout=5000)
        # 等待 hover 效果渲染（子菜单展开、按钮出现等）
        await page.wait_for_timeout(800)
        return f"已 hover 到 '{selector}'，请用 browser_get_content() 查看新出现的元素。当前 URL: {page.url}"
    except Exception:
        pass

    # 回退：尝试文本匹配
    text = ""
    if selector.startswith("text="):
        text = selector[5:].strip().strip("'\"")
    elif ":has-text(" in selector:
        import re as _re
        m = _re.search(r':has-text\(["\']?([^"\')\]]+)', selector)
        if m:
            text = m.group(1)

    if text:
        try:
            alt_sel = f'text="{text}"'
            await page.hover(alt_sel, timeout=3000)
            await page.wait_for_timeout(800)
            return f"已 hover 到 '{alt_sel}'（文本回退），请用 browser_get_content() 查看新出现的元素。"
        except Exception:
            pass

    return (
        f"❌ hover 失败：selector '{selector}' 未找到元素。"
        f"{'（提取文本: ' + text + '）' if text else ''}\n"
        f"建议：用 browser_get_content 确认元素是否存在。"
    )


@mcp.tool()
async def browser_click(selector: str) -> str:
    """点击页面元素。selector 为 CSS 选择器或文本内容（如 'text=登录'）。
    
    内置智能回退：原始 selector 失败时自动尝试文本匹配和 XPath 回退，
    全部失败返回友好错误信息（不抛异常），方便 Agent 决策跳过。
    """
    import re as _re
    page = await _ensure_browser()

    # ---- 策略 1：直接用给定 selector ----
    try:
        await page.click(selector, timeout=5000)
        await page.wait_for_load_state("domcontentloaded")
        return f"已点击 {selector}，当前 URL: {page.url}"
    except Exception:
        pass

    # ---- 提取文本用于回退 ----
    text = ""
    if selector.startswith("text="):
        text = selector[5:].strip().strip("'\"")
    elif ":has-text(" in selector:
        m = _re.search(r':has-text\(["\']?([^"\')\]]+)', selector)
        if m:
            text = m.group(1)
    elif "text" not in selector and "//" not in selector:
        # 纯 CSS selector，尝试从页面获取元素文本作为回退
        try:
            el = await page.query_selector(selector)
            if el:
                text = (await el.inner_text()).strip()[:50]
        except Exception as e:
            print(f"[browser] ⚠️ 获取元素文本失败: {e}")

    # ---- 策略 2：用 text= 精确文本匹配 ----
    if text:
        try:
            alt_sel = f'text="{text}"'
            await page.click(alt_sel, timeout=3000)
            await page.wait_for_load_state("domcontentloaded")
            return f"已点击 {alt_sel}（原 selector '{selector}' 失败，文本回退成功），当前 URL: {page.url}"
        except Exception:
            pass

    # ---- 策略 3：用 XPath 模糊文本匹配（button/a/span/div） ----
    if text:
        try:
            xpath_sel = (
                f"//button[contains(.,'{text}')] | "
                f"//a[contains(.,'{text}')] | "
                f"//span[contains(.,'{text}')] | "
                f"//div[contains(.,'{text}')]"
            )
            await page.click(xpath_sel, timeout=3000)
            await page.wait_for_load_state("domcontentloaded")
            return f"已点击（XPath 回退: '{text}'），当前 URL: {page.url}"
        except Exception:
            pass

    # ---- 策略 4：用 role 属性匹配（适用于 ARIA 按钮） ----
    if text:
        try:
            role_sel = f'role=button[name="{text}"]'
            await page.click(role_sel, timeout=2000)
            await page.wait_for_load_state("domcontentloaded")
            return f"已点击（ARIA role 回退: '{text}'），当前 URL: {page.url}"
        except Exception:
            pass

    # ---- 全部失败：返回友好错误信息，不抛异常 ----
    return (
        f"❌ 点击失败：selector '{selector}' 未找到可点击元素。"
        f"{'（提取文本: ' + text + '）' if text else ''}\n"
        f"建议：1) 用 browser_get_content 查看当前页面可点击元素；"
        f"2) 如果该操作已失败 2 次，直接跳过打 ✅ 进入下一个。"
    )


@mcp.tool()
async def browser_fill(selector: str, value: str) -> str:
    """在输入框中填写内容。"""
    page = await _ensure_browser()
    await page.fill(selector, value, timeout=10000)
    return f"已在 {selector} 填入 '{value[:50]}'"


@mcp.tool()
async def browser_get_content() -> str:
    """获取当前页面的关键信息（精简模式）：URL、标题、表单、链接、按钮、输入框、核心文本。

    `inputs` 字段会列出所有可见输入框（含 SPA 框架如 Element UI 中无 name 属性的输入框），
    每项附带 selector，可直接传给 `browser_fill` 使用，无需再用 JS 探测。
    """
    page = await _ensure_browser()

    content = await page.evaluate("""() => {
        const result = {url: location.href, title: document.title};
        const host = location.hostname;

        // 生成稳定的 CSS selector（id > placeholder > type+nth）
        const selectorOf = (el) => {
            if (!el) return '';
            if (el.id) return '#' + CSS.escape(el.id);
            // 优先用 placeholder 定位（Element UI/AntD/Vue 等很常见）
            if (el.placeholder) {
                return `${el.tagName.toLowerCase()}[placeholder="${el.placeholder.replace(/"/g, '\\\\"')}"]`;
            }
            // 用 type + nth-of-type
            const type = el.type || '';
            if (type === 'password') return 'input[type="password"]';
            const tag = el.tagName.toLowerCase();
            const sel = type ? `${tag}[type="${type}"]` : tag;
            const all = Array.from(document.querySelectorAll(sel));
            const idx = all.indexOf(el);
            if (idx === 0) return sel;
            if (idx > 0) return `${sel}:nth-of-type(${idx + 1})`;
            return sel;
        };

        // 表单（精简：只保留 name + type）
        result.forms = Array.from(document.forms).map(f => ({
            action: f.action, method: f.method,
            inputs: Array.from(f.elements)
                .filter(e => e.name)
                .map(e => e.name + ':' + (e.type || e.tagName.toLowerCase()))
        }));

        // ★ 所有可见输入框（含 SPA 框架中无 name 属性的）—— 子 Agent 可直接 browser_fill
        const isVisible = (el) => {
            const r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0;
        };
        result.inputs = Array.from(document.querySelectorAll(
            'input:not([type="hidden"]), textarea, select'
        ))
            .filter(isVisible)
            .slice(0, 30)
            .map(e => {
                const item = {
                    type: e.type || e.tagName.toLowerCase(),
                    selector: selectorOf(e),
                };
                if (e.placeholder) item.placeholder = e.placeholder;
                if (e.name) item.name = e.name;
                if (e.value && e.type !== 'password') item.value = e.value.slice(0, 30);
                return item;
            });

        // 链接（去重，优先同域，限 20 条）
        const allLinks = [...new Set(Array.from(document.querySelectorAll('a[href]'))
            .map(a => a.href).filter(h => h.startsWith('http')))];
        const sameHost = allLinks.filter(h => new URL(h).hostname === host);
        const otherHost = allLinks.filter(h => new URL(h).hostname !== host);
        result.links = sameHost.slice(0, 15).concat(otherHost.slice(0, 5));
        if (allLinks.length > 20) result.links_total = allLinks.length;

        // 按钮（增强版：扩大选择器范围，提取 aria-label/title，限 30 个）
        const btnSelector = 'button, input[type=submit], [role=button], [role=menuitem], [role=tab], [role=columnheader], a.btn, a.el-button, [class*=btn]:not(input):not(select)';
        const rawBtns = Array.from(document.querySelectorAll(btnSelector));
        // 额外收集有 onclick 或 cursor:pointer 的 div/span（自定义可点击元素）
        const clickableDivs = Array.from(document.querySelectorAll('div[onclick], span[onclick]'))
            .filter(el => !rawBtns.includes(el));
        // 额外收集可排序的表头（th[class*=sort] / th[class*=order] / ant-table / el-table 排序列）
        const sortableHeaders = Array.from(document.querySelectorAll(
            'th[class*=sort], th[class*=order], th[aria-sort], .ant-table-column-sorter, .ant-table-column-has-sorters, .el-table .sort-caret, [class*=sortable]'
        )).filter(el => !rawBtns.includes(el) && !clickableDivs.includes(el));
        const allBtns = rawBtns.concat(clickableDivs).concat(sortableHeaders);
        result.buttons = allBtns
            .filter(b => {
                const r = b.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
            })
            .slice(0, 30)
            .map(b => {
                const text = b.textContent?.trim()?.replace(/\\s+/g, ' ')?.slice(0, 30) || '';
                const ariaLabel = b.getAttribute('aria-label') || '';
                const title = b.getAttribute('title') || '';
                // 图标按钮：自身无文本但有 aria-label 或 title
                const label = text || ariaLabel || title;
                if (!label) return null;
                const item = {text: label};
                // 附带 selector 方便 LLM 直接使用
                if (b.id) item.selector = '#' + CSS.escape(b.id);
                else if (ariaLabel) item.selector = `[aria-label="${ariaLabel.replace(/"/g, '\\\\"')}"]`;
                else if (title) item.selector = `[title="${title.replace(/"/g, '\\\\"')}"]`;
                else if (text) item.selector = `text=${text.slice(0, 20)}`;
                // 标注来源（帮助 LLM 理解元素类型）
                if (ariaLabel && !text) item.note = 'icon-btn';
                if (sortableHeaders.includes(b) || b.tagName === 'TH' || b.getAttribute('aria-sort')) item.note = 'sortable-column';
                return item;
            })
            .filter(Boolean);

        // 页面核心文本（1000 字符）
        result.text = document.body?.innerText?.slice(0, 1000) || '';

        return result;
    }""")

    import json
    return json.dumps(content, ensure_ascii=False, indent=2)


@mcp.tool()
async def browser_screenshot(name: str = "screenshot") -> str:
    """截取当前页面截图，保存到 data/reports/ 目录。"""
    page = await _ensure_browser()
    path = Path("data/reports") / f"{name}.png"
    path.parent.mkdir(parents=True, exist_ok=True)
    await page.screenshot(path=str(path), full_page=True)
    return f"截图已保存到 {path}"


@mcp.tool()
async def browser_get_accessibility_tree(max_depth: int = 5) -> str:
    """获取当前页面的无障碍树（Accessibility Tree），发现 DOM 提取可能遗漏的交互元素。

    当 browser_get_content 返回的按钮/链接很少时使用此工具作为补充。
    返回所有可交互节点（button/link/textbox/menuitem/tab 等）及其名称和角色。
    """
    page = await _ensure_browser()
    import json

    snapshot = await page.accessibility.snapshot()
    if not snapshot:
        return json.dumps({"error": "无法获取无障碍树，页面可能未完全加载"}, ensure_ascii=False)

    # 只保留可交互角色的节点，精简输出
    interactive_roles = {
        'button', 'link', 'textbox', 'menuitem', 'tab', 'checkbox',
        'radio', 'combobox', 'switch', 'option', 'menuitemcheckbox',
        'menuitemradio', 'searchbox', 'spinbutton', 'slider', 'treeitem'
    }

    def _filter_tree(node, depth=0):
        """递归过滤，只保留可交互节点及其路径"""
        if depth > max_depth:
            return None
        role = node.get('role', '')
        name = node.get('name', '')
        children = node.get('children', [])

        # 当前节点是可交互的
        is_interactive = role.lower() in interactive_roles

        # 递归处理子节点
        filtered_children = []
        for child in children:
            result = _filter_tree(child, depth + 1)
            if result:
                filtered_children.append(result)

        # 如果当前节点可交互，或者有可交互的子节点，则保留
        if is_interactive:
            item = {'role': role}
            if name:
                item['name'] = name[:50]
            if filtered_children:
                item['children'] = filtered_children
            return item
        elif filtered_children:
            # 容器节点：如果有名称则保留作为上下文
            if name and role in ('navigation', 'menu', 'toolbar', 'tablist', 'menubar', 'group', 'region'):
                return {'role': role, 'name': name[:30], 'children': filtered_children}
            # 否则直接展平子节点
            if len(filtered_children) == 1:
                return filtered_children[0]
            return {'role': role or 'group', 'children': filtered_children}
        return None

    filtered = _filter_tree(snapshot)
    if not filtered:
        return json.dumps({"message": "未发现可交互元素"}, ensure_ascii=False)

    # 控制输出大小（最多 4000 字符）
    output = json.dumps(filtered, ensure_ascii=False, indent=1)
    if len(output) > 4000:
        # 截断并提示
        output = output[:3900] + '\n... (已截断，共发现更多元素)'

    return output


@mcp.tool()
async def browser_get_cookies() -> str:
    """获取当前浏览器的所有 Cookie（精简模式：name + domain + 值前20字符）。"""
    page = await _ensure_browser()
    ctx = page.context
    cookies = await ctx.cookies()
    import json
    # RTK Smart Filtering: 只保留安全测试需要的字段
    compact = []
    for c in cookies:
        item = {"name": c["name"], "domain": c.get("domain", ""), "value": c["value"][:20]}
        if c.get("httpOnly"):
            item["httpOnly"] = True
        if c.get("secure"):
            item["secure"] = True
        if "sameSite" in c and c["sameSite"] != "None":
            item["sameSite"] = c["sameSite"]
        compact.append(item)
    return json.dumps(compact, ensure_ascii=False)


@mcp.tool()
async def browser_set_cookie(name: str, value: str, domain: str, path: str = "/") -> str:
    """设置 Cookie（用于切换用户测试越权）。"""
    page = await _ensure_browser()
    ctx = page.context
    await ctx.add_cookies([{"name": name, "value": value, "domain": domain, "path": path}])
    return f"Cookie {name}={value[:30]}... 已设置"


@mcp.tool()
async def browser_evaluate(js_code: str) -> str:
    """在页面上下文中执行 JavaScript，返回结果。

    注意：如果 JS 代码执行的是 .click() 等无返回值操作，结果为 null 是正常的，表示操作已执行成功。
    不要因为返回 null 就重复执行同样的代码！请用 proxy_get_traffic 查看操作是否触发了 API 请求。
    """
    page = await _ensure_browser()
    result = await page.evaluate(js_code)
    import json
    if result is None:
        # .click() / .focus() 等 DOM 操作无返回值，返回明确的成功提示
        return ("✅ JS 已执行成功（返回 null 表示无返回值，属于正常行为）。\n"
                "如果你执行的是点击/输入操作，请用 proxy_get_traffic 查看是否触发了新的 API 请求，\n"
                "或用 browser_get_content 查看页面内容是否发生变化。不要重复执行同样的操作。")
    return json.dumps(result, ensure_ascii=False, default=str)[:5000]


@mcp.tool()
async def js_extract_apis() -> str:
    """列出当前页面加载的所有资源文件清单（JS/TS/JSON/Map/配置等），供你根据经验判断哪些值得深度分析。

    返回完整资源列表后，你需要根据渗透测试经验判断：
    - .js/.ts/.tsx — 业务逻辑JS选中分析，框架库(vue/react/echarts)跳过
    - .map — Source Map泄露，高优先级！能还原完整源码
    - .json — 可能是API schema、swagger定义、配置文件
    - .env/.config/.yaml/.xml — 配置泄露
    - .wasm — WebAssembly，可能藏关键逻辑
    - .css/.png/.woff/.svg — 纯样式/资源，通常跳过

    选好后调用 `js_analyze_selected` 传入选中的 URL 列表进行深度分析。
    """
    import httpx
    from urllib.parse import urlparse

    page = await _ensure_browser()

    # 收集页面加载的所有资源 URL（通过 Performance API 获取最全的列表）
    all_resources = await page.evaluate("""() => {
        const resources = new Map();

        // 1. script 标签
        document.querySelectorAll('script[src]').forEach(s => {
            resources.set(s.src, 'script');
        });

        // 2. link 标签（stylesheet, preload 等）
        document.querySelectorAll('link[href]').forEach(l => {
            const href = l.href;
            if (href && href.startsWith('http')) {
                resources.set(href, l.rel || 'link');
            }
        });

        // 3. Performance API — 最全面，包含动态加载的资源
        if (window.performance) {
            performance.getEntriesByType('resource').forEach(r => {
                if (r.name.startsWith('http') && !resources.has(r.name)) {
                    resources.set(r.name, r.initiatorType || 'other');
                }
            });
        }

        // 转为数组
        return [...resources.entries()].map(([url, type]) => ({url, type}));
    }""")

    if not all_resources:
        return "未发现任何加载资源"

    # 分类：值得关注的 vs 纯资源
    # 值得关注的扩展名（LLM可能想分析的）
    interesting_exts = {'.js', '.mjs', '.ts', '.tsx', '.jsx', '.map', '.json',
                       '.xml', '.yaml', '.yml', '.env', '.config', '.wasm',
                       '.graphql', '.gql', '.proto'}
    # 纯资源扩展名（通常跳过）
    static_exts = {'.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                   '.woff', '.woff2', '.ttf', '.eot', '.webp', '.avif', '.mp4', '.webm'}

    def _get_ext(url):
        path = urlparse(url).path
        name = path.split('/')[-1]
        if '.' in name:
            return '.' + name.rsplit('.', 1)[-1].lower()
        return ''

    interesting = []
    static_count = {}

    for res in all_resources:
        ext = _get_ext(res['url'])
        if ext in interesting_exts or ext == '' or ext not in static_exts:
            interesting.append(res)
        else:
            static_count[ext] = static_count.get(ext, 0) + 1

    # 用 HEAD 请求获取有意思的文件的大小
    file_info = []
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for res in interesting:
            name = res['url'].split('/')[-1].split('?')[0]
            ext = _get_ext(res['url'])
            try:
                resp = await client.head(res['url'])
                size = int(resp.headers.get('content-length', 0))
                content_type = resp.headers.get('content-type', '')
                file_info.append({
                    "url": res['url'], "name": name, "ext": ext,
                    "size": size, "type": res['type'], "content_type": content_type
                })
            except Exception:
                file_info.append({
                    "url": res['url'], "name": name, "ext": ext,
                    "size": -1, "type": res['type'], "content_type": ""
                })

    # 按扩展名分组，组内按大小降序
    from collections import defaultdict
    groups = defaultdict(list)
    for f in file_info:
        groups[f['ext'] or '(无扩展名)'].append(f)
    for ext in groups:
        groups[ext].sort(key=lambda x: -x['size'])

    # 输出
    total = len(all_resources)
    lines = [
        f"## 页面加载资源清单（共 {total} 个，{len(file_info)} 个值得关注）\n",
        "请根据你的渗透测试经验判断哪些文件需要深度分析，选好后调用 `js_analyze_selected` 传入 URL。\n",
    ]

    # 跳过的静态资源汇总
    if static_count:
        skipped = ', '.join(f"{ext}({cnt})" for ext, cnt in sorted(static_count.items(), key=lambda x: -x[1]))
        lines.append(f"**已跳过的纯资源**: {skipped}\n")

    # 按扩展名分组显示
    # 优先显示高价值类型
    priority_order = ['.map', '.json', '.env', '.config', '.yaml', '.yml', '.xml',
                      '.ts', '.tsx', '.jsx', '.wasm', '.graphql', '.gql', '.proto',
                      '.js', '.mjs']
    shown_exts = set()

    for ext in priority_order:
        if ext in groups:
            _render_group(lines, ext, groups[ext])
            shown_exts.add(ext)

    # 剩余类型
    for ext in sorted(groups.keys()):
        if ext not in shown_exts:
            _render_group(lines, ext, groups[ext])

    lines.append(f"\n**分析建议**: "
                 f".map 文件最高优先级（Source Map泄露）；"
                 f"业务 .js 次之（app/index/main/chunk + hash 是业务JS，vue/react/echarts 是框架）；"
                 f".json 可能含 API schema/swagger；"
                 f".ts/.tsx 说明源码可能泄露。")

    return "\n".join(lines)


def _render_group(lines: list, ext: str, files: list):
    """渲染一个扩展名分组的文件列表。"""
    lines.append(f"\n### {ext} 文件（{len(files)} 个）")
    lines.append("| # | 文件名 | 大小 | Content-Type | 完整 URL |")
    lines.append("|---|--------|------|-------------|----------|")
    for i, f in enumerate(files, 1):
        size_str = f"{f['size']//1024}KB" if f['size'] >= 0 else "未知"
        ct = f['content_type'].split(';')[0] if f['content_type'] else "-"
        lines.append(f"| {i} | `{f['name']}` | {size_str} | {ct} | {f['url']} |")


@mcp.tool()
async def js_analyze_selected(js_urls_csv: str) -> str:
    """对你选定的 JS 文件进行深度分析，提取 API 端点、密钥、WebSocket、baseURL 配置和 Source Map。

    参数:
        js_urls_csv: 要分析的 JS 文件 URL，用逗号分隔。例如:
                     "https://example.com/js/app.abc123.js,https://example.com/js/chunk-main.js"
    """
    import re
    import httpx

    page = await _ensure_browser()

    # 解析 URL 列表
    js_urls = [u.strip() for u in js_urls_csv.split(',') if u.strip()]
    if not js_urls:
        return "错误：未提供 JS 文件 URL，请传入逗号分隔的 URL 列表"

    # 正则模式
    api_pattern = re.compile(r'''["'](/(?:api|v[0-9]|rest|service|graphql|ws|internal|admin|auth|user|public)[^\s"']{2,}?)["']''')
    url_pattern = re.compile(r'https?://[^\s"\'<>]{5,}')
    secret_pattern = re.compile(r'''(?:api[_-]?key|secret[_-]?key|token|password|credential|appkey|app_secret)\s*[=:]\s*["']([^"']{8,})["']''', re.I)
    ws_pattern = re.compile(r'wss?://[^\s"\']+')
    path_pattern = re.compile(r'''["'](/[a-zA-Z][a-zA-Z0-9_/\-]{3,}?)["']''')
    base_url_pattern = re.compile(r'''(?:baseURL|BASE_URL|API_URL|apiPrefix|apiBase|base_url|API_BASE)\s*[=:]\s*["']([^"']+)["']''')
    sourcemap_pattern = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')

    # ★ 前端路由提取：匹配 Vue/React/Angular 路由定义中的相对路径
    # path: "monitor/battery", path: 'alarm/center', path: "schedule/strategy"
    route_path_pattern = re.compile(r'''path\s*:\s*["']([a-zA-Z][a-zA-Z0-9_/\-:.]*?)["']''')
    # component: () => import("xxx.vue") — 提取组件路径
    route_component_pattern = re.compile(r'''import\(\s*["']([^"']*?\.vue)["']\s*\)''')

    # 纯 CRUD 操作路径，不应作为独立 API（通常是路径片段不是完整端点）
    _generic_segments = {'/list', '/detail', '/info', '/create', '/add', '/save',
                         '/update', '/edit', '/modify', '/delete', '/remove',
                         '/export', '/import', '/batch', '/upload', '/download',
                         '/search', '/query', '/get', '/post', '/put', '/index'}
    # 纯框架/通用路由名，不是业务路由
    _generic_routes = {'', '/', '*', '**', '404', 'index', 'home', 'layout', 'redirect'}

    static_exts = {'.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff', '.ttf', '.map', '.gif', '.webp'}

    all_apis = set()
    all_urls = set()
    all_secrets = []
    all_ws = set()
    all_routes = []       # ★ 前端路由列表
    base_urls_found = []
    sourcemaps_found = []
    js_file_sizes = {}
    failed = []
    key_js_contents = {}  # ★ 关键业务 JS 的原始内容缓存（js_name → content）

    # ★ 关键业务 JS 文件名识别正则（入口/主业务 bundle）
    _KEY_JS_RE = __import__('re').compile(
        r'(?:^|/)(?:index|main|app|bundle)(?:[-.][\w]+)?\.(?:js|mjs)$',
        __import__('re').IGNORECASE,
    )

    # 批量下载并分析
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        for js_url in js_urls:
            js_name = js_url.split('/')[-1].split('?')[0]
            try:
                resp = await client.get(js_url)
                content = resp.text[:MAX_JS_FILE_SIZE]  # 单文件最大尺寸限制
                js_file_sizes[js_name] = len(resp.text)

                # ★ 缓存关键业务 JS 内容（供末尾提取代码片段给 LLM 分析）
                if _KEY_JS_RE.search(js_url.split('?')[0]) and len(content) > 50000:
                    key_js_contents[js_name] = content

                # API 路径
                for m in api_pattern.findall(content):
                    if not any(m.endswith(ext) for ext in static_exts):
                        all_apis.add(m)

                # 通用路径
                for m in path_pattern.findall(content):
                    if not any(m.endswith(ext) for ext in static_exts):
                        if len(m) > 4 and '/' in m[1:]:
                            # 排除纯 CRUD 操作路径（如 /list, /create）
                            if m.lower() not in _generic_segments:
                                all_apis.add(m)

                # 完整 URL
                for m in url_pattern.findall(content):
                    clean = m.rstrip('.,;)\'"')
                    if not any(clean.endswith(ext) for ext in static_exts):
                        all_urls.add(clean)

                # 密钥
                for m in secret_pattern.findall(content):
                    all_secrets.append({"value": m[:50], "file": js_name})

                # WebSocket
                for m in ws_pattern.findall(content):
                    all_ws.add(m.rstrip('.,;)\'"'))

                # baseURL 配置
                for m in base_url_pattern.findall(content):
                    base_urls_found.append({"url": m, "file": js_name})

                # Source Map
                for m in sourcemap_pattern.findall(content):
                    sourcemaps_found.append({"map": m, "file": js_name})

                # ★ 前端路由提取
                for m in route_path_pattern.findall(content):
                    route = m.strip().strip("/")
                    if route and route.lower() not in _generic_routes and len(route) > 1:
                        # 跳过纯参数路由（如 ":id"）和重定向别名
                        if not route.startswith(":") and not route.startswith("*"):
                            all_routes.append({"path": route, "file": js_name})

                # 组件路径提取（从 import() 中拿 .vue 文件路径）
                for m in route_component_pattern.findall(content):
                    # /src/views/admin/monitor/BatteryMonitor.vue → 提取有意义的路径
                    vue_path = m.strip()
                    if vue_path:
                        all_routes.append({"component": vue_path, "file": js_name})

            except Exception as e:
                failed.append(f"{js_name}: {e}")
                continue

    # 检查 Source Map 可访问性
    sourcemap_accessible = []
    if sourcemaps_found:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            for sm in sourcemaps_found[:5]:
                try:
                    map_url = sm["map"]
                    if not map_url.startswith("http"):
                        base = js_urls[0].rsplit('/', 1)[0]
                        map_url = f"{base}/{map_url}"
                    r = await client.head(map_url)
                    if r.status_code == 200:
                        sourcemap_accessible.append(map_url)
                except Exception:
                    pass

    # 输出
    lines = [f"## JS 深度分析结果（分析了 {len(js_file_sizes)}/{len(js_urls)} 个文件）\n"]

    # 已分析文件
    lines.append("### 已分析文件")
    for name, size in sorted(js_file_sizes.items(), key=lambda x: -x[1]):
        lines.append(f"  {name} ({size//1024}KB)")

    if failed:
        lines.append(f"\n### ❌ 下载失败（{len(failed)} 个）")
        for f in failed:
            lines.append(f"  {f}")

    # baseURL 配置
    if base_urls_found:
        lines.append(f"\n### baseURL 配置")
        for b in base_urls_found[:10]:
            lines.append(f"  `{b['url']}` ({b['file']})")

    # API 路径
    if all_apis:
        high = [a for a in sorted(all_apis) if any(k in a.lower() for k in
                ['/admin', '/internal', '/debug', '/manage', '/upload', '/user',
                 '/auth', '/account', '/order', '/pay', '/delete', '/export'])]
        other = [a for a in sorted(all_apis) if a not in high]

        lines.append(f"\n### API 路径（共 {len(all_apis)} 个）")
        if high:
            lines.append(f"**高优先级（{len(high)} 个）**:")
            for a in high[:50]:
                lines.append(f"  {a}")
        if other:
            lines.append(f"**一般（{len(other)} 个）**:")
            for a in other[:30]:
                lines.append(f"  {a}")
            if len(other) > 30:
                lines.append(f"  ... 还有 {len(other)-30} 个一般路径")

    # ★ 前端路由表
    if all_routes:
        # 去重：按 path 去重
        seen_paths = set()
        unique_routes = []
        unique_components = []
        for r in all_routes:
            if "path" in r:
                if r["path"] not in seen_paths:
                    seen_paths.add(r["path"])
                    unique_routes.append(r)
            elif "component" in r:
                unique_components.append(r)

        if unique_routes:
            lines.append(f"\n### 🗺️ 前端路由（{len(unique_routes)} 个页面）")
            lines.append("**⚠️ 每个路由 = 一个功能点，必须逐个添加到功能清单！**")
            for r in sorted(unique_routes, key=lambda x: x["path"]):
                lines.append(f"  `{r['path']}`")

        if unique_components:
            seen_comp = set()
            dedup_comp = []
            for c in unique_components:
                if c["component"] not in seen_comp:
                    seen_comp.add(c["component"])
                    dedup_comp.append(c)
            lines.append(f"\n### 📦 Vue/React 组件（{len(dedup_comp)} 个）")
            for c in sorted(dedup_comp, key=lambda x: x["component"]):
                lines.append(f"  `{c['component']}`")

    # 密钥
    if all_secrets:
        lines.append(f"\n### ⚠️ 疑似密钥（{len(all_secrets)} 个）")
        for s in all_secrets[:10]:
            lines.append(f"  `{s['value']}` ({s['file']})")

    # WebSocket
    if all_ws:
        lines.append(f"\n### WebSocket")
        for w in list(all_ws)[:10]:
            lines.append(f"  {w}")

    # 内部 URL
    internal = [u for u in all_urls if any(k in u for k in ['127.0.0.1', 'localhost', '192.168.', '10.', '172.16', '172.17'])]
    if internal:
        lines.append(f"\n### 内部 URL（{len(internal)} 个）")
        for u in internal[:10]:
            lines.append(f"  {u}")

    # Source Map
    if sourcemap_accessible:
        lines.append(f"\n### ⚠️ Source Map 可访问！")
        for sm in sourcemap_accessible:
            lines.append(f"  {sm}")

    # ★ 关键业务 JS 代码片段（供 LLM 理解代码逻辑，提取正则遗漏的 API）
    #    对 main.js / index.js / app.js 等入口文件，提取 API 相关代码片段
    _API_KW = ("axios", "fetch(", ".get(", ".post(", ".put(", ".delete(",
               "baseURL", "BASE_URL", "apiBase", "request(", "interceptor")
    if key_js_contents:
        lines.append(f"\n### 🔍 关键业务 JS 代码片段（供你分析 API 调用逻辑）")
        lines.append("以下是入口 JS 文件中与 API 调用相关的代码片段。**请仔细分析这些代码**：")
        lines.append("- 识别 `axios.create({baseURL:...})` 等实例配置")
        lines.append("- 追踪 minified 变量（如 `Kt.get()` → 实际是 `axios.get()`）")
        lines.append("- 拼接完整 API 路径（baseURL + 相对路径）")
        lines.append("- 发现正则未匹配到的 API 端点，添加到功能点时一并关联\n")
        for js_name, _content in key_js_contents.items():
            # 提取 API 关键词附近的代码片段（±1.5KB）
            _CHUNK_R = 1500
            positions = []
            for kw in _API_KW:
                start = 0
                while True:
                    idx = _content.find(kw, start)
                    if idx == -1 or len(positions) > 80:
                        break
                    positions.append(idx)
                    start = idx + len(kw)

            if not positions:
                # 没有找到 API 关键词 → 取文件头 15KB
                snippet = _content[:15000]
            else:
                # 合并重叠区间
                positions = sorted(set(positions))
                intervals = []
                for pos in positions:
                    s = max(0, pos - _CHUNK_R)
                    e = min(len(_content), pos + _CHUNK_R)
                    if intervals and s <= intervals[-1][1]:
                        intervals[-1] = (intervals[-1][0], e)
                    else:
                        intervals.append((s, e))

                chunks = []
                total = 0
                for s, e in intervals:
                    chunk = _content[s:e]
                    if total + len(chunk) > 40000:  # 单文件最多 40KB 片段
                        remaining = 40000 - total
                        if remaining > 500:
                            chunks.append(chunk[:remaining] + "\n// ... (截断)")
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                snippet = "\n\n// --- 片段分隔 ---\n\n".join(chunks) if chunks else _content[:15000]

            if snippet:
                lines.append(f"#### {js_name} 片段")
                lines.append("```javascript")
                lines.append(snippet[:40000])
                lines.append("```\n")

    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
