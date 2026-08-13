"""
CredentialInjector — 独立的手动登录凭证注入器。

工作流程：
1. 用 Playwright 启动浏览器（有头模式，支持验证码手动处理）
2. 导航到目标登录页
3. 自动检测并填写用户名/密码表单
4. 检测验证码，支持自动识别或人工介入
5. 提交表单，等待登录成功
6. 捕获登录后的 Cookie / localStorage Token / Authorization 头
7. 返回结构化凭证数据，供爬虫和漏洞测试复用

与 core/crawler/login_mixin.py 的区别：
- LoginMixin 是爬虫内部的登录 Mixin，依赖 AutoCrawler 实例上下文
- CredentialInjector 是独立模块，不依赖任何爬虫/会话上下文
- 前端直接调用，获取凭证后再启动扫描
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator
from urllib.parse import urlparse

from core.log import get_logger

log = get_logger("credential_injector")


# ============================================================
# 数据结构
# ============================================================

@dataclass
class CapturedCredentials:
    """登录后捕获的凭证数据。"""

    success: bool = False
    cookies: list[dict] = field(default_factory=list)
    cookie_string: str = ""
    local_storage: dict[str, str] = field(default_factory=dict)
    auth_header: str = ""
    final_url: str = ""
    login_method: str = ""        # "form_login" / "manual" / "cookie_inject"
    error: str = ""
    captcha_detected: str | None = None  # 验证码类型（如检测到）
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "cookies": self.cookies,
            "cookie_string": self.cookie_string,
            "local_storage": self.local_storage,
            "auth_header": self.auth_header,
            "final_url": self.final_url,
            "login_method": self.login_method,
            "error": self.error,
            "captcha_detected": self.captcha_detected,
            "duration_seconds": round(self.duration_seconds, 1),
        }

    def to_scan_message_extras(self) -> str:
        """生成可拼接到扫描指令的凭证文本。"""
        parts: list[str] = []
        if self.cookie_string:
            parts.append(f"使用Cookie: {self.cookie_string}")
        if self.auth_header:
            parts.append(f"Authorization: {self.auth_header}")
        if self.local_storage:
            # 把 localStorage 作为额外请求头传递（JWT 场景）
            ls_json = json.dumps(self.local_storage, ensure_ascii=False)
            parts.append(f"localStorage: {ls_json}")
        return "\n".join(parts)


# ============================================================
# 凭证注入器
# ============================================================

class CredentialInjector:
    """独立登录凭证注入器。

    用法：
        injector = CredentialInjector()
        async for event in injector.login(target_url, login_url, username, password):
            # event = {"type": "status"|"error"|"success", "message": "...", "data": {...}}
            ...
    """

    # 用户名输入框选择器（与 LoginMixin 保持一致）
    USERNAME_SELECTORS = [
        'input[name="username"]', 'input[name="account"]', 'input[name="email"]',
        'input[name="login"]', 'input[name="user"]', 'input[name="loginName"]',
        'input[name="phone"]', 'input[name="mobile"]', 'input[name="userName"]',
        'input[name="userId"]', 'input[name="login_name"]',
        'input[placeholder*="用户名"]', 'input[placeholder*="账号"]',
        'input[placeholder*="手机"]', 'input[placeholder*="邮箱"]',
        'input[placeholder*="请输入用户"]', 'input[placeholder*="请输入账"]',
        'input[placeholder*="Username"]', 'input[placeholder*="Email"]',
        'input[placeholder*="Account"]', 'input[placeholder*="Phone"]',
        '#username', '#account', '#email', '#phone', '#loginName',
        'input[type="text"]:visible', 'input[type="email"]', 'input[type="tel"]',
        'input[type="text"]',
    ]

    # 密码输入框选择器
    PASSWORD_SELECTORS = [
        'input[name="password"]', 'input[name="passwd"]', 'input[name="pwd"]',
        'input[name="loginPwd"]', 'input[name="pass"]',
        'input[placeholder*="密码"]', 'input[placeholder*="Password"]',
        'input[type="password"]', '#password', '#passwd',
    ]

    # 提交按钮选择器
    SUBMIT_SELECTORS = [
        'button[type="submit"]', 'input[type="submit"]',
        'button:has-text("登录")', 'button:has-text("Login")',
        'button:has-text("Sign in")', 'button:has-text("登陆")',
        'button:has-text("Log in")', 'button:has-text("确定")',
        '.login-btn', '#login-btn', '.btn-login', '#btn-login',
        'button.submit', 'a:has-text("登录")',
    ]

    # 登录页导航链接选择器
    LOGIN_NAV_SELECTORS = [
        'a:has-text("登录")', 'a:has-text("Login")', 'a:has-text("Sign in")',
        'a:has-text("登陆")', 'a:has-text("Log in")',
        'a[href*="login"]', 'a[href*="signin"]',
        'button:has-text("登录")', 'button:has-text("Login")',
        '[role="tab"]:has-text("账号")', '[role="tab"]:has-text("密码")',
        '.tab:has-text("账号")', '.tab:has-text("密码登录")',
        'a:has-text("账号登录")', 'span:has-text("账号登录")',
    ]

    def __init__(self, headless: bool = False, timeout: int = 180):
        """
        Args:
            headless: 是否无头模式。默认 False（有头模式，支持验证码手动处理）。
            timeout: 登录超时时间（秒），用于手动登录等待。
        """
        self.headless = headless
        self.timeout = timeout
        self._cancelled = False

    def cancel(self):
        """取消正在进行的登录流程。"""
        self._cancelled = True

    async def login(
        self,
        target_url: str,
        username: str,
        password: str,
        login_url: str = "",
    ) -> AsyncGenerator[dict, None]:
        """执行登录流程，通过异步生成器推送实时状态事件。

        Args:
            target_url: 目标站点 URL
            username: 用户名
            password: 密码
            login_url: 登录页 URL（可选，为空时自动从目标站检测）

        Yields:
            事件字典: {"type": "status"|"warning"|"error"|"success"|"captcha", "message": "...", "data": {...}}
        """
        import time
        start_time = time.time()

        if not target_url:
            yield {"type": "error", "message": "目标 URL 不能为空"}
            return
        if not username or not password:
            yield {"type": "error", "message": "用户名和密码不能为空"}
            return

        result = CapturedCredentials()

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            yield {"type": "error", "message": "Playwright 未安装，请运行: pip install playwright && python -m playwright install chromium"}
            return

        # 确定浏览器可执行文件路径
        from core.browser_resolver import get_launch_executable_path
        exe_path = get_launch_executable_path()

        launch_opts: dict[str, Any] = {
            "headless": self.headless,
            "args": [
                "--ignore-certificate-errors",
                "--disable-blink-features=AutomationControlled",
                "--disable-web-security",
                "--disable-features=IsolateOrigins,site-per-process",
            ],
        }
        if exe_path:
            launch_opts["executable_path"] = exe_path

        _REAL_UA = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        launch_opts["args"].append(f"--user-agent={_REAL_UA}")

        pw = None
        browser = None

        try:
            pw = await async_playwright().start()
            yield {"type": "status", "message": "正在启动浏览器..."}

            browser = await pw.chromium.launch(**launch_opts)
            ctx = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
                user_agent=_REAL_UA,
            )

            # 注入反检测脚本
            await ctx.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
                Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en']});
                window.chrome = {runtime: {}};
            """)

            page = await ctx.new_page()

            # ======== Step 1: 导航到登录页 ========
            nav_url = login_url or target_url
            yield {"type": "status", "message": f"正在打开页面: {nav_url}"}

            try:
                await page.goto(nav_url, wait_until="domcontentloaded", timeout=60000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                await asyncio.sleep(1)
            except Exception as e:
                yield {"type": "warning", "message": f"首次访问超时，重试中... ({e})"}
                try:
                    await page.goto(nav_url, wait_until="commit", timeout=60000)
                    await asyncio.sleep(2)
                except Exception as e2:
                    result.error = f"无法访问目标站点: {e2}"
                    result.duration_seconds = time.time() - start_time
                    yield {"type": "error", "message": result.error, "data": result.to_dict()}
                    return

            # 记录登录前状态
            pre_url = page.url
            pre_cookies = await page.context.cookies()
            pre_cookie_count = len(pre_cookies)
            try:
                pre_hash = await page.evaluate("() => location.hash") or ""
            except Exception:
                pre_hash = ""

            # ======== Step 2: 如果没有指定 login_url，尝试点击登录链接 ========
            if not login_url:
                for selector in self.LOGIN_NAV_SELECTORS:
                    if self._cancelled:
                        result.error = "用户取消了登录"
                        yield {"type": "error", "message": result.error, "data": result.to_dict()}
                        return
                    try:
                        await page.click(selector, timeout=2000)
                        await page.wait_for_load_state("domcontentloaded", timeout=5000)
                        yield {"type": "status", "message": f"已点击登录入口: {selector}"}
                        break
                    except Exception:
                        continue

            # ======== Step 3: 检测验证码 ========
            captcha_kind = await self._detect_captcha(page)
            if captcha_kind:
                result.captcha_detected = captcha_kind
                captcha_label = self._captcha_label(captcha_kind)
                yield {"type": "captcha", "message": f"检测到{captcha_label}，尝试自动识别...", "data": {"kind": captcha_kind}}

                # 尝试自动识别验证码
                solved = False
                try:
                    from core.captcha_solver import auto_solve
                    solved = await auto_solve(page, captcha_kind)
                except Exception:
                    solved = False

                if solved:
                    yield {"type": "status", "message": f"✅ {captcha_label}自动识别成功"}
                else:
                    # 自动识别失败 → 等待用户手动处理
                    if self.headless:
                        yield {"type": "warning", "message": f"⚠️ {captcha_label}自动识别失败（无头模式无法手动操作），继续尝试表单填写..."}
                    else:
                        yield {"type": "captcha", "message": f"⚠️ {captcha_label}自动识别失败，请在浏览器窗口中手动完成验证...", "data": {"kind": captcha_kind, "manual": True}}
                        # 等待用户手动处理验证码（最多 120 秒）
                        ok = await self._wait_for_manual_captcha(page, timeout=120)
                        if ok:
                            yield {"type": "status", "message": "✅ 用户已手动完成验证"}
                        else:
                            yield {"type": "warning", "message": "验证码等待超时，继续尝试提交..."}

            # ======== Step 4: 填写用户名 ========
            yield {"type": "status", "message": "正在填写用户名..."}
            username_filled = False
            for u_sel in self.USERNAME_SELECTORS:
                if self._cancelled:
                    result.error = "用户取消了登录"
                    yield {"type": "error", "message": result.error, "data": result.to_dict()}
                    return
                try:
                    await page.fill(u_sel, username, timeout=600)
                    username_filled = True
                    break
                except Exception:
                    continue

            # ======== Step 5: 填写密码 ========
            yield {"type": "status", "message": "正在填写密码..."}
            password_filled = False
            for p_sel in self.PASSWORD_SELECTORS:
                try:
                    await page.fill(p_sel, password, timeout=600)
                    password_filled = True
                    break
                except Exception:
                    continue

            if not username_filled or not password_filled:
                # 表单填写失败，可能需要手动登录
                if not username_filled and not password_filled:
                    yield {"type": "warning", "message": "未识别到账号密码表单，请在浏览器中手动登录..."}
                    if not self.headless:
                        ok = await self._wait_for_manual_login(page, pre_url, pre_cookies, pre_hash, timeout=self.timeout)
                        if ok:
                            result.success = True
                            result.login_method = "manual"
                            yield {"type": "status", "message": "✅ 用户已手动完成登录"}
                        else:
                            result.error = "手动登录超时"
                            result.duration_seconds = time.time() - start_time
                            yield {"type": "error", "message": result.error, "data": result.to_dict()}
                            return
                    else:
                        result.error = "无法识别登录表单（无头模式下无法手动操作）"
                        result.duration_seconds = time.time() - start_time
                        yield {"type": "error", "message": result.error, "data": result.to_dict()}
                        return
                else:
                    msg_parts = []
                    if not username_filled:
                        msg_parts.append("用户名框未找到")
                    if not password_filled:
                        msg_parts.append("密码框未找到")
                    result.error = f"表单填写不完整: {'; '.join(msg_parts)}"
                    result.duration_seconds = time.time() - start_time
                    yield {"type": "error", "message": result.error, "data": result.to_dict()}
                    return
            else:
                yield {"type": "status", "message": f"✅ 表单已填写 (用户名={'✓' if username_filled else '✗'}, 密码={'✓' if password_filled else '✗'})"}

            # ======== Step 6: 提交前验证码再检测 ========
            if not result.success:  # 手动登录已成功则跳过
                post_fill_captcha = await self._detect_captcha(page)
                if post_fill_captcha and post_fill_captcha != captcha_kind:
                    yield {"type": "captcha", "message": f"提交前检测到{self._captcha_label(post_fill_captcha)}，请手动处理...", "data": {"kind": post_fill_captcha, "manual": True}}
                    if not self.headless:
                        await self._wait_for_manual_captcha(page, timeout=120)

                # ======== Step 7: 提交表单 ========
                yield {"type": "status", "message": "正在提交登录表单..."}
                submitted = False
                for s_sel in self.SUBMIT_SELECTORS:
                    try:
                        await page.click(s_sel, timeout=2000)
                        try:
                            await page.wait_for_load_state("networkidle", timeout=3000)
                        except Exception:
                            pass
                        submitted = True
                        yield {"type": "status", "message": f"已点击提交按钮"}
                        break
                    except Exception:
                        continue

                if not submitted:
                    try:
                        await page.keyboard.press("Enter")
                        try:
                            await page.wait_for_load_state("networkidle", timeout=3000)
                        except Exception:
                            pass
                        submitted = True
                        yield {"type": "status", "message": "已按 Enter 提交"}
                    except Exception:
                        pass

                if not submitted:
                    result.error = "找不到提交按钮，无法提交登录表单"
                    result.duration_seconds = time.time() - start_time
                    yield {"type": "error", "message": result.error, "data": result.to_dict()}
                    return

                # ======== Step 8: 等待登录结果 ========
                yield {"type": "status", "message": "等待登录响应..."}
                login_ok = await self._wait_for_login_result(
                    page, pre_url, pre_hash, pre_cookie_count
                )

                if login_ok:
                    result.success = True
                    result.login_method = "form_login"
                    yield {"type": "status", "message": "✅ 登录成功！正在捕获凭证..."}
                else:
                    # 登录可能失败，检查是否需要手动介入
                    fail_cap = await self._detect_captcha(page)
                    if fail_cap and not self.headless:
                        yield {"type": "captcha", "message": f"登录后仍处于验证页（{self._captcha_label(fail_cap)}），请手动完成...", "data": {"kind": fail_cap, "manual": True}}
                        ok = await self._wait_for_manual_login(page, pre_url, pre_cookies, pre_hash, timeout=self.timeout)
                        if ok:
                            result.success = True
                            result.login_method = "manual"
                            yield {"type": "status", "message": "✅ 用户已手动完成登录"}
                        else:
                            result.error = "登录失败：未检测到成功标志，且手动登录超时"
                            result.duration_seconds = time.time() - start_time
                            yield {"type": "error", "message": result.error, "data": result.to_dict()}
                            return
                    else:
                        result.error = "登录可能失败：URL 未变化且无新增认证 Cookie"
                        result.duration_seconds = time.time() - start_time
                        yield {"type": "error", "message": result.error, "data": result.to_dict()}
                        return

            # ======== Step 9: 捕获凭证 ========
            result.final_url = page.url

            # 捕获 Cookie
            all_cookies = await page.context.cookies()
            target_domain = urlparse(target_url).netloc
            relevant_cookies = [
                c for c in all_cookies
                if target_domain.endswith(c.get("domain", "").lstrip("."))
                or c.get("domain", "").lstrip(".").endswith(target_domain)
            ]
            if not relevant_cookies:
                relevant_cookies = all_cookies  # 保留所有 cookie
            result.cookies = relevant_cookies
            result.cookie_string = "; ".join(f"{c['name']}={c['value']}" for c in relevant_cookies)

            yield {"type": "status", "message": f"🍪 已捕获 {len(relevant_cookies)} 个 Cookie"}

            # 捕获 localStorage Token
            try:
                local_storage_items = await page.evaluate("""() => {
                    const result = {};
                    for (const key of Object.keys(localStorage)) {
                        const val = localStorage.getItem(key);
                        if (!val || val.length <= 10) continue;
                        const kl = String(key).toLowerCase();
                        const vl = String(val);
                        if (vl.startsWith('eyJ') || kl.includes('token') || kl.includes('auth')
                            || kl.includes('jwt') || kl.includes('session')) {
                            result[key] = val;
                        }
                    }
                    return Object.keys(result).length > 0 ? result : null;
                }""")
                if local_storage_items:
                    result.local_storage = local_storage_items
                    # 提取 JWT token 作为 Authorization 头
                    first_token = next(
                        (v for v in local_storage_items.values()
                         if isinstance(v, str) and v.startswith("eyJ")),
                        None,
                    )
                    if first_token:
                        result.auth_header = f"Bearer {first_token}"
                    yield {"type": "status", "message": f"🔑 已捕获 {len(local_storage_items)} 个 localStorage Token"}
            except Exception as e:
                log.debug("localStorage 提取失败: %s", e)

            result.duration_seconds = time.time() - start_time

            # 汇总
            summary_parts = [f"Cookie: {len(result.cookies)} 个"]
            if result.local_storage:
                summary_parts.append(f"Token: {len(result.local_storage)} 个")
            if result.auth_header:
                summary_parts.append("Authorization 头: 已获取")
            yield {
                "type": "success",
                "message": f"✅ 凭证捕获完成！({'; '.join(summary_parts)})",
                "data": result.to_dict(),
            }

        except Exception as e:
            log.exception("凭证注入异常")
            result.error = f"登录过程异常: {e}"
            result.duration_seconds = time.time() - start_time
            yield {"type": "error", "message": result.error, "data": result.to_dict()}
        finally:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass
            if pw:
                try:
                    await pw.stop()
                except Exception:
                    pass

    # ============================================================
    # 辅助方法
    # ============================================================

    @staticmethod
    def _captcha_label(kind: str) -> str:
        return {
            "image_captcha": "图形验证码",
            "slider_captcha": "滑块验证",
            "third_party_captcha": "第三方人机验证（极验/防水墙/reCAPTCHA 等）",
            "sms_code": "手机/邮箱验证码",
            "text_hint": "验证码（按页面提示）",
            "no_form": "无账号密码表单（请手动登录）",
        }.get(kind, kind)

    async def _detect_captcha(self, page) -> str | None:
        """检测页面是否存在人机验证/验证码。"""
        try:
            # 图形验证码
            try:
                cnt = await page.locator(
                    'img[src*="captcha" i], img[src*="verify" i], img[src*="vcode" i], '
                    'img[alt*="验证码"], canvas.captcha, canvas[class*="captcha"]'
                ).count()
                if cnt > 0:
                    return "image_captcha"
            except Exception:
                pass

            # 第三方验证码
            try:
                cnt = await page.locator(
                    '.geetest_box, .geetest_panel, .geetest_btn, '
                    '.nc_iconfont, .nc_wrapper, .nc-lang-cnt, '
                    '.yidun_slider, .yidun_panel, '
                    '#tcaptcha_iframe, iframe[src*="hcaptcha"], iframe[src*="recaptcha"], '
                    'iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]'
                ).count()
                if cnt > 0:
                    return "third_party_captcha"
            except Exception:
                pass

            # 短信验证码
            try:
                sms_input = await page.locator(
                    'input[placeholder*="验证码"], input[placeholder*="短信"], '
                    'input[placeholder*="动态码"], input[placeholder*="captcha" i], '
                    'input[name*="code" i]:not([name*="encode" i]):not([name*="codec" i]), '
                    'input[name*="captcha" i], input[name*="verify" i], '
                    'input[name*="smsCode" i], input[id*="captcha" i], '
                    'input[id*="smsCode" i]'
                ).count()
                sms_btn = await page.locator(
                    'button:has-text("获取验证码"), button:has-text("发送验证码"), '
                    'button:has-text("获取短信"), button:has-text("发送短信"), '
                    'a:has-text("获取验证码"), a:has-text("发送验证码")'
                ).count()
                if sms_input > 0 or sms_btn > 0:
                    return "sms_code"
            except Exception:
                pass

            # 文本提示兜底
            try:
                body_text = await page.evaluate(
                    "() => (document.body && document.body.innerText || '').slice(0, 800)"
                )
                body_lower = (body_text or "").lower()
                hint_kws_zh = ["验证码", "请完成验证", "拖动滑块", "短信验证", "扫码登录", "请按住滑块"]
                hint_kws_en = ["captcha", "verification code", "verify you are human", "i'm not a robot"]
                if any(kw in body_text for kw in hint_kws_zh) or any(kw in body_lower for kw in hint_kws_en):
                    return "text_hint"
            except Exception:
                pass
        except Exception:
            return None
        return None

    async def _wait_for_manual_captcha(self, page, timeout: int = 120) -> bool:
        """等待用户手动完成验证码。

        检测条件：验证码元素消失或页面发生变化。
        """
        loop = asyncio.get_event_loop()
        start = loop.time()
        while loop.time() - start < timeout:
            if self._cancelled:
                return False
            await asyncio.sleep(2)
            cap = await self._detect_captcha(page)
            if cap is None:
                return True
        return False

    async def _wait_for_manual_login(
        self, page, pre_url: str, pre_cookies: list, pre_hash: str, timeout: int = 180
    ) -> bool:
        """轮询等待用户手动完成登录。"""
        pre_cookie_names = {c["name"] for c in pre_cookies}
        loop = asyncio.get_event_loop()
        start = loop.time()

        while loop.time() - start < timeout:
            if self._cancelled:
                return False
            await asyncio.sleep(2)
            try:
                current_url = page.url
                current_cookies_list = await page.context.cookies()
                current_cookie_names = {c["name"] for c in current_cookies_list}

                url_changed = (
                    current_url != pre_url
                    and not any(kw in current_url.lower() for kw in ["login", "signin", "captcha", "verify"])
                )
                new_cookies = current_cookie_names - pre_cookie_names
                auth_cookie_added = any(
                    any(kw in name.lower() for kw in ("session", "token", "auth", "uid", "sid", "jwt", "jsessionid", "phpsessid"))
                    for name in new_cookies
                )

                local_token = ""
                try:
                    local_token = await page.evaluate("""() => {
                        const keys = ['token','access_token','accessToken','auth_token','authToken','jwt','id_token','idToken','Authorization','user_token'];
                        for (const store of [localStorage, sessionStorage]) {
                            for (const k of keys) {
                                const v = store.getItem(k);
                                if (v && v.length > 10) return k;
                            }
                        }
                        return '';
                    }""")
                except Exception:
                    local_token = ""

                if url_changed or auth_cookie_added or bool(local_token):
                    await asyncio.sleep(2)
                    return True
            except Exception:
                continue
        return False

    async def _wait_for_login_result(
        self, page, pre_url: str, pre_hash: str, pre_cookie_count: int, max_wait: int = 15
    ) -> bool:
        """轮询等待登录结果（最多 max_wait 秒）。"""
        login_fail_keywords = [
            "密码错误", "用户名或密码", "账号不存在", "登录失败", "验证码",
            "password incorrect", "invalid credentials", "login failed",
        ]

        def _check_auth_cookies(cookies):
            return [c for c in cookies if any(
                k in c["name"].lower()
                for k in ("session", "token", "auth", "jwt", "sid", "jsessionid", "phpsessid", "access_token")
            )]

        for _attempt in range(max_wait):
            if self._cancelled:
                return False
            await asyncio.sleep(1)
            try:
                post_url = page.url
                post_cookies = await page.context.cookies()
                post_cookie_count = len(post_cookies)
                post_hash = await page.evaluate("() => location.hash") or ""

                url_changed = post_url != pre_url and "login" not in post_url.lower()
                hash_changed = post_hash != pre_hash and "login" not in post_hash.lower()
                cookie_increased = post_cookie_count > pre_cookie_count
                auth_cookies = _check_auth_cookies(post_cookies)

                local_token = await page.evaluate("""() => {
                    const keys = ['token', 'access_token', 'accessToken', 'auth_token',
                                  'jwt', 'Authorization', 'user_token'];
                    for (const key of keys) {
                        const val = localStorage.getItem(key);
                        if (val && val.length > 10) return key + '=' + val.slice(0, 20);
                    }
                    return '';
                }""")

                has_fail_sign = False
                if not url_changed and not hash_changed:
                    try:
                        page_text = await page.evaluate("() => document.body?.innerText?.slice(0, 2000) || ''")
                        has_fail_sign = any(kw in page_text.lower() for kw in [k.lower() for k in login_fail_keywords])
                    except Exception:
                        has_fail_sign = False

                if url_changed or hash_changed or bool(auth_cookies) or bool(local_token):
                    return True
                if has_fail_sign:
                    return False
            except Exception:
                pass

        return False
