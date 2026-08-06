"""
LoginMixin — 登录相关：验证码检测 / 手动登录等待 / 自动登录尝试 / 代理检查。

包含的方法：
- _captcha_label             : 验证码类型 → 中文标签（staticmethod）
- _detect_captcha            : 检测页面验证码类型
- _wait_for_manual_login     : 轮询等待用户手动完成登录
- _attempt_login             : 自动尝试登录
- _check_proxy               : 检查代理可用性（staticmethod）
"""

from __future__ import annotations

import asyncio
import os
import re


class LoginMixin:
    """登录相关 mixin。"""

    @staticmethod
    def _captcha_label(kind: str) -> str:
        """把验证码类型代码转为人类可读的中文标签。"""
        return {
            "image_captcha": "图形验证码",
            "slider_captcha": "滑块验证",
            "third_party_captcha": "第三方人机验证（极验/防水墙/reCAPTCHA 等）",
            "sms_code": "手机/邮箱验证码",
            "text_hint": "验证码（按页面提示）",
            "no_form": "无账号密码表单（请手动登录）",
        }.get(kind, kind)

    async def _detect_captcha(self, page) -> str | None:
        """检测页面是否存在人机验证 / 验证码 / 二次验证。

        返回检测到的类型字符串（image_captcha / slider_captcha / sms_code /
        third_party_captcha / text_hint），未检测到返回 None。
        """
        try:
            # 1) 图形验证码（img / canvas）
            try:
                cnt = await page.locator(
                    'img[src*="captcha" i], img[src*="verify" i], img[src*="vcode" i], '
                    'img[alt*="验证码"], canvas.captcha, canvas[class*="captcha"]'
                ).count()
                if cnt > 0:
                    return "image_captcha"
            except Exception:
                pass

            # 2) 主流滑块 / 行为验证厂商
            try:
                cnt = await page.locator(
                    # 极验
                    '.geetest_box, .geetest_panel, .geetest_btn, '
                    # 阿里 NoCaptcha
                    '.nc_iconfont, .nc_wrapper, .nc-lang-cnt, '
                    # 网易易盾
                    '.yidun_slider, .yidun_panel, '
                    # 腾讯防水墙 / hCaptcha / reCAPTCHA / Cloudflare Turnstile
                    '#tcaptcha_iframe, iframe[src*="hcaptcha"], iframe[src*="recaptcha"], '
                    'iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]'
                ).count()
                if cnt > 0:
                    return "third_party_captcha"
            except Exception:
                pass

            # 3) 手机/邮箱验证码输入框（手机号登录的核心特征）
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
                    'a:has-text("获取验证码"), a:has-text("发送验证码"), '
                    'span:has-text("获取验证码"), span:has-text("发送验证码")'
                ).count()
                if sms_input > 0 or sms_btn > 0:
                    return "sms_code"
            except Exception:
                pass

            # 4) 文本提示兜底（截取前 800 字）
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

    async def _wait_for_manual_login(self, page, timeout: int = 120) -> bool:
        """轮询等待用户在有头浏览器中手动完成登录。

        判定成功条件（任一）：
        1) URL 跳转到非登录页（不再包含 login/signin/captcha）
        2) 出现 session/token/auth 类 cookie
        3) localStorage 出现 token

        返回 True=用户已完成登录，False=超时。
        """
        try:
            pre_url = page.url
            pre_cookies = {c["name"] for c in await page.context.cookies()}
        except Exception:
            pre_url = ""
            pre_cookies = set()

        loop = asyncio.get_event_loop()
        start = loop.time()
        last_remaining_tick = -1

        while loop.time() - start < timeout:
            await asyncio.sleep(2)
            try:
                current_url = page.url
                current_cookies_list = await page.context.cookies()
                current_cookie_names = {c["name"] for c in current_cookies_list}

                url_changed = (
                    current_url != pre_url
                    and not any(kw in current_url.lower() for kw in ["login", "signin", "captcha", "verify"])
                )
                new_cookies = current_cookie_names - pre_cookies
                auth_cookie_added = any(
                    any(kw in name.lower() for kw in ("session", "token", "auth", "uid", "sid", "jwt", "jsessionid", "phpsessid"))
                    for name in new_cookies
                )

                local_token = ""
                try:
                    local_token = await page.evaluate("""() => {
                        const keys = ['token','access_token','accessToken','auth_token','authToken','jwt','id_token','idToken','Authorization','user_token','Sc-Id-Token','c-token'];
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
                    # 再等一会儿让 cookie 全部种完
                    await asyncio.sleep(2)
                    self._emit_event("manual_intervention_done", {
                        "success": True,
                        "reason": "url_changed" if url_changed else ("cookie" if auth_cookie_added else "localStorage"),
                    })
                    return True

                # 每 10 秒推一次倒计时
                remaining = int(timeout - (loop.time() - start))
                if remaining // 10 != last_remaining_tick:
                    last_remaining_tick = remaining // 10
                    self._emit_event("manual_intervention_tick", {"remaining": remaining})
            except Exception:
                continue

        self._emit_event("manual_intervention_done", {"success": False, "reason": "timeout"})
        return False


    async def _attempt_login(self, page, login_info: dict, captured: list) -> bool:
        """尝试登录。返回 True=登录成功，False=失败。"""
        self._report(f"  尝试登录 (角色: {login_info.get('role', 'unknown')})")

        # 记录登录前状态（用于验证）
        pre_cookies = await page.context.cookies()
        pre_cookie_count = len(pre_cookies)

        # 先访问目标（SPA 需要等 JS 渲染完成）
        try:
            await page.goto(self.target, wait_until="domcontentloaded", timeout=60000)
            # SPA 等待：最多等 3s networkidle，失败也继续
            try:
                await page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                pass
            await asyncio.sleep(1)
        except Exception:
            try:
                self._report("  ⚠️ 首次访问超时，重试中...")
                await page.goto(self.target, wait_until="commit", timeout=60000)
                await asyncio.sleep(2)
            except Exception:
                self._report("  ⚠️ 无法访问目标站点")
                return False

        pre_url = page.url
        # 记录 hash（SPA hash 路由变化检测）
        pre_hash = await page.evaluate("() => location.hash") or ""

        # 如果提供了登录 URL，直接去
        login_url = login_info.get("login_url", "")
        if login_url:
            try:
                await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
            except Exception:
                pass
        else:
            # 尝试点击登录链接/tab
            login_nav_selectors = [
                'a:has-text("登录")', 'a:has-text("Login")', 'a:has-text("Sign in")',
                'a:has-text("登陆")', 'a:has-text("Log in")',
                'a[href*="login"]', 'a[href*="signin"]',
                'button:has-text("登录")', 'button:has-text("Login")',
                # Tab 切换（如"账号登录" tab）
                '[role="tab"]:has-text("账号")', '[role="tab"]:has-text("密码")',
                '.tab:has-text("账号")', '.tab:has-text("密码登录")',
                'a:has-text("账号登录")', 'span:has-text("账号登录")',
            ]
            for selector in login_nav_selectors:
                try:
                    await page.click(selector, timeout=2000)
                    await page.wait_for_load_state("domcontentloaded", timeout=5000)
                    break
                except Exception:
                    continue

        # 填写用户名（扩展选择器覆盖更多场景）
        username = login_info.get("username", "")
        password = login_info.get("password", "")
        username_filled = False
        password_filled = False

        username_selectors = [
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
        for u_sel in username_selectors:
            try:
                await page.fill(u_sel, username, timeout=600)
                username_filled = True
                break
            except Exception:
                continue

        # 填写密码
        password_selectors = [
            'input[name="password"]', 'input[name="passwd"]', 'input[name="pwd"]',
            'input[name="loginPwd"]', 'input[name="pass"]',
            'input[placeholder*="密码"]', 'input[placeholder*="Password"]',
            'input[type="password"]', '#password', '#passwd',
        ]
        for p_sel in password_selectors:
            try:
                await page.fill(p_sel, password, timeout=600)
                password_filled = True
                break
            except Exception:
                continue

        self._report(f"  填写表单: 用户名={'✓' if username_filled else '✗'}, 密码={'✓' if password_filled else '✗'}")

        if not username_filled or not password_filled:
            # 用户名/密码框都没找到 → 大概率是"手机号登录"/"扫码登录"/纯验证码登录
            # 这时直接走人工介入流程（用户可能要输手机号 → 收验证码 → 登录）
            if not username_filled and not password_filled:
                cap = await self._detect_captcha(page)
                # ★ 先尝试自动识别验证码
                if cap is not None:
                    from core.captcha_solver import auto_solve
                    try:
                        solved = await auto_solve(page, cap)
                    except Exception:
                        solved = False
                    if solved:
                        self._report(f"  ✅ 验证码自动识别成功（{self._captcha_label(cap)}）")
                        # 验证码已填入，尝试直接提交
                        return True
                # auto 模式下有头浏览器也给用户手动机会
                allow_manual = os.getenv("BROWSER_HEADLESS", "auto").lower() != "true"
                if cap is not None or allow_manual:
                    self._report("  🧑 未识别到账号密码表单，等待用户在浏览器中手动完成登录...")
                    self._emit_event("manual_intervention", {
                        "reason": cap or "no_form",
                        "reason_label": self._captcha_label(cap or "no_form"),
                        "timeout": int(os.getenv("MANUAL_LOGIN_TIMEOUT", "180")),
                        "role": login_info.get("role", "user"),
                    })
                    ok = await self._wait_for_manual_login(
                        page, timeout=int(os.getenv("MANUAL_LOGIN_TIMEOUT", "180"))
                    )
                    if ok:
                        self._report("  ✅ 用户已手动完成登录，继续爬取")
                        return True
                    self._report("  ❌ 用户未在规定时间内完成登录")
                    return False
            self._report(f"  ❌ 登录表单填写失败（用户名={'✓' if username_filled else '✗'}, 密码={'✓' if password_filled else '✗'}）")
            return False

        # ★ 提交前：检测是否需要人工介入（验证码 / 滑块 / 二次验证）
        captcha_kind = await self._detect_captcha(page)
        if captcha_kind is not None:
            # ★ 先尝试自动识别验证码
            from core.captcha_solver import auto_solve
            try:
                solved = await auto_solve(page, captcha_kind)
            except Exception:
                solved = False
            if solved:
                self._report(f"  ✅ 验证码自动识别成功（{self._captcha_label(captcha_kind)}）")
                # 继续提交登录
            else:
                # 自动识别失败 → 回退到原有手动流程
                self._report(f"  ⚠️ 验证码自动识别失败（{self._captcha_label(captcha_kind)}），等待用户手动完成...")
                timeout_s = int(os.getenv("MANUAL_LOGIN_TIMEOUT", "180"))
                self._emit_event("manual_intervention", {
                    "reason": captcha_kind,
                    "reason_label": self._captcha_label(captcha_kind),
                    "timeout": timeout_s,
                    "role": login_info.get("role", "user"),
                })
                ok = await self._wait_for_manual_login(page, timeout=timeout_s)
                if ok:
                    self._report("  ✅ 用户已手动完成登录，继续爬取")
                    return True
                self._report("  ❌ 用户未在规定时间内完成登录")
                return False

        # 提交
        submit_selectors = [
            'button[type="submit"]', 'input[type="submit"]',
            'button:has-text("登录")', 'button:has-text("Login")',
            'button:has-text("Sign in")', 'button:has-text("登陆")',
            'button:has-text("Log in")', 'button:has-text("确定")',
            '.login-btn', '#login-btn', '.btn-login', '#btn-login',
            'button.submit', 'a:has-text("登录")',
        ]
        submitted = False
        for s_sel in submit_selectors:
            try:
                await page.click(s_sel, timeout=2000)
                # SPA 登录后不等 networkidle（可能有 WebSocket 导致永远不 idle）
                try:
                    await page.wait_for_load_state("networkidle", timeout=2000)
                except Exception:
                    pass
                submitted = True
                self._report(f"  已点击提交按钮: {s_sel}")
                break
            except Exception:
                continue

        if not submitted:
            # 试 Enter 键
            try:
                await page.keyboard.press("Enter")
                try:
                    await page.wait_for_load_state("networkidle", timeout=2000)
                except Exception:
                    pass
                submitted = True
                self._report("  已按 Enter 提交")
            except Exception:
                pass

        if not submitted:
            self._report("  ❌ 登录提交失败：找不到提交按钮")
            return False

        # ======== 登录成功验证（轮询重试，最多等 10s）========
        # 背景：SPA 登录后 hash 跳转 + JS 写 cookie 均是异步的，
        # 2s 不够；需要轮询直到出现成功信号或超时。
        login_fail_keywords = [
            "密码错误", "用户名或密码", "账号不存在", "登录失败", "验证码",
            "password incorrect", "invalid credentials", "login failed",
            "captcha", "verification code", "请输入验证码",
        ]

        def _check_auth_cookies(cookies):
            return [c for c in cookies if any(
                k in c["name"].lower()
                for k in ("session", "token", "auth", "jwt", "sid", "jsessionid", "phpsessid", "access_token")
            )]

        url_changed = hash_changed = cookie_increased = False
        auth_cookies: list = []
        local_token = ""
        has_fail_sign = False
        post_url = pre_url
        post_hash = pre_hash

        # 轮询：每 1s 采样一次，最多 10 次（共 10s）
        for _attempt in range(10):
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

                # 检查 localStorage token
                local_token = await page.evaluate("""() => {
                    const keys = ['token', 'access_token', 'accessToken', 'auth_token',
                                  'jwt', 'Authorization', 'user_token'];
                    for (const key of keys) {
                        const val = localStorage.getItem(key);
                        if (val && val.length > 10) return key + '=' + val.slice(0, 20);
                    }
                    return '';
                }""")

                # 检查页面是否有失败标志（只在仍在登录页时才检查，避免误判后台页面）
                if not url_changed and not hash_changed:
                    try:
                        page_text = await page.evaluate("() => document.body?.innerText?.slice(0, 2000) || ''")
                        has_fail_sign = any(kw in page_text.lower() for kw in [k.lower() for k in login_fail_keywords])
                    except Exception:
                        has_fail_sign = False

                # 已出现任何成功信号 → 提前退出轮询
                if url_changed or hash_changed or bool(auth_cookies) or bool(local_token):
                    break

                # 明确失败（页面有错误提示）→ 提前退出轮询
                if has_fail_sign:
                    break

            except Exception:
                pass  # 页面切换时可能短暂报错，忽略继续等

        login_success = (url_changed or hash_changed or cookie_increased
                         or bool(auth_cookies) or bool(local_token)) and not has_fail_sign

        # 提交后兜底：如果判定失败，但页面出现验证码/二次验证，先自动尝试再给用户手动机会
        if not login_success:
            cap_after = await self._detect_captcha(page)
            if cap_after is not None:
                # ★ 先尝试自动识别验证码
                from core.captcha_solver import auto_solve
                try:
                    solved = await auto_solve(page, cap_after)
                except Exception:
                    solved = False
                if solved:
                    self._report(f"  ✅ 提交后验证码自动识别成功（{self._captcha_label(cap_after)}）")
                    login_success = True
                else:
                    allow_manual = os.getenv("BROWSER_HEADLESS", "auto").lower() != "true"
                    if allow_manual:
                        self._report(f"  ⚠️ 登录提交后仍处于验证页（{self._captcha_label(cap_after)}），等待用户手动完成...")
                        timeout_s = int(os.getenv("MANUAL_LOGIN_TIMEOUT", "180"))
                        self._emit_event("manual_intervention", {
                            "reason": cap_after,
                            "reason_label": self._captcha_label(cap_after),
                            "timeout": timeout_s,
                            "role": login_info.get("role", "user"),
                        })
                        ok = await self._wait_for_manual_login(page, timeout=timeout_s)
                        if ok:
                            self._report("  ✅ 用户已手动完成登录，继续爬取")
                            return True

        if login_success:
            cookie_names = ", ".join(c["name"] for c in auth_cookies[:3]) if auth_cookies else "无特征 cookie"
            extra = ""
            if hash_changed:
                extra += f", hash: {pre_hash}→{post_hash}"
            if local_token:
                extra += f", localStorage: {local_token}"
            self._report(f"  ✅ 登录成功: URL={post_url[:60]}, Cookie 增加 {post_cookie_count - pre_cookie_count} 个 ({cookie_names}){extra}")
        else:
            reasons = []
            if not url_changed:
                reasons.append("URL 未变化（仍在登录页）")
            if not cookie_increased:
                reasons.append("Cookie 未增加")
            if has_fail_sign:
                reasons.append(f"页面有失败标志")
            self._report(f"  ⚠️ 登录可能失败: {'; '.join(reasons)}")
            self._report(f"     → 后续爬取可能是未登录态，功能清单不完整")
            self._report(f"     → 建议提供 login_url 参数或人工登录后提供 Cookie")

        return login_success


    @staticmethod
    def _has_authenticated_api_success(captured: list[dict] | None) -> bool:
        """判断页面加载期间是否已有带认证头的业务 API 成功响应。"""
        if not captured:
            return False

        auth_header_names = {
            "authorization", "sc-id-token", "x-token", "x-auth-token",
            "x-access-token", "token", "access-token", "access_token",
            "c-token", "id-token", "id_token", "jwt",
        }
        positive_markers = (
            '"code":"000000"', '"code": "000000"', '"success":true',
            '"success": true', '"message":"success"', '"message": "success"',
        )
        negative_markers = (
            "invalid uri root", "unauthorized", "未登录", "登录", "forbidden",
            "no permission", "permission denied", "token invalid", "token expired",
        )

        for item in captured:
            try:
                status_code = int(item.get("status_code") or 0)
            except Exception:
                status_code = 0
            if status_code < 200 or status_code >= 300:
                continue

            url = str(item.get("url") or "").lower()
            resource_type = str(item.get("resource_type") or "").lower()
            if resource_type not in ("xhr", "fetch") and "/api/" not in url:
                continue

            headers = item.get("headers") or {}
            lowered_headers = {str(k).lower(): str(v) for k, v in headers.items()}
            if not any(name in lowered_headers and lowered_headers[name] for name in auth_header_names):
                continue

            body = str(item.get("response_body") or "").lower()
            compact_body = body.replace(" ", "")
            if not compact_body:
                continue
            if any(marker.replace(" ", "") in compact_body for marker in positive_markers):
                return True
            if not any(marker.replace(" ", "") in compact_body for marker in negative_markers) and len(compact_body) > 20:
                return True

        return False

    async def _verify_cookie_login(self, page, captured: list[dict] | None = None) -> bool:
        """Cookie/Header 注入后验证登录是否真正生效（通用方法，适用于所有网站）。

        策略：
        1. 导航到 target 页面
        2. 检查最终 URL 是否被重定向到登录页（含 login/signin/auth/sso 等关键词）
        3. 检查页面是否有登录表单特征（password input、登录按钮等）
        4. 如果以上都没命中 → 认为登录成功

        Returns:
            True = 登录态有效，False = 被重定向到登录页/凭证无效
        """
        import asyncio

        try:
            # 导航到目标页面
            resp = await page.goto(self.target, wait_until="domcontentloaded", timeout=15000)

            # ★ 等待 SPA JS 重定向（5 秒，之前 2 秒太短，SPA 路由跳转经常 >2s）
            await asyncio.sleep(5)

            final_url = page.url.lower()

            # ★ 检查 0：SPA error 页面（前端路由守卫判定未登录/出错后跳 #/error 等）
            ERROR_URL_KEYWORDS = ("/error", "/404", "/forbidden", "/no-permission", "/unauthorized")
            if any(kw in final_url for kw in ERROR_URL_KEYWORDS):
                if self._has_authenticated_api_success(captured):
                    self._report(
                        f"  ⚠️ 页面跳转到错误页面: {page.url}，"
                        "但已捕获带认证头的业务 API 成功响应；仅判定 API 登录态有效，页面登录未成功"
                    )
                    return False
                self._report(f"  ⚠️ 页面跳转到错误页面: {page.url}，前端路由守卫判定未登录或出错")
                return False

            # ★ 检查 1：URL 是否包含登录页关键词
            LOGIN_URL_KEYWORDS = (
                "/login", "/signin", "/sign-in", "/sign_in",
                "/auth", "/sso", "/cas/", "/oauth",
                "/accounts/page/login", "/passport/",
                "redirect_uri=", "login_redirect",
            )
            url_has_login = any(kw in final_url for kw in LOGIN_URL_KEYWORDS)

            # ★ 如果 URL 没有登录关键词，直接判定成功（最常见的情况）
            if not url_has_login:
                return True

            # ★ 检查 2：URL 有登录关键词时，进一步检查页面内容
            # （有些网站 URL 里带 auth 但不是登录页，如 /auth/settings）
            try:
                page_indicators = await page.evaluate("""() => {
                    const body = document.body;
                    if (!body) return {hasForm: false, hasLoginBtn: false, text: ''};

                    // 检查是否有密码输入框
                    const pwdInputs = document.querySelectorAll('input[type="password"]');
                    const hasForm = pwdInputs.length > 0;

                    // 检查是否有登录按钮
                    const allBtns = document.querySelectorAll('button, input[type="submit"], a.btn');
                    const loginBtnTexts = ['登录', '登 录', 'login', 'sign in', 'log in', '立即登录'];
                    let hasLoginBtn = false;
                    for (const btn of allBtns) {
                        const txt = (btn.textContent || btn.value || '').trim().toLowerCase();
                        if (loginBtnTexts.some(k => txt.includes(k))) {
                            hasLoginBtn = true;
                            break;
                        }
                    }

                    // 页面文本摘要（用于辅助判断）
                    const text = (body.innerText || '').slice(0, 500).toLowerCase();
                    return {hasForm, hasLoginBtn, text};
                }""")

                has_password_form = page_indicators.get("hasForm", False)
                has_login_btn = page_indicators.get("hasLoginBtn", False)

                # URL 有登录关键词 + 页面有密码框或登录按钮 → 确认是登录页
                if has_password_form or has_login_btn:
                    return False

                # URL 有登录关键词但页面没有登录表单 → 可能是误判（如 /auth/dashboard）
                # 保守策略：认为登录成功
                return True

            except Exception:
                # JS 执行失败（页面可能还在加载）→ 仅靠 URL 判断
                return not url_has_login

        except Exception as e:
            # 导航失败（网络错误等）→ 保守认为注入成功，后续爬取会自然发现问题
            self._report(f"  ⚠️ Cookie 验证导航失败: {e}，保守假设注入成功")
            return True


    @staticmethod
    async def _check_proxy(proxy_url: str, target_url: str = "") -> bool:
        """检查代理是否可用 — 直接通过代理访问目标站点（不依赖外网）。"""
        import httpx
        # 优先用目标站点测试，fallback 到代理自身
        test_urls = []
        if target_url:
            test_urls.append(target_url)
        test_urls.append(f"{proxy_url}/")  # mitmproxy 本身也能响应
        
        for url in test_urls:
            try:
                async with httpx.AsyncClient(proxy=proxy_url, timeout=5, verify=False) as c:
                    resp = await c.get(url)
                    return True
            except Exception:
                continue
        return False
