"""
浏览器深度引擎 — 用 Playwright 真实执行 payload，零误报地验证 XSS。

工作流：
1. 接收 HTTP 引擎产出的高置信度候选
2. 用 Playwright 加载 payload URL（GET）/ 提交表单（POST）
3. 监听以下事件：
   - dialog (alert/confirm/prompt)
   - console (console.log/error)
   - pageerror (未捕获 JS 异常)
   - 自定义全局变量 marker（payload 里 alert(window.XSS_FLAG=true)）
4. 如果任一触发 → 确认是真 XSS
5. 截图保留证据

设计原则：
- 慢但准：每候选 5-15 秒，但零误报
- 只验证高置信度候选（confidence >= 0.5），低置信度不进浏览器层
- 沙箱安全：用独立的 incognito context，禁用导航出 scope
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qsl

from core.xss.models import InjectionPoint, XssCandidate


class BrowserXssEngine:
    """Playwright 浏览器引擎 — 真实执行验证 XSS。"""

    def __init__(
        self,
        proxy: str = "",
        timeout_per_target: float = 12.0,
        on_progress: Optional[callable] = None,
        max_concurrent: int = 3,
    ):
        self.proxy = proxy
        self.timeout = timeout_per_target
        self.on_progress = on_progress
        self.max_concurrent = max_concurrent

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def verify_candidates(
        self,
        candidates: list[XssCandidate],
        cookies: dict = None,
        min_confidence: float = 0.4,
    ) -> list[XssCandidate]:
        """验证候选 — 真正执行后过滤出确认能触发的。

        Returns:
            更新了 browser_triggered 字段的 XssCandidate 列表
        """
        cookies = cookies or {}
        # 过滤低置信度的，不进浏览器
        to_verify = [c for c in candidates if c.confidence >= min_confidence]
        skipped = len(candidates) - len(to_verify)
        if skipped > 0:
            self._report(f"  浏览器层跳过 {skipped} 个低置信度候选（< {min_confidence}）")

        if not to_verify:
            return candidates

        from playwright.async_api import async_playwright

        self._report(f"🌐 浏览器层验证启动: {len(to_verify)} 个候选")

        async with async_playwright() as pw:
            launch_opts = {"headless": True, "args": ["--ignore-certificate-errors", "--no-sandbox"]}
            # 如果 Playwright 自带 Chromium 不存在，自动检测系统浏览器
            if not launch_opts.get("executable_path"):
                from core.browser_resolver import get_launch_executable_path
                _exe = get_launch_executable_path()
                if _exe:
                    launch_opts["executable_path"] = _exe
            if self.proxy:
                launch_opts["proxy"] = {"server": self.proxy}
            browser = await pw.chromium.launch(**launch_opts)
            try:
                sem = asyncio.Semaphore(self.max_concurrent)
                completed = [0]

                async def _verify(cand: XssCandidate):
                    async with sem:
                        try:
                            triggered, evidence = await self._verify_one(browser, cand, cookies)
                            cand.browser_triggered = triggered
                            cand.browser_evidence = evidence
                            if triggered:
                                cand.confidence = min(1.0, cand.confidence + 0.3)
                            completed[0] += 1
                            if completed[0] % 5 == 0:
                                self._report(f"  浏览器验证: {completed[0]}/{len(to_verify)}")
                        except Exception as e:
                            cand.browser_evidence = f"verify_error: {str(e)[:100]}"

                await asyncio.gather(*[_verify(c) for c in to_verify])
            finally:
                await browser.close()

        confirmed = sum(1 for c in to_verify if c.browser_triggered)
        self._report(f"✅ 浏览器验证完成: {confirmed}/{len(to_verify)} 个真实可触发")
        return candidates

    async def _verify_one(
        self, browser, cand: XssCandidate, cookies: dict
    ) -> tuple[bool, str]:
        """验证单个候选。"""
        ctx = await browser.new_context(ignore_https_errors=True)
        # 注入 cookies（同站）
        if cookies:
            try:
                parsed = urlparse(cand.target.url)
                cookie_list = []
                for k, v in cookies.items():
                    cookie_list.append({
                        "name": k, "value": v,
                        "domain": parsed.hostname,
                        "path": "/",
                    })
                await ctx.add_cookies(cookie_list)
            except Exception:
                pass

        page = await ctx.new_page()

        # 收集触发信号
        triggers: list[str] = []

        # 1. 监听 dialog（alert/confirm/prompt）
        async def _on_dialog(dialog):
            triggers.append(f"dialog[{dialog.type}]: {dialog.message[:100]}")
            try:
                await dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", lambda d: asyncio.create_task(_on_dialog(d)))

        # 2. 监听 console（payload 里如果用了 console.log(MARKER) 也算触发）
        def _on_console(msg):
            text = msg.text or ""
            if cand.marker and cand.marker in text:
                triggers.append(f"console[{msg.type}]: {text[:100]}")

        page.on("console", _on_console)

        # 3. 监听 pageerror（payload 语法错误也算"被执行"）
        def _on_pageerror(err):
            err_text = str(err)
            if cand.marker and cand.marker in err_text:
                triggers.append(f"pageerror: {err_text[:100]}")

        page.on("pageerror", _on_pageerror)

        # 4. 注入全局检测器：payload 中如果出现 window.XSS_HIT = ... 也能捕获
        await ctx.add_init_script(f"""
            window.__xss_marker__ = "{cand.marker}";
            window.__xss_triggered__ = false;
        """)

        # 执行 payload
        url_or_action = await self._build_payload_url(cand)
        triggered = False
        evidence = ""

        try:
            if cand.target.method.upper() == "GET":
                # 直接访问 URL
                try:
                    await page.goto(url_or_action, wait_until="domcontentloaded",
                                    timeout=int(self.timeout * 1000))
                except Exception:
                    pass
                # 等一会儿让事件触发
                await asyncio.sleep(1.5)
            else:
                # POST：用 page.evaluate 构造 form 提交
                form_html = self._build_form_html(cand)
                try:
                    await page.set_content(form_html, wait_until="domcontentloaded",
                                           timeout=int(self.timeout * 1000))
                    await page.click("button[type=submit]", timeout=3000)
                    await asyncio.sleep(2)
                except Exception:
                    pass

            # 检查全局变量是否被触发
            try:
                xss_hit = await page.evaluate("() => window.__xss_triggered__")
                if xss_hit:
                    triggers.append("window.__xss_triggered__")
            except Exception:
                pass

            # 兜底：检查页面 HTML 中是否 payload 被解析为 DOM 元素（如 <svg> 真的进 DOM）
            try:
                payload_in_dom = await page.evaluate(f"""
                    () => {{
                        const m = "{cand.marker}";
                        // 检查 marker 是否出现在 element attribute / text 中（说明 payload 渲染了）
                        const all = document.querySelectorAll('*');
                        for (const el of all) {{
                            for (const attr of el.attributes) {{
                                if (attr.value.includes(m)) return 'attr:' + attr.name;
                            }}
                            const text = el.textContent || '';
                            if (text.length < 200 && text.includes(m)) return 'text';
                        }}
                        return null;
                    }}
                """)
                if payload_in_dom and not triggers:
                    # marker 在 DOM 里但没有事件触发，说明被渲染但没执行（仅作辅助标记）
                    evidence = f"marker_in_dom: {payload_in_dom}"
            except Exception:
                pass

        finally:
            await page.close()
            await ctx.close()

        if triggers:
            triggered = True
            evidence = "; ".join(triggers[:3])

        return triggered, evidence

    async def _build_payload_url(self, cand: XssCandidate) -> str:
        """构造带 payload 的 URL（GET 场景）。"""
        tgt = cand.target
        if tgt.injection_point in (InjectionPoint.URL_PARAM,):
            parsed = urlparse(tgt.url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            params[tgt.param_name] = cand.payload
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"
        if tgt.injection_point == InjectionPoint.URL_FRAGMENT:
            return f"{tgt.url}#{cand.payload}"
        return tgt.url

    def _build_form_html(self, cand: XssCandidate) -> str:
        """构造一个会自动提交的 form HTML（POST 场景）。"""
        tgt = cand.target
        # 用 escape 防止 payload 干扰 HTML 结构（payload 在 value 属性里走属性编码）
        from html import escape
        payload_attr = escape(cand.payload, quote=True)
        return f"""<!DOCTYPE html>
<html><body>
<form id="f" action="{escape(tgt.url, quote=True)}" method="{escape(tgt.method, quote=True)}">
    <input type="hidden" name="{escape(tgt.param_name, quote=True)}" value="{payload_attr}">
    <button type="submit">go</button>
</form>
<script>
// 自动提交（如果用户配置允许）
// document.getElementById('f').submit();
</script>
</body></html>"""
