"""
postMessage / DOM Clobbering 扫描 — P1 现代 SPA 必检漏洞。

postMessage 漏洞：
- 页面 A 监听 message 事件，未校验 event.origin
- 攻击者从 iframe / popup 发任意来源消息
- 处理代码用 event.data 作为 innerHTML/eval/重定向参数
- 一次 message 就能 XSS

DOM Clobbering：
- HTML 元素的 id/name 属性会被自动挂到 window 上
- 如果代码用 `if (window.config) ...` 这种判断
- 攻击者通过 `<form id=config><input name=foo>` 污染 window.config
- 进而绕过安全检查 / 触发 eval

扫描策略：
1. 静态：扫 JS 找 addEventListener('message',...) + event.data 使用模式
2. 动态：用浏览器加载页面 + iframe.postMessage 注入 + 监听执行
3. DOM Clobbering：找 if (window.X) 模式 + 测试 X 是否可被 HTML 污染
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

from core.xss.models import (
    ContextType,
    EchoMatch,
    InjectionPoint,
    InjectionTarget,
    XssCandidate,
    XssType,
)

if TYPE_CHECKING:
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)


# ============================================================
# 静态分析：识别 postMessage handler 风险
# ============================================================
POSTMESSAGE_HANDLER_PATTERNS = [
    # addEventListener('message', handler)
    re.compile(r"""addEventListener\s*\(\s*['"]message['"]""", re.IGNORECASE),
    # window.onmessage = handler
    re.compile(r"""window\.onmessage\s*=""", re.IGNORECASE),
    re.compile(r"""onmessage\s*=\s*(?:function|\()""", re.IGNORECASE),
]

# 危险的 event.data 使用模式
DANGEROUS_DATA_USE = [
    re.compile(r"""\.innerHTML\s*=\s*[^;]*\bdata\b""", re.IGNORECASE),
    re.compile(r"""\.outerHTML\s*=\s*[^;]*\bdata\b""", re.IGNORECASE),
    re.compile(r"""document\.write[ln]?\s*\([^)]*\bdata\b""", re.IGNORECASE),
    re.compile(r"""eval\s*\([^)]*\bdata\b""", re.IGNORECASE),
    re.compile(r"""Function\s*\([^)]*\bdata\b""", re.IGNORECASE),
    re.compile(r"""location(?:\.href)?\s*=\s*[^;]*\bdata\b""", re.IGNORECASE),
    re.compile(r"""insertAdjacentHTML\s*\([^)]*,[^)]*\bdata\b""", re.IGNORECASE),
]

# origin 校验缺失迹象
ORIGIN_CHECK_PATTERN = re.compile(
    r"""(?:event|e|msg)\.origin""", re.IGNORECASE
)


def find_postmessage_risks_in_js(js_text: str, js_url: str = "") -> list[dict]:
    """在 JS 文件中找 postMessage 风险点。

    Returns:
        list of {handler_offset, data_use_offset, data_use_pattern, has_origin_check, code_snippet}
    """
    risks: list[dict] = []
    if not js_text or len(js_text) > 5_000_000:
        return risks

    # 找所有 message handler 位置
    handler_positions: list[int] = []
    for pat in POSTMESSAGE_HANDLER_PATTERNS:
        for m in pat.finditer(js_text):
            handler_positions.append(m.start())

    if not handler_positions:
        return risks

    # 对每个 handler 位置，向后扫 1500 字符（典型 handler 内代码）
    for hpos in handler_positions:
        scan_window = js_text[hpos: hpos + 1500]
        has_origin_check = bool(ORIGIN_CHECK_PATTERN.search(scan_window))

        for dpat in DANGEROUS_DATA_USE:
            for dm in dpat.finditer(scan_window):
                # 该 risk 在 handler 范围内
                full_offset = hpos + dm.start()
                start = max(0, hpos - 30)
                end = min(len(js_text), full_offset + 200)
                snippet = js_text[start: end]
                risks.append({
                    "handler_offset": hpos,
                    "data_use_offset": full_offset,
                    "data_use_pattern": dm.group(0)[:80],
                    "has_origin_check": has_origin_check,
                    "code_snippet": snippet[:600],
                    "js_url": js_url,
                })

    return risks


# ============================================================
# 静态分析：DOM Clobbering 风险
# ============================================================
# 危险模式：if (window.X) / if (X && ...)
DOM_CLOBBERING_PATTERNS = [
    # if (window.config) {...}
    re.compile(r"""\bif\s*\(\s*window\.(\w+)\s*[\)\&\|]""", re.IGNORECASE),
    # var x = window.config || ...
    re.compile(r"""window\.(\w+)\s*\|\|""", re.IGNORECASE),
    # config.value 直接访问（隐式 window.config）
    # 太多误报，跳过
]


def find_dom_clobbering_risks_in_js(js_text: str, js_url: str = "") -> list[dict]:
    """识别 DOM Clobbering 风险点。"""
    risks: list[dict] = []
    if not js_text or len(js_text) > 5_000_000:
        return risks
    seen: set[str] = set()
    for pat in DOM_CLOBBERING_PATTERNS:
        for m in pat.finditer(js_text):
            var_name = m.group(1)
            # 排除常见原生 window 属性
            if var_name.lower() in {"location", "document", "history", "navigator",
                                     "screen", "performance", "console", "fetch",
                                     "localstorage", "sessionstorage", "indexeddb",
                                     "innerwidth", "innerheight", "scrollx", "scrolly",
                                     "name", "top", "self", "parent", "frames",
                                     "addeventlistener", "removeeventlistener",
                                     "setinterval", "settimeout", "clearinterval"}:
                continue
            if var_name in seen:
                continue
            seen.add(var_name)
            start = max(0, m.start() - 40)
            end = min(len(js_text), m.end() + 120)
            risks.append({
                "var_name": var_name,
                "offset": m.start(),
                "code_snippet": js_text[start: end],
                "js_url": js_url,
            })
    return risks[:20]  # 限量


# ============================================================
# 动态验证：浏览器中实测 postMessage XSS
# ============================================================
class PostMessageScanner:
    """postMessage / DOM Clobbering 扫描器。"""

    def __init__(
        self,
        proxy: str = "",
        cookies: dict = None,
        timeout: float = 15.0,
        on_progress: Optional[callable] = None,
        max_pages: int = 15,
    ):
        self.proxy = proxy
        self.cookies = cookies or {}
        self.timeout = timeout
        self.on_progress = on_progress
        self.max_pages = max_pages

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def scan(self, sitemap: "Sitemap") -> list[XssCandidate]:
        """主入口：静态扫 JS → 选关键页面动态验证。"""
        # 1. 静态分析
        pm_risks, clobber_risks = self._static_analyze(sitemap)
        self._report(
            f"  postMessage 静态: {len(pm_risks)} 个风险点; "
            f"DOM Clobbering: {len(clobber_risks)} 个风险点"
        )

        candidates: list[XssCandidate] = []

        # 静态风险转为 candidate（confidence 中等，依赖浏览器验证）
        for risk in pm_risks[:10]:
            target = InjectionTarget(
                url=risk.get("js_url", "") or "",
                method="GET",
                injection_point=InjectionPoint.URL_FRAGMENT,
                param_name="postMessage",
                original_value="",
            )
            confidence = 0.45 if not risk.get("has_origin_check") else 0.25
            cand = XssCandidate(
                target=target,
                payload=f"[postMessage handler→{risk.get('data_use_pattern', '')}]",
                marker="",
                echo_matches=[EchoMatch(
                    snippet=risk.get("code_snippet", "")[:300],
                    context=ContextType.JS_CODE,
                    encoded=False,
                )],
                confidence=confidence,
                xss_type=XssType.DOM,
                request_packet=risk.get("code_snippet", "")[:1000],
                response_packet=f"JS 文件: {risk.get('js_url', '')}\n"
                                f"handler offset: {risk.get('handler_offset')}\n"
                                f"has_origin_check: {risk.get('has_origin_check')}",
                scanner="xss_postmessage_static",
            )
            candidates.append(cand)

        for risk in clobber_risks[:8]:
            target = InjectionTarget(
                url=risk.get("js_url", "") or "",
                method="GET",
                injection_point=InjectionPoint.URL_PARAM,
                param_name=risk.get("var_name", ""),
                original_value="",
            )
            cand = XssCandidate(
                target=target,
                payload=f"<form id={risk.get('var_name', '')}><input name=x value=clobbered>",
                marker="",
                echo_matches=[EchoMatch(
                    snippet=risk.get("code_snippet", "")[:300],
                    context=ContextType.HTML_TEXT,
                    encoded=False,
                )],
                confidence=0.3,
                xss_type=XssType.DOM,
                request_packet=risk.get("code_snippet", "")[:600],
                response_packet=f"window.{risk.get('var_name')} 可能被 DOM Clobbering 污染",
                scanner="xss_dom_clobbering",
            )
            candidates.append(cand)

        # 2. 动态验证（如有 postMessage handler，用浏览器实测）
        if pm_risks:
            try:
                dyn_cands = await self._dynamic_postmessage_test(sitemap, pm_risks)
                candidates.extend(dyn_cands)
            except Exception as e:
                log.debug("dynamic postmessage test failed: %s", e)

        return candidates

    def _static_analyze(self, sitemap: "Sitemap") -> tuple[list, list]:
        """静态扫所有 JS。"""
        pm_all: list[dict] = []
        clobber_all: list[dict] = []

        # 复用 dom_analyzer 的 JS 文件采集逻辑
        files: list[tuple[str, str]] = []
        pages = getattr(sitemap, "pages", {}) or {}
        for purl, page in pages.items():
            if isinstance(page, dict):
                js_files = page.get("js_files") or {}
            else:
                js_files = getattr(page, "js_files", {})
            if isinstance(js_files, dict):
                for jsurl, jscontent in js_files.items():
                    if jscontent and isinstance(jscontent, str):
                        files.append((jsurl, jscontent))

        js_analysis = getattr(sitemap, "js_analysis", None) \
                      or getattr(sitemap, "js_analyses", None) or {}
        if isinstance(js_analysis, dict):
            for url, info in js_analysis.items():
                if isinstance(info, dict):
                    content = info.get("content") or info.get("text") or ""
                else:
                    content = str(info)
                if content:
                    files.append((url, content))

        # 去重
        seen = set()
        unique = []
        for url, content in files:
            if url not in seen:
                seen.add(url)
                unique.append((url, content))

        for url, content in unique:
            try:
                pm_all.extend(find_postmessage_risks_in_js(content, js_url=url))
                clobber_all.extend(find_dom_clobbering_risks_in_js(content, js_url=url))
            except Exception:
                continue

        return pm_all, clobber_all

    async def _dynamic_postmessage_test(
        self, sitemap: "Sitemap", risks: list[dict]
    ) -> list[XssCandidate]:
        """选关键页面用 Playwright 注入 postMessage 实测。"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self._report("  ⚠️ playwright 不可用，跳过 postMessage 动态验证")
            return []

        # 选页面：sitemap.pages 的前 N 个（最可能包含 postMessage handler）
        pages = getattr(sitemap, "pages", {}) or {}
        page_urls = list(pages.keys())[: self.max_pages]
        if not page_urls:
            return []

        # 准备 marker（用于检测注入的 postMessage 是否被处理）
        marker = "pmxss" + uuid.uuid4().hex[:10]
        # 构造测试 payload：尝试触发 innerHTML 等 sink
        test_payloads = [
            # 标准对象 + 危险字段
            {"action": "render", "html": f"<img src=x onerror=window.__pm_hit__='{marker}'>"},
            {"type": "exec", "code": f"window.__pm_hit__='{marker}'"},
            # 字符串直接（很多 handler 直接当 innerHTML）
            f"<img src=x onerror=window.__pm_hit__='{marker}'>",
            # JSON.parse 的 string
            f'<script>window.__pm_hit__="{marker}"</script>',
        ]

        candidates: list[XssCandidate] = []

        async with async_playwright() as pw:
            launch_opts = {"headless": True,
                           "args": ["--ignore-certificate-errors", "--no-sandbox",
                                    "--disable-web-security",
                                    "--disable-features=IsolateOrigins,site-per-process"]}
            # 自动检测系统浏览器（如果 Playwright Chromium 不存在）
            from core.browser_resolver import get_launch_executable_path
            _exe = get_launch_executable_path()
            if _exe:
                launch_opts["executable_path"] = _exe
            if self.proxy:
                launch_opts["proxy"] = {"server": self.proxy}
            browser = await pw.chromium.launch(**launch_opts)
            try:
                ctx = await browser.new_context(ignore_https_errors=True)
                if self.cookies:
                    # 注入 cookies 到所有相关域名
                    domain_map: dict[str, list] = {}
                    for url in page_urls:
                        parsed = urlparse(url)
                        if not parsed.hostname:
                            continue
                        for k, v in self.cookies.items():
                            domain_map.setdefault(parsed.hostname, []).append({
                                "name": k, "value": v,
                                "domain": parsed.hostname,
                                "path": "/",
                            })
                    cookie_list = []
                    for ck_list in domain_map.values():
                        cookie_list.extend(ck_list)
                    if cookie_list:
                        try:
                            await ctx.add_cookies(cookie_list)
                        except Exception:
                            pass

                sem = asyncio.Semaphore(2)

                async def _test_page(url: str):
                    async with sem:
                        try:
                            cand = await self._test_one_page(ctx, url, test_payloads, marker)
                            if cand:
                                candidates.append(cand)
                        except Exception as e:
                            log.debug("pm dyn test %s: %s", url, e)

                await asyncio.gather(*[_test_page(u) for u in page_urls])
            finally:
                await browser.close()

        if candidates:
            self._report(f"  🎯 postMessage 动态: {len(candidates)} 个页面真实可触发")
        return candidates

    async def _test_one_page(
        self, ctx, url: str, payloads: list, marker: str
    ) -> Optional[XssCandidate]:
        """对一个页面做 postMessage 注入实测。"""
        page = await ctx.new_page()
        triggered = False
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=int(self.timeout * 1000))
            await asyncio.sleep(1)
            # 注入检测 hook
            await page.evaluate("""
                () => {
                    window.__pm_hit__ = '';
                }
            """)
            # 逐个 payload 发 postMessage
            for payload in payloads:
                try:
                    if isinstance(payload, dict):
                        await page.evaluate(f"""
                            (data) => window.postMessage(data, '*');
                        """, payload)
                    else:
                        await page.evaluate(f"""
                            (s) => window.postMessage(s, '*');
                        """, payload)
                    await asyncio.sleep(0.5)
                    # 检查 hit
                    val = await page.evaluate("() => window.__pm_hit__")
                    if val and marker in str(val):
                        triggered = True
                        break
                except Exception:
                    continue
        finally:
            await page.close()

        if triggered:
            target = InjectionTarget(
                url=url,
                method="POSTMESSAGE",
                injection_point=InjectionPoint.URL_PARAM,
                param_name="postMessage.data",
            )
            return XssCandidate(
                target=target,
                payload=f"window.postMessage({{action:'render', html:'<img src=x onerror=...{marker}>'}}, '*')",
                marker=marker,
                echo_matches=[EchoMatch(
                    snippet=f"postMessage handler 在 {url} 处理 untrusted data",
                    context=ContextType.JS_CODE,
                    encoded=False,
                )],
                confidence=0.95,
                xss_type=XssType.DOM,
                browser_triggered=True,
                browser_evidence=f"window.__pm_hit__ 包含 marker {marker}",
                request_packet=f"页面: {url}\n通过 postMessage 注入 data 后触发 sink",
                response_packet=f"marker={marker} 被写入 window.__pm_hit__",
                scanner="xss_postmessage_dynamic",
            )
        return None
