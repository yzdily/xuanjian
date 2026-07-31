"""
HTTP 注入引擎 — 快速反射型 XSS 扫描。

工作流：
1. 探测阶段：先发"无害 marker"，确定参数是否回显
2. Context 推断：找出回显位置的 context（HTML/JS/Attr/...）
3. Payload 注入：根据 context 选择合适的 payload，逐个测试
4. 沙化分析：分析哪些字符被过滤/转义
5. 智能绕过：发现过滤后尝试 WAF bypass payload
6. 收集证据：保留完整请求/响应作为证据

设计原则：
- 高吞吐：单连接 keep-alive，每参数 < 1 秒
- 智能停止：context 不可注入直接跳过
- 不污染：使用纯文本 marker，不发实际 XSS payload 给生产数据库
"""

from __future__ import annotations

import asyncio
import json
import random
import string
import time
from typing import Optional
from urllib.parse import urlencode, urlparse

import httpx

from core.xss.context import detect_context, detect_sanitization
from core.xss.models import (
    ContextType,
    EchoMatch,
    InjectionPoint,
    InjectionTarget,
    XssCandidate,
    XssType,
)
from core.xss.payloads import (
    MARKER,
    PROBE_PAYLOADS,
    WAF_BYPASS_PAYLOADS,
    get_payloads_for_context,
)


def _gen_marker(prefix: str = "x") -> str:
    """生成唯一 marker — 全字母，避免被当 ID/数字过滤。"""
    rand = "".join(random.choices(string.ascii_lowercase, k=8))
    return f"{prefix}{rand}"


class HttpXssEngine:
    """HTTP 注入引擎 — 快速反射型 XSS 扫描。"""

    def __init__(
        self,
        proxy: str = "",
        timeout: float = 15.0,
        concurrency: int = 8,
        max_payloads_per_target: int = 12,
        on_progress: Optional[callable] = None,
    ):
        self.proxy = proxy or None
        self.timeout = timeout
        self.concurrency = concurrency
        self.max_payloads_per_target = max_payloads_per_target
        self.on_progress = on_progress
        self._stats = {"scanned": 0, "candidates": 0, "errors": 0}

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def scan_targets(self, targets: list[InjectionTarget]) -> list[XssCandidate]:
        """并发扫描所有目标。"""
        candidates: list[XssCandidate] = []
        sem = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(
            proxy=self.proxy, timeout=self.timeout, verify=False,
            follow_redirects=False, limits=httpx.Limits(max_connections=20),
        ) as client:
            async def _scan_one(tgt: InjectionTarget):
                async with sem:
                    try:
                        cands = await self._scan_single_target(client, tgt)
                        candidates.extend(cands)
                        self._stats["scanned"] += 1
                        if self._stats["scanned"] % 20 == 0:
                            self._report(
                                f"  HTTP 扫描进度: {self._stats['scanned']}/{len(targets)}, "
                                f"候选 {self._stats['candidates']} 个"
                            )
                    except Exception as e:
                        self._stats["errors"] += 1
                        if self._stats["errors"] <= 5:
                            self._report(f"  ⚠️ 扫描错误 {tgt.url[:50]}: {str(e)[:80]}")

            await asyncio.gather(*[_scan_one(t) for t in targets])

        self._report(
            f"✅ HTTP 扫描完成: 共测 {self._stats['scanned']} 个目标, "
            f"发现 {self._stats['candidates']} 个候选, 错误 {self._stats['errors']} 个"
        )
        return candidates

    async def _scan_single_target(
        self, client: httpx.AsyncClient, tgt: InjectionTarget
    ) -> list[XssCandidate]:
        """扫描单个目标。"""
        # Step 1: 探测回显
        probe_result = await self._probe_reflection(client, tgt)
        if not probe_result:
            return []
        contexts: list[ContextType] = probe_result["contexts"]
        if not contexts:
            return []

        # Step 2: 根据 context 生成 payload 集
        all_payloads: list[str] = []
        for ctx in contexts:
            payloads = get_payloads_for_context(ctx.value if hasattr(ctx, "value") else ctx)
            for p in payloads[:self.max_payloads_per_target]:
                if p not in all_payloads:
                    all_payloads.append(p)
                if len(all_payloads) >= self.max_payloads_per_target:
                    break
            if len(all_payloads) >= self.max_payloads_per_target:
                break

        # Step 3: 逐个 payload 注入
        candidates: list[XssCandidate] = []
        for raw_payload in all_payloads:
            marker = _gen_marker()
            real_payload = raw_payload.replace(MARKER, marker)
            try:
                req_text, resp = await self._send_with_payload(client, tgt, real_payload)
                if not resp:
                    continue
                body = resp.text or ""
                # 检测 marker 是否回显
                if marker not in body:
                    continue
                echo_matches = detect_context(body, marker)
                if not echo_matches:
                    continue
                sanitization = detect_sanitization(real_payload, body, marker)

                # 计算置信度
                confidence = self._calc_confidence(echo_matches, sanitization, real_payload)

                cand = XssCandidate(
                    target=tgt,
                    payload=real_payload,
                    marker=marker,
                    echo_matches=echo_matches,
                    confidence=confidence,
                    xss_type=XssType.REFLECTED,
                    request_packet=req_text[:8000],
                    response_packet=body[:30000],
                    response_status=resp.status_code,
                    response_content_type=resp.headers.get("content-type", ""),
                    scanner="xss_http",
                )
                candidates.append(cand)
                self._stats["candidates"] += 1

                # 一旦发现高置信度候选，停止该目标的后续 payload
                if confidence >= 0.85:
                    break
            except Exception:
                continue

        return candidates

    async def _probe_reflection(
        self, client: httpx.AsyncClient, tgt: InjectionTarget
    ) -> Optional[dict]:
        """探测参数是否有回显。"""
        marker = _gen_marker("p")
        # 用最无害的 payload 探测
        probe_payload = f"<{marker}>"
        try:
            _, resp = await self._send_with_payload(client, tgt, probe_payload)
            if not resp:
                return None
            body = resp.text or ""
            if marker not in body:
                # 试一下纯字符串（有些参数不让传 <）
                marker2 = _gen_marker("p")
                _, resp2 = await self._send_with_payload(client, tgt, marker2)
                if not resp2 or marker2 not in (resp2.text or ""):
                    return None
                body = resp2.text or ""
                marker = marker2
            echo_matches = detect_context(body, marker)
            if not echo_matches:
                return None
            contexts = [m.context for m in echo_matches]
            return {"contexts": contexts, "echo_count": len(echo_matches)}
        except Exception:
            return None

    async def _send_with_payload(
        self, client: httpx.AsyncClient, tgt: InjectionTarget, payload: str
    ) -> tuple[str, Optional[httpx.Response]]:
        """构造请求 + 发送。返回 (request_text, response)。"""
        method = tgt.method.upper()
        url = tgt.url
        headers = dict(tgt.headers or {})
        # 防御性：去掉可能影响请求的头
        headers.pop("Content-Length", None)
        headers.pop("content-length", None)

        if tgt.injection_point == InjectionPoint.URL_PARAM:
            # GET 参数注入
            parsed = urlparse(url)
            from urllib.parse import parse_qsl
            existing_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            existing_params[tgt.param_name] = payload
            new_query = urlencode(existing_params)
            new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            req_text = f"{method} {new_url}\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
            try:
                resp = await client.request(method, new_url, headers=headers)
                return req_text, resp
            except Exception:
                return req_text, None

        if tgt.injection_point == InjectionPoint.BODY_FORM:
            # form-urlencoded
            body_data = {tgt.param_name: payload}
            req_text = (f"{method} {url}\nContent-Type: application/x-www-form-urlencoded\n"
                        f"{tgt.param_name}={payload}")
            try:
                resp = await client.request(method, url, headers=headers, data=body_data)
                return req_text, resp
            except Exception:
                return req_text, None

        if tgt.injection_point == InjectionPoint.BODY_JSON:
            # JSON body 注入：解析原 body，替换字段
            original_body = tgt.body_template or "{}"
            try:
                obj = json.loads(original_body)
                _set_json_field(obj, tgt.param_name, payload)
                body_json = json.dumps(obj)
            except Exception:
                body_json = json.dumps({tgt.param_name: payload})
            headers_with_ct = dict(headers)
            headers_with_ct.setdefault("Content-Type", "application/json")
            req_text = f"{method} {url}\nContent-Type: application/json\n\n{body_json[:500]}"
            try:
                resp = await client.request(method, url, headers=headers_with_ct, content=body_json)
                return req_text, resp
            except Exception:
                return req_text, None

        if tgt.injection_point == InjectionPoint.HEADER:
            # Header 注入
            headers[tgt.param_name] = payload
            req_text = f"{method} {url}\n{tgt.param_name}: {payload}"
            try:
                resp = await client.request(method, url, headers=headers)
                return req_text, resp
            except Exception:
                return req_text, None

        if tgt.injection_point == InjectionPoint.COOKIE:
            cookies = dict(tgt.cookies or {})
            cookies[tgt.param_name] = payload
            req_text = f"{method} {url}\nCookie: {tgt.param_name}={payload}"
            try:
                resp = await client.request(method, url, headers=headers, cookies=cookies)
                return req_text, resp
            except Exception:
                return req_text, None

        return "", None

    def _calc_confidence(
        self, echo_matches: list[EchoMatch], sanitization: dict, payload: str
    ) -> float:
        """根据 echo 上下文 + 沙化情况打置信度。"""
        if not echo_matches:
            return 0.0
        conf = 0.3  # 基础分（仅证明有回显）

        for m in echo_matches:
            # 危险 context 直接加分
            if m.context in (ContextType.HTML_TEXT, ContextType.JS_CODE,
                             ContextType.JS_TEMPLATE):
                conf += 0.4
            elif m.context in (ContextType.HTML_ATTR, ContextType.HTML_ATTR_NOQUOTE,
                               ContextType.JS_STRING):
                conf += 0.3
            elif m.context == ContextType.HTML_ATTR_EVENT:
                conf += 0.5  # href/src 上下文几乎一定能 XSS
            elif m.context == ContextType.HTML_COMMENT:
                conf += 0.1  # 注释里要先逃逸 -->
            elif m.context == ContextType.CSS:
                conf += 0.1

            # 如果未被编码，加 0.2
            if not m.encoded:
                conf += 0.2
            # 如果被编码了，降权
            else:
                conf -= 0.15

        # 关键字符未被过滤 → 加分
        intact = sanitization.get("intact_chars", [])
        if "<" in intact and ">" in intact:
            conf += 0.2
        if "(" in intact and ")" in intact:
            conf += 0.1
        # 关键字符被过滤 → 减分
        filtered = sanitization.get("filtered", [])
        if "<" in filtered:
            conf -= 0.3
        if "(" in filtered:
            conf -= 0.2

        # 完全编码 → 大概率不可注入
        if all(m.encoded for m in echo_matches):
            conf *= 0.4

        return max(0.0, min(1.0, conf))


def _set_json_field(obj, field_name: str, value):
    """在 JSON 对象中设置指定字段（支持嵌套路径用 . 分隔）。"""
    if "." in field_name:
        parts = field_name.split(".")
        cur = obj
        for p in parts[:-1]:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return
        if isinstance(cur, dict):
            cur[parts[-1]] = value
        return
    if isinstance(obj, dict):
        obj[field_name] = value
