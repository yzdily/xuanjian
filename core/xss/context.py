"""
Context 推断 — 给定 payload 在响应中的位置，推断它处于什么上下文。

这是 XSS 扫描器的核心：context 决定 payload 类型，决定 WAF 绕过策略。

实现思路：
- 找到 marker 在 response body 中的位置
- 向前回溯，找最近的关键字符（< > " ' { } ;）
- 根据上下文模式打标签

例如：
  响应: ... <input value="xxxMARKERxxx"> ...
  位置: 在 <input> 标签的属性值里
  推断: HTML_ATTR (双引号)

  响应: ... <script>var name = "xxxMARKERxxx";</script> ...
  推断: JS_STRING
"""

from __future__ import annotations

import re
from typing import List, Tuple

from core.xss.models import ContextType, EchoMatch


# 预编译正则
_TAG_PATTERN = re.compile(r"</?([a-zA-Z][a-zA-Z0-9]*)", re.IGNORECASE)
_SCRIPT_START = re.compile(r"<script[^>]*>", re.IGNORECASE)
_SCRIPT_END = re.compile(r"</script>", re.IGNORECASE)
_STYLE_START = re.compile(r"<style[^>]*>", re.IGNORECASE)
_STYLE_END = re.compile(r"</style>", re.IGNORECASE)


def find_marker_positions(body: str, marker: str) -> List[int]:
    """找出 marker 在 body 中的所有位置（字节偏移）。"""
    if not marker or not body:
        return []
    positions = []
    start = 0
    while True:
        idx = body.find(marker, start)
        if idx < 0:
            break
        positions.append(idx)
        start = idx + len(marker)
    return positions


def _is_inside_script(body: str, pos: int) -> bool:
    """判断 pos 是否在 <script>...</script> 内部。"""
    before = body[:pos]
    last_script_start = list(_SCRIPT_START.finditer(before))
    last_script_end = list(_SCRIPT_END.finditer(before))
    if not last_script_start:
        return False
    last_open_pos = last_script_start[-1].end()
    if last_script_end:
        last_close_pos = last_script_end[-1].start()
        return last_open_pos > last_close_pos
    return True


def _is_inside_style(body: str, pos: int) -> bool:
    """判断 pos 是否在 <style>...</style> 内部。"""
    before = body[:pos]
    last_style_start = list(_STYLE_START.finditer(before))
    last_style_end = list(_STYLE_END.finditer(before))
    if not last_style_start:
        return False
    last_open_pos = last_style_start[-1].end()
    if last_style_end:
        last_close_pos = last_style_end[-1].start()
        return last_open_pos > last_close_pos
    return True


def _is_inside_html_comment(body: str, pos: int) -> bool:
    """判断 pos 是否在 <!-- ... --> 内部。"""
    before = body[:pos]
    last_open = before.rfind("<!--")
    if last_open < 0:
        return False
    last_close = before.rfind("-->")
    return last_open > last_close


def _detect_attr_context(body: str, pos: int) -> Tuple[ContextType, bool]:
    """检测属性上下文。返回 (context_type, found)。"""
    # 向前回溯找 < 标签起始
    before = body[max(0, pos - 500):pos]
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt < 0 or last_lt < last_gt:
        return ContextType.UNKNOWN, False

    # 在 < 和 pos 之间，说明在标签内
    in_tag = before[last_lt:]
    # 找最近的等号
    last_eq = in_tag.rfind("=")
    if last_eq < 0:
        # 没有等号，可能在标签名/属性名位置（罕见 XSS 场景）
        return ContextType.HTML_ATTR_NOQUOTE, True

    after_eq = in_tag[last_eq + 1:]
    # 跳过空白
    after_eq_stripped = after_eq.lstrip()
    if not after_eq_stripped:
        return ContextType.HTML_ATTR_NOQUOTE, True

    first_char = after_eq_stripped[0]
    # 提取属性名（用于判断是不是 href/src 等 URL 属性）
    attr_name_match = re.search(r"([a-zA-Z-]+)\s*=\s*$", in_tag[:last_eq + 1])
    attr_name = (attr_name_match.group(1) if attr_name_match else "").lower()

    url_attrs = {"href", "src", "action", "formaction", "data", "poster", "background", "cite"}
    event_attrs = attr_name.startswith("on")  # onload, onclick, ...

    if first_char in ('"', "'"):
        # 引号风格属性
        if attr_name in url_attrs:
            return ContextType.HTML_ATTR_EVENT, True
        if event_attrs:
            return ContextType.JS_CODE, True
        return ContextType.HTML_ATTR, True
    else:
        # 无引号属性
        if attr_name in url_attrs:
            return ContextType.HTML_ATTR_EVENT, True
        return ContextType.HTML_ATTR_NOQUOTE, True


def _detect_js_context(body: str, pos: int) -> ContextType:
    """已知在 <script> 内部，进一步判断 JS context 子类型。"""
    before = body[max(0, pos - 200):pos]

    # 找最近的引号或反引号
    last_double = before.rfind('"')
    last_single = before.rfind("'")
    last_back = before.rfind("`")

    # 简单判定：取最近的那个
    candidates = [
        (last_double, '"', ContextType.JS_STRING),
        (last_single, "'", ContextType.JS_STRING),
        (last_back, "`", ContextType.JS_TEMPLATE),
    ]
    # 排除已经闭合的引号（找开始时要检查是否成对）
    candidates.sort(key=lambda x: -x[0])
    for offset, quote, ctx in candidates:
        if offset < 0:
            continue
        # 计算从 offset 到 pos 之间，未转义的同种引号数量
        between = before[offset:]
        # 简化判断：如果同种引号在 between 中只出现 1 次（offset 处），则未闭合
        count = 0
        i = 1  # 跳过 offset 那个引号本身
        while i < len(between):
            if between[i] == "\\":
                i += 2
                continue
            if between[i] == quote:
                count += 1
            i += 1
        if count == 0:
            # offset 那个引号未闭合 → 在字符串内
            return ctx
    # 没找到引号 → 在 JS 代码中
    return ContextType.JS_CODE


def detect_context(body: str, marker: str) -> List[EchoMatch]:
    """检测 marker 在响应中所有位置的 context。"""
    matches = []
    positions = find_marker_positions(body, marker)
    for pos in positions:
        snippet_start = max(0, pos - 50)
        snippet_end = min(len(body), pos + len(marker) + 50)
        snippet = body[snippet_start:snippet_end]

        # 优先级判断顺序：注释 > 脚本 > 样式 > 属性 > 文本
        if _is_inside_html_comment(body, pos):
            ctx = ContextType.HTML_COMMENT
        elif _is_inside_script(body, pos):
            ctx = _detect_js_context(body, pos)
        elif _is_inside_style(body, pos):
            ctx = ContextType.CSS
        else:
            attr_ctx, in_attr = _detect_attr_context(body, pos)
            if in_attr:
                ctx = attr_ctx
            else:
                ctx = ContextType.HTML_TEXT

        # 检测是否被 HTML 转义（< 变成 &lt;）
        encoded = False
        sanitized = []
        # 看 marker 周围是否有原 payload 字符被转义
        # 此处只能粗略判断：如果 marker 周围 5 字符内出现 &lt; / &gt; / &quot; 等
        nearby = snippet
        if "&lt;" in nearby or "&gt;" in nearby:
            encoded = True
            if "&lt;" in nearby:
                sanitized.append("<")
            if "&gt;" in nearby:
                sanitized.append(">")
        if "&quot;" in nearby or "&#34;" in nearby:
            encoded = True
            sanitized.append('"')
        if "&apos;" in nearby or "&#39;" in nearby:
            encoded = True
            sanitized.append("'")

        matches.append(EchoMatch(
            snippet=snippet,
            offset=pos,
            context=ctx,
            encoded=encoded,
            sanitized_chars=sanitized,
        ))
    return matches


def detect_sanitization(original_payload: str, response_body: str, marker: str) -> dict:
    """对比原 payload 和响应中的 marker 位置，分析哪些字符被过滤/转义。

    Returns:
        {
            "filtered": ["<", ">"],          # 完全消失的字符
            "encoded": {"<": "&lt;"},        # 被编码的字符
            "intact_chars": ["{","}"],       # 完整保留的特殊字符
            "marker_intact": True,           # marker 本身是否完整
        }
    """
    result = {
        "filtered": [],
        "encoded": {},
        "intact_chars": [],
        "marker_intact": marker in response_body,
    }
    if not result["marker_intact"]:
        # marker 没出现 → 整个 payload 被拦截 / 编码 / 不回显
        return result

    # 检查每个特殊字符是否在 marker 附近出现
    special_chars = ['<', '>', '"', "'", '(', ')', '/', '\\', ';', '`', '{', '}']
    pos = response_body.find(marker)
    if pos < 0:
        return result
    nearby = response_body[max(0, pos - 200):pos + len(marker) + 200]

    encoded_map = {
        '<': ['&lt;', '&#60;', '&#x3c;'],
        '>': ['&gt;', '&#62;', '&#x3e;'],
        '"': ['&quot;', '&#34;', '&#x22;'],
        "'": ['&apos;', '&#39;', '&#x27;'],
        '(': ['&#40;', '&#x28;'],
        ')': ['&#41;', '&#x29;'],
    }
    for ch in special_chars:
        if ch in original_payload:
            if ch in nearby:
                result["intact_chars"].append(ch)
            elif ch in encoded_map:
                # 检查是否被实体编码
                for enc in encoded_map[ch]:
                    if enc.lower() in nearby.lower():
                        result["encoded"][ch] = enc
                        break
                else:
                    result["filtered"].append(ch)
            else:
                result["filtered"].append(ch)

    return result
