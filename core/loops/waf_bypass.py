"""
core/loops/waf_bypass.py — WAF 绕过三态验证 + 静默剥离检测（§3.7 verify_bypass 三态 + 静默剥离）。

## 为什么需要（grep 核验）
注入原语仅 `core/loops/waf_bypass_primitives.yaml` 23 条静态串
（sql×10 + xss×5 + command×8），缺对"绕过是否真生效"的判定：
- 无 `verify_bypass` 三态（confirmed / passed_waf / waf_blocked）
- 无 `bypass_coverage` 账本（绕过覆盖率记账）
- 无静默剥离检测（WAF 静默丢包→假阴性漏报）
现有 `core/fuzz/waf_bypass.py` 只做"403→200 即停"的 fuzz，未区分"穿过 WAF"
与"确认可利用"，易把静默丢包的空 200 误判为绕过成功（假阳性）。本模块补
三态定性 + 静默剥离告警。

## 能力
- `verify_bypass`：confirmed 须 --confirm 命中（响应体出现确认标记），
  规避静默剥离假阳性；否则只判 passed_waf / waf_blocked。
- `detect_silent_strip`：基线有响应体、WAF 后响应空→静默丢包→告警（漏报高危）。

## 零依赖
纯 stdlib；不模块级 import httpx。`http` 参数为响应 dict（可注入测试 mock）。
"""
from __future__ import annotations

from typing import Any

# WAF 拦截状态码（与 identify_waf.BLOCK_STATUS 对齐，本模块自包含不耦合）
_BLOCK_STATUS = (403, 406, 418, 429, 503)

# WAF 拦截页特征关键词（与 fuzz/waf_bypass.py 对齐）
_BLOCK_KEYWORDS = (
    "blocked", "forbidden", "firewall", "security",
    "access denied", "请求被拦截", "安全拦截", "非法请求",
    "illegal request", "attack detected", "not acceptable", "request rejected",
)

# 三态枚举
WAF_BLOCKED = "waf_blocked"
PASSED_WAF = "passed_waf"
CONFIRMED = "confirmed"


def _code_of(resp: Any) -> int:
    if not isinstance(resp, dict):
        return 0
    v = resp.get("http_code") or resp.get("status") or 0
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _body_of(resp: Any) -> str:
    if not isinstance(resp, dict):
        return ""
    body = resp.get("body")
    if body is None:
        body = resp.get("data") or resp.get("text") or ""
    if isinstance(body, (dict, list)):
        return str(body)
    return str(body) if body else ""


def _has_content(resp: Any) -> bool:
    """响应是否含可读内容（body/data/text 非空）。"""
    if not isinstance(resp, dict):
        return False
    body = resp.get("body")
    if body is None:
        body = resp.get("data") or resp.get("text") or ""
    if isinstance(body, (dict, list)):
        return len(body) > 0
    return bool(str(body).strip())


def _is_blocked(resp: dict[str, Any]) -> bool:
    """响应是否被 WAF 拦截（拦截状态码或拦截页关键词）。"""
    if _code_of(resp) in _BLOCK_STATUS:
        return True
    text = _body_of(resp).lower()
    return any(kw in text for kw in _BLOCK_KEYWORDS)


def verify_bypass(http, payload: str, *, confirm: str | None = None) -> str:
    """"waf_blocked" | "passed_waf" | "confirmed"；confirmed 须 --confirm 命中，规避静默剥离假阳性。

    Args:
        http: 发送 payload 后的响应 dict（含 http_code/body）
        payload: 待验证的注入 payload（上下文）
        confirm: 确认标记串；提供且出现在响应体→confirmed（证明 payload 真执行）
    """
    if _is_blocked(http):
        return WAF_BLOCKED
    # 穿过 WAF；须 --confirm 命中（响应体出现标记）才升为 confirmed，
    # 否则只判 passed_waf，规避静默剥离空 200 的假阳性
    if confirm and confirm in _body_of(http):
        return CONFIRMED
    return PASSED_WAF


def detect_silent_strip(baseline: dict, after: dict) -> bool:
    """WAF 静默丢包致假阴性→告警(漏报高危)。

    基线有响应内容、WAF 后响应空/缺失→WAF 静默丢包（假阴性，漏报高危）。

    Args:
        baseline: 未过 WAF 的基线响应 dict
        after: 过 WAF 后的响应 dict
    """
    return _has_content(baseline) and not _has_content(after)


__all__ = ["verify_bypass", "detect_silent_strip", "WAF_BLOCKED", "PASSED_WAF", "CONFIRMED"]
