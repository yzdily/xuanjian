"""core/loops/chain_search.py — 多参数链路枚举 + 存储型跨端点验证（§3.12.1 (6)）。

链路枚举：对同一请求的多个参数同时注入，寻找"任一参数可注入即成功"的链路。
存储型验证：在 A 端点提交 payload，在 B 端点（列表/详情页）读取，验证存储型 XSS。

零外部依赖（纯 stdlib）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

from core.loops.waf_bypass import CONFIRMED, PASSED_WAF, WAF_BLOCKED, verify_bypass


@dataclass
class ChainResult:
    """单次链路枚举结果。"""
    param: str
    payload: str
    status: str  # confirmed / passed_waf / blocked
    http: dict = field(default_factory=dict)


async def chain_enumerate(
    request_fn: Callable[..., Awaitable[dict]],
    params: dict[str, str],
    payload: str,
    *,
    confirm: str | None = None,
) -> list[ChainResult]:
    """对多个参数逐个注入同一 payload，返回各参数的 WAF 状态。

    Args:
        request_fn: 异步请求函数 async(params: dict) -> dict
        params: 原始参数字典
        payload: 注入 payload
        confirm: 确认标记串

    Returns:
        list[ChainResult]（按参数顺序）
    """
    results: list[ChainResult] = []
    for param in params:
        injected = dict(params)
        injected[param] = payload
        try:
            http = await request_fn(injected)
        except Exception:
            http = {}
        status = verify_bypass(http, payload, confirm=confirm)
        results.append(ChainResult(param=param, payload=payload, status=status, http=http))
    return results


async def chain_multi_payload(
    request_fn: Callable[..., Awaitable[dict]],
    params: dict[str, str],
    payloads: list[str],
    *,
    confirm: str | None = None,
) -> list[ChainResult]:
    """对所有参数 × 所有 payload 做笛卡尔积枚举，返回全部结果。"""
    results: list[ChainResult] = []
    for payload in payloads:
        for param in params:
            injected = dict(params)
            injected[param] = payload
            try:
                http = await request_fn(injected)
            except Exception:
                http = {}
            status = verify_bypass(http, payload, confirm=confirm)
            results.append(ChainResult(param=param, payload=payload, status=status, http=http))
    return results


@dataclass
class StoredXssResult:
    """存储型 XSS 跨端点验证结果。"""
    submitted_at: str  # 提交端点
    reflected_at: str  # 回显端点
    payload: str
    confirmed: bool
    read_http: dict = field(default_factory=dict)


async def verify_stored_xss(
    submit_fn: Callable[..., Awaitable[dict]],
    read_fn: Callable[..., Awaitable[dict]],
    payload: str,
    *,
    marker: str | None = None,
    submit_endpoint: str = "submit",
    read_endpoint: str = "list",
) -> StoredXssResult:
    """存储型 XSS 跨端点验证：提交 → 读取 → 检测 marker。

    Args:
        submit_fn: async(payload: str) -> dict  提交 payload
        read_fn: async() -> dict  读取回显页面
        payload: 注入 payload
        marker: 回显标记（默认用 payload 本身）
        submit_endpoint / read_endpoint: 仅用于结果标注

    Returns:
        StoredXssResult
    """
    await submit_fn(payload)
    read_http = await read_fn()
    confirm_marker = marker or payload
    confirmed = confirm_marker in _body(read_http)
    return StoredXssResult(
        submitted_at=submit_endpoint,
        reflected_at=read_endpoint,
        payload=payload,
        confirmed=confirmed,
        read_http=read_http,
    )


def _body(http: dict) -> str:
    """从响应 dict 取 body（兼容多种字段名）。"""
    if not http:
        return ""
    for key in ("body", "text", "content"):
        v = http.get(key)
        if isinstance(v, str):
            return v
        if isinstance(v, bytes):
            try:
                return v.decode("utf-8", errors="ignore")
            except Exception:
                pass
    return ""


__all__ = [
    "ChainResult", "StoredXssResult",
    "chain_enumerate", "chain_multi_payload", "verify_stored_xss",
    "CONFIRMED", "PASSED_WAF", "WAF_BLOCKED",
]
