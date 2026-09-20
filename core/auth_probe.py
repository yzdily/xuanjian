"""F2 — 认证有效性前置探活（0901 P1-C 教训落地）。

token 过期后所有请求返回"token 失效"，玄鉴不探活 → 0 发现告警。
每批次测试开始前，用 1 个已知有数据接口发 1 个请求做探活。
"""
from __future__ import annotations

from typing import Any


class AuthInvalidError(Exception):
    """认证探活失败。"""


def is_auth_blocked(body: str) -> bool:
    """检测响应体是否为认证拦截页面。"""
    if not body:
        return False
    body_lower = body.lower()
    blocked_markers = [
        "token失效",
        '"state":false',
        '"code":401',
        '"code":403',
        "未登录",
        "请先登录",
        "unauthorized",
        "please login",
        "session expired",
        "login expired",
        "access denied",
    ]
    return any(m in body_lower for m in blocked_markers)


def verify_auth_validity(
    baseline_api: dict[str, Any],
    current_credential: dict[str, Any],
    request_fn: Any | None = None,
) -> bool:
    """每批次测试开始前，用 1 个已知接口发 1 个请求做探活。

    Args:
        baseline_api: 已知有数据的接口 {method, url, body}
        current_credential: 当前凭据 {headers, cookies}
        request_fn: 请求回调

    Raises:
        AuthInvalidError: 探活失败
    """
    if not request_fn:
        return True

    resp = request_fn(
        baseline_api.get("method", "GET"),
        baseline_api.get("url", ""),
        headers=current_credential.get("headers", {}),
    )

    status = getattr(resp, "status", 200)
    body = getattr(resp, "body", "") or ""

    if status in (401, 403):
        raise AuthInvalidError(f"探活失败: HTTP {status}")
    if is_auth_blocked(body):
        raise AuthInvalidError("探活失败: 响应为认证拦截")
    if len(body) < 10 and status != 204:
        raise AuthInvalidError("探活失败: 响应体为空")

    return True


__all__ = ["verify_auth_validity", "is_auth_blocked", "AuthInvalidError"]
