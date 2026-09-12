"""F9 — 普通用户 vs 管理员双身份对照表自动生成。

BOLA/IDOR 检测：对每个端点输出 [低权限, 高权限] 状态码对，标记越权候选。
"""
from __future__ import annotations

import re
from typing import Any

SENSITIVE_FIELD_PATTERNS = [
    r"password",
    r"passwd",
    r"secret",
    r"token",
    r"hash",
    r"phone",
    r"mobile",
    r"idcard",
    r"email",
    r"bank",
    r"card",
    r"balance",
    r"salary",
]


def generate_double_identity_matrix(
    apis: list[dict[str, Any]],
    low_priv_cred: dict[str, Any],
    high_priv_cred: dict[str, Any],
    request_fn: Any | None = None,
) -> list[dict[str, Any]]:
    """对每个端点输出 [低权限, 高权限] 状态码对，标记越权候选。"""
    matrix: list[dict[str, Any]] = []
    for api in apis:
        entry: dict[str, Any] = {
            "endpoint": api.get("path", ""),
            "method": api.get("method", "GET"),
        }

        if request_fn:
            low_resp = request_fn(
                api.get("method", "GET"),
                api.get("path", ""),
                headers=low_priv_cred.get("headers", {}),
            )
            high_resp = request_fn(
                api.get("method", "GET"),
                api.get("path", ""),
                headers=high_priv_cred.get("headers", {}),
            )
            low_status = getattr(low_resp, "status", 200)
            high_status = getattr(high_resp, "status", 200)
            low_body = getattr(low_resp, "body", "")
        else:
            low_status = -1
            high_status = -1
            low_body = ""

        entry["low_status"] = low_status
        entry["high_status"] = high_status

        candidate = _classify_candidate(low_status, high_status, low_body)
        entry["candidate"] = candidate
        entry["sensitive_fields"] = scan_sensitive_fields(low_body)
        matrix.append(entry)

    return matrix


def _classify_candidate(low_status: int, high_status: int, low_body: str) -> str | None:
    """根据状态码对分类越权候选。"""
    if low_status == 403 and high_status == 200:
        return "VERTICAL_PRIV_ESCALATION"
    if low_status == 200 and high_status == 200:
        if contains_sensitive_fields(low_body):
            return "IDOR_SENSITIVE_LEAK"
    if low_status == 200 and high_status == 403:
        return "INVERTED_ACCESS_CONTROL"
    return None


def contains_sensitive_fields(body: str) -> bool:
    body_lower = body.lower()
    return any(re.search(p, body_lower) for p in SENSITIVE_FIELD_PATTERNS)


def scan_sensitive_fields(body: str) -> list[str]:
    """扫描响应体中的敏感字段名。"""
    body_lower = body.lower()
    found: list[str] = []
    for pat in SENSITIVE_FIELD_PATTERNS:
        if re.search(pat, body_lower):
            found.append(pat.replace(r"\\", ""))
    return found


__all__ = [
    "generate_double_identity_matrix",
    "contains_sensitive_fields",
    "scan_sensitive_fields",
]
