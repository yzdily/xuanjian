"""
core/loops/signature_enforcement.py — 签名校验有效性（§2.6.2 / G11，dangan）。

## 判定逻辑
重放请求并**篡改 sign** 后与原始（正确 sign）响应比对：
- 篡改后**仍返回 200 且业务数据一致** → 签名**未生效**（CWE-345 / CWE-347）
- 篡改后被拒（401/403 或业务失败码）→ 签名生效，正常

## 玄鉴现状（grep 核验）
`signature` 在 xuanjian 中仅出现在 JWT/crypto **解析**场景，
**没有"签名校验有效性测试"** → 净新增。
"""
from __future__ import annotations

from typing import Any

_DENY_STATUS = (401, 403, 500)


def _status_of(resp: Any) -> int:
    if not isinstance(resp, dict):
        return 0
    v = resp.get("http_code") or resp.get("status") or 0
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _payload_of(resp: Any) -> str:
    if not isinstance(resp, dict):
        return ""
    body = resp.get("body")
    if body is None:
        body = resp.get("data") or resp.get("text") or ""
    return str(body)


def verify_signature(ok_resp: dict[str, Any], bad_resp: dict[str, Any]) -> dict[str, Any]:
    """比对「正确 sign」与「篡改 sign」两次响应，判定签名是否真生效。

    Returns:
        {"enforced": bool, "reason": str, "cwe": str|None}
        enforced=False 表示签名未生效（是漏洞信号）。
    """
    ok_status, bad_status = _status_of(ok_resp), _status_of(bad_resp)
    ok_body, bad_body = _payload_of(ok_resp), _payload_of(bad_resp)

    # 篡改后被明确拒绝 → 签名生效
    if bad_status in _DENY_STATUS:
        return {"enforced": True, "reason": "篡改 sign 被拒绝", "cwe": None}

    # 篡改后仍成功且返回数据一致 → 签名未生效
    if bad_status == ok_status and bad_body == ok_body and ok_body:
        return {
            "enforced": False,
            "reason": "篡改 sign 后响应与原始一致 → 签名未生效",
            "cwe": "CWE-345/347",
        }

    # 篡改后成功但内容不同（可能走了别的分支）→ 证据不足
    return {"enforced": True, "reason": "篡改 sign 后响应不同（证据不足，不判漏洞）",
            "cwe": None}


__all__ = ["verify_signature"]
