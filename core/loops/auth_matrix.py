"""
core/loops/auth_matrix.py — 三身份授权矩阵 + 凭据域路由（修复 1.4）。

## 解决什么
1. **F3 完整 Cookie 集**：`required_cookies` 参数已存在于
   `credential_injector._wait_for_login_result` / `login_judge.attempt_login`，
   但全仓 0 处实参调用。本模块提供"三身份"维度，让登录判定有据可依。
2. **双域凭据隔离**：凭据按 `applicable_domains` 路由，域不匹配**硬返回空**，
   禁止静默复用全局 token（对齐 api-pentest-workflow 的 P0-B 铁律）。
3. **token ↔ 主体绑定**：同 token 替换 userid 能遍历他人数据 = 认证绕过
   （CWE-287 + CWE-639）。`bind_token_userid` 提供纯 stdlib 的绑定校验。

## 零依赖
JWT 解析只用 base64 + json（stdlib），不引 PyJWT。
"""
from __future__ import annotations

import base64
import json
from typing import Any

# 三身份：无凭据 / 低权限 / 高权限
THREE_IDENTITIES: list[str] = ["noauth", "low", "high"]

# JWT 载荷中常见的"主体标识"字段，按优先级尝试
_SUBJECT_KEYS = ("sub", "user_id", "userId", "uid", "userid", "user", "account")


def _b64url_decode(seg: str) -> bytes | None:
    """base64url 解码，自动补 padding。失败返回 None。"""
    try:
        pad = "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg + pad)
    except Exception:
        return None


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """解析 JWT 的 payload 段（不校验签名，仅读载荷）。非 JWT 返回 None。"""
    if not token or not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    raw = _b64url_decode(parts[1])
    if raw is None:
        return None
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def bind_token_userid(token: str, userid: str) -> bool:
    """校验 token 是否与 userid 绑定。

    命中 JWT 载荷中 sub/user_id/uid/... 任一字段等于 userid → True（已绑定）。
    载荷缺失或全部不等 → False（**可能**是"同 token 换 userid 遍历"的绕过特征）。

    注意：False 只是"未绑定"的**信号**，是否成漏洞由上层结合响应判定
    （200 + 业务成功码 + 数据非空 才算实锤，见 verdict 三层判定）。
    """
    payload = decode_jwt_payload(token)
    if payload is None:
        return False
    for key in _SUBJECT_KEYS:
        val = payload.get(key)
        if val is not None and str(val) == str(userid):
            return True
    return False


def cred_for(domain: str, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    """按 domain 路由取凭据集；域不匹配返回 {}（硬校验，不静默复用全局）。

    Args:
        domain:   域名/业务域标识（如 "webapp" / "fts"）
        registry: 形如 {"credential_sets": [{"applicable_domains": [...], ...}]}

    Returns:
        命中的凭据 dict；无匹配返回 {}。
    """
    if not domain:
        return {}
    sets = (registry or {}).get("credential_sets") or []
    for cred in sets:
        domains = cred.get("applicable_domains") or []
        if domain in domains:
            return cred
    return {}


def identities_covered(identities: list[str] | None) -> bool:
    """三身份是否全覆盖（缺任一项 → 授权矩阵证据不足）。"""
    ids = set(identities or [])
    return all(i in ids for i in THREE_IDENTITIES)


__all__ = [
    "THREE_IDENTITIES",
    "cred_for",
    "bind_token_userid",
    "decode_jwt_payload",
    "identities_covered",
]
