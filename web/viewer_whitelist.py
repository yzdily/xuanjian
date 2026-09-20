"""web/viewer_whitelist.py — viewer 白名单（§4 Phase 2 item 8，strix §6）。

安全机制：
1. 不可猜 token —— 进程启动时生成 32 字节 URL-safe token，URL 必须携带
2. 邮箱白名单 —— 可配置允许访问的邮箱列表（环境变量 XUANJIAN_VIEWER_EMAILS）
3. 访问日志 —— 所有访问记录（脱敏邮箱 + 时间戳 + IP）

零外部依赖（纯 stdlib）。
"""
from __future__ import annotations

import hmac
import os
import secrets
import time
from pathlib import Path

# per-process 不可猜 token（secrets.token_urlsafe(32)）
_VIEWER_TOKEN: str = secrets.token_urlsafe(32)

# 邮箱白名单（逗号分隔，环境变量配置）
_VIEWER_EMAILS: set[str] = set(
    e.strip().lower()
    for e in os.getenv("XUANJIAN_VIEWER_EMAILS", "").split(",")
    if e.strip()
)

# 访问日志（内存环形，最多 1000 条）
_ACCESS_LOG: list[dict] = []
_MAX_LOG = 1000


def get_viewer_token() -> str:
    """获取当前进程的 viewer 不可猜 token。"""
    return _VIEWER_TOKEN


def verify_viewer_token(token: str | None) -> bool:
    """校验 viewer token（常量时间比较，防时序攻击）。"""
    if not token:
        return False
    return hmac.compare_digest(token, _VIEWER_TOKEN)


def verify_email_whitelist(email: str | None) -> bool:
    """校验邮箱是否在白名单内。白名单为空时允许所有（本地开发）。"""
    if not _VIEWER_EMAILS:
        return True  # 未配置白名单 → 允许（本地开发）
    if not email:
        return False
    return email.strip().lower() in _VIEWER_EMAILS


def check_viewer_access(token: str | None, email: str | None = None,
                        client_ip: str = "") -> dict:
    """综合校验 viewer 访问权限。

    Returns:
        {allowed: bool, reason: str}
    """
    if not verify_viewer_token(token):
        return {"allowed": False, "reason": "invalid_token"}
    if not verify_email_whitelist(email):
        return {"allowed": False, "reason": "email_not_whitelisted"}
    # 记录访问日志
    _ACCESS_LOG.append({
        "ts": time.time(),
        "email": (email or "").lower(),
        "ip": client_ip,
    })
    if len(_ACCESS_LOG) > _MAX_LOG:
        _ACCESS_LOG.pop(0)
    return {"allowed": True, "reason": "ok"}


def get_access_log() -> list[dict]:
    """返回访问日志（脱敏：邮箱仅保留前 2 字符 + @domain）。"""
    out = []
    for entry in _ACCESS_LOG:
        email = entry["email"]
        if "@" in email:
            local, _, domain = email.partition("@")
            masked = (local[:2] + "***@" + domain) if len(local) > 2 else email
        else:
            masked = email or "anonymous"
        out.append({"ts": entry["ts"], "email": masked, "ip": entry["ip"]})
    return out
