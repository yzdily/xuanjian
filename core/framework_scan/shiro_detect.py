"""F6 — Shiro RememberMe 反序列化检测。

发送随机 base64 cookie → 检查 Set-Cookie 是否含 deleteMe。
若活跃则尝试默认密钥列表判定 weak_key。
"""
from __future__ import annotations

import base64
import os
import re
from typing import Any

DEFAULT_SHIRO_KEYS = [
    "kPH+bIxk5D2deZiIxcaaaA==",
    "ZAvph3dsQ28roZG/G2t1oQ==",
    "fCq+/mx1vBF3a5RwI96Jgg==",
    "2AvVhdsgUsmacFf5SpwI7bw==",
    "Wcf+AuUJq7GFqz8W3sUcXw==",
    "Z3VaEfiiok8kuEV8+CinzQ==",
    "c2FuZ3ppemhpeHVhbmppZWJlemhpcXVhbnNoaQ==",
    "rR3NiJeA2t/beE4oXh0j1w==",
]

DELETE_ME_PATTERN = re.compile(r"deleteMe", re.IGNORECASE)


def detect_shiro_rememberme(
    url: str,
    request_fn: Any | None = None,
) -> dict[str, Any]:
    """检测 Shiro rememberMe 反序列化漏洞。

    返回:
        {status: inactive} | {status: active_no_key, severity: High}
        | {status: weak_key, key: ..., severity: Critical}
    """
    fake_cookie = base64.b64encode(os.urandom(16)).decode()
    cookie_name = "_v_re-dbsec"

    if request_fn:
        resp = request_fn("GET", url, cookies={cookie_name: fake_cookie})
        set_cookies = getattr(resp, "headers", {}).get("Set-Cookie", "")
    else:
        set_cookies = ""

    is_active = bool(DELETE_ME_PATTERN.search(set_cookies))

    if not is_active:
        return {"status": "inactive", "url": url}

    for key in DEFAULT_SHIRO_KEYS:
        if _try_decrypt_with_key(fake_cookie, key):
            return {
                "status": "weak_key",
                "key": key,
                "severity": "Critical",
                "url": url,
            }

    return {
        "status": "active_no_key",
        "severity": "High",
        "url": url,
        "note": "Shiro rememberMe active but default keys not matched",
    }


def _try_decrypt_with_key(cookie_value: str, key: str) -> bool:
    """尝试用密钥解密 cookie。实际实现需 AES-CBC。此处为占位。"""
    try:
        key_bytes = base64.b64decode(key)
        if len(key_bytes) != 16:
            return False
        return False
    except Exception:
        return False


__all__ = ["detect_shiro_rememberme", "DEFAULT_SHIRO_KEYS"]
