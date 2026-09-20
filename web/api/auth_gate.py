"""F17 — 扫描前授权门（strix SOFT 缺口补强 → 玄鉴合规差异化）。

扫描前强制校验：目标是否在书面授权白名单内。
玄鉴若做同类产品，这是 Strix 没有的"硬合规门"。
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class AuthScopeError(Exception):
    """授权范围检查失败。"""


def load_scope_file(scope_path: str | Path) -> dict[str, Any]:
    """加载授权 scope 文件。

    格式:
    {
        "signed": true,
        "domains": ["https://target.example.com", "https://*.example.com"],
        "expires_at": "2026-12-31T23:59:59",
        "signed_by": "John Doe"
    }
    """
    path = Path(scope_path)
    if not path.exists():
        raise AuthScopeError(f"scope 文件不存在: {path}")
    try:
        scope = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AuthScopeError(f"scope 文件解析失败: {exc}")
    return scope


def verify_authorization(target_url: str, scope_file: str | Path | None = None) -> bool:
    """扫描前强制校验：目标是否在书面授权白名单内。

    Args:
        target_url: 待扫描目标 URL
        scope_file: 授权 scope 文件路径

    Raises:
        AuthScopeError: 授权检查失败
    """
    if not scope_file:
        raise AuthScopeError("未提供 scope 文件（需 --scope-file 显式传入）")

    scope = load_scope_file(scope_file)

    if not scope.get("signed"):
        raise AuthScopeError("scope 文件未签名（需线下签字后扫描）")

    domains = scope.get("domains", [])
    target_netloc = urlparse(target_url).netloc.lower()
    target_scheme = urlparse(target_url).scheme.lower()

    matched = False
    for domain in domains:
        domain = domain.strip().lower()
        if domain.startswith("https://") or domain.startswith("http://"):
            d_scheme, _, d_host = domain.partition("://")
            if target_scheme == d_scheme and _match_host(target_netloc, d_host):
                matched = True
                break
        elif _match_host(target_netloc, domain):
            matched = True
            break

    if not matched:
        raise AuthScopeError(
            f"目标 {target_url} 不在授权范围 {domains} 内"
        )

    expires_at = scope.get("expires_at")
    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at)
            if datetime.now() > expiry:
                raise AuthScopeError(f"授权已过期（{expires_at}）")
        except ValueError:
            raise AuthScopeError(f"scope 文件 expires_at 格式非法: {expires_at}")

    return True


def _match_host(target: str, pattern: str) -> bool:
    """检查目标域名是否匹配授权模式（支持 *.example.com 通配）。"""
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return target.endswith(suffix) or target == suffix
    return target == pattern


def enforce_pre_scan_gate(
    target_url: str,
    scope_file: str | Path | None = None,
    *,
    strict: bool | None = None,
) -> dict[str, Any]:
    """扫描前置授权门（SOFT 门，§3.8）。

    设计（与规格 §5 数据流一致）：
      - **未提供 scope 文件** → 默认**告警降级**（不阻断），返回 ``degraded=True``；
        置 ``XJ_AUTH_GATE_STRICT=1`` 或 ``strict=True`` → 改为阻断（抛 AuthScopeError）。
      - **提供了 scope 文件** → 严格校验（签名 / 域名 / 有效期）；
        目标越域或授权过期 → 抛 ``AuthScopeError`` **阻断**。
      - ``XJ_AUTH_GATE=0`` → 整门关闭（返回 ``skipped=True``），零副作用回滚。

    Why SOFT：玄鉴大量使用场景是**自有/内网/靶场**目标，强制要求签字 scope 文件
    会把常规使用全部挡死。故默认"允许但留痕"，把"强制"留给合规部署方开关。

    Returns:
        dict：``{"enforced": bool, "degraded": bool, "skipped": bool,
        "scope_file": str|None, "target": str, "reason": str}``

    Raises:
        AuthScopeError: 目标不在授权范围 / 授权过期 / （strict 模式下）未提供 scope 文件。
    """
    result: dict[str, Any] = {
        "enforced": False,
        "degraded": False,
        "skipped": False,
        "scope_file": str(scope_file) if scope_file else None,
        "target": target_url or "",
        "reason": "",
    }

    if str(os.getenv("XJ_AUTH_GATE", "1")).strip().lower() in ("0", "false", "off", "no"):
        result["skipped"] = True
        result["reason"] = "XJ_AUTH_GATE=0（授权门已关闭）"
        return result

    strict_mode = (
        strict
        if strict is not None
        else str(os.getenv("XJ_AUTH_GATE_STRICT", "0")).strip().lower()
        in ("1", "true", "on", "yes")
    )

    if not scope_file:
        if strict_mode:
            raise AuthScopeError(
                "未提供 scope 文件（XJ_AUTH_GATE_STRICT=1 要求显式授权）"
            )
        result["degraded"] = True
        result["reason"] = "未提供 scope 文件 → 降级放行（SOFT 门；合规部署可置 XJ_AUTH_GATE_STRICT=1 强制）"
        return result

    if not target_url:
        raise AuthScopeError("未提供扫描目标 URL，无法做授权范围校验")

    verify_authorization(target_url, scope_file)
    result["enforced"] = True
    result["reason"] = f"授权范围校验通过（{scope_file}）"
    return result


__all__ = [
    "verify_authorization",
    "load_scope_file",
    "enforce_pre_scan_gate",
    "AuthScopeError",
]
