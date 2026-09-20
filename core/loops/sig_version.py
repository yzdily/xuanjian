"""core/loops/sig_version.py — 多 payload 同目标 N 次请求一致性校验（§3.12.1 (7)）。

签名版本：对同一目标发送 N 次相同/不同 payload，校验响应一致性，
区分：
- 稳定拦截：N 次均 blocked → WAF 规则稳定
- 偶发放行：部分 passed → 可能是 CDN 缓存或 WAF 降级
- 随机响应：响应内容差异大 → 可能是负载均衡到不同后端

零外部依赖（纯 stdlib）。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from core.loops.waf_bypass import CONFIRMED, PASSED_WAF, WAF_BLOCKED, verify_bypass


@dataclass
class SigResult:
    """单次请求的签名结果。"""
    attempt: int
    status: str  # confirmed / passed_waf / blocked
    body_hash: str
    http_code: int = 0


@dataclass
class SigReport:
    """N 次请求的一致性报告。"""
    payload: str
    attempts: list[SigResult] = field(default_factory=list)
    consistency: str = "unknown"  # stable_blocked / stable_passed / mixed / flaky
    confirmed: bool = False


def _body_hash(http: dict) -> str:
    """计算响应 body 的 MD5 签名。"""
    body = ""
    for key in ("body", "text", "content"):
        v = http.get(key) if isinstance(http, dict) else None
        if isinstance(v, str):
            body = v
            break
        if isinstance(v, bytes):
            try:
                body = v.decode("utf-8", errors="ignore")
                break
            except Exception:
                pass
    return hashlib.md5(body.encode("utf-8")).hexdigest()[:16]


async def signature_check(
    request_fn: Callable[..., Awaitable[dict]],
    payload: str,
    *,
    attempts: int = 3,
    confirm: str | None = None,
) -> SigReport:
    """对同一目标发送 N 次 payload，校验响应一致性。

    Args:
        request_fn: async(payload: str) -> dict
        payload: 注入 payload
        attempts: 重复次数（默认 3）
        confirm: 确认标记串

    Returns:
        SigReport
    """
    results: list[SigResult] = []
    for i in range(attempts):
        try:
            http = await request_fn(payload)
        except Exception:
            http = {}
        status = verify_bypass(http, payload, confirm=confirm)
        results.append(SigResult(
            attempt=i,
            status=status,
            body_hash=_body_hash(http),
            http_code=http.get("http_code", 0) if isinstance(http, dict) else 0,
        ))

    # 判断一致性
    statuses = {r.status for r in results}
    hashes = {r.body_hash for r in results}
    confirmed = any(r.status == CONFIRMED for r in results)

    if statuses == {WAF_BLOCKED}:
        consistency = "stable_blocked"
    elif statuses in ({PASSED_WAF}, {CONFIRMED}, {PASSED_WAF, CONFIRMED}):
        consistency = "stable_passed"
    elif len(statuses) > 1:
        consistency = "flaky" if len(hashes) > 1 else "mixed"
    else:
        consistency = "stable" if len(hashes) == 1 else "flaky"

    return SigReport(
        payload=payload,
        attempts=results,
        consistency=consistency,
        confirmed=confirmed,
    )


def is_waf_flaky(report: SigReport) -> bool:
    """判断 WAF 是否存在偶发放行（flaky）。"""
    return report.consistency in ("flaky", "mixed")


def is_bypass_confirmed(report: SigReport) -> bool:
    """判断是否确认绕过。"""
    return report.confirmed


__all__ = [
    "SigResult", "SigReport",
    "signature_check", "is_waf_flaky", "is_bypass_confirmed",
    "CONFIRMED", "PASSED_WAF", "WAF_BLOCKED",
]
