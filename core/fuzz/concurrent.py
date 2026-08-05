"""
Concurrent — 并发发包基础设施

提供高性能的并发 HTTP 请求能力，供竞态条件验证器等使用。
支持精确的同时发送（尽量让所有请求在同一时刻到达服务器）。
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from core.log import get_logger

log = get_logger("fuzz.concurrent")


# ============================================================
# 共享 HTTP 客户端（连接池复用）
# ============================================================
_http_client: httpx.AsyncClient | None = None


async def get_http_client() -> httpx.AsyncClient:
    """获取共享的 HTTP 客户端（连接池复用）。"""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(30.0, connect=10.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
    return _http_client


@dataclass
class ConcurrentResult:
    """并发请求的结果集"""
    responses: list[dict[str, Any]] = field(default_factory=list)
    total_requests: int = 0
    elapsed_seconds: float = 0.0
    success_count: int = 0
    error_count: int = 0

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.success_count / self.total_requests

    def status_distribution(self) -> dict[int, int]:
        """统计各状态码的分布。"""
        dist: dict[int, int] = {}
        for r in self.responses:
            s = r.get("status", 0)
            dist[s] = dist.get(s, 0) + 1
        return dist


async def send_concurrent(
    requests: list[dict[str, Any]],
    concurrency: int = 50,
    proxy_url: str = "",
    timeout: float = 15.0,
    sync_start: bool = True,
) -> ConcurrentResult:
    """并发发送多个 HTTP 请求。

    Args:
        requests: 请求列表，每个元素为 {"method", "url", "headers", "body"}
        concurrency: 最大并发数
        proxy_url: 代理地址
        timeout: 单请求超时
        sync_start: 是否使用 barrier 同步启动（尽量同时发出）

    Returns:
        ConcurrentResult: 所有响应的汇总
    """
    t0 = time.time()
    result = ConcurrentResult(total_requests=len(requests))

    if not requests:
        return result

    # 使用 barrier 让所有协程同时开始发送
    barrier = asyncio.Barrier(min(len(requests), concurrency)) if sync_start else None
    semaphore = asyncio.Semaphore(concurrency)

    async def _send_one(idx: int, req: dict) -> dict[str, Any]:
        async with semaphore:
            if barrier:
                try:
                    await asyncio.wait_for(barrier.wait(), timeout=5.0)
                except (asyncio.TimeoutError, asyncio.BrokenBarrierError):
                    pass  # 超时就不等了，直接发

            t_start = time.time()
            try:
                kwargs: dict[str, Any] = {
                    "method": req.get("method", "GET").upper(),
                    "url": req["url"],
                    "headers": req.get("headers", {}),
                    "timeout": timeout,
                    "follow_redirects": True,
                }
                if proxy_url:
                    kwargs["proxy"] = proxy_url
                body = req.get("body", "")
                if body:
                    kwargs["content"] = body.encode("utf-8", errors="replace")

                client = await get_http_client()
                resp = await client.request(**kwargs)
                return {
                    "index": idx,
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text[:5000],
                    "elapsed": time.time() - t_start,
                    "error": None,
                }
            except Exception as e:
                return {
                    "index": idx,
                    "status": 0,
                    "headers": {},
                    "body": "",
                    "elapsed": time.time() - t_start,
                    "error": f"{type(e).__name__}: {e}",
                }

    # 并发执行
    tasks = [_send_one(i, req) for i, req in enumerate(requests)]
    responses = await asyncio.gather(*tasks)

    result.responses = sorted(responses, key=lambda r: r["index"])
    result.elapsed_seconds = time.time() - t0
    result.success_count = sum(1 for r in responses if r["error"] is None)
    result.error_count = sum(1 for r in responses if r["error"] is not None)

    return result


async def send_repeated(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    count: int = 50,
    concurrency: int = 50,
    proxy_url: str = "",
    timeout: float = 15.0,
) -> ConcurrentResult:
    """重复发送同一个请求 N 次（竞态条件测试的典型场景）。

    Args:
        method: HTTP 方法
        url: 目标 URL
        headers: 请求头
        body: 请求体
        count: 重复次数
        concurrency: 并发数
        proxy_url: 代理
        timeout: 超时

    Returns:
        ConcurrentResult
    """
    requests = [
        {"method": method, "url": url, "headers": headers or {}, "body": body}
        for _ in range(count)
    ]
    return await send_concurrent(
        requests, concurrency=concurrency,
        proxy_url=proxy_url, timeout=timeout, sync_start=True,
    )
