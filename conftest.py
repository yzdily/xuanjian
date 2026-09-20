"""
共享测试基础设施（生产级）。

提供跨测试套件复用的 fixture：
- make_response   : 构造 httpx.Response 的工厂（无需真实网络）
- fast_scanner    : FastScanner 实例（_request 由测试自行替换为 mock）
- route_request   : 将 scanner._request 替换为「按 URL 子串路由」的假实现，
                    支持 drop_auth 维度（未授权 / 认证矩阵对照需要）
- sample_target   : 构造 ScanTarget 的工厂

设计原则：
- 所有漏洞检测测试零网络、零 LLM —— 通过替换 self._request 注入伪造响应。
- 同步测试函数内部用 asyncio.run(...) 驱动 async 检测方法，避免依赖 pytest-asyncio。
"""
from __future__ import annotations

import asyncio
from typing import Callable

import httpx
import pytest

from core.fast_scanner import FastScanner, ScanTarget


@pytest.fixture
def make_response():
    """构造 httpx.Response 的工厂。默认 200 + 文本体。"""
    def _make(status_code: int = 200, text: str = "", headers: dict | None = None):
        return httpx.Response(status_code, text=text, headers=headers or {})
    return _make


@pytest.fixture
def fast_scanner():
    """FastScanner 实例。config 显式初始化（防御性），_request 由测试替换。"""
    scanner = FastScanner(max_workers=1, request_rate_limit=0)
    scanner.config = getattr(scanner, "config", None) or {}
    yield scanner


@pytest.fixture
def route_request():
    """安装器：把 scanner._request 换成按 URL 子串路由的假协程。

    mapping        : {url子串: httpx.Response}  用于普通（带认证）请求
    drop_auth_map  : {url子串: httpx.Response}  仅当请求带 drop_auth=True 时生效
                     （用于未授权访问 / 认证矩阵的三身份对照）
    default        : 未命中任何 key 时的兜底响应
    """
    def _install(
        scanner: FastScanner,
        mapping: dict[str, httpx.Response],
        default: httpx.Response | None = None,
        drop_auth_map: dict[str, httpx.Response] | None = None,
    ) -> FastScanner:
        async def _fake(
            method, url, headers=None, content=None,
            drop_auth: bool = False, rule_tag: str = "", payload_tag: str = "",
        ):
            if drop_auth and drop_auth_map:
                for key, resp in drop_auth_map.items():
                    if key in url:
                        return resp
            for key, resp in mapping.items():
                if key in url:
                    return resp
            return default or httpx.Response(200, text="ok")
        scanner._request = _fake
        return scanner
    return _install


@pytest.fixture
def sample_target():
    """构造 ScanTarget 的工厂。"""
    def _make(
        url: str,
        method: str = "GET",
        params: dict | None = None,
        headers: dict | None = None,
        body: str = "",
        auth_headers: dict | None = None,
    ) -> ScanTarget:
        return ScanTarget(
            url=url,
            method=method,
            params=params or {},
            headers=headers or {},
            body=body,
            auth_headers=auth_headers or {},
        )
    return _make


def run_async(coro):
    """在同步测试里驱动 async 协程（检测方法均为 async）。"""
    return asyncio.run(coro)
