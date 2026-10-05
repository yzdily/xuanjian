"""
共享测试固件（fixtures）

生产级测试基座要点：
1. 日志隔离：测试前把 LOG_DIR 指向临时目录，避免污染 ./data/logs。
2. 确定性：FalsePositiveManager 使用 MemoryRuleStore + 可控时钟，无文件系统副作用。
3. 真实 I/O：提供本地 HTTP 服务器固件，用真实 httpx 响应验证规则引擎，
   而不是只用 MagicMock（MagicMock 无法捕获序列化/编码类回归）。
4. 环境诊断：会话启动探测 socketpair 可用性——受限网络环境下 Windows asyncio
   事件循环创建必失败（WinError 10051 / '_ssock' AttributeError），提前警告
   让"环境红"与"代码红"可区分（XUANJIAN_TECHNICAL_OPTIMIZATION_PLAN P0-T1）。
5. 单例隔离：每个用例结束后重置共享单例（如 core/fuzz/base.py 的模块级
   httpx.AsyncClient），切断跨测试/跨事件循环泄漏。
"""

from __future__ import annotations

import http.server
import os
import socket
import tempfile
import threading
import warnings
from datetime import datetime
from typing import Callable

import pytest

# ---- 1. 日志隔离：在任何 core.* 模块导入前设置 ----
os.environ.setdefault("LOG_DIR", tempfile.mkdtemp(prefix="xj_test_logs_"))
os.environ.setdefault("LOG_LEVEL", "WARNING")


# ---- 0. 会话启动环境诊断（P0-T1）----
@pytest.fixture(scope="session", autouse=True)
def _env_network_diagnostic():
    """探测 socketpair 可用性，受限环境提前给出自解释警告。

    Windows 上每次 asyncio.run() 创建事件循环都依赖 socketpair()
    （内部绑定 + 连接 127.0.0.1:<临时端口>）。受限网络环境下该调用被阻断，
    产生大量 WinError 10051 / 'ProactorEventLoop' object has no attribute
    '_ssock' 失败，掩盖真实测试结果。会话启动时先探一次，让"环境红"
    与"代码红"在 warnings 汇总中一眼可辨。
    """
    try:
        a, b = socket.socketpair()
    except OSError as exc:
        # ASCII 文本：避免 GBK 控制台乱码，保证任何 codepage 下可读
        warnings.warn(
            "[xuanjian-test] Network-restricted environment detected: "
            f"socket.socketpair() failed ({exc}). On Windows, asyncio event "
            "loop creation depends on socketpair, so ALL asyncio tests will "
            "fail with WinError 10051 / '_ssock' AttributeError. These are "
            "ENVIRONMENT failures, not product bugs - rerun in an "
            "unrestricted shell or CI to get the real pass rate.",
            UserWarning,
            stacklevel=1,
        )
    else:
        a.close()
        b.close()


# ---- 0b. 每用例单例清理（P0-T1）----
@pytest.fixture(autouse=True)
def _reset_shared_singletons():
    """每个用例结束后重置共享单例，切断跨测试/跨事件循环泄漏。

    core/fuzz/base.py 的模块级 httpx.AsyncClient 单例已通过
    register_resetter("core_fuzz_base__http_client", ...) 注册进 DI，
    此处消费既有钩子（零新机制）。清理失败不掩盖测试结果。
    """
    yield
    try:
        from core.di import reset_singletons

        reset_singletons(["core_fuzz_base__http_client"])
    except Exception:  # noqa: BLE001
        pass


class FakeClock:
    """可被测试推进的时钟，替代 datetime.now 以确定性验证时间相关逻辑。"""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, 0, 0, 0)

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: int = 1) -> None:
        from datetime import timedelta

        self._now = self._now + timedelta(seconds=seconds)


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def fp_manager(fake_clock: FakeClock):
    """每个测试一个全新的、内存态的误报管理器（零 I/O）。"""
    from core.false_positive_manager import FalsePositiveManager, MemoryRuleStore

    return FalsePositiveManager(store=MemoryRuleStore(), clock=fake_clock.now)


@pytest.fixture
def fp_memory_store():
    """直接提供内存存储，便于断言持久化行为。"""
    from core.false_positive_manager import MemoryRuleStore

    return MemoryRuleStore()


class _RouteHandler(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def _dispatch(self) -> None:
        path = self.path.split("?", 1)[0]
        route = self.routes.get(path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, ctype, body = route
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def log_message(self, *args) -> None:  # noqa: D401, ANN001
        pass


@pytest.fixture
def http_target():
    """工厂固件：启动一个本地 HTTP 服务器并返回 base_url。

    用法：
        url = http_target({"/api/x": (200, "application/json", '{"code":500}')})
    服务器在测试结束后自动关闭。
    """
    servers: list[http.server.ThreadingHTTPServer] = []

    def _make(routes: dict[str, tuple[int, str, str]]) -> str:
        handler = type(
            "Handler",
            (_RouteHandler,),
            {"routes": dict(routes)},
        )
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        servers.append(httpd)
        port = httpd.server_address[1]
        return f"http://127.0.0.1:{port}"

    yield _make

    for s in servers:
        s.shutdown()
        s.server_close()
