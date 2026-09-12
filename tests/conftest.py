"""
共享测试固件（fixtures）

生产级测试基座要点：
1. 日志隔离：测试前把 LOG_DIR 指向临时目录，避免污染 ./data/logs。
2. 确定性：FalsePositiveManager 使用 MemoryRuleStore + 可控时钟，无文件系统副作用。
3. 真实 I/O：提供本地 HTTP 服务器固件，用真实 httpx 响应验证规则引擎，
   而不是只用 MagicMock（MagicMock 无法捕获序列化/编码类回归）。
"""

from __future__ import annotations

import http.server
import os
import tempfile
import threading
from datetime import datetime
from typing import Callable

import pytest

# ---- 1. 日志隔离：在任何 core.* 模块导入前设置 ----
os.environ.setdefault("LOG_DIR", tempfile.mkdtemp(prefix="xj_test_logs_"))
os.environ.setdefault("LOG_LEVEL", "WARNING")


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
