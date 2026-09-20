"""E3-1 · 真实网络验证：对着本地 mock actuator 服务跑完整深挖链。

与 `test_loop_deep_dive_e2e.py`（假 HTTP 层）的区别：本测试**起一个真实 HTTP 服务**，
让 `arequest` / `srequest` 走真的 httpx、真的 socket、真的线程池（`asyncio.to_thread`）。
用于验证三件在假响应下测不到的事：

  1. `FrameworkScanner(request_fn=arequest)` 的 async 约定在真实 event loop 里成立；
  2. `heapdump_download_extract` 的 `asyncio.to_thread` 真能跑通且**不阻塞**事件循环
     （用"下载期间另一个协程能推进"来断言）；
  3. 产物（actuator_url → 明文凭据 → shiro_key）在真实 IO 下逐级传递无误。
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from core.loops import step_handlers as sh
from core.loops.deep_dive import run_deep_dive
from core.sitemap.models import CheckItem, CheckResult, FeaturePoint
from core.sitemap.sitemap import Sitemap

ENV_JSON = {
    "activeProfiles": ["prod"],
    "propertySources": [{
        "name": "applicationConfig",
        "properties": {
            "spring.datasource.url": {"value": "jdbc:mysql://db.internal:3306/app"},
            "spring.datasource.password": {"value": "Sup3rS3cret!"},
        },
    }],
}
HEAPDUMP_BODY = (
    b'cipherKey="kPH+bIxk5D2deZiIxcaaaA=="\n'
    b'spring.datasource.password=Sup3rS3cret!\n'
)


class _Handler(BaseHTTPRequestHandler):
    server_version = "MockActuator/1.0"

    def log_message(self, *args):        # 静音，避免污染测试输出
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/")
        if path in ("", "/actuator"):
            self._send(200, b'{"_links":{}}')
        elif path == "/actuator/env":
            self._send(200, json.dumps(ENV_JSON).encode())
        elif path == "/actuator/heapdump":
            self._send(200, HEAPDUMP_BODY, ctype="application/octet-stream")
        elif path in ("/actuator/beans", "/actuator/mappings", "/actuator/configprops"):
            self._send(200, b"{}")
        else:
            self._send(404, b'{"error":"not found"}')


@pytest.fixture()
def mock_actuator():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    host, port = srv.server_address[0], srv.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


class FakeSession:
    def __init__(self, sitemap: Sitemap):
        self.sitemap = sitemap
        self.task_id = sitemap.task_id
        self.events: list[tuple[str, object]] = []

    def _event(self, event_type: str, data, full: str = "") -> str:
        self.events.append((event_type, data))
        return f"data: {event_type}\n\n"

    def loop_events(self) -> list[dict]:
        return [d for t, d in self.events if t == "loop" and isinstance(d, dict)]


def _session_for(base: str) -> FakeSession:
    sm = Sitemap(target=base, task_id="task_live_loop")
    fp = FeaturePoint(id="fp1", name="首页", related_apis=[f"GET {base}/"])
    fp.checklist.append(CheckItem(
        vuln_type="actuator_exposure", result=CheckResult.VULNERABLE,
        detail="actuator 暴露", severity="critical",
    ))
    sm.features[fp.id] = fp
    return FakeSession(sm)


def test_live_chain_against_mock_actuator(monkeypatch, tmp_path, mock_actuator):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "1")
    monkeypatch.setenv("XJ_LOOP_TRIGGERS", "actuator_exposure")
    # ⚠️ 刻意不 patch sh.arequest / sh.srequest —— 走真实 httpx

    session = _session_for(mock_actuator)

    async def _run():
        async for _ in run_deep_dive(session):
            pass
    asyncio.run(_run())

    ev = session.loop_events()
    assert ev, "链条未产生结构化事件"
    types = sorted(f["vuln_type"] for f in ev[0]["findings"])
    assert types == ["actuator_env_leak", "actuator_exposure", "heapdump_leak"], types

    checks = {c.vuln_type: c for c in session.sitemap.features["fp1"].checklist}
    assert checks["actuator_env_leak"].result == CheckResult.VULNERABLE
    assert checks["heapdump_leak"].result == CheckResult.VULNERABLE
    # 真实 IO 下明文凭据照样落进 detail（报告要明文）
    assert "Sup3rS3cret!" in checks["actuator_env_leak"].detail

    path = Path("data/tasks") / "task_live_loop-loops.json"
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["chains"][0]["status"] == "completed"
    assert payload["chains"][0]["written_back"] == 2


def test_heapdump_download_does_not_block_event_loop(monkeypatch, mock_actuator):
    """`asyncio.to_thread` 的意义：同步重活期间事件循环仍能推进其它协程。"""
    ticks: list[float] = []

    async def ticker(stop_after: float):
        t0 = time.time()
        while time.time() - t0 < stop_after:
            ticks.append(time.time())
            await asyncio.sleep(0.01)

    async def _run():
        ctx = {"base_url": mock_actuator}
        step = {"step": "heapdump_download_extract", "max_size_mb": 32}
        t = asyncio.create_task(ticker(0.05))
        await sh.heapdump_download_extract(step, ctx)
        await t
        return ctx

    ctx = asyncio.run(_run())
    assert ctx.get("shiro_key") == "kPH+bIxk5D2deZiIxcaaaA=="
    assert len(ticks) >= 2, "同步下载期间事件循环被阻塞（ticks 太少）"
