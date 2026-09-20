"""E3-2 · 真实网络验证：对着本地 mock Shiro 服务跑完整深挖链。

与 `test_loop_shiro_chain_e2e.py`（假 HTTP 层）的区别：本测试**起一个真实 HTTP 服务**，
让 `srequest` 走真 httpx、真 socket、真线程池（`asyncio.to_thread`）。验证三件假响应测不到的事：

  1. `detect_shiro_rememberme` 期望的**同步** request_fn（`shiro_detect.py:41`）在真实
     httpx 下成立，且 fake cookie 真的被发出去了；
  2. 整函数丢 `asyncio.to_thread` 后不阻塞事件循环；
  3. 链条在第 3 步（C 类）**停下**——mock 服务的请求数必须停在 1（没有任何利用流量）。
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

TRIGGER = "shiro_remmeberme_active"
DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA=="


class _Handler(BaseHTTPRequestHandler):
    server_version = "MockShiro/1.0"
    requests: list[dict] = []          # 类属性：跨请求累加

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).requests.append({
            "path": self.path,
            "cookie": self.headers.get("Cookie", ""),
        })
        body = b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # Shiro rememberMe 活跃的特征：任意请求都回写 deleteMe
        self.send_header("Set-Cookie", "rememberMe=deleteMe; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def mock_shiro():
    _Handler.requests = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
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

    def msgs(self) -> list[str]:
        return [d for t, d in self.events if t == "system" and isinstance(d, str)]

    def loop_events(self) -> list[dict]:
        return [d for t, d in self.events if t == "loop" and isinstance(d, dict)]


def _session_for(base: str) -> FakeSession:
    sm = Sitemap(target=base, task_id="task_live_shiro")
    fp = FeaturePoint(id="fp1", name="首页", related_apis=[f"GET {base}/"])
    fp.checklist.append(CheckItem(
        vuln_type=TRIGGER, result=CheckResult.VULNERABLE,
        detail="Shiro rememberMe 活跃", severity="high",
    ))
    sm.features[fp.id] = fp
    return FakeSession(sm)


def test_live_shiro_chain_against_mock_service(monkeypatch, tmp_path, mock_shiro):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "1")
    monkeypatch.setenv("XJ_LOOP_TRIGGERS", TRIGGER)
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    # ⚠️ 刻意不 patch sh.srequest —— 走真实 httpx / 真 socket / asyncio.to_thread

    session = _session_for(mock_shiro)

    async def _run():
        async for _ in run_deep_dive(session):
            pass
    asyncio.run(_run())

    # ① 真实 HTTP：检测请求带上了 shiro 检测用的随机 cookie
    assert len(_Handler.requests) == 1, _Handler.requests
    assert "_v_re-dbsec=" in _Handler.requests[0]["cookie"]

    ev = session.loop_events()
    assert ev, "链条未产生结构化事件"
    event = ev[0]
    assert event["trigger"] == TRIGGER and event["status"] == "completed"
    assert [f["vuln_type"] for f in event["findings"]] == [
        "shiro_remmeberme_active", "shiro_cipherKey_leak"]

    # ② 第 3 步（C 类）停下等人工确认（三问齐全），且**没有**任何利用请求
    statuses = [s["status"] for s in event["steps"]]
    assert statuses[:2] == ["finding", "finding"], statuses
    assert statuses[2] == "awaiting_manual", statuses
    assert len(event["steps"]) == 3, "C 类步骤未确认前不得继续往下执行"
    manual = event["awaiting_manual"]
    assert [e["step"] for e in manual] == ["construct_deserialization_payload"]
    for entry in manual:
        assert entry["why"].strip() and entry["ready"] and entry["actions"]
    assert len(_Handler.requests) == 1, "C 类步骤产生了网络流量（绝不允许）"

    # ③ 人类可读事件有明确提示（用户要求："至少有个提示"）
    assert any("需人工确认" in m for m in session.msgs())

    # ④ 纵深发现写回原功能点；触发链本身不重复写回
    checks = session.sitemap.features["fp1"].checklist
    added = [c.vuln_type for c in checks if c.source == "loop_deep_dive"]
    assert added == ["shiro_cipherKey_leak"], added

    # ⑤ 落盘带 awaiting_manual，供只读 API / ChainTimeline 渲染
    path = Path("data/tasks") / "task_live_shiro-loops.json"
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    chain = payload["chains"][0]
    assert chain["status"] == "completed"
    assert len(chain["awaiting_manual"]) == 1
    assert chain["steps"][2]["status"] == "awaiting_manual"


def test_srequest_set_cookie_is_case_insensitive(mock_shiro):
    """真实网络才发现：`dict(r.headers)` 会把头名小写化，`headers.get("Set-Cookie")` 就取不到了。

    这里直接钉住 srequest 的响应壳对头名大小写不敏感（否则 Shiro 检测永远判"不活跃"）。
    """
    resp = sh.srequest("GET", mock_shiro + "/")
    assert resp is not None and resp.status == 200
    for name in ("Set-Cookie", "set-cookie", "SET-COOKIE"):
        assert "deleteMe" in resp.headers.get(name, ""), name


def test_sync_detect_does_not_block_event_loop(monkeypatch, mock_shiro):
    """`asyncio.to_thread` 的意义：同步检测期间事件循环仍能推进其它协程。"""
    ticks: list[float] = []

    async def ticker(stop_after: float):
        t0 = time.time()
        while time.time() - t0 < stop_after:
            ticks.append(time.time())
            await asyncio.sleep(0.005)

    async def _run():
        ctx = {"base_url": mock_shiro}
        step = {"step": "detect_rememberme_active"}
        t = asyncio.create_task(ticker(0.08))
        await sh.detect_rememberme_active(step, ctx)
        await t
        return ctx

    ctx = asyncio.run(_run())
    assert ctx["rememberme_active"] is True
    assert len(ticks) >= 3, "同步检测期间事件循环被阻塞（ticks 太少）"
