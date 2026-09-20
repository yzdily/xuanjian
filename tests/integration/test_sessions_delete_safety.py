"""删除会话的数据安全护栏 + 四件套 + 回收区 + 空会话清理（I1 / C1 / C2）。

覆盖 PRD 8.1 与 IMPACT C1/C2：
1. 运行中会话删除 → HTTP 409（含 task_id 与 hint），且**未**取消后台任务、资产完好；
2. 显式 ``force=true`` 可绕过护栏（内部调用能力）；
3. 四件套齐清：`data/tasks/{id}*` / `data/reports/{id}*` /
   `data/scan_artifacts/{id}/` / scan_store 软删；
4. 文件进入 `data/_trash/<ts>/` 而非消失，且回收区不在 reports/tasks 之下（R3）；
5. cleanup 不命中 running / current，并给出 skipped 原因。

全部路径 monkeypatch 到 tmp_path，绝不碰真实 data/。
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import core.scan_store as scan_store
from web._state import STATE, _sessions
from web.api import sessions_api


class _FakeTask:
    """模拟 asyncio.Task：只需 done()/cancel() 两个契约。"""

    def __init__(self, done: bool = False):
        self._done = done
        self.cancelled = False

    def done(self) -> bool:
        return self._done

    def cancel(self) -> None:
        self.cancelled = True
        self._done = True


class _StubSession:
    def __init__(self, bg=None):
        self._bg_task = bg
        self._event_queue = None
        self.sitemap = None


@pytest.fixture()
def env(tmp_path, monkeypatch):
    dirs = SimpleNamespace(
        tasks=tmp_path / "data" / "tasks",
        reports=tmp_path / "data" / "reports",
        artifacts=tmp_path / "data" / "scan_artifacts",
        trash=tmp_path / "data" / "_trash",
    )
    for d in (dirs.tasks, dirs.reports, dirs.artifacts):
        d.mkdir(parents=True)

    monkeypatch.setattr(sessions_api, "TASKS_DIR", dirs.tasks)
    monkeypatch.setattr(sessions_api, "REPORTS_DIR", dirs.reports)
    monkeypatch.setattr(sessions_api, "ARTIFACTS_DIR", dirs.artifacts)
    monkeypatch.setattr(sessions_api, "TRASH_DIR", dirs.trash)
    monkeypatch.setattr(scan_store, "_DB_PATH", tmp_path / "scan_store.db")
    monkeypatch.setattr(scan_store._state, "conn", None)

    saved_sessions = dict(_sessions)
    saved_cur = STATE["current_session_id"]
    _sessions.clear()
    STATE["current_session_id"] = None

    app = FastAPI()
    app.include_router(sessions_api.router)
    client = TestClient(app)
    client._dirs = dirs

    yield client

    _sessions.clear()
    _sessions.update(saved_sessions)
    STATE["current_session_id"] = saved_cur
    if scan_store._state.conn is not None:
        scan_store._state.conn.close()
        scan_store._state.conn = None


def _seed_task(client, tid: str, *, features=None, chat: bool = False) -> None:
    """在磁盘上造出该会话的全部资产（sitemap / report / artifact）。"""
    d = client._dirs
    feats = features if features is not None else {"f1": {"name": "x"}}
    target = "https://shop.example.com" if feats else ""
    (d.tasks / f"{tid}-sitemap.json").write_text(
        json.dumps({"task_id": tid, "target": target, "features": feats}),
        encoding="utf-8",
    )
    if chat:
        (d.tasks / f"{tid}-chat.jsonl").write_text('{"type":"user"}\n', encoding="utf-8")
    (d.reports / f"{tid}-realtime-report.md").write_text("# report", encoding="utf-8")
    ad = d.artifacts / tid
    ad.mkdir(parents=True, exist_ok=True)
    (ad / "report.sarif").write_text("{}", encoding="utf-8")


# ---------------------------------------------------------------- ① running 409

def test_delete_running_returns_409_and_keeps_assets(env):
    _seed_task(env, "task_run")
    bg = _FakeTask(done=False)
    _sessions["task_run"] = _StubSession(bg)

    res = env.post("/api/sessions/delete", json={"task_id": "task_run"})

    assert res.status_code == 409
    body = res.json()
    assert body["error"] == "会话正在扫描，请先停止任务再删除"
    assert body["task_id"] == "task_run"
    assert body["hint"] == "POST /api/stop 后可重试"
    # 护栏必须"先拦后动"：任务未被取消、会话未弹出、资产完好
    assert bg.cancelled is False
    assert "task_run" in _sessions
    assert (env._dirs.tasks / "task_run-sitemap.json").exists()
    assert (env._dirs.artifacts / "task_run").exists()


# ---------------------------------------------------------------- ② force 绕过

def test_force_bypasses_guard_and_cancels_task(env):
    _seed_task(env, "task_run")
    bg = _FakeTask(done=False)
    _sessions["task_run"] = _StubSession(bg)

    res = env.post("/api/sessions/delete", json={"task_id": "task_run", "force": True})

    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert bg.cancelled is True                      # 护栏通过后才 cancel
    assert "task_run" not in _sessions


# ---------------------------------------------------------------- ③④ 四件套 + 回收区

def test_delete_clears_four_pieces_into_trash(env):
    _seed_task(env, "task_x")
    scan_store.upsert_scan("task_x", "https://shop.example.com", status="finished")
    scan_store.upsert_vuln("task_x", "f1", "XSS", severity="high")

    res = env.post("/api/sessions/delete", json={"task_id": "task_x"})
    assert res.status_code == 200
    d = env._dirs

    # ① tasks ② reports ③ scan_artifacts 均已离开原位
    assert not (d.tasks / "task_x-sitemap.json").exists()
    assert not (d.reports / "task_x-realtime-report.md").exists()
    assert not (d.artifacts / "task_x").exists()

    # ④ scan_store 软删：默认列表不含，显式排查可取到
    assert scan_store.get_scan("task_x")["status"] == "deleted"
    assert all(s["task_id"] != "task_x" for s in scan_store.list_scans())
    assert [s["task_id"] for s in scan_store.list_scans(include_deleted=True)] == ["task_x"]

    # ④ 文件"进回收区"而非消失，且回收区在 data/_trash/ 下（不在 reports/tasks 内）
    trashed = Path(res.json()["trashed_dir"])
    assert trashed.exists() and trashed.parent == d.trash
    assert d.reports.resolve() not in trashed.resolve().parents
    assert d.tasks.resolve() not in trashed.resolve().parents
    names = {p.name for p in trashed.iterdir()}
    assert {"task_x-sitemap.json", "task_x-realtime-report.md", "task_x"} <= names
    assert (trashed / "task_x" / "report.sarif").exists()

    # 报告中心（纯 iterdir + 后缀过滤）看不到回收区里的 .md
    assert [p.name for p in d.reports.iterdir() if p.suffix == ".md"] == []


def test_delete_reports_and_tasks_are_moved_not_copied(env):
    """原位置必须真的空了（是 move 而非 copy）。"""
    _seed_task(env, "task_m")
    env.post("/api/sessions/delete", json={"task_id": "task_m"})
    assert list(env._dirs.tasks.glob("task_m*")) == []
    assert list(env._dirs.reports.glob("task_m*")) == []


# ---------------------------------------------------------------- ⑤ cleanup

def test_cleanup_skips_running_and_current(env):
    _seed_task(env, "task_empty", features={})       # 空会话 → 应被清
    _seed_task(env, "task_run")                      # running → skip
    _seed_task(env, "task_cur")                      # current → skip
    _seed_task(env, "task_full")                     # 有 target/features → 不动
    _sessions["task_run"] = _StubSession(_FakeTask(done=False))
    STATE["current_session_id"] = "task_cur"

    res = env.post("/api/sessions/cleanup")

    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["removed"] == 1
    assert body["removed_ids"] == ["task_empty"]
    assert {s["task_id"]: s["reason"] for s in body["skipped"]} == {
        "task_run": "running",
        "task_cur": "current",
    }
    # 被清理者进回收区；running / current / 非空会话资产完好
    assert not (env._dirs.tasks / "task_empty-sitemap.json").exists()
    assert (env._dirs.tasks / "task_run-sitemap.json").exists()
    assert (env._dirs.tasks / "task_cur-sitemap.json").exists()
    assert (env._dirs.tasks / "task_full-sitemap.json").exists()


def test_cleanup_keeps_empty_session_with_chat_history(env):
    _seed_task(env, "task_chat", features={}, chat=True)
    body = env.post("/api/sessions/cleanup").json()
    assert body["removed"] == 0
    assert body["removed_ids"] == []
    assert (env._dirs.tasks / "task_chat-chat.jsonl").exists()
