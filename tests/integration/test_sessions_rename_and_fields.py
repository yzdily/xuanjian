"""侧栏会话面板的后端契约测试（阶段 2）。

前端面板依赖 `/api/sessions` 下发的派生字段，以及新增的 `/api/sessions/rename`。
这些都是"两端各写一半"的接线，任一端改动都不会报错、只会静默失效 —— 所以钉住契约。

重点覆盖：
1. `/api/sessions` 必须带 `title / raw_target / running / phase / has_credentials / empty`；
   **`running` 必须按后台任务判定**（`_bg_task` 未完成），不能用 `active` ——
   切换会话不会中断旧会话，两者语义不同（UI 分组靠它）。
2. `empty` 判定口径：无目标 + 无功能点 + 无对话历史（前端据此折叠空会话，而不是逐条刷屏）。
3. `rename` 写 sidecar `{task_id}-meta.json`，**不碰 sitemap**（sitemap 参与 diff 快照）；
   净化换行/控制字符与长度（别名会进报告标题）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from web import _state  # noqa: E402
from web.api import sessions_api  # noqa: E402


# ---------------------------------------------------------------- /api/sessions 字段

@pytest.fixture()
def tasks_dir(monkeypatch, tmp_path):
    """把相对路径的 data/tasks 换到临时目录（_list_saved_sessions 内部是相对路径）。"""
    monkeypatch.chdir(tmp_path)
    d = tmp_path / "data" / "tasks"
    d.mkdir(parents=True)
    return d


def test_list_exposes_panel_fields(tasks_dir):
    (tasks_dir / "task_a-sitemap.json").write_text(
        json.dumps({"target": "http://h:8080", "features": {}}), encoding="utf-8")
    (tasks_dir / "task_a-chat.jsonl").write_text("", encoding="utf-8")
    (tasks_dir / "task_a-meta.json").write_text(
        json.dumps({"title": "某某公司某某系统URL测试"}), encoding="utf-8")
    (tasks_dir / "task_b-chat.jsonl").write_text("", encoding="utf-8")   # 无 sitemap/无目标

    sessions = {s["task_id"]: s for s in _state._list_saved_sessions()}

    for key in ("title", "raw_target", "running", "phase", "has_credentials", "empty"):
        assert key in sessions["task_a"], f"面板字段缺失: {key}"

    assert sessions["task_a"]["title"] == "某某公司某某系统URL测试"
    assert sessions["task_a"]["empty"] is False
    assert sessions["task_b"]["empty"] is True          # 无目标无功能点 → 空会话


def test_running_uses_bg_task_not_active(tasks_dir, monkeypatch):
    """running 必须来自 _bg_task；active 只是"当前指针"。"""
    (tasks_dir / "task_run-sitemap.json").write_text(
        json.dumps({"target": "http://h:8080", "features": {}}), encoding="utf-8")

    class _Bg:
        def __init__(self, done): self._done = done
        def done(self): return self._done

    class _Sess:
        phase = "explore"
        _bg_task = _Bg(False)
        sitemap = None

    monkeypatch.setitem(_state.STATE, "current_session_id", "task_run")
    monkeypatch.setitem(_state._sessions, "task_run", _Sess())

    row = next(s for s in _state._list_saved_sessions() if s["task_id"] == "task_run")
    assert row["running"] is True and row["phase"] == "explore"

    # 后台跑完 → running 归 false（即便它仍是当前选中）
    monkeypatch.setitem(_state._sessions, "task_run", type("S", (), {
        "phase": "report", "_bg_task": _Bg(True), "sitemap": None})())
    row2 = next(s for s in _state._list_saved_sessions() if s["task_id"] == "task_run")
    assert row2["running"] is False and row2["active"] is True


# ---------------------------------------------------------------- rename

@pytest.fixture()
def client(monkeypatch, tmp_path):
    tasks = tmp_path / "tasks"
    tasks.mkdir()
    monkeypatch.setattr(sessions_api, "TASKS_DIR", tasks)
    app = FastAPI()
    app.include_router(sessions_api.router)
    c = TestClient(app)
    c._tasks = tasks
    return c


def test_rename_writes_sidecar_not_sitemap(client):
    (client._tasks / "task_x-sitemap.json").write_text('{"target":"http://h"}', encoding="utf-8")

    res = client.post("/api/sessions/rename",
                      json={"task_id": "task_x", "title": "某银行核心系统URL测试"})
    assert res.status_code == 200 and res.json()["status"] == "ok"

    meta = json.loads((client._tasks / "task_x-meta.json").read_text(encoding="utf-8"))
    assert meta["title"] == "某银行核心系统URL测试"
    # ★ sitemap 不得被污染（它参与 diff 快照与报告生成）
    assert json.loads((client._tasks / "task_x-sitemap.json").read_text(encoding="utf-8")) == {"target": "http://h"}


def test_rename_sanitizes_and_truncates(client):
    res = client.post("/api/sessions/rename",
                      json={"task_id": "task_y", "title": "  含\n换行\t与控制\x01字符  " + "长" * 100})
    title = res.json()["title"]
    assert "\n" not in title and "\t" not in title and "\x01" not in title
    assert len(title) <= 60


def test_rename_empty_clears_alias(client):
    client.post("/api/sessions/rename", json={"task_id": "task_z", "title": "临时名"})
    client.post("/api/sessions/rename", json={"task_id": "task_z", "title": "   "})
    meta = json.loads((client._tasks / "task_z-meta.json").read_text(encoding="utf-8"))
    assert "title" not in meta


@pytest.mark.parametrize("bad", ["../evil", "a/b", ".."])
def test_rename_rejects_bad_task_id(client, bad):
    res = client.post("/api/sessions/rename", json={"task_id": bad, "title": "x"})
    assert res.status_code == 400
