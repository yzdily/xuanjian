"""附件孤儿清理端点 `POST /api/upload/cleanup`。

覆盖：
1. 默认 dry-run：只列候选，**不删任何文件**，返回 total_bytes；
2. 真删必须 `{"dry_run": false, "confirm": true}`（缺 confirm → 400）；
3. 被任一 `*-chat.jsonl` 引用过的文件**不清理**（轻量字符串包含判定）；
4. 真删先进回收区 `data/_trash/`；`days` 可覆盖默认 7 天。

全部路径 monkeypatch 到 tmp_path，绝不碰真实 data/。
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from web.api import upload_api


@pytest.fixture()
def env(tmp_path, monkeypatch):
    uploads = tmp_path / "data" / "uploads"
    tasks = tmp_path / "data" / "tasks"
    trash = tmp_path / "data" / "_trash"
    uploads.mkdir(parents=True)
    tasks.mkdir(parents=True)

    monkeypatch.setattr(upload_api, "UPLOAD_DIR", uploads)
    monkeypatch.setattr(upload_api, "TASKS_DIR", tasks)
    monkeypatch.setattr(upload_api, "TRASH_DIR", trash)

    app = FastAPI()
    app.include_router(upload_api.router)
    client = TestClient(app)
    client._uploads = uploads
    client._tasks = tasks
    client._trash = trash
    return client


def _make(path: Path, size: int, age_days: float) -> Path:
    path.write_bytes(b"x" * size)
    stamp = time.time() - age_days * 86400
    os.utime(path, (stamp, stamp))
    return path


def _cleanup(client, **body):
    return client.post("/api/upload/cleanup", json=body)


# ---------------------------------------------------------------- ① dry-run

def test_dry_run_lists_candidates_without_deleting(env):
    old = _make(env._uploads / "aaa_old.docx", 100, age_days=10)
    fresh = _make(env._uploads / "bbb_fresh.docx", 200, age_days=1)
    (env._tasks / "task_1-chat.jsonl").write_text(
        '{"data":"data/uploads/aaa2_ref.docx"}\n', encoding="utf-8")
    ref = _make(env._uploads / "aaa2_ref.docx", 300, age_days=10)

    res = _cleanup(env)                              # 默认 dry_run=true
    assert res.status_code == 200
    body = res.json()

    assert body["dry_run"] is True
    assert body["removed"] == 0
    assert body["total_bytes"] == 100
    assert [c["filename"] for c in body["candidates"]] == ["aaa_old.docx"]
    cand = body["candidates"][0]
    assert cand["size"] == 100 and "mtime" in cand and cand["reason"]
    # 不删任何东西
    assert old.exists() and fresh.exists() and ref.exists()
    assert body["trashed_dir"] == ""


# ---------------------------------------------------------------- ② confirm 门槛

def test_real_delete_requires_confirm(env):
    old = _make(env._uploads / "aaa_old.docx", 100, age_days=10)
    res = _cleanup(env, dry_run=False)
    assert res.status_code == 400
    assert "confirm" in res.json()["error"]
    assert old.exists()                                    # 未删
    assert not env._trash.exists()


# ---------------------------------------------------------------- ③ 引用保护

def test_referenced_file_is_never_cleaned(env):
    ref = _make(env._uploads / "abc123_report.docx", 500, age_days=30)
    (env._tasks / "task_1-chat.jsonl").write_text(
        '{"path":"data/uploads/abc123_report.docx"}\n', encoding="utf-8")

    body = _cleanup(env, dry_run=False, confirm=True).json()
    assert body["removed"] == 0
    assert body["candidates"] == []
    assert ref.exists()


# ---------------------------------------------------------------- ④ 真删进回收区

def test_confirm_moves_file_to_trash_and_reports_bytes(env):
    old = _make(env._uploads / "aaa_old.docx", 100, age_days=10)
    keep = _make(env._uploads / "bbb_fresh.docx", 200, age_days=1)

    body = _cleanup(env, dry_run=False, confirm=True).json()

    assert body["dry_run"] is False
    assert body["removed"] == 1
    assert body["total_bytes"] == 100
    assert not old.exists()
    assert keep.exists()
    trashed = Path(body["trashed_dir"])
    assert trashed.exists() and trashed.parent == env._trash
    assert (trashed / "aaa_old.docx").exists()


def test_days_parameter_overrides_default(env):
    two_days = _make(env._uploads / "ccc_two.docx", 50, age_days=2)
    ten_days = _make(env._uploads / "ddd_ten.docx", 60, age_days=10)

    within = _cleanup(env, days=1).json()
    assert [c["filename"] for c in within["candidates"]] == ["ccc_two.docx", "ddd_ten.docx"]

    wide = _cleanup(env, days=30).json()
    assert wide["candidates"] == []
    assert two_days.exists() and ten_days.exists()


def test_invalid_days_rejected(env):
    assert _cleanup(env, days="abc").status_code == 400
    assert _cleanup(env, days=-1).status_code == 400
