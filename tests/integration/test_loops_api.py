"""E3-1 · LOOP 链只读 API 测试。

覆盖：
  1. `/api/loops/matrix` 返回矩阵全部 trigger（前端能力展示的数据源）；
  2. `/api/loops/{task_id}` 无数据时的**空态**（必须给出 enabled_triggers + 人话 hint）；
  3. 有数据时解析出 chains + summary；
  4. task_id 非法字符被拒（**路径穿越防线** —— 这条是真实踩过的坑：
     `validate_task_id` 返回 bool 而非抛异常，try/except 写法会让校验形同虚设）。
"""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from web.api import loops_api
from web.api.loops_api import get_task_loops, loops_matrix


@pytest.fixture()
def client():
    app = FastAPI()
    app.include_router(loops_api.router)
    return TestClient(app)


def test_matrix_lists_all_triggers(client):
    res = client.get("/api/loops/matrix")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 10
    names = {t["trigger"] for t in body["triggers"]}
    assert "actuator_exposure" in names
    actuator = next(t for t in body["triggers"] if t["trigger"] == "actuator_exposure")
    assert actuator["step_count"] == 3
    assert actuator["steps"][0] == "scan_all_actuator_endpoints"
    assert "heapdump_unreachable" in actuator["termination"]
    # E3-1 只默认开这一条
    assert body["enabled_triggers"] == ["actuator_exposure"]
    assert body["loop_enabled"] is True


def test_empty_state_explains_why(client, monkeypatch, tmp_path):
    monkeypatch.setattr(loops_api, "TASKS_DIR", tmp_path)
    res = client.get("/api/loops/task_nothing_here")
    assert res.status_code == 200
    body = res.json()
    assert body["empty"] is True and body["chains"] == []
    assert body["enabled_triggers"] == ["actuator_exposure"]
    # 空态必须能解释原因，否则用户会以为功能坏了
    assert "XJ_LOOP_ENABLED" in body["hint"]
    assert "trigger" in body["hint"]


def test_reads_chain_payload(client, monkeypatch, tmp_path):
    monkeypatch.setattr(loops_api, "TASKS_DIR", tmp_path)
    chains = [{
        "trigger": "actuator_exposure", "origin": "http://h:8080", "status": "completed",
        "steps": [{"step": "scan_all_actuator_endpoints", "status": "ok"}],
        "findings": [{"vuln_type": "actuator_exposure"}, {"vuln_type": "heapdump_leak"}],
        "written_back": 2, "missing_handlers": ["download_heapdump"], "elapsed": 1.2,
    }]
    (tmp_path / "task_abc-loops.json").write_text(
        json.dumps({"task_id": "task_abc", "updated_at": 123.0, "chains": chains}),
        encoding="utf-8")

    res = client.get("/api/loops/task_abc")
    body = res.json()
    assert body["empty"] is False
    assert len(body["chains"]) == 1
    assert body["updated_at"] == 123.0
    assert body["summary"] == {
        "chains": 1, "completed": 1, "findings": 2, "written_back": 2,
        "missing_handlers": ["download_heapdump"],
    }


def test_corrupt_payload_degrades_to_empty(client, monkeypatch, tmp_path):
    monkeypatch.setattr(loops_api, "TASKS_DIR", tmp_path)
    (tmp_path / "task_bad-loops.json").write_text("{ not json", encoding="utf-8")
    res = client.get("/api/loops/task_bad")
    body = res.json()
    assert body["empty"] is True and "损坏" in body["hint"]


# ---------------------------------------------------------------- 安全

@pytest.mark.parametrize("bad", ["../secret", "..", "a/b", "*", "", "x y"])
def test_invalid_task_id_rejected(bad, monkeypatch, tmp_path):
    monkeypatch.setattr(loops_api, "TASKS_DIR", tmp_path)
    res = asyncio.run(get_task_loops(bad))
    assert res.status_code == 400, f"{bad!r} 应被拒绝"


def test_matrix_route_not_shadowed_by_task_id(client):
    """`/api/loops/matrix` 必须先于 `/api/loops/{task_id}` 注册，否则被当成 task_id。"""
    res = client.get("/api/loops/matrix")
    assert res.status_code == 200
    assert "triggers" in res.json()


def test_loops_module_exported_paths():
    paths = [r.path for r in loops_api.router.routes]
    assert paths == ["/api/loops/matrix", "/api/loops/{task_id}"]
