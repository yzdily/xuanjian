"""修复 1.3：F13 spawner 编排钩子（含防空转）。"""
from __future__ import annotations

import asyncio

from core.loops.hypothesis_spawner import (
    MAX_DEPTH_CHAIN,
    MAX_SPAWN_PER_FINDING,
    run_spawner,
)


class _Session:
    task_id = "t-1"
    target = "https://x.test"


def _run(findings, **kw):
    return asyncio.run(run_spawner(_Session(), findings, **kw))


def test_spawns_and_caps_per_finding():
    async def agent(session, finding, info):
        assert info["task_id"] == "t-1"
        return ["d1", "d2", "d3", "d4"]  # 超出上限

    out = _run(
        [{"rule": "actuator_exposure"}],
        should_spawn=lambda f: "actuator",
        spawn_agent=agent,
    )
    assert out == ["d1", "d2", "d3"]
    assert len(out) == MAX_SPAWN_PER_FINDING


def test_no_match_yields_nothing():
    async def agent(*a):
        return ["should-not-appear"]

    out = _run([{"rule": "other"}], should_spawn=lambda f: None, spawn_agent=agent)
    assert out == []


def test_depth_cap_stops_spawn():
    async def agent(*a):
        return ["x"]

    out = _run(
        [{"rule": "actuator_exposure"}],
        depth=MAX_DEPTH_CHAIN,
        should_spawn=lambda f: "actuator",
        spawn_agent=agent,
    )
    assert out == []


def test_empty_findings_returns_empty():
    assert _run([]) == []


def test_non_dict_finding_skipped():
    out = _run(["not-a-dict"], should_spawn=lambda f: "x", spawn_agent=lambda *a: None)
    assert out == []


def test_agent_exception_does_not_break_loop():
    call_count = {"n": 0}

    async def agent(session, finding, info):
        call_count["n"] += 1
        raise RuntimeError("boom")

    out = _run(
        [{"rule": "a"}, {"rule": "b"}],
        should_spawn=lambda f: "hit",
        spawn_agent=agent,
    )
    assert out == []
    assert call_count["n"] == 2  # 第一个失败后仍继续处理第二个


def test_multiple_findings_aggregate():
    async def agent(session, finding, info):
        return [f"desc-{finding['rule']}"]

    out = _run(
        [{"rule": "a"}, {"rule": "b"}],
        should_spawn=lambda f: "hit",
        spawn_agent=agent,
    )
    assert out == ["desc-a", "desc-b"]
