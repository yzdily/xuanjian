"""
test_replay.py — core/replay 模块完整单测

覆盖：
- frame 模型：序列化/反序列化、新 ID 生成
- store：保存/加载/列出/删除剧本
- recorder：事件 payload 转剧本帧
- miner：从剧本反推 lessons
- register：事件订阅幂等性
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from core.events import Events, bus
from core.replay import (
    FrameKind,
    ReplayFrame,
    delete_run,
    list_runs,
    load_script,
    mine_lessons_from_script,
    save_frame,
)
from core.replay.frame import new_frame_id, new_run_id
from core.replay.miner import write_back_to_memory


@pytest.fixture()
def isolated_replay(tmp_path, monkeypatch):
    """重定向 REPLAY_ROOT 到临时目录。"""
    from core.replay import store as store_mod
    monkeypatch.setattr(store_mod, "REPLAY_ROOT", tmp_path / "data" / "replays")
    monkeypatch.chdir(tmp_path)
    yield tmp_path


def _mk_frame(run_id="run1", kind=FrameKind.DECISION, **kw):
    return ReplayFrame(
        frame_id=new_frame_id(),
        run_id=run_id,
        kind=kind,
        timestamp=time.time(),
        **kw,
    )


# ============================================================
# Frame
# ============================================================

class TestFrame:
    def test_to_from_dict_roundtrip(self):
        f = _mk_frame(feature_id="feat_1", vuln_type="sql_injection", payload="' or 1=1")
        d = f.to_dict()
        assert d["kind"] == "decision"
        f2 = ReplayFrame.from_dict(d)
        assert f2.feature_id == "feat_1"
        assert f2.vuln_type == "sql_injection"
        assert f2.kind == FrameKind.DECISION

    def test_from_dict_unknown_kind_falls_back(self):
        f = ReplayFrame.from_dict({
            "frame_id": "x", "run_id": "r", "kind": "unknown_x", "timestamp": 0,
        })
        assert f.kind == FrameKind.NOTE

    def test_from_dict_ignores_unknown_fields(self):
        """未来加新字段时，老剧本读取不应报错。"""
        f = ReplayFrame.from_dict({
            "frame_id": "x", "run_id": "r", "kind": "decision", "timestamp": 0,
            "future_field_xyz": "should be ignored",
        })
        assert f.frame_id == "x"

    def test_new_run_id_unique(self):
        ids = {new_run_id("t") for _ in range(50)}
        assert len(ids) == 50


# ============================================================
# Store
# ============================================================

class TestStore:
    def test_save_and_load(self, isolated_replay):
        f1 = _mk_frame(run_id="r1", feature_name="登录")
        f2 = _mk_frame(run_id="r1", kind=FrameKind.HARM_VALIDATED, conclusion="vulnerable")
        assert save_frame(f1) is True
        assert save_frame(f2) is True

        frames, meta = load_script("r1")
        assert len(frames) == 2
        assert meta["frame_count"] == 2
        assert meta["run_id"] == "r1"

    def test_save_without_run_id_fails(self, isolated_replay):
        f = _mk_frame(run_id="")
        assert save_frame(f) is False

    def test_list_runs_sorted(self, isolated_replay):
        save_frame(_mk_frame(run_id="r1"))
        time.sleep(0.01)
        save_frame(_mk_frame(run_id="r2"))
        runs = list_runs()
        assert len(runs) == 2
        # 按 ended_at 倒序
        assert runs[0]["run_id"] == "r2"

    def test_delete_run(self, isolated_replay):
        save_frame(_mk_frame(run_id="r1"))
        assert delete_run("r1") is True
        assert delete_run("r1") is False

    def test_max_size_protection(self, isolated_replay, monkeypatch):
        from core.replay import store as store_mod
        monkeypatch.setattr(store_mod, "MAX_SCRIPT_SIZE", 100)  # 100 bytes
        # 写若干帧直到超限
        for i in range(50):
            save_frame(_mk_frame(run_id="r1", feature_name=f"large_{i}" * 10))
        # 文件不会无限大
        sf = store_mod._script_file("r1")
        assert sf.stat().st_size <= 100 + 1024  # 容忍一帧的余量


# ============================================================
# Recorder
# ============================================================

class TestRecorder:
    def test_on_worker_decision(self, isolated_replay):
        from core.replay.recorder import on_worker_decision
        on_worker_decision({
            "task_id": "t1",
            "feature_id": "feat_1",
            "feature_name": "登录",
            "vuln_type": "sql_injection",
            "skill_used": "sqli_basic",
            "payload": "' or 1=1",
            "target_url": "https://x.com/login",
        })
        frames, meta = load_script("t1")
        assert len(frames) == 1
        assert frames[0].kind == FrameKind.DECISION
        assert frames[0].vuln_type == "sql_injection"

    def test_on_harm_validated(self, isolated_replay):
        from core.replay.recorder import on_harm_validated
        on_harm_validated({
            "task_id": "t1",
            "feature_id": "feat_1",
            "vuln_type": "sql_injection",
            "conclusion": "vulnerable",
            "severity": "high",
        })
        frames, _ = load_script("t1")
        assert frames[0].kind == FrameKind.HARM_VALIDATED
        assert frames[0].conclusion == "vulnerable"

    def test_no_task_id_uses_process_run_id(self, isolated_replay, monkeypatch):
        # 重置进程级 run_id
        from core.replay import recorder as rec_mod
        monkeypatch.setattr(rec_mod, "_PROCESS_RUN_ID", "")

        rec_mod.on_worker_decision({"feature_name": "x", "vuln_type": "xss"})
        runs = list_runs()
        assert len(runs) == 1
        assert runs[0]["run_id"].startswith("proc_")


# ============================================================
# Miner
# ============================================================

class TestMiner:
    def test_pair_decision_with_validation(self):
        frames = [
            _mk_frame(run_id="r1", kind=FrameKind.DECISION,
                      feature_id="f1", vuln_type="sql", skill_used="sqli", payload="x"),
            _mk_frame(run_id="r1", kind=FrameKind.HARM_VALIDATED,
                      feature_id="f1", vuln_type="sql", conclusion="vulnerable"),
        ]
        out = mine_lessons_from_script(frames, min_total=1, success_threshold=0.5, fail_threshold=0.5)
        assert len(out) == 1
        assert out[0].scope_value == "sql"
        assert out[0].success_count == 1

    def test_min_total_filters_low_evidence(self):
        frames = [
            _mk_frame(run_id="r1", kind=FrameKind.DECISION,
                      vuln_type="sql", skill_used="sqli"),
            _mk_frame(run_id="r1", kind=FrameKind.HARM_VALIDATED,
                      vuln_type="sql", conclusion="vulnerable"),
        ]
        # min_total=3 → 单次配对会被过滤
        out = mine_lessons_from_script(frames, min_total=3)
        assert out == []

    def test_high_success_rate_positive_lesson(self):
        frames = []
        for _ in range(4):
            frames.append(_mk_frame(run_id="r1", kind=FrameKind.DECISION,
                                    vuln_type="xss", skill_used="xss_basic"))
            frames.append(_mk_frame(run_id="r1", kind=FrameKind.HARM_VALIDATED,
                                    vuln_type="xss", conclusion="vulnerable"))
        # 1 次失败
        frames.append(_mk_frame(run_id="r1", kind=FrameKind.DECISION,
                                vuln_type="xss", skill_used="xss_basic"))
        frames.append(_mk_frame(run_id="r1", kind=FrameKind.HARM_VALIDATED,
                                vuln_type="xss", conclusion="not_vuln"))
        out = mine_lessons_from_script(frames, min_total=3, success_threshold=0.66)
        assert len(out) == 1
        ls = out[0]
        assert ls.success_count == 4
        assert ls.fail_count == 1
        assert "命中率较高" in ls.lesson

    def test_low_success_rate_negative_lesson(self):
        frames = []
        # 4 次失败 + 1 次成功
        for _ in range(4):
            frames.append(_mk_frame(run_id="r1", kind=FrameKind.DECISION,
                                    vuln_type="csrf", skill_used="csrf_basic"))
            frames.append(_mk_frame(run_id="r1", kind=FrameKind.HARM_VALIDATED,
                                    vuln_type="csrf", conclusion="not_vuln"))
        frames.append(_mk_frame(run_id="r1", kind=FrameKind.DECISION,
                                vuln_type="csrf", skill_used="csrf_basic"))
        frames.append(_mk_frame(run_id="r1", kind=FrameKind.HARM_VALIDATED,
                                vuln_type="csrf", conclusion="vulnerable"))
        out = mine_lessons_from_script(frames, min_total=3, fail_threshold=0.34)
        assert len(out) == 1
        assert "未命中" in out[0].lesson

    def test_write_back_calls_memory_record(self, isolated_replay, monkeypatch):
        # mock memory.record
        called = []

        def mock_record(**kwargs):
            called.append(kwargs)

        import core.memory as mem
        monkeypatch.setattr(mem, "record", mock_record)

        from core.replay.miner import MinedLesson
        lessons = [MinedLesson(
            scope="vuln_type", scope_value="sql",
            trigger="sql sqli", lesson="test",
            success_count=3, fail_count=0,
        )]
        n = write_back_to_memory(lessons)
        assert n == 1
        assert called[0]["scope_value"] == "sql"
        assert called[0]["source"] == "self_learn"


# ============================================================
# Register
# ============================================================

class TestRegister:
    def test_attach_idempotent(self, isolated_replay, monkeypatch):
        from core.replay import register as reg_mod
        # 先把已有挂载清掉
        reg_mod.detach()

        before = bus.stats().get(Events.WORKER_DECISION, 0)
        reg_mod.attach()
        reg_mod.attach()
        reg_mod.attach()
        after = bus.stats().get(Events.WORKER_DECISION, 0)
        assert after == before + 1

        # 清理
        reg_mod.detach()

    def test_event_triggers_recorder(self, isolated_replay, monkeypatch):
        from core.replay import register as reg_mod
        reg_mod.detach()
        reg_mod.attach()
        try:
            bus.emit(Events.WORKER_DECISION, {
                "task_id": "evt_test",
                "feature_name": "登录",
                "vuln_type": "sql_injection",
                "skill_used": "sqli_basic",
            })
            frames, _ = load_script("evt_test")
            assert len(frames) == 1
            assert frames[0].vuln_type == "sql_injection"
        finally:
            reg_mod.detach()
