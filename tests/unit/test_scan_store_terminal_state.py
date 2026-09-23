"""scan_store 终态语义测试（T16 / T13 / 修 D5 + D10）。

★ 背景（0923 实测）：
``data/scan_store.db`` 中 ``running = 31`` / ``finished = 32`` / ``deleted = 1``，
最早残留 2026-07-31 —— 失败任务永久停在 ``running``：
- 仪表盘/统计会认为"还有 31 个任务在跑"
- 「删除会话」护栏会误拦
- 任何基于 ``scans.status`` 的续跑判断没有依据

根因两条：
1. ``upsert_scan`` 的 UPDATE 分支把 kwargs **直接当列名**拼 SQL，
   而 ``scans`` 表没有 ``resumable`` / ``fail_reason`` 等列 → 写终态必抛
   ``sqlite3.OperationalError: no such column``。
2. 失败路径只发 SSE 事件、从不落库；``finish_scan`` 只被报告阶段调用。
"""

from __future__ import annotations

import sqlite3
import time

import pytest

import core.scan_store as ss


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """把 scan_store 指向临时库（隔离真实 data/scan_store.db）。"""
    monkeypatch.setattr(ss, "_DB_PATH", tmp_path / "scan_store_test.db")
    monkeypatch.setattr(ss._state, "conn", None)
    ss._ensure_conn()
    yield ss
    try:
        if ss._state.conn is not None:
            ss._state.conn.close()
    except Exception:
        pass
    monkeypatch.setattr(ss._state, "conn", None)


def _cols(conn) -> set[str]:
    return {r[1] for r in conn.execute("PRAGMA table_info(scans)")}


# ============================================================
# 1. 老库迁移（修 D10：缺列会让终态写入直接抛 SQL 错）
# ============================================================

class TestMigration:
    def test_new_db_has_terminal_columns(self, store):
        cols = _cols(store._ensure_conn())
        for c in ("phase_status", "fail_reason", "resumable", "resume_phase"):
            assert c in cols, f"新库应包含 {c}"

    def test_legacy_db_gets_columns_added(self, tmp_path, monkeypatch):
        """模拟"0923 之前建的老库"（无终态列）→ 应被幂等补列。"""
        db = tmp_path / "legacy.db"
        raw = sqlite3.connect(db)
        raw.executescript("""
            CREATE TABLE scans (
                task_id TEXT PRIMARY KEY, target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                scan_mode TEXT DEFAULT 'batch', model TEXT DEFAULT '',
                metrics_json TEXT DEFAULT '{}',
                created_at REAL NOT NULL, updated_at REAL NOT NULL,
                finished_at REAL
            );
        """)
        raw.commit()
        raw.close()

        monkeypatch.setattr(ss, "_DB_PATH", db)
        monkeypatch.setattr(ss._state, "conn", None)
        conn = ss._ensure_conn()
        cols = _cols(conn)
        for c in ("phase_status", "fail_reason", "resumable", "resume_phase"):
            assert c in cols, f"老库应被补上 {c}"
        conn.close()
        monkeypatch.setattr(ss._state, "conn", None)

    def test_migration_is_idempotent(self, store):
        conn = store._ensure_conn()
        assert store._migrate_columns(conn) == 0, "重复迁移不应再加列"
        assert store._migrate_columns(conn) == 0


# ============================================================
# 2. set_terminal_state（T13）
# ============================================================

class TestSetTerminalState:
    def test_writes_five_state(self, store):
        store.upsert_scan("t1", target="https://a/", status="running")
        n = store.set_terminal_state(
            "t1", status="failed", phase="analyze",
            reason="llm_error", resumable=True,
        )
        assert n == 1
        row = store.get_scan("t1")
        assert row["status"] == "failed"
        assert row["phase_status"] == "analyze"
        assert row["fail_reason"] == "llm_error"
        assert row["resumable"] == 1
        assert row["resume_phase"] == "analyze"
        assert row["finished_at"]

    @pytest.mark.parametrize("status", ["completed", "partial", "unreachable",
                                        "failed", "aborted", "finished"])
    def test_all_valid_statuses_accepted(self, store, status):
        store.upsert_scan("t", target="https://a/")
        assert store.set_terminal_state("t", status=status) == 1

    def test_invalid_status_raises(self, store):
        store.upsert_scan("t", target="https://a/")
        with pytest.raises(ValueError, match="非法终态"):
            store.set_terminal_state("t", status="done")   # 拼错不应静默写入

    def test_not_resumable_clears_resume_phase(self, store):
        store.upsert_scan("t", target="https://a/")
        store.set_terminal_state("t", status="aborted", phase="test",
                                 resumable=False)
        row = store.get_scan("t")
        assert row["resumable"] == 0
        assert row["resume_phase"] == "", "不可续跑时不得留断点阶段"

    def test_missing_row_returns_zero_without_insert(self, store):
        """未 upsert 过的 task 不应被凭空插入一条 target 为空的幽灵记录。"""
        assert store.set_terminal_state("ghost", status="failed") == 0
        assert store.get_scan("ghost") is None

    def test_metrics_recorded(self, store):
        store.upsert_scan("t", target="https://a/")
        store.set_terminal_state("t", status="completed", metrics={"apis": 94})
        assert "94" in store.get_scan("t")["metrics_json"]


# ============================================================
# 3. 存量回填（修 D5 的"31 条残留"）
# ============================================================

class TestMarkStaleRunning:
    def test_backfills_only_old_running(self, store):
        now = time.time()
        conn = store._ensure_conn()
        for tid, hours_ago in (("old1", 48), ("old2", 10), ("fresh", 0.2)):
            conn.execute(
                "INSERT INTO scans (task_id, target, status, created_at, updated_at)"
                " VALUES (?,?,?,?,?)",
                (tid, "https://a/", "running", now, now - hours_ago * 3600),
            )
        # 已完成的任务不应被碰
        conn.execute(
            "INSERT INTO scans (task_id, target, status, created_at, updated_at)"
            " VALUES (?,?,?,?,?)",
            ("done1", "https://a/", "finished", now, now - 100 * 3600),
        )
        conn.commit()

        assert store.mark_stale_running(max_age_hours=6.0) == 2

        assert store.get_scan("old1")["status"] == "failed"
        assert store.get_scan("old1")["fail_reason"] == "stale_running_backfilled"
        assert store.get_scan("old1")["resumable"] == 0
        assert store.get_scan("old2")["status"] == "failed"
        assert store.get_scan("fresh")["status"] == "running", "近 6 小时内的不应被回填"
        assert store.get_scan("done1")["status"] == "finished", "非 running 不得被改"

    def test_idempotent(self, store):
        conn = store._ensure_conn()
        now = time.time()
        conn.execute(
            "INSERT INTO scans (task_id, target, status, created_at, updated_at)"
            " VALUES (?,?,?,?,?)",
            ("old", "https://a/", "running", now, now - 48 * 3600),
        )
        conn.commit()
        assert store.mark_stale_running(6.0) == 1
        assert store.mark_stale_running(6.0) == 0, "重复调用应为 0"

    def test_no_residue_after_call(self, store):
        """V12' 判据：回填后不得再有超龄 running。"""
        conn = store._ensure_conn()
        now = time.time()
        for i in range(5):
            conn.execute(
                "INSERT INTO scans (task_id, target, status, created_at, updated_at)"
                " VALUES (?,?,?,?,?)",
                (f"r{i}", "https://a/", "running", now, now - (10 + i) * 3600),
            )
        conn.commit()
        store.mark_stale_running(6.0)
        left = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status='running' AND updated_at < ?",
            (now - 6 * 3600,),
        ).fetchone()[0]
        assert left == 0


# ============================================================
# 4. upsert_scan 白名单（防一个笔误打死整条终态链路）
# ============================================================

class TestUpsertWhitelist:
    def test_unknown_kwarg_is_ignored_not_fatal(self, store):
        store.upsert_scan("t", target="https://a/", status="running")
        # 未知列名不应抛 sqlite3.OperationalError
        store.upsert_scan("t", target="https://a/", typo_column_xyz=1)
        assert store.get_scan("t")["status"] == "running"

    def test_known_optional_columns_still_work(self, store):
        store.upsert_scan("t", target="https://a/", status="running")
        store.upsert_scan("t", target="https://a/", resumable=1,
                          resume_phase="test", fail_reason="")
        row = store.get_scan("t")
        assert row["resumable"] == 1
        assert row["resume_phase"] == "test"


# ============================================================
# 5. finish_scan 签名保持（不能破坏既有两处调用点）
# ============================================================

class TestFinishScanSignaturePreserved:
    def test_finish_scan_unchanged(self, store):
        """finish_scan(task_id, metrics) 被 _report_phase 与 task_queue 调用，
        签名与 'finished' 语义必须保持。"""
        import inspect
        params = list(inspect.signature(store.finish_scan).parameters)
        assert params == ["task_id", "metrics"], (
            f"finish_scan 签名被改动: {params}；新增终态请用 set_terminal_state"
        )
        store.upsert_scan("t", target="https://a/", status="running")
        store.finish_scan("t", {"a": 1})
        assert store.get_scan("t")["status"] == "finished"
