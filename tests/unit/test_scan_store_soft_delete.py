"""scan_store 软删（C1 四件套第 4 项）单元测试。

关注点：
1. ``mark_scan_deleted`` 后 ``list_scans()`` 默认不再返回该行（CI 门禁
   ``_latest_task_id()`` 因此顺延到上一条真实存在的扫描）；
2. ``include_deleted=True`` / 显式 ``status='deleted'`` 仍能排查到；
3. ``mark_vulns_deleted`` 让 vulns 聚合列表不再含该 task_id；
4. 零 schema 变更（复用既有 status 字段）。

全部在 tmp_path 上跑：monkeypatch ``_DB_PATH`` + 重置模块级连接单例，
绝不碰真实 ``data/scan_store.db``。
"""
from __future__ import annotations

import pytest

import core.scan_store as scan_store


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """把 scan_store 的 DB 重定向到 tmp_path，并在用例后关闭连接。"""
    monkeypatch.chdir(tmp_path)                     # 隔离 list_all_vulns 的 data/tasks 兜底
    monkeypatch.setattr(scan_store, "_DB_PATH", tmp_path / "scan_store.db")
    monkeypatch.setattr(scan_store._state, "conn", None)
    yield scan_store
    if scan_store._state.conn is not None:
        scan_store._state.conn.close()
        scan_store._state.conn = None


def test_soft_delete_hidden_from_list_scans_by_default(store):
    store.upsert_scan("task_a", "https://a.example", status="finished")
    store.upsert_scan("task_b", "https://b.example", status="finished")

    assert store.mark_scan_deleted("task_a") == 1

    ids = [s["task_id"] for s in store.list_scans()]
    assert ids == ["task_b"]                        # 按 created_at 倒序；a 被过滤

    # CI 门禁取最新一条 → 自动顺延到 b，不再是"磁盘上已不存在"的 a
    assert store.list_scans(limit=1)[0]["task_id"] == "task_b"

    # 行仍物理存在（软删、可撤销），status 已被改写
    assert store.get_scan("task_a")["status"] == "deleted"


def test_include_deleted_and_explicit_status_can_fetch_it(store):
    store.upsert_scan("task_a", "https://a.example", status="finished")
    store.upsert_scan("task_b", "https://b.example", status="finished")
    store.mark_scan_deleted("task_a")

    all_ids = {s["task_id"] for s in store.list_scans(include_deleted=True)}
    assert all_ids == {"task_a", "task_b"}

    deleted_ids = [s["task_id"] for s in store.list_scans(status="deleted")]
    assert deleted_ids == ["task_a"]
    assert store.list_scans(status="finished")[0]["task_id"] == "task_b"


def test_mark_scan_deleted_unknown_task_returns_zero(store):
    assert store.mark_scan_deleted("task_not_exist") == 0


def test_mark_vulns_deleted_hides_from_aggregate(store):
    store.upsert_scan("task_a", "https://a.example", status="finished")
    store.upsert_scan("task_b", "https://b.example", status="finished")
    store.upsert_vuln("task_a", "fp1", "SQL注入", severity="high")
    store.upsert_vuln("task_b", "fp2", "XSS", severity="low")

    assert store.mark_vulns_deleted("task_a") == 1

    # 单任务查询保留原始行（排查用），但 status 已标 deleted
    assert store.get_vulns("task_a")[0]["status"] == "deleted"
    # 聚合列表不再含已软删任务的漏洞
    agg_ids = {v["task_id"] for v in store.list_all_vulns()}
    assert agg_ids == {"task_b"}
    assert store.mark_vulns_deleted("task_a") == 1  # 幂等：重复软删不报错


def test_soft_delete_keeps_stats_queryable(store):
    """软删不破坏 stats（行仍在 DB，只是默认列表过滤）。"""
    store.upsert_scan("task_a", "https://a.example", status="finished")
    store.mark_scan_deleted("task_a")
    assert store.get_stats()["total_scans"] == 1
