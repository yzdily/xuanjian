"""
test_sitemap_diff.py — core/diff 模块的单测

覆盖：
- snapshot 拍摄/列出/加载/删除
- differ 对 pages / endpoints / features 的差分逻辑
- regression 方案构建
- 通过事件总线触发的零侵入挂载（register）
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.diff import (
    ChangeKind,
    diff_snapshots,
    list_snapshots,
    load_snapshot,
    take_snapshot,
)
from core.diff.regression import build_regression_plan, save_regression_plan
from core.diff.snapshot import delete_snapshot
from core.events import Events, EventBus


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture()
def isolated_data_dir(tmp_path, monkeypatch):
    """把 data 目录临时切到 tmp_path，避免污染真实数据。"""
    monkeypatch.chdir(tmp_path)
    # 重定向 SNAPSHOT_ROOT 等模块级常量
    from core.diff import snapshot as snap_mod
    from core.diff import regression as reg_mod
    monkeypatch.setattr(snap_mod, "SNAPSHOT_ROOT", tmp_path / "data" / "sitemap_snapshots")
    monkeypatch.setattr(snap_mod, "TASK_SITEMAP_DIR", tmp_path / "data" / "tasks")
    monkeypatch.setattr(reg_mod, "REGRESSION_PLAN_DIR", tmp_path / "data" / "regression_plans")
    yield tmp_path


def _make_sitemap_dict(target="https://demo.test", apis=None, pages=None, features=None):
    return {
        "target": target,
        "task_id": "t1",
        "pages": pages or {},
        "apis": apis or {},
        "features": features or {},
    }


def _write_task_sitemap(tmp_path: Path, task_id: str, data: dict) -> Path:
    d = tmp_path / "data" / "tasks"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{task_id}-sitemap.json"
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


# ============================================================
# Snapshot
# ============================================================

class TestSnapshot:
    def test_take_snapshot_writes_files(self, isolated_data_dir):
        _write_task_sitemap(isolated_data_dir, "t1",
                            _make_sitemap_dict(apis={"GET /api/x": {"method": "GET", "url": "/api/x"}}))
        meta = take_snapshot("t1", tag="v1")
        assert meta is not None
        assert meta.host == "demo.test"
        assert meta.tag == "v1"
        assert meta.apis_count == 1

        snap_dir = isolated_data_dir / "data" / "sitemap_snapshots" / "demo.test" / "v1"
        assert (snap_dir / "sitemap.json").exists()
        assert (snap_dir / "meta.json").exists()

    def test_take_snapshot_missing_source_returns_none(self, isolated_data_dir):
        assert take_snapshot("nonexistent", tag="v1") is None

    def test_list_snapshots_sorted_desc(self, isolated_data_dir):
        _write_task_sitemap(isolated_data_dir, "t1", _make_sitemap_dict())
        m1 = take_snapshot("t1", tag="v1")
        m2 = take_snapshot("t1", tag="v2")
        snaps = list_snapshots("demo.test")
        assert len(snaps) == 2
        # 时间倒序（v2 后建，应排前面）
        assert snaps[0]["tag"] == "v2"
        assert snaps[1]["tag"] == "v1"

    def test_load_snapshot_roundtrip(self, isolated_data_dir):
        sd = _make_sitemap_dict(apis={"GET /a": {"method": "GET", "url": "/a"}})
        _write_task_sitemap(isolated_data_dir, "t1", sd)
        take_snapshot("t1", tag="v1")
        loaded = load_snapshot("demo.test", "v1")
        assert loaded is not None
        assert loaded["apis"] == sd["apis"]

    def test_delete_snapshot(self, isolated_data_dir):
        _write_task_sitemap(isolated_data_dir, "t1", _make_sitemap_dict())
        take_snapshot("t1", tag="v1")
        assert delete_snapshot("demo.test", "v1") is True
        assert delete_snapshot("demo.test", "v1") is False  # 不存在

    def test_take_snapshot_safe_tag(self, isolated_data_dir):
        _write_task_sitemap(isolated_data_dir, "t1", _make_sitemap_dict())
        meta = take_snapshot("t1", tag="../etc/passwd")
        assert meta is not None
        assert "/" not in meta.tag


# ============================================================
# Differ — endpoints
# ============================================================

class TestDifferEndpoints:
    def test_added_endpoint(self):
        a = _make_sitemap_dict()
        b = _make_sitemap_dict(apis={
            "POST /api/login": {"method": "POST", "url": "/api/login", "params": ["user", "pwd"]},
        })
        r = diff_snapshots(a, b)
        assert len(r.endpoints) == 1
        assert r.endpoints[0].kind == ChangeKind.ADDED
        assert r.endpoints[0].added_params == ["user", "pwd"]
        assert r.summary["endpoints_added"] == 1

    def test_removed_endpoint(self):
        a = _make_sitemap_dict(apis={
            "GET /api/old": {"method": "GET", "url": "/api/old"}
        })
        b = _make_sitemap_dict()
        r = diff_snapshots(a, b)
        assert len(r.endpoints) == 1
        assert r.endpoints[0].kind == ChangeKind.REMOVED
        assert r.summary["endpoints_removed"] == 1

    def test_modified_endpoint_param_change(self):
        a = _make_sitemap_dict(apis={
            "POST /api/x": {"method": "POST", "url": "/api/x", "params": ["a"]}
        })
        b = _make_sitemap_dict(apis={
            "POST /api/x": {"method": "POST", "url": "/api/x", "params": ["a", "b"]}
        })
        r = diff_snapshots(a, b)
        assert len(r.endpoints) == 1
        assert r.endpoints[0].kind == ChangeKind.MODIFIED
        assert r.endpoints[0].added_params == ["b"]

    def test_modified_endpoint_field_change(self):
        a = _make_sitemap_dict(apis={
            "GET /a": {"method": "GET", "url": "/a", "auth_required": True}
        })
        b = _make_sitemap_dict(apis={
            "GET /a": {"method": "GET", "url": "/a", "auth_required": False}
        })
        r = diff_snapshots(a, b)
        assert len(r.endpoints) == 1
        assert r.endpoints[0].kind == ChangeKind.MODIFIED
        assert "auth_required" in r.endpoints[0].diff_fields

    def test_unchanged_endpoint_excluded(self):
        a = _make_sitemap_dict(apis={
            "GET /a": {"method": "GET", "url": "/a", "params": ["x"]}
        })
        b = _make_sitemap_dict(apis={
            "GET /a": {"method": "GET", "url": "/a", "params": ["x"]}
        })
        r = diff_snapshots(a, b)
        assert r.endpoints == []
        assert r.has_changes() is False


# ============================================================
# Differ — pages
# ============================================================

class TestDifferPages:
    def test_added_page(self):
        a = _make_sitemap_dict()
        b = _make_sitemap_dict(pages={
            "/dashboard": {"url": "/dashboard", "title": "Dashboard", "forms": [{}]}
        })
        r = diff_snapshots(a, b)
        assert len(r.pages) == 1
        assert r.pages[0].kind == ChangeKind.ADDED
        assert r.pages[0].added_forms == 1

    def test_modified_page_button_change(self):
        a = _make_sitemap_dict(pages={
            "/x": {"url": "/x", "title": "X", "buttons": ["登录"]}
        })
        b = _make_sitemap_dict(pages={
            "/x": {"url": "/x", "title": "X", "buttons": ["登录", "注册"]}
        })
        r = diff_snapshots(a, b)
        assert len(r.pages) == 1
        assert r.pages[0].kind == ChangeKind.MODIFIED
        assert "注册" in r.pages[0].diff_fields["buttons"]["added"]


# ============================================================
# Differ — features
# ============================================================

class TestDifferFeatures:
    def test_added_feature(self):
        a = _make_sitemap_dict()
        b = _make_sitemap_dict(features={
            "feat_001": {
                "id": "feat_001", "name": "登录", "module": "认证",
                "related_apis": ["POST /api/login"],
                "priority": "high", "test_status": "not_tested"
            }
        })
        r = diff_snapshots(a, b)
        assert len(r.features) == 1
        assert r.features[0].kind == ChangeKind.ADDED
        assert r.features[0].name == "登录"

    def test_modified_feature_via_name_match(self):
        """同名功能但 API 列表变化，应识别为 MODIFIED 而非 REMOVED+ADDED。"""
        a = _make_sitemap_dict(features={
            "feat_001": {
                "id": "feat_001", "name": "登录", "module": "认证",
                "related_apis": ["POST /api/login"],
                "priority": "high", "test_status": "not_tested"
            }
        })
        b = _make_sitemap_dict(features={
            "feat_002": {  # id 变了，但 name+module 一样
                "id": "feat_002", "name": "登录", "module": "认证",
                "related_apis": ["POST /api/login", "POST /api/login/2fa"],
                "priority": "high", "test_status": "not_tested"
            }
        })
        r = diff_snapshots(a, b)
        kinds = [f.kind for f in r.features]
        assert ChangeKind.MODIFIED in kinds
        # 应识别出新增了 2fa API
        modified = next(f for f in r.features if f.kind == ChangeKind.MODIFIED)
        assert "POST /api/login/2fa" in modified.added_apis


# ============================================================
# Regression plan
# ============================================================

class TestRegressionPlan:
    def test_build_plan_skips_removed(self):
        a = _make_sitemap_dict(apis={
            "GET /old": {"method": "GET", "url": "/old"}
        })
        b = _make_sitemap_dict(apis={
            "POST /new": {"method": "POST", "url": "/new", "params": ["x"]}
        })
        plan = build_regression_plan(diff_snapshots(a, b))
        # 删除的不进 plan
        assert all(it.target_id != "GET /old" for it in plan.items)
        # 新增的进 plan
        assert any(it.target_id == "POST /new" for it in plan.items)

    def test_added_endpoint_high_priority(self):
        a = _make_sitemap_dict()
        b = _make_sitemap_dict(apis={
            "GET /new": {"method": "GET", "url": "/new"}
        })
        plan = build_regression_plan(diff_snapshots(a, b))
        ep_items = [it for it in plan.items if it.kind == "endpoint"]
        assert len(ep_items) == 1
        assert ep_items[0].priority == "high"

    def test_modified_with_new_params_high_priority(self):
        a = _make_sitemap_dict(apis={
            "POST /a": {"method": "POST", "url": "/a", "params": ["x"]}
        })
        b = _make_sitemap_dict(apis={
            "POST /a": {"method": "POST", "url": "/a", "params": ["x", "y"]}
        })
        plan = build_regression_plan(diff_snapshots(a, b))
        ep = next(it for it in plan.items if it.kind == "endpoint")
        assert ep.priority == "high"  # 有新参数
        assert "new_params" in ep.reason

    def test_save_plan_creates_file(self, isolated_data_dir):
        a = _make_sitemap_dict()
        b = _make_sitemap_dict(apis={"GET /a": {"method": "GET", "url": "/a"}})
        plan = build_regression_plan(diff_snapshots(a, b))
        path = save_regression_plan(plan)
        assert path.exists()
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded["summary"]["total"] >= 1


# ============================================================
# 事件零侵入挂载
# ============================================================

class TestRegister:
    def test_attach_subscribes_handler(self, isolated_data_dir, monkeypatch):
        from core.diff import register as reg_mod
        # 重置已挂载状态，否则后续测试看不到订阅
        monkeypatch.setattr(reg_mod, "_attached", False)

        # 准备一份 sitemap，等待事件触发后自动拍快照
        _write_task_sitemap(isolated_data_dir, "t1",
                            _make_sitemap_dict(apis={"GET /a": {"method": "GET", "url": "/a"}}))

        from core.events import bus as global_bus
        # 临时使用真实 bus，但测试结束前清理订阅
        before = global_bus.stats().get(Events.CRAWL_SNAPSHOT_DONE, 0)
        reg_mod.attach()
        after = global_bus.stats().get(Events.CRAWL_SNAPSHOT_DONE, 0)
        assert after == before + 1

        # 触发事件 → 自动拍快照
        global_bus.emit(Events.CRAWL_SNAPSHOT_DONE,
                        {"task_id": "t1", "tag": "auto-v1"})
        snaps = list_snapshots("demo.test")
        assert any(s["tag"] == "auto-v1" for s in snaps)

    def test_attach_idempotent(self, monkeypatch):
        from core.diff import register as reg_mod
        monkeypatch.setattr(reg_mod, "_attached", False)
        from core.events import bus as global_bus
        before = global_bus.stats().get(Events.CRAWL_SNAPSHOT_DONE, 0)
        reg_mod.attach()
        reg_mod.attach()
        reg_mod.attach()
        after = global_bus.stats().get(Events.CRAWL_SNAPSHOT_DONE, 0)
        assert after == before + 1  # 只订阅一次
