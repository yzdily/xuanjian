"""修复 1.2：RegressionPlan → 补测任务翻译。"""
from __future__ import annotations

from core.diff.regression import RegressionItem, RegressionPlan
from core.diff.runner import _item_to_feature_task, run_regression_plan


def _plan(items):
    return RegressionPlan(
        target="https://x.test",
        snapshot_a="a",
        snapshot_b="b",
        created_at=0.0,
        items=items,
        summary={"total": len(items)},
    )


def _endpoint_item():
    return RegressionItem(
        kind="endpoint",
        target_id="POST /api/login",
        reason="added",
        priority="high",
        detail={"method": "post", "url": "/api/login", "added_params": ["pwd"]},
    )


def test_endpoint_surface_key_normalized():
    task = _item_to_feature_task(_endpoint_item())
    assert task["surface_key"] == "POST /api/login"
    assert task["method"] == "POST"
    assert task["priority"] == "high"
    assert task["detail"]["added_params"] == ["pwd"]


def test_run_regression_plan_translates_all_items():
    items = [
        _endpoint_item(),
        RegressionItem(
            kind="feature",
            target_id="f-1",
            reason="modified",
            priority="medium",
            detail={"name": "登录模块"},
        ),
        RegressionItem(
            kind="page", target_id="/p", reason="added", priority="medium", detail={}
        ),
    ]
    tasks = run_regression_plan("https://x.test", _plan(items))
    assert len(tasks) == 3
    assert all("surface_key" in t for t in tasks)
    assert tasks[0]["surface_key"] == "POST /api/login"
    assert tasks[1]["surface_key"] == "登录模块"
    assert tasks[2]["surface_key"] == "/p"


def test_empty_plan_returns_empty():
    assert run_regression_plan("t", _plan([])) == []


def test_plan_without_items_attr_is_safe():
    class _Bare:
        items = None

    assert run_regression_plan("t", _Bare()) == []
