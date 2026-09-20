"""
core/diff/runner.py — 增量回归的"翻译层"（修复 1.2）。

## 定位
`core/diff/`（snapshot / differ / regression）代码完整，但 CLI 从未暴露。
本模块只做一件事：把 `RegressionPlan.items` **翻译**成现有补测框架
（`_run_supplementary_test`）能消费的 feature task 列表。

## 设计取舍（沿用 regression.py 的零侵入原则）
- 不直接调 orchestrator，避免依赖其易变签名
- 纯函数，输入输出确定，便于单测
- 只回答"该测什么"，何时跑/并发多少由调用方决定
"""
from __future__ import annotations

from typing import Any

SURFACE_KEY_SEP = " "


def _surface_key_for(item: Any) -> str:
    """为回归项生成稳定的 surface_key（供补测框架去重/分组）。"""
    detail = getattr(item, "detail", None) or {}
    kind = getattr(item, "kind", "")

    if kind == "endpoint":
        method = (detail.get("method") or "").upper()
        url = detail.get("url") or ""
        return f"{method}{SURFACE_KEY_SEP}{url}".strip()

    if kind == "feature":
        return str(detail.get("name") or getattr(item, "target_id", ""))

    # page 或未知类型：直接用 target_id（url）
    return str(getattr(item, "target_id", ""))


def _item_to_feature_task(item: Any) -> dict[str, Any]:
    """把一条 RegressionItem 映射成补测任务的 dict。"""
    detail = getattr(item, "detail", None) or {}
    return {
        "surface_key": _surface_key_for(item),
        "kind": getattr(item, "kind", ""),
        "target_id": getattr(item, "target_id", ""),
        "reason": getattr(item, "reason", ""),
        "priority": getattr(item, "priority", "medium"),
        "url": detail.get("url", ""),
        "method": (detail.get("method") or "").upper(),
        "feature_id": detail.get("name") or getattr(item, "target_id", ""),
        "detail": dict(detail),
    }


def run_regression_plan(target: str, plan: Any) -> list[dict[str, Any]]:
    """把 RegressionPlan 翻译成补测任务列表。

    Args:
        target: 扫描目标（仅用于透传/日志上下文）
        plan:   `core.diff.regression.RegressionPlan`（鸭子类型：有 .items 即可）

    Returns:
        补测任务 dict 列表，每项含 `surface_key`。
    """
    items = getattr(plan, "items", None) or []
    return [_item_to_feature_task(it) for it in items]


__all__ = ["run_regression_plan", "_item_to_feature_task"]
