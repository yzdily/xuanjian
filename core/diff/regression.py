"""
core/diff/regression.py — 增量回归扫描调度

## 核心思路
拿到 DiffResult 后，把"新增 + 改动"的功能点 / API key 列表整理成回归任务清单，
**输出一个标准化的 JSON 清单**，供：
1. WebUI 展示"需要重测的项"
2. 主流程（worker_agent / orchestrator）按这个清单只测变化部分

## 设计取舍
本模块**不直接调用** orchestrator，而是把"该测什么"翻译成清单，
让用户/主流程决定何时跑、用什么并发。这样：
- 零侵入：不依赖 orchestrator 的具体签名（它本身经常变）
- 易测试：纯函数输入输出，单测覆盖直接做
- 易集成：清单可以喂给现有任意启动方式（手动 / orchestrator / CLI）
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.diff.models import ChangeKind, DiffResult
from core.log import get_logger

log = get_logger("diff.regression")

REGRESSION_PLAN_DIR = Path("data/regression_plans")


@dataclass
class RegressionItem:
    """回归测试清单中的一项。"""
    kind: str                          # "feature" | "endpoint" | "page"
    target_id: str                     # feature_id / api key / page url
    reason: str                        # "added" | "modified" | "added_param:xxx"
    priority: str = "medium"           # critical | high | medium | low
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class RegressionPlan:
    """完整的回归测试方案。"""
    target: str
    snapshot_a: str
    snapshot_b: str
    created_at: float
    items: list[RegressionItem] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "snapshot_a": self.snapshot_a,
            "snapshot_b": self.snapshot_b,
            "created_at": self.created_at,
            "created_at_human": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)
            ),
            "summary": self.summary,
            "items": [
                {
                    "kind": it.kind,
                    "target_id": it.target_id,
                    "reason": it.reason,
                    "priority": it.priority,
                    "detail": it.detail,
                }
                for it in self.items
            ],
        }


def _priority_for_endpoint(change_reason: str, has_new_params: bool) -> str:
    """新增端点 high；新增参数的改动 high；其他 modified medium。"""
    if change_reason == "added":
        return "high"
    if has_new_params:
        return "high"
    return "medium"


def build_regression_plan(diff: DiffResult) -> RegressionPlan:
    """把 DiffResult 翻译成可执行的回归测试清单。"""
    items: list[RegressionItem] = []

    # 端点变化
    for ep in diff.endpoints:
        if ep.kind == ChangeKind.REMOVED:
            continue  # 删除的端点不需要回归测试
        reason = ep.kind.value
        has_new_params = bool(ep.added_params)
        items.append(RegressionItem(
            kind="endpoint",
            target_id=ep.key,
            reason=reason if not has_new_params else f"{reason}+new_params",
            priority=_priority_for_endpoint(reason, has_new_params),
            detail={
                "method": ep.method,
                "url": ep.url,
                "added_params": ep.added_params,
                "removed_params": ep.removed_params,
                "diff_fields": ep.diff_fields,
            },
        ))

    # 功能点变化
    for f in diff.features:
        if f.kind == ChangeKind.REMOVED:
            continue
        items.append(RegressionItem(
            kind="feature",
            target_id=f.feature_id,
            reason=f.kind.value,
            priority="high" if f.kind == ChangeKind.ADDED else "medium",
            detail={
                "name": f.name,
                "added_apis": f.added_apis,
                "removed_apis": f.removed_apis,
                "diff_fields": f.diff_fields,
            },
        ))

    # 页面变化（仅记录 ADDED + MODIFIED 中带表单的）
    for p in diff.pages:
        if p.kind == ChangeKind.REMOVED:
            continue
        if p.kind == ChangeKind.ADDED or p.added_forms > 0 or p.removed_forms > 0:
            items.append(RegressionItem(
                kind="page",
                target_id=p.url,
                reason=p.kind.value,
                priority="medium",
                detail={
                    "title": p.title,
                    "added_forms": p.added_forms,
                    "removed_forms": p.removed_forms,
                    "diff_fields": p.diff_fields,
                },
            ))

    summary = {
        "total": len(items),
        "endpoints": sum(1 for it in items if it.kind == "endpoint"),
        "features": sum(1 for it in items if it.kind == "feature"),
        "pages": sum(1 for it in items if it.kind == "page"),
        "high_priority": sum(1 for it in items if it.priority in ("critical", "high")),
    }

    return RegressionPlan(
        target=diff.target,
        snapshot_a=diff.snapshot_a,
        snapshot_b=diff.snapshot_b,
        created_at=time.time(),
        items=items,
        summary=summary,
    )


def save_regression_plan(plan: RegressionPlan) -> Path:
    """把回归方案保存到 data/regression_plans/<target>-<ts>.json"""
    REGRESSION_PLAN_DIR.mkdir(parents=True, exist_ok=True)
    safe_target = (plan.target or "unknown").replace("/", "_").replace(":", "_")
    fname = f"{safe_target}-{int(plan.created_at)}.json"
    path = REGRESSION_PLAN_DIR / fname
    try:
        path.write_text(
            json.dumps(plan.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        log.info("保存回归方案: %s items=%d", path, len(plan.items))
    except Exception as e:
        log.warning("保存回归方案失败: %s", e)
    return path


__all__ = [
    "RegressionItem",
    "RegressionPlan",
    "build_regression_plan",
    "save_regression_plan",
]
