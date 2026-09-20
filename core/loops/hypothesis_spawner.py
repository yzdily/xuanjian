"""
core/loops/hypothesis_spawner.py — F13 假设生成器的编排钩子（修复 1.3）。

## 背景
`core/parallel/_orch_phases/_supplement.py` 已经定义了：
- `FINDING_SPAWN_PATTERNS`（:191，含 `actuator_exposure` 等 6 类）
- `should_spawn_for_finding(finding) -> str | None`（:201）
- `_spawn_hypothesis_agent(session, finding, session_info) -> list[str]`（:210，async）

但**编排从不调用它们** → 假设深挖链空转（F13 未接线）。

## 设计
- **懒加载**：`_supplement` 依赖 httpx/config/prompts/sitemap，模块级导入过重；
  默认实现放在函数内按需导入，同时允许调用方注入替身 → 单测无需重依赖。
- **防空转**：`MAX_DEPTH_CHAIN`（复用 F8 depth_chain 上限）+ `MAX_SPAWN_PER_FINDING`。
- **只产出任务描述**：是否真的起 WorkerAgent 由编排决定（保持零侵入）。
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable

MAX_SPAWN_PER_FINDING = 3
MAX_DEPTH_CHAIN = 5

_SPAWN_STATE_ATTR = "_xj_spawn_state"


def _session_info(session: Any) -> dict[str, Any]:
    """从 session 抽取下游 agent 所需上下文（保持可序列化）。"""
    info: dict[str, Any] = {}
    for attr in ("task_id", "target", "tenant_id"):
        try:
            value = getattr(session, attr, None)
        except Exception:
            value = None
        if value is not None:
            info[attr] = value
    return info


def _default_should_spawn():
    from core.parallel._orch_phases._supplement import should_spawn_for_finding

    return should_spawn_for_finding


def _default_spawn_agent():
    from core.parallel._orch_phases._supplement import _spawn_hypothesis_agent

    return _spawn_hypothesis_agent


async def run_spawner(
    session: Any,
    confirmed_findings: list[dict[str, Any]] | None,
    *,
    depth: int = 0,
    should_spawn: Callable[[dict[str, Any]], str | None] | None = None,
    spawn_agent: Callable[..., Awaitable[list[str]]] | None = None,
    max_per_finding: int | None = None,
    max_depth: int | None = None,
) -> list[str]:
    """遍历 confirmed findings，命中 spawn pattern 则产出下游验证任务描述。

    Args:
        session:            编排 session（提供 task_id/target 等上下文）
        confirmed_findings: 已确认的 finding 列表
        depth:              当前深挖层级（>= max_depth 直接停止，防空转）
        should_spawn:       判定函数，默认 `should_spawn_for_finding`
        spawn_agent:        异步产出函数，默认 `_spawn_hypothesis_agent`
        max_per_finding:    单 finding 下游任务上限，默认 MAX_SPAWN_PER_FINDING
        max_depth:          深度上限，默认 MAX_DEPTH_CHAIN

    Returns:
        下游任务描述列表（可能为空）。
    """
    per_finding = MAX_SPAWN_PER_FINDING if max_per_finding is None else max_per_finding
    depth_cap = MAX_DEPTH_CHAIN if max_depth is None else max_depth

    if depth >= depth_cap:
        return []
    if not confirmed_findings:
        return []

    if should_spawn is None:
        should_spawn = _default_should_spawn()
    if spawn_agent is None:
        spawn_agent = _default_spawn_agent()

    info = _session_info(session)
    spawned: list[str] = []

    for finding in confirmed_findings:
        if not isinstance(finding, dict):
            continue
        try:
            hit = should_spawn(finding)
        except Exception:
            hit = None
        if hit is None:
            continue

        try:
            descs = await spawn_agent(session, finding, info)
        except Exception:
            # 单个 finding 的 spawn 失败不影响整体（编排不得因假设链中断）
            continue

        for desc in (descs or [])[:per_finding]:
            if isinstance(desc, str) and desc:
                spawned.append(desc)

    return spawned


__all__ = ["run_spawner", "MAX_SPAWN_PER_FINDING", "MAX_DEPTH_CHAIN"]
