"""依赖注入与单例隔离基础（收敛全局可变状态）。

DEVELOPMENT_PLAN §4.7 目标：将 core 中 31 处 ``global`` 可变状态收敛为依赖注入。
本模块是迁移入口，提供两种收敛手段：

1. **进程级懒加载单例** → 通过 :func:`register_resetter` 注册重置钩子，
   测试用 :func:`reset_singletons` 在用例间显式重置（**非 autouse**，避免破坏依赖
   跨用例共享状态的测试）。解决 §2.2「不可并行测试」问题。
2. **任务/租户级上下文态** → 用 :func:`set_context` / :func:`reset_context` 包装
   ``contextvars.ContextVar``（参考 ``core.llm.set_current_task``），支持并行扫描
   / 多租户隔离。**仅适用于任务级身份态**（如 run_id / task_id）；进程级缓存单例
   不应强行 ContextVar 化（会破坏共享语义，例如 replay.recorder 的进程级兜底 run_id
   故意全局以聚合散落数据）。

已注册 resetter（迁移进度）：
- ``fuzz_router``       — core.fuzz.registry.reset_fuzz_router
- ``skill_registry``    — core.skill_registry.reset_registry
- ``exploit_skill_map`` — core.skill_registry.reset_exploit_skill_map

待迁移（剩余 ~28 处 ``global``，按 ROI 逐步推进，清单见 DEVELOPMENT_PLAN §2.2）。
迁移规则：每收敛一处单例，即在定义处 ``register_resetter(name, reset_fn)`` 注册，
使 ``reset_singletons()`` 可统一重置，无需各测试自行 patch。
"""

from __future__ import annotations

import threading
from typing import Callable

_RESETTERS: dict[str, Callable[[], None]] = {}
_LOCK = threading.Lock()


def register_resetter(name: str, fn: Callable[[], None]) -> None:
    """注册单例重置钩子（同名覆盖；幂等）。

    Args:
        name: 单例标识（建议「模块.变量」风格，如 ``"fuzz_router"``）。
        fn: 无参重置函数，通常把对应 ``global`` 变量置回 ``None`` / 初值。
    """
    with _LOCK:
        _RESETTERS[name] = fn


def reset_singletons(names: list[str] | None = None) -> list[str]:
    """重置已注册的单例。

    Args:
        names: 指定要重置的单例名列表；``None`` 表示重置全部。未知名字被忽略。

    Returns:
        实际执行了重置的单例名列表（按注册顺序）。
    """
    with _LOCK:
        targets = list(_RESETTERS) if names is None else [n for n in names if n in _RESETTERS]
    for n in targets:
        _RESETTERS[n]()
    return targets


def registered_singletons() -> list[str]:
    """返回已注册的单例名（排序）。"""
    with _LOCK:
        return sorted(_RESETTERS)


def set_context(var, value):
    """设置 ``ContextVar`` 并返回 token（供 :func:`reset_context` 还原）。

    用于任务/租户级上下文态注入，例如::

        from core.llm._context import _current_task_id
        tok = set_context(_current_task_id, task_id)
        try:
            ...  # 该上下文内 get_current_task() 返回 task_id
        finally:
            reset_context(_current_task_id, tok)
    """
    return var.set(value)


def reset_context(var, token) -> None:
    """用 token 还原 ``ContextVar`` 到 set 之前的状态。"""
    var.reset(token)


__all__ = [
    "register_resetter",
    "reset_singletons",
    "registered_singletons",
    "set_context",
    "reset_context",
]
