"""LLM 上下文与并发池（caller 隔离信号量）。

从 core.llm 拆分而来；行为与原模块完全一致。
导入副作用：注册 harm_validation 并发池。
"""
from __future__ import annotations

import contextvars
import threading

from core.log import get_logger

log = get_logger("llm")

_current_task_id: contextvars.ContextVar[str] = contextvars.ContextVar("xuanjian_current_task_id", default="")


def set_current_task(task_id: str):
    return _current_task_id.set(task_id or "")


def reset_current_task(token) -> None:
    _current_task_id.reset(token)


def get_current_task() -> str:
    return _current_task_id.get() or ""


# ============================================================
# ★ LLM 并发池 — 按 caller 隔离，避免扫描阶段挤占危害验证导致 429
# ============================================================
# 问题根因：服务端 org max concurrency=3，扫描 worker 和 harm_validation
# 共享同一并发上限，互相挤占导致大量 429 重试浪费。
# 解决方案：为关键 caller 注册独立信号量，使其不被扫描阶段饿死。
# 注意：这是限流器不是放大器——总调用量持平或下降（429 重试减少）。

_LLM_CALLER_SEMAPHORES: dict[str, "threading.Semaphore"] = {}
_LLM_SEMAPHORES_LOCK = threading.Lock()
_DEFAULT_LLM_CONCURRENCY = 3  # 贴合常见 org concurrency 上限


def register_llm_caller_pool(caller_prefix: str,
                             concurrency: int = _DEFAULT_LLM_CONCURRENCY) -> None:
    """注册一个独立的 LLM 并发池。

    不同 caller 共享同一 org concurrency 上限，但独立池可让关键阶段
    （如 harm_validation）不被扫描阶段挤占，从而减少 429 重试浪费。
    """
    with _LLM_SEMAPHORES_LOCK:
        if caller_prefix not in _LLM_CALLER_SEMAPHORES:
            _LLM_CALLER_SEMAPHORES[caller_prefix] = threading.Semaphore(concurrency)
            log.info("注册 LLM 并发池: caller_prefix=%s, concurrency=%d",
                     caller_prefix, concurrency)


def _get_caller_semaphore(caller: str) -> "threading.Semaphore | None":
    """按 caller 名称获取独立信号量。未注册的 caller 返回 None（不限流）。"""
    if not caller:
        return None
    with _LLM_SEMAPHORES_LOCK:
        # 精确匹配优先，前缀匹配兜底
        if caller in _LLM_CALLER_SEMAPHORES:
            return _LLM_CALLER_SEMAPHORES[caller]
        for key, sem in _LLM_CALLER_SEMAPHORES.items():
            if caller.startswith(key):
                return sem
    return None


# 默认为 harm_validation 注册独立池，确保危害验证不被扫描阶段挤占
register_llm_caller_pool("harm_validation", concurrency=_DEFAULT_LLM_CONCURRENCY)
