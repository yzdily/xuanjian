"""LLM 响应健康度与「空解析熔断」。

★ 924 实证（task_1790223312_c75b16）。

## 为什么要这个模块

914/923 期的失败是"调用直接报错"（模型名 404 / 余额不足 / 429），
所以有 ``_failure.classify_llm_failure`` + ``_preflight`` 覆盖。

924 出现了**第四种失败形态**：调用**成功返回、不报任何错**，但响应体
既无 content 也无 tool_calls —— 因为模型（``wuwen``）返回的流不是标准
OpenAI SSE，``_parse_sse_chat_payload`` 降级解析后拿到空对象。

该形态的危险性在于它**完全静默**：

- ``core.llm._config`` 只打了一条 ``log.warning`` 就放行；
- 调用方（chat_loop / worker_agent）拿到一个"合法的空响应"，按正常路径继续；
- 于是主 Agent 连续 4 轮"纯文字无工具调用"被 nudge 强制推进，
  业务理解降级为规则推导，**Phase 2.6 危害验证 6 次调用全部"成功但为空"**
  → 19 个候选 0 接受 → proven 报告「0 已证明漏洞」。
- 用户侧看到的是一份"扫完了、基本安全"的报告，而不是"这次没扫成"。
  实测该 warning 在单次任务里出现 17 次、全日志 **147 次**。

## 本模块做什么

1. 记录连续空解析次数（进程级、线程安全 —— worker 走 ``asyncio.to_thread``）；
2. 达到阈值即**熔断**，由 ``_client.chat`` 抛出 ``LLMEmptyResponseError``，
   让失败**显式化**（宁可报错，不要静默跑完给假结论）；
3. 换模型时自动重置计数（不同模型互不牵连）；
4. 提供 ``stats()`` 供报告/告警引用。

## 逃生门

``XUANJIAN_LLM_EMPTY_PARSE_BREAKER=0`` 关闭熔断（只统计不抛异常）；
``XUANJIAN_LLM_EMPTY_PARSE_BREAKER=<n>`` 调整阈值（默认 3）。
"""

from __future__ import annotations

import os
import threading

from core.log import get_logger

log = get_logger("llm.health")

# 连续空解析达到该次数即熔断。0 / 负数 = 只统计不熔断。
_DEFAULT_BREAKER_THRESHOLD = 3

class _HealthState:
    """空解析健康度状态（可变容器）。

    ★ 刻意用**实例属性**而不是模块级 ``global`` 变量：``core/`` 有
    ``tests/unit/test_global_count_gate.py`` 硬限制 ``global`` 语句总数 ≤2，
    用状态对象既满足该约束，也让"重置 / 快照"这类操作有明确归属。
    """

    __slots__ = ("streak", "streak_model", "tripped", "total_empty",
                 "total_ok", "last_caller", "last_raw_len")

    def __init__(self) -> None:
        self.streak = 0
        self.streak_model = ""
        self.tripped = False
        self.total_empty = 0
        self.total_ok = 0
        self.last_caller = ""
        self.last_raw_len = 0


_lock = threading.Lock()
_state = _HealthState()


class LLMEmptyResponseError(RuntimeError):
    """LLM 连续返回空响应（既无 content 也无 tool_calls）—— 模型链路不兼容。

    与 ``ContextLimitError`` 的区别：后者是"上下文太大"（可通过裁剪解决），
    本异常是"模型协议不兼容"（**必须换模型**，重试与裁剪都无效）。
    """

    def __init__(self, model: str, streak: int, caller: str = "", raw_len: int = 0):
        self.model = model
        self.streak = streak
        self.caller = caller
        self.raw_len = raw_len
        super().__init__(
            f"模型 `{model}` 连续 {streak} 次返回空响应（既无 content 也无 tool_calls）。"
            f"这通常表示该模型的流式返回格式与本系统不兼容（SSE 降级解析后为空）。"
            f"重试与上下文压缩均无效，请到「设置 → 模型」更换标准 OpenAI 兼容模型。"
            f"（最近一次调用方: {caller or '?'}，原始响应 {raw_len} 字节）"
        )


def breaker_threshold() -> int:
    """熔断阈值（读环境变量 ``XUANJIAN_LLM_EMPTY_PARSE_BREAKER``，默认 3）。

    ``0`` 表示关闭熔断（只统计）。
    """
    raw = (os.environ.get("XUANJIAN_LLM_EMPTY_PARSE_BREAKER") or "").strip()
    if not raw:
        return _DEFAULT_BREAKER_THRESHOLD
    try:
        return int(float(raw))
    except ValueError:
        return _DEFAULT_BREAKER_THRESHOLD


def record_empty_parse(model: str = "", caller: str = "", raw_len: int = 0) -> bool:
    """记一次空解析。

    Args:
        model: 模型名；与上次不同则先重置计数（换模型 = 重新开始）。
        caller: 调用方标识（便于定位是哪个环节瞎了）。
        raw_len: 原始响应字节数（诊断用）。

    Returns:
        是否**已熔断**（调用方据此决定抛不抛 ``LLMEmptyResponseError``）。
    """
    with _lock:
        _m = model or ""
        if _m and _m != _state.streak_model:
            # 换模型 → 重新计数（旧模型的结论不适用于新模型）
            _state.streak_model = _m
            _state.streak = 0
            _state.tripped = False
        _state.streak += 1
        _state.total_empty += 1
        _state.last_caller = caller or ""
        _state.last_raw_len = int(raw_len or 0)
        _th = breaker_threshold()
        if _th > 0 and _state.streak >= _th:
            _state.tripped = True
        return _state.tripped


def record_ok_parse(model: str = "") -> None:
    """记一次健康响应（有 content 或 tool_calls）—— 重置连续计数。"""
    with _lock:
        _m = model or ""
        if _m and _state.streak_model and _m != _state.streak_model:
            _state.streak_model = _m
        _state.streak = 0
        _state.tripped = False
        _state.total_ok += 1


def is_tripped() -> bool:
    """当前是否处于熔断状态。"""
    with _lock:
        return _state.tripped


def empty_parse_streak() -> int:
    """当前连续空解析次数。"""
    with _lock:
        return _state.streak


def reset() -> None:
    """重置全部状态（新任务开始时调用）。

    保留累计统计（``_total_*``），只清"连续"语义与熔断标记。
    """
    with _lock:
        _state.streak = 0
        _state.tripped = False


def stats() -> dict:
    """健康度统计快照（供报告 / 告警引用）。"""
    with _lock:
        return {
            "model": _state.streak_model,
            "streak": _state.streak,
            "tripped": _state.tripped,
            "threshold": breaker_threshold(),
            "total_empty": _state.total_empty,
            "total_ok": _state.total_ok,
            "last_caller": _state.last_caller,
            "last_raw_len": _state.last_raw_len,
        }


def get_llm_health_stats() -> dict:
    """``stats()`` 的公开别名（供外部/报告引用，语义更明确）。"""
    return stats()


def reset_llm_health() -> None:
    """``reset()`` 的公开别名（新任务开始 / 用户切换模型后调用）。"""
    reset()


def looks_empty(message: object) -> bool:
    """判断一条已解析的 message 是否为"空响应"。

    空 = 既无 content、也无 tool_calls、也无 reasoning_content。
    （纯 reasoning 响应不算空 —— 那是思考模型的正常输出形态。）

    Args:
        message: 形如 ``resp.choices[0].message`` 的对象。

    Returns:
        True 表示该响应为空（异常）。
    """
    if message is None:
        return True
    _content = getattr(message, "content", None)
    if isinstance(_content, str) and _content.strip():
        return False
    if getattr(message, "tool_calls", None):
        return False
    _reasoning = getattr(message, "reasoning_content", None)
    if isinstance(_reasoning, str) and _reasoning.strip():
        return False
    return True


__all__ = [
    "LLMEmptyResponseError",
    "breaker_threshold",
    "empty_parse_streak",
    "get_llm_health_stats",
    "is_tripped",
    "looks_empty",
    "record_empty_parse",
    "record_ok_parse",
    "reset",
    "reset_llm_health",
    "stats",
]
