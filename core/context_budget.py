"""上下文预算可行性 —— 「固定开销 > 可用输入预算」的统一处置。

★ 924（task_1790223312_c75b16）实证问题：

- 模型 ``wuwen`` 未登记窗口 → 按默认 32768 估算；预算
  ``int(32768 × 0.6) − 4096 = 15564``。
- 子 Agent 的**固定开销**（``WORKER_SYSTEM_PROMPT`` 4113 tok
  + 2 个预注入 SKILL ≈ 13K tok + 工具 schema）实测 ≈ 17510，**已经超过预算**。
- 于是 worker 在**第 1 轮**（历史为空）就撞 ``ContextLimitError``；
  而当时的兜底是 ``ContextManager.compress()`` —— 它按设计**只压 history、
  不碰 system_messages**，实测压缩前后估算值一位不差（17351 → 17351），
  重试必然再失败 → worker 直接死、36 项 checklist 全跳过、真实完成率 2.0%。

结论：治"固定开销超预算"只能靠**裁剪 system 块**，不能靠 compress。
本模块把这件事收敛为单一实现，供 ``worker_agent`` 与 ``browse_worker`` 共用
（两处逻辑原本各自复制一份，既重复又容易漂移）。
"""

from __future__ import annotations

from typing import Any, Iterable

from core.log import get_logger

log = get_logger("context.budget")

#: 给首轮任务消息预留的最小空间（tokens）
MIN_TASK_ROOM = 1500


def compute_fit(
    context: Any,
    model: str,
    tools: Iterable[dict] | None = None,
    *,
    reserve_ratio: float = 0.9,
) -> dict:
    """只计算可行性，不做任何裁剪（纯读）。

    Args:
        context: ``ContextManager`` 实例。
        model: 模型名（决定窗口 → 预算）。
        tools: 工具 schema（其开销必须计入固定开销）。
        reserve_ratio: 余量比例，``预算 × reserve_ratio`` 之后再扣
            ``MIN_TASK_ROOM`` 作为可行上限。

    Returns:
        ``{"model","budget","before","target","ok"}``；预算计算不可用时返回
        ``{"ok": True, "skipped": <原因>}``（fail-open，不因自检本身阻塞扫描）。
    """
    try:
        from core.llm import available_input_budget, estimate_messages_tokens
    except Exception as e:  # pragma: no cover
        return {"ok": True, "skipped": f"{type(e).__name__}: {e}"}

    budget = available_input_budget(model)
    before = estimate_messages_tokens(context.system_messages, list(tools or ()) or None)
    room = max(MIN_TASK_ROOM, int(budget * (1.0 - float(reserve_ratio))))
    ceiling = budget - room
    return {
        "model": model,
        "budget": budget,
        "before": before,
        "target": ceiling,
        "ok": before <= ceiling,
        "shrunk": None,
    }


def ensure_context_fits(
    context: Any,
    model: str,
    tools: Iterable[dict] | None = None,
    *,
    reserve_ratio: float = 0.9,
    who: str = "?",
) -> dict:
    """断言固定开销可行；不可行则按优先级裁剪 system 块。

    在**每一次** LLM 调用之前都应可安全调用（幂等：可行时零副作用）。

    Returns:
        同 ``compute_fit``，外带 ``shrunk``（``shrink_system_messages`` 的统计）
        与最终 ``ok``。
    """
    stats = compute_fit(context, model, tools, reserve_ratio=reserve_ratio)
    if stats.get("skipped") or stats.get("ok"):
        return stats

    _tools = list(tools or ()) or None
    shrunk = context.shrink_system_messages(stats["target"], _tools)
    stats["shrunk"] = shrunk
    after = int(shrunk.get("after", stats["before"]))
    stats["ok"] = bool(shrunk.get("ok")) and after <= stats["target"]

    if stats["ok"]:
        log.warning(
            "[%s] 固定开销超预算，已按优先级裁剪 system 块自救: %d → %d tokens"
            "（预算 %d，丢弃 %d 块: %s）",
            who, stats["before"], after, stats["budget"],
            shrunk.get("dropped", 0), shrunk.get("dropped_kinds"),
        )
    else:
        log.error(
            "[%s] 固定开销超预算且裁剪后仍不可行: %d → %d tokens（预算 %d，模型 %s）。"
            "请更换上下文窗口 ≥64K 的模型。",
            who, stats["before"], after, stats["budget"], model,
        )
    return stats


def infeasible_message(stats: dict) -> str:
    """把不可行结论转成面向用户的文案（给 worker_error 事件 / 报告）。"""
    return (
        f"固定开销 {stats.get('before')} tokens 超出模型 `{stats.get('model')}` 的"
        f"可用输入预算 {stats.get('budget')} tokens，且裁剪 system 块后仍超限。"
        f"请更换上下文窗口 ≥64K 的模型后重试。"
    )


__all__ = ["MIN_TASK_ROOM", "compute_fit", "ensure_context_fits", "infeasible_message"]
