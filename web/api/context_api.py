"""上下文水位只读 API（阶段 5-E2 · D2 ContextGauge）。

## 为什么需要

长任务后半程「没力气」是用户能直接感知的现象，但原因藏在上下文压缩里：
`ContextManager.compress()` 会把超出保留窗口的消息压成摘要。修复前 tool 消息
（测试样本结论）根本不进摘要 → 丢弃即不可恢复（实测 M4b：60 轮丢 53 条）。

**可见化是这次修复的一半** —— 用户需要能回答："现在上下文用了多少？压过几次？
有没有样本被丢掉？离硬拦截还有多远？"

## 数据来源与限制

上下文对象（`ContextManager`）**只存在于进程内存**中。因此：

- 会话仍在内存（本次进程创建）→ 返回实时指标 `live: true`
- 会话只存在于磁盘（进程已重启）→ `live: false` + 解释性 `hint`
  （**不能**返回 0 冒充"水位很低"，那是假数据）

## 文案原则（D2 设计要求）

用**后果语言**而非内部术语：说"样本可能被跳过"，不说"compress 触发"。
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from core.log import get_logger
from web._security import validate_task_id
from web._state import _sessions

log = get_logger("web.context_api")

router = APIRouter()

#: 与 core.context 的默认阈值保持一致（用于展示"离阈值还差多少"）
_DEFAULT_TOKEN_THRESHOLD = 24000
_DEFAULT_TURN_THRESHOLD = 20
_DEFAULT_WINDOW = 65536
_DEFAULT_SAFETY = 0.6


def _thresholds() -> tuple[int, int]:
    try:
        from core.context import COMPRESS_THRESHOLD, CONTEXT_TOKEN_COMPRESS_THRESHOLD
        return int(CONTEXT_TOKEN_COMPRESS_THRESHOLD), int(COMPRESS_THRESHOLD)
    except Exception:                                       # pragma: no cover
        return _DEFAULT_TOKEN_THRESHOLD, _DEFAULT_TURN_THRESHOLD


@router.get("/api/context/{task_id}")
async def get_context_usage(task_id: str):
    """某会话的上下文水位（token / 轮次 / 预算 / 压缩与接力统计）。只读。"""
    if not validate_task_id(task_id):
        return JSONResponse(status_code=400, content={"error": f"非法 task_id: {task_id!r}"})

    token_threshold, turn_threshold = _thresholds()
    base = {
        "task_id": task_id,
        "thresholds": {
            "tokens": token_threshold,
            "turns": turn_threshold,
            "window": _DEFAULT_WINDOW,
            "safety": _DEFAULT_SAFETY,
        },
    }

    session = _sessions.get(task_id)
    ctx = getattr(session, "current_context", None) if session else None

    if ctx is None:
        base.update({
            "live": False,
            "hint": (
                "该会话的上下文不在当前进程中（服务重启后会话仍在磁盘，但上下文对象不持久化），"
                "因此无法显示实时水位。发起新任务或继续该会话后即可看到。"
            ),
        })
        return base

    try:
        tokens = int(ctx.estimate_tokens())
    except Exception:
        tokens = 0
    turns = int(getattr(ctx, "turn_count", 0) or 0)

    try:
        budget_usage = float(ctx.check_context_budget(_DEFAULT_WINDOW, _DEFAULT_SAFETY))
    except Exception:
        budget_usage = 0.0
    try:
        allows = bool(ctx.budget_allows_injection(_DEFAULT_WINDOW, _DEFAULT_SAFETY))
    except Exception:
        allows = True

    result = ctx.last_compress_stats or {}
    handoff = getattr(session, "_last_handoff", None) or {}

    base.update({
        "live": True,
        "tokens": {
            "current": tokens,
            "threshold": token_threshold,
            "ratio": round(tokens / token_threshold, 3) if token_threshold else 0.0,
        },
        "turns": {
            "current": turns,
            "threshold": turn_threshold,
            "ratio": round(turns / turn_threshold, 3) if turn_threshold else 0.0,
        },
        "budget": {
            # usage >= 1.0 表示已达 60% 安全预算上限 → 会**拒绝继续注入样本**
            "usage": round(budget_usage, 3),
            "allows_injection": allows,
            "rejected": not allows,
        },
        "compress": {
            "count": int(getattr(ctx, "compress_count", 0) or 0),
            "last": {
                "removed_messages": int(result.get("dropped_messages", 0) or 0),
                "removed_samples": int(result.get("dropped_tool_samples", 0) or 0),
                "samples_kept_in_summary": int(result.get("tool_samples_in_summary", 0) or 0),
                "before_tokens": int(result.get("before_tokens", 0) or 0),
                "after_tokens": int(result.get("after_tokens", 0) or 0),
            },
        },
        "handoff": {
            "count": int(getattr(session, "_handoff_count", 0) or 0),
            "last": handoff,
            "from_phase": getattr(session, "_handoff_from_phase", "") or "",
        },
    })
    return base
