"""
core/replay/recorder.py — 事件订阅 → 剧本帧

监听以下事件并自动落盘：
- worker.decision     → DECISION 帧
- harm.validated      → HARM_VALIDATED 帧
- lesson.candidate    → LESSON 帧

run_id 选取规则：
- payload 显式带 run_id 优先用
- 否则用 task_id 作为 run_id（一个 task = 一个 run）
- 都没有就用进程级默认 run（避免数据散落）
"""

from __future__ import annotations

import time
from typing import Any

from core.events import Events
from core.log import get_logger
from core.replay.frame import FrameKind, ReplayFrame, new_frame_id, new_run_id
from core.replay.store import save_frame

log = get_logger("replay.recorder")

_PROCESS_RUN_ID: str = ""


def _get_process_run_id() -> str:
    """进程级兜底 run_id，避免没传 task_id 时数据散落。"""
    # @intentional_global D7-D类：进程级兜底 run_id，故意全局聚合散落数据，CI 白名单豁免
    global _PROCESS_RUN_ID
    if not _PROCESS_RUN_ID:
        _PROCESS_RUN_ID = new_run_id("proc")
    return _PROCESS_RUN_ID


def _resolve_run_id(payload: dict[str, Any]) -> str:
    return (
        payload.get("run_id")
        or payload.get("task_id")
        or _get_process_run_id()
    )


def _meta_patch(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": payload.get("task_id", ""),
        "target": payload.get("target", "") or payload.get("target_url", ""),
    }


# ============================================================
# Event handlers
# ============================================================

def on_worker_decision(payload: dict[str, Any]) -> None:
    """payload 字段（建议）：
        task_id, run_id, feature_id, feature_name, vuln_type,
        skill_used, payload, target_url, llm_summary
    """
    run_id = _resolve_run_id(payload)
    frame = ReplayFrame(
        frame_id=new_frame_id(),
        run_id=run_id,
        kind=FrameKind.DECISION,
        timestamp=time.time(),
        feature_id=payload.get("feature_id", ""),
        feature_name=payload.get("feature_name", ""),
        vuln_type=payload.get("vuln_type", ""),
        skill_used=payload.get("skill_used", ""),
        payload=str(payload.get("payload", ""))[:2000],
        target_url=payload.get("target_url", ""),
        llm_summary=str(payload.get("llm_summary", ""))[:2000],
        extra={k: v for k, v in payload.items() if k not in {
            "task_id", "run_id", "feature_id", "feature_name", "vuln_type",
            "skill_used", "payload", "target_url", "llm_summary", "target"
        }},
    )
    save_frame(frame, _meta_patch(payload))


def on_harm_validated(payload: dict[str, Any]) -> None:
    """payload 字段（建议）：
        task_id, run_id, feature_id, vuln_type, conclusion,
        severity, target_url, llm_summary
    """
    run_id = _resolve_run_id(payload)
    frame = ReplayFrame(
        frame_id=new_frame_id(),
        run_id=run_id,
        kind=FrameKind.HARM_VALIDATED,
        timestamp=time.time(),
        feature_id=payload.get("feature_id", ""),
        feature_name=payload.get("feature_name", ""),
        vuln_type=payload.get("vuln_type", ""),
        skill_used=payload.get("skill_used", ""),
        target_url=payload.get("target_url", ""),
        conclusion=payload.get("conclusion", ""),
        severity=payload.get("severity", ""),
        llm_summary=str(payload.get("llm_summary", ""))[:2000],
        extra={k: v for k, v in payload.items() if k not in {
            "task_id", "run_id", "feature_id", "feature_name", "vuln_type",
            "skill_used", "target_url", "llm_summary", "conclusion", "severity",
            "target"
        }},
    )
    save_frame(frame, _meta_patch(payload))


def on_lesson_candidate(payload: dict[str, Any]) -> None:
    """payload 字段：lesson, vuln_type, target_url, scope, scope_value"""
    run_id = _resolve_run_id(payload)
    frame = ReplayFrame(
        frame_id=new_frame_id(),
        run_id=run_id,
        kind=FrameKind.LESSON,
        timestamp=time.time(),
        vuln_type=payload.get("vuln_type", ""),
        target_url=payload.get("target_url", ""),
        llm_summary=str(payload.get("lesson", ""))[:2000],
        extra={
            "scope": payload.get("scope", ""),
            "scope_value": payload.get("scope_value", ""),
            "trigger": payload.get("trigger", ""),
        },
    )
    save_frame(frame, _meta_patch(payload))


# ============================================================
# 暴露给 register.py 的事件→handler 映射
# ============================================================

EVENT_HANDLERS = {
    Events.WORKER_DECISION: on_worker_decision,
    Events.HARM_VALIDATED: on_harm_validated,
    Events.LESSON_CANDIDATE: on_lesson_candidate,
}


__all__ = [
    "on_worker_decision",
    "on_harm_validated",
    "on_lesson_candidate",
    "EVENT_HANDLERS",
]
