"""
core/replay/emit_helper.py — 决策剧场事件发送的统一入口

设计目标：
- 让 worker / realtime_worker / tool_executor 用一行代码就能 emit
- 所有 try/except 兜底，emit 失败绝不影响主流程（safety-first）
- 统一字段命名，避免每个调用方拼 payload 时各自为政

事件分类（track）：
- "llm"     — LLM 自主决策（worker 选工具、调用 SKILL）★ 当前任务核心
- "scanner" — 自动扫描器（XSS 13-step 流水线等）
- "system"  — 系统里程碑（Phase 切换 / SKILL 加载）

为什么不直接用 core.events.bus？
因为 emit payload 字段多、字符串裁剪规则统一、且需要兼容三套调用方
（worker / realtime_worker / tool_executor），抽出 helper 后调用方
只关心"发生了什么"，不必关心 payload schema。
"""

from __future__ import annotations

from typing import Any

from core.events import Events, bus
from core.log import get_logger

log = get_logger("replay.emit")

# 字段长度兜底（避免 LLM 输出爆炸进存储）
_MAX_PAYLOAD = 2000
_MAX_SUMMARY = 2000


def _truncate(s: Any, n: int) -> str:
    """安全地把任意输入截断成字符串，None/异常都不抛。"""
    if s is None:
        return ""
    try:
        text = s if isinstance(s, str) else str(s)
    except Exception:
        return ""
    if len(text) <= n:
        return text
    return text[:n] + "...(截断)"


def emit_decision(
    *,
    task_id: str = "",
    worker_id: str = "",
    feature_id: str = "",
    feature_name: str = "",
    vuln_type: str = "",
    skill_used: str = "",
    payload: Any = "",
    target_url: str = "",
    llm_summary: Any = "",
    track: str = "llm",
    **extras: Any,
) -> None:
    """发送一帧"决策"事件（kind=DECISION）。

    典型场景：
      - LLM 选了一个工具调用（tool_call）
      - SKILL 被注入到 worker 上下文
      - 系统 Phase 推进
    """
    try:
        body: dict[str, Any] = {
            "task_id": task_id or "",
            "run_id": task_id or "",  # 让 recorder 用 task_id 作为 run_id
            "worker_id": worker_id or "",
            "feature_id": feature_id or "",
            "feature_name": _truncate(feature_name, 200),
            "vuln_type": vuln_type or "",
            "skill_used": skill_used or "",
            "payload": _truncate(payload, _MAX_PAYLOAD),
            "target_url": target_url or "",
            "llm_summary": _truncate(llm_summary, _MAX_SUMMARY),
            "track": track or "llm",
        }
        # 额外字段（不覆盖核心字段）
        for k, v in extras.items():
            if k not in body:
                body[k] = v
        bus.emit(Events.WORKER_DECISION, body)
    except Exception as e:
        # 永远不能让 emit 影响主流程
        log.debug("emit_decision 失败（已忽略）: %s", e)


def emit_harm(
    *,
    task_id: str = "",
    worker_id: str = "",
    feature_id: str = "",
    feature_name: str = "",
    vuln_type: str = "",
    skill_used: str = "",
    payload: Any = "",
    target_url: str = "",
    conclusion: str = "",
    severity: str = "",
    llm_summary: Any = "",
    track: str = "llm",
    **extras: Any,
) -> None:
    """发送一帧"危害验证结论"事件（kind=HARM_VALIDATED）。

    典型场景：
      - worker 调用 checklist_mark（vulnerable / not_vuln / needs_review）
      - 主 Agent _handle_checklist_mark 落地结论
    """
    try:
        body: dict[str, Any] = {
            "task_id": task_id or "",
            "run_id": task_id or "",
            "worker_id": worker_id or "",
            "feature_id": feature_id or "",
            "feature_name": _truncate(feature_name, 200),
            "vuln_type": vuln_type or "",
            "skill_used": skill_used or "",
            "payload": _truncate(payload, _MAX_PAYLOAD),
            "target_url": target_url or "",
            "conclusion": conclusion or "",
            "severity": severity or "",
            "llm_summary": _truncate(llm_summary, _MAX_SUMMARY),
            "track": track or "llm",
        }
        for k, v in extras.items():
            if k not in body:
                body[k] = v
        bus.emit(Events.HARM_VALIDATED, body)
    except Exception as e:
        log.debug("emit_harm 失败（已忽略）: %s", e)


__all__ = ["emit_decision", "emit_harm"]
