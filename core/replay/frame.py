"""
core/replay/frame.py — Replay 数据模型

设计原则：
- 每一帧（ReplayFrame）是一次有意义的"决策"或"结论"
- 帧是不可变的（写入后只读），便于回放/审计
- 字段尽量扁平、JSON 友好，不嵌套复杂对象
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class FrameKind(str, Enum):
    DECISION = "decision"          # Worker 选了 SKILL / payload
    HARM_VALIDATED = "harm_validated"  # 危害验证产出结论
    LESSON = "lesson"              # 抽取到经验
    NOTE = "note"                  # 自定义备注


@dataclass
class ReplayFrame:
    """剧本的一帧。"""
    frame_id: str
    run_id: str
    kind: FrameKind
    timestamp: float

    # 上下文（任选）
    feature_id: str = ""
    feature_name: str = ""
    vuln_type: str = ""
    skill_used: str = ""
    payload: str = ""
    target_url: str = ""

    # 结论（HARM_VALIDATED / LESSON）
    conclusion: str = ""           # vulnerable / not_vuln / needs_review
    severity: str = ""             # critical / high / medium / low

    # LLM 思考摘要（可选）
    llm_summary: str = ""

    # 任意附加字段
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # 枚举转字符串
        d["kind"] = self.kind.value if hasattr(self.kind, "value") else str(self.kind)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ReplayFrame":
        # 枚举重建
        kind = d.get("kind", FrameKind.NOTE.value)
        if isinstance(kind, str):
            try:
                kind = FrameKind(kind)
            except Exception:
                kind = FrameKind.NOTE
        # 过滤未知字段，避免新版字段加进来导致老剧本读不出来
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in d.items() if k in known}
        clean["kind"] = kind
        return cls(**clean)


@dataclass
class ScriptMeta:
    """一个剧本的元数据（保存在每个 run 目录的 meta.json）。"""
    run_id: str
    task_id: str = ""
    target: str = ""
    started_at: float = 0
    ended_at: float = 0
    frame_count: int = 0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["started_at_human"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.started_at)) if self.started_at else ""
        d["ended_at_human"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.ended_at)) if self.ended_at else ""
        return d


def new_frame_id() -> str:
    return f"f_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"


def new_run_id(task_id: str = "") -> str:
    base = task_id or "run"
    return f"{base}_{int(time.time())}_{uuid.uuid4().hex[:6]}"


__all__ = [
    "FrameKind",
    "ReplayFrame",
    "ScriptMeta",
    "new_frame_id",
    "new_run_id",
]
