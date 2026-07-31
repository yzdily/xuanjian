"""
core/replay/miner.py — 从剧本反推 lessons

核心算法：
1. 把所有 DECISION 帧按 (vuln_type, skill_used) 分组
2. 对每个组，找紧跟其后的 HARM_VALIDATED 帧的 conclusion
3. 统计成功率：vulnerable / (vulnerable + not_vuln)
   - 高成功率组合 → "正向经验"：在 X 类功能用 SKILL Y 有效
   - 低成功率组合 → "反向经验"：避免在 X 类用 Y
4. 调用 memory.record() 写回（**只调旧公共 API，不改旧代码**）

输出 MinedLesson 列表，调用方可决定是否真正写入 memory。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from core.log import get_logger
from core.replay.frame import FrameKind, ReplayFrame

log = get_logger("replay.miner")


@dataclass
class MinedLesson:
    """从剧本中挖出的一条候选经验。"""
    scope: str = "vuln_type"          # 默认 vuln_type 维度
    scope_value: str = ""
    trigger: str = ""
    lesson: str = ""
    evidence: str = ""
    success_count: int = 0
    fail_count: int = 0

    @property
    def total(self) -> int:
        return self.success_count + self.fail_count

    @property
    def success_rate(self) -> float:
        return self.success_count / self.total if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "scope_value": self.scope_value,
            "trigger": self.trigger,
            "lesson": self.lesson,
            "evidence": self.evidence,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "success_rate": round(self.success_rate, 2),
        }


def _pair_decision_with_validation(
    frames: list[ReplayFrame],
) -> list[tuple[ReplayFrame, ReplayFrame | None]]:
    """把每个 DECISION 帧与紧随其后第一个 HARM_VALIDATED 帧配对。

    匹配条件：相同 vuln_type 或同一 feature_id，时间相邻。
    """
    pairs: list[tuple[ReplayFrame, ReplayFrame | None]] = []
    n = len(frames)
    for i, f in enumerate(frames):
        if f.kind != FrameKind.DECISION:
            continue
        # 向后找第一个 HARM_VALIDATED，且匹配 feature_id 或 vuln_type
        match: ReplayFrame | None = None
        for j in range(i + 1, n):
            g = frames[j]
            if g.kind != FrameKind.HARM_VALIDATED:
                continue
            same_feat = bool(f.feature_id) and f.feature_id == g.feature_id
            same_vt = bool(f.vuln_type) and f.vuln_type == g.vuln_type
            if same_feat or same_vt:
                match = g
                break
        pairs.append((f, match))
    return pairs


def mine_lessons_from_script(
    frames: list[ReplayFrame],
    min_total: int = 3,
    success_threshold: float = 0.66,
    fail_threshold: float = 0.34,
) -> list[MinedLesson]:
    """从剧本帧列表挖经验。

    Args:
        frames: 一个 run 的所有帧
        min_total: 一个 (vuln_type, skill) 组合至少有多少次配对才纳入分析
        success_threshold: 高于此成功率视为"正向经验"
        fail_threshold: 低于此成功率视为"反向经验"

    Returns:
        候选经验列表，由调用方决定是否真正写入 memory。
    """
    pairs = _pair_decision_with_validation(frames)

    # 分组：(vuln_type, skill_used) → [conclusion列表]
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    sample_evidence: dict[tuple[str, str], str] = {}

    for dec, val in pairs:
        if val is None:
            continue
        key = (dec.vuln_type or "unknown", dec.skill_used or "unknown")
        groups[key].append(val.conclusion or "")
        # 保留一条原始证据（payload + 结论）
        if key not in sample_evidence and (dec.payload or val.llm_summary):
            sample_evidence[key] = (
                f"payload={dec.payload[:200]} | conclusion={val.conclusion} | "
                f"summary={val.llm_summary[:200]}"
            )[:1500]

    out: list[MinedLesson] = []
    for (vt, skill), concls in groups.items():
        success = sum(1 for c in concls if c == "vulnerable")
        fail = sum(1 for c in concls if c == "not_vuln")
        total = success + fail
        if total < min_total:
            continue
        rate = success / total if total else 0.0
        if rate >= success_threshold:
            out.append(MinedLesson(
                scope="vuln_type",
                scope_value=vt,
                trigger=f"{vt} {skill}".strip(),
                lesson=(
                    f"在 {vt} 类漏洞测试中，使用 SKILL `{skill}` 命中率较高"
                    f"（{success}/{total}）。优先尝试此 SKILL。"
                ),
                evidence=sample_evidence.get((vt, skill), ""),
                success_count=success,
                fail_count=fail,
            ))
        elif rate <= fail_threshold:
            out.append(MinedLesson(
                scope="vuln_type",
                scope_value=vt,
                trigger=f"{vt} {skill}".strip(),
                lesson=(
                    f"在 {vt} 类漏洞测试中，SKILL `{skill}` 多次未命中"
                    f"（{fail}/{total}）。下次优先尝试其他 SKILL，避免浪费 token。"
                ),
                evidence=sample_evidence.get((vt, skill), ""),
                success_count=success,
                fail_count=fail,
            ))

    return out


def write_back_to_memory(lessons: list[MinedLesson]) -> int:
    """把挖到的经验写回 core.memory。

    返回成功写入的数量。永远不抛异常。
    """
    if not lessons:
        return 0
    try:
        from core import memory as _memory
    except Exception as e:
        log.warning("memory 模块不可用，跳过写回: %s", e)
        return 0

    ok = 0
    for ls in lessons:
        try:
            _memory.record(
                scope=ls.scope,
                scope_value=ls.scope_value,
                trigger=ls.trigger,
                lesson=ls.lesson,
                evidence=ls.evidence,
                source="self_learn",
            )
            ok += 1
        except Exception as e:
            log.warning("写入经验失败 [%s]: %s", ls.scope_value, e)
    log.info("Lesson Miner 写回 %d/%d 条经验", ok, len(lessons))
    return ok


__all__ = [
    "MinedLesson",
    "mine_lessons_from_script",
    "write_back_to_memory",
]
