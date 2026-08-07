"""Skill routing — 把漏洞类型 / 发现映射到治理它的 SKILL（确定性，零 LLM）。

让 fast 模式在不调用 LLM 的前提下获得「skill 引导」：
- 为每个发现标注其治理 SKILL（VULN_TO_SKILL 确定性映射）
- 为一组漏洞类型选出最相关、优先级最高的 SKILL（供补充测试 / 报告指引）

设计要点（对齐 REDESIGN_AND_TESTING_PLAN.md 的可测性目标）：
- 纯函数 + 可注入 registry，零网络 / 零文件副作用，可 100% 单测。
- 不调用 LLM：SKILL *选择* 完全由 VULN_TO_SKILL（漏洞类型→SKILL 名）决定，
  与优先级，确定性可复现。把 SKILL *正文（散文攻击链）* 展开成可执行探针
  才是 LLM 的活，留作可选的后续层（由 ScanExecutor 注释说明，默认关闭、有界）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from core.log import get_logger

log = get_logger("skill_router")


@dataclass
class SkillRoute:
    """一个漏洞类型 → 治理它的 SKILL 的映射。"""

    vuln_type: str
    skill_name: str
    skill_path: str = ""
    priority: int = 5

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "skill_name": self.skill_name,
            "skill_path": self.skill_path,
            "priority": self.priority,
        }


def _resolve_registry(registry: Any | None) -> Any:
    """返回注入的 registry，或懒加载全局单例（已缓存，仅首次扫描 skills_my/）。"""
    if registry is not None:
        return registry
    from core.skill_registry import get_registry

    return get_registry()


def _skill_meta(registry: Any, skill_name: str) -> tuple[str, int]:
    """返回 (skill_path, priority)；registry 缺字段时安全回退到空 / 5。"""
    skills = getattr(registry, "skills", None) or {}
    entry = skills.get(skill_name)
    if entry is None:
        return "", 5
    path = str(getattr(entry, "path", "") or "")
    prio = int(getattr(entry, "priority", 5) or 5)
    return path, prio


def lookup_skill_for_vuln_type(
    vuln_type: str,
    registry: Any | None = None,
) -> SkillRoute | None:
    """为单个漏洞类型查其治理 SKILL。无映射返回 None（零 LLM）。"""
    if not vuln_type:
        return None
    registry = _resolve_registry(registry)
    vts = getattr(registry, "vuln_to_skill", None) or {}
    name = vts.get(vuln_type)
    if not name:
        return None
    path, prio = _skill_meta(registry, name)
    return SkillRoute(
        vuln_type=vuln_type,
        skill_name=name,
        skill_path=path,
        priority=prio,
    )


def build_vuln_to_skill_routes(
    vuln_types: Iterable[str],
    registry: Any | None = None,
) -> dict[str, SkillRoute]:
    """为一组漏洞类型构建完整查找表（不截断、不按 SKILL 去重）。

    用于给每个发现打标：vuln_type → SkillRoute。
    未命中映射的 vuln_type 不会出现在结果里（容错）。
    """
    return {
        vt: route
        for vt in vuln_types
        if vt
        and (route := lookup_skill_for_vuln_type(vt, registry)) is not None
    }


def route_vuln_types_to_skills(
    vuln_types: Iterable[str],
    registry: Any | None = None,
    top_n: int = 3,
) -> list[SkillRoute]:
    """把一组漏洞类型映射到治理它们的 SKILL（供报告 / 补充测试选择）。

    规则：
    - 经 VULN_TO_SKILL 查表（确定性，无 LLM）
    - 同一 SKILL 去重（一个 SKILL 可能覆盖多个漏洞类型），保留最高优先级命中
    - 按 SKILL priority 降序、SKILL 名升序稳定排序
    - 截断到 top_n（fast 模式用于约束补充测试规模）

    Returns:
        选中的 SkillRoute 列表（已按优先级排序、截断）。
    """
    registry = _resolve_registry(registry)

    # skill_name -> (vuln_type, priority)，按 SKILL 去重时保留优先级更高者
    seen: dict[str, tuple[str, int]] = {}
    for vt in vuln_types:
        if not vt:
            continue
        route = lookup_skill_for_vuln_type(vt, registry)
        if route is None:
            continue
        prev = seen.get(route.skill_name)
        if prev is None or route.priority > prev[1]:
            seen[route.skill_name] = (route.vuln_type, route.priority)

    routes: list[SkillRoute] = []
    for skill_name, (vt, prio) in seen.items():
        path, _ = _skill_meta(registry, skill_name)
        routes.append(
            SkillRoute(vuln_type=vt, skill_name=skill_name, skill_path=path, priority=prio)
        )

    # 稳定排序：优先级降序，skill 名升序
    routes.sort(key=lambda r: (-r.priority, r.skill_name))

    if top_n and top_n > 0:
        routes = routes[:top_n]
    return routes
