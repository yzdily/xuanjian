"""
SKILL Registry — 扫描 skills_my/ 下所有 SKILL.md，从 YAML frontmatter 中提取自注册映射。

设计目标：
- 让安全工程师**只写 SKILL.md 就能让 Agent 自动加载**，不用改 Python 源码
- 完全向后兼容：未填新字段的 SKILL 仍按 `core/config.py` 默认映射工作
- 支持热重载（WebUI /api/skills/reload）

SKILL.md frontmatter 约定（向 CONTRIBUTING_SKILLS.md 看齐）：

    ---
    name: my-skill-name              # 必填，对应文件夹名
    description: "..."               # 可选，一句话描述
    enabled: true                    # 可选，默认 true；false 则跳过加载
    vuln_types:                      # 可选，本 SKILL 覆盖的漏洞类型（中文标准名）
      - SQL注入
      - 注入漏洞
    triggers:                        # ⚠️ 已废弃（保留以兼容老 SKILL.md，解析时被忽略）
      - 搜索                         #    历史用途：功能点关键词 → 自动追加到 FEATURE_VULN_MAPPING
      - search                       #    废弃原因：自注册导致 checklist 规则爆炸（数十个 SKILL 同时认领高频词
      - 查询                         #    "登录/认证/用户"等，使单个功能点 checklist 膨胀到 50+ 项）
                                     #    替代方案：如需让某关键词触发漏洞类型，请直接编辑
                                     #    core/config.py 的 FEATURE_VULN_MAPPING（精选可控）
    synonyms:                        # 可选，LLM 可能用的别名 → 映射到第一个 vuln_types
      - sqli
      - sql-injection
    priority: 5                      # 可选 1-10，越大越优先（多个 SKILL 覆盖同一 vuln_type 时）
    metadata:
      tags: "..."
      category: "..."
    ---
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.di import register_resetter

try:
    import yaml  # PyYAML，PentestAgent 已依赖 mitmproxy 间接装上
    _HAS_YAML = True
except ImportError:
    yaml = None  # type: ignore
    _HAS_YAML = False


SKILLS_DIR = Path("skills_my")


@dataclass
class SkillEntry:
    """单个 SKILL 的元信息（解析 frontmatter 后得到）。"""

    name: str                          # = 目录名
    path: Path                         # SKILL.md 绝对路径
    description: str = ""
    enabled: bool = True
    vuln_types: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    synonyms: list[str] = field(default_factory=list)
    priority: int = 5
    category: str = ""
    tags: list[str] = field(default_factory=list)
    raw_frontmatter: dict = field(default_factory=dict)
    body_size: int = 0                 # 正文字符数（用于 WebUI 展示）
    knowledge_files: list[str] = field(default_factory=list)  # knowledge/ 子文件列表

    @property
    def relative_path(self) -> str:
        """相对 skills_my/ 的展示路径。"""
        try:
            return str(self.path.relative_to(SKILLS_DIR.resolve()))
        except (ValueError, RuntimeError):
            return str(self.path)


@dataclass
class SkillRegistry:
    """所有 SKILL 的集合 + 合并后的运行时映射。"""

    skills: dict[str, SkillEntry] = field(default_factory=dict)        # name → entry
    vuln_to_skill: dict[str, str] = field(default_factory=dict)        # 合并后的 VULN_TO_SKILL
    feature_triggers: list[tuple[list[str], list[str]]] = field(default_factory=list)  # 合并后的 FEATURE_VULN_MAPPING
    vuln_synonyms: dict[str, str] = field(default_factory=dict)        # 合并后的 VULN_SYNONYMS
    errors: list[str] = field(default_factory=list)                    # 解析失败的 SKILL 报告

    @property
    def count(self) -> int:
        return len(self.skills)

    @property
    def enabled_count(self) -> int:
        return sum(1 for s in self.skills.values() if s.enabled)


_FM_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _parse_frontmatter(content: str) -> tuple[dict, str]:
    """从 markdown 内容里提取 YAML frontmatter，返回 (meta_dict, body)。

    无 frontmatter 时返回 ({}, content)。
    """
    m = _FM_PATTERN.match(content)
    if not m:
        return {}, content
    fm_text = m.group(1)
    body = content[m.end():]
    if not _HAS_YAML:
        # 极简兜底解析（仅支持平层 key: value 形式）
        meta = {}
        for line in fm_text.splitlines():
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            if ":" in line and not line.startswith(" "):
                k, _, v = line.partition(":")
                meta[k.strip()] = v.strip().strip('"').strip("'")
        return meta, body
    try:
        data = yaml.safe_load(fm_text)
        if not isinstance(data, dict):
            return {}, body
        return data, body
    except Exception:
        return {}, body


def _to_str_list(value: Any) -> list[str]:
    """容错地把 frontmatter 字段转成 str 列表。

    支持以下形式：
    - YAML list: ["SQL注入", "注入"]
    - 单字符串: "SQL注入"
    - 逗号分隔字符串: "SQL注入, 注入, sqli"
    """
    if not value:
        return []
    if isinstance(value, str):
        return [s.strip() for s in re.split(r"[,;|]", value) if s.strip()]
    if isinstance(value, (list, tuple)):
        result = []
        for x in value:
            if x is None:
                continue
            result.append(str(x).strip())
        return [s for s in result if s]
    return [str(value).strip()]


def parse_skill_file(skill_md: Path) -> SkillEntry | None:
    """解析单个 SKILL.md 文件，返回 SkillEntry。"""
    try:
        content = skill_md.read_text(encoding="utf-8")
    except Exception:
        return None

    meta, body = _parse_frontmatter(content)
    name = str(meta.get("name") or skill_md.parent.name).strip()

    md_meta = meta.get("metadata") or {}
    if not isinstance(md_meta, dict):
        md_meta = {}

    # 扫描 knowledge/ 子目录
    knowledge_dir = skill_md.parent / "knowledge"
    knowledge_files: list[str] = []
    if knowledge_dir.is_dir():
        for kf in sorted(knowledge_dir.glob("*.md")):
            knowledge_files.append(kf.stem)

    return SkillEntry(
        name=name,
        path=skill_md.resolve(),
        description=str(meta.get("description") or "").strip(),
        enabled=bool(meta.get("enabled", True)) if "enabled" in meta else True,
        vuln_types=_to_str_list(meta.get("vuln_types")),
        triggers=_to_str_list(meta.get("triggers")),
        synonyms=_to_str_list(meta.get("synonyms")),
        priority=int(meta.get("priority", 5) or 5),
        category=str(meta.get("category") or md_meta.get("category") or "").strip(),
        tags=_to_str_list(md_meta.get("tags") or meta.get("tags")),
        raw_frontmatter=meta,
        body_size=len(body),
        knowledge_files=knowledge_files,
    )


def _is_exploit_skill(entry: SkillEntry) -> bool:
    """判断一个 SKILL 是否是 exploit 类（位于 skills_my/exploit/ 目录下）。

    判断标准（满足任一即可）：
    1. SKILL.md 路径中包含 /exploit/ 目录层级（且上级是 skills_my）
    2. SKILL name 以 "exploit-" 开头
    """
    # 方式 1：路径判断
    path_str = str(entry.path)
    if "/exploit/" in path_str:
        # 确认是 skills_my/exploit/ 而非其他目录中的 exploit
        parts = path_str.split("/")
        for i, part in enumerate(parts):
            if part == "exploit" and i > 0 and parts[i - 1] in ("skills_my", "skills"):
                return True

    # 方式 2：名称前缀判断（兜底）
    if entry.name.startswith("exploit-"):
        return True

    return False


def scan_skills(skills_dir: Path = SKILLS_DIR) -> SkillRegistry:
    """扫描所有 skills_my/**/SKILL.md，构建 Registry。

    合并策略：
    1. 默认值来自 core.config（VULN_TO_SKILL / FEATURE_VULN_MAPPING / VULN_SYNONYMS）
    2. SKILL.md frontmatter 中显式声明的覆盖默认
    3. 同一 vuln_type 被多个 SKILL 声明时，priority 高的胜出
    """
    from core import config as _conf

    registry = SkillRegistry()

    # 1) 加载 config.py 默认映射作为基础
    # ★ 关键：必须用「原始默认值」而非当前已合并的全局状态，否则禁用 SKILL 后清理不彻底
    # config.py 在 _backup_defaults() 中已备份原始默认值；调用 reset_to_defaults() 让模块全局变量回到原始
    _conf._backup_defaults()
    base_vts = dict(_conf._DEFAULT_VULN_TO_SKILL or _conf.VULN_TO_SKILL)
    base_fvm = [(list(kw), list(vt)) for kw, vt in (_conf._DEFAULT_FEATURE_VULN_MAPPING or _conf.FEATURE_VULN_MAPPING)]
    base_syn = dict(_conf._DEFAULT_VULN_SYNONYMS or _conf.VULN_SYNONYMS)
    registry.vuln_to_skill = base_vts
    registry.feature_triggers = base_fvm
    registry.vuln_synonyms = base_syn

    if not skills_dir.exists():
        registry.errors.append(f"SKILL 目录不存在: {skills_dir}")
        return registry

    # 2) 扫描所有 SKILL.md
    found: list[SkillEntry] = []
    for skill_md in sorted(skills_dir.rglob("SKILL.md")):
        entry = parse_skill_file(skill_md)
        if entry is None:
            registry.errors.append(f"解析失败: {skill_md}")
            continue
        found.append(entry)
        registry.skills[entry.name] = entry

    # 3) 合并 frontmatter 中的映射；priority 高的胜出
    # 先按 priority 升序遍历（高 priority 后写覆盖）
    found_sorted = sorted(found, key=lambda e: e.priority)

    # ★ 收集被禁用的 SKILL 名字（用于稍后从 vuln_to_skill 中清理对它的映射）
    disabled_names = {e.name for e in found if not e.enabled}

    for entry in found_sorted:
        if not entry.enabled:
            continue

        # ★ exploit 类 SKILL 不参与 Phase 2 的 VULN_TO_SKILL 映射
        # 它们只在 harm_validation（Phase 2.6 危害证明）阶段被加载
        # 判断标准：位于 skills_my/exploit/ 目录下（目录路径包含 /exploit/）
        if _is_exploit_skill(entry):
            continue

        # vuln_types → VULN_TO_SKILL
        for vt in entry.vuln_types:
            registry.vuln_to_skill[vt] = entry.name

        # ⚠️ triggers 字段已废弃：不再合并进 FEATURE_VULN_MAPPING
        # 历史问题：74+ 个 SKILL 各自声明 triggers 后，"登录/用户/认证" 等高频词被多个 SKILL
        # 重复认领，单个功能点 checklist 从 ~10 项膨胀到 50+ 项。
        # 新策略：FEATURE_VULN_MAPPING 只来自 core/config.py 默认表（人工精选、可控、可读）。
        # 如需新增触发规则，请直接编辑 core/config.py。
        # （SKILL.md 里的 triggers 字段保留只是为了向后兼容，解析后被忽略。）

        # synonyms → VULN_SYNONYMS（指向第一个 vuln_type）
        if entry.synonyms and entry.vuln_types:
            target = entry.vuln_types[0]
            for syn in entry.synonyms:
                registry.vuln_synonyms[syn] = target

    # 4) ★ 清理被禁用 SKILL 的所有映射
    # 即使该 SKILL 在 core/config.py 默认 VULN_TO_SKILL 中被映射，
    # 用户显式 enabled: false 后也应该不再加载它。
    if disabled_names:
        # 4a) 从 VULN_TO_SKILL 中移除所有指向被禁用 SKILL 的条目
        registry.vuln_to_skill = {
            k: v for k, v in registry.vuln_to_skill.items()
            if v not in disabled_names
        }
        # 4b) 此前还会清理 FEATURE_VULN_MAPPING 中由禁用 SKILL 注入的 trigger 规则；
        #     现在 triggers 已不参与合并，feature_triggers 始终等于 config.py 的默认值，无需清理。

    # 5) 追加用户自定义触发规则（来自 skills_my/_user_triggers.yaml）
    # 这是替代"SKILL 自注册 triggers"的可控方案：用户在 WebUI 上维护，独立 yaml 持久化，
    # 不污染 config.py 默认表，也不会因为 SKILL 数量增长而爆炸（用户能直接看到全量规则）。
    try:
        from core.user_triggers import load_user_triggers
        user_rules = load_user_triggers()
        if user_rules:
            registry.feature_triggers = list(registry.feature_triggers) + user_rules
    except Exception as ex:  # 任何失败都不应阻塞 SKILL 注册
        registry.errors.append(f"加载用户触发规则失败: {ex}")

    return registry


# ============================================================
# 全局单例 + 热重载
# ============================================================

@dataclass
class _SkillRegistryState:
    registry: SkillRegistry | None = None
    exploit_skill_map: dict[str, str] | None = None


_state = _SkillRegistryState()


def get_registry() -> SkillRegistry:
    """获取全局 SkillRegistry 单例（懒加载）。"""
    if _state.registry is None:
        _state.registry = scan_skills()
    return _state.registry


def reload_registry() -> SkillRegistry:
    """强制重新扫描，刷新单例。返回新的 registry。"""
    _state.registry = scan_skills()
    reset_exploit_skill_map()  # ★ 同步重置 exploit skill 映射缓存
    return _state.registry


def reset_registry() -> None:
    """重置 SkillRegistry 单例为 None（下次 get_registry 懒加载重建）。

    与 reload_registry 的区别：不立即触发扫描，仅置空，供测试隔离使用
    （已通过 core.di.register_resetter 注册，可由 reset_singletons 统一调用）。
    """
    _state.registry = None
    reset_exploit_skill_map()


def find_skill_path(skill_name: str) -> Path | None:
    """按 SKILL name（目录名）找到 SKILL.md 路径。"""
    reg = get_registry()
    entry = reg.skills.get(skill_name)
    if entry:
        return entry.path
    # 兜底：直接遍历目录
    for p in SKILLS_DIR.rglob("SKILL.md"):
        if p.parent.name == skill_name:
            return p
    return None


# ============================================================
# Exploit SKILL 查找（供 harm_validation Phase 2.6 使用）
# ============================================================

# 漏洞类型 → exploit skill 名称的映射（独立于 VULN_TO_SKILL）
# 由 exploit skills 的 vuln_types 字段构建
# 已合并入 _SkillRegistryState.exploit_skill_map


def _build_exploit_skill_map() -> dict[str, str]:
    """构建 vuln_type → exploit skill name 的映射。

    只包含位于 skills_my/exploit/ 目录下的 SKILL。
    """
    reg = get_registry()
    mapping: dict[str, str] = {}
    # 按 priority 升序（高优先级后写覆盖）
    exploit_skills = sorted(
        [e for e in reg.skills.values() if e.enabled and _is_exploit_skill(e)],
        key=lambda e: e.priority,
    )
    for entry in exploit_skills:
        for vt in entry.vuln_types:
            mapping[vt] = entry.name
    return mapping


def get_exploit_skill_map() -> dict[str, str]:
    """获取 exploit skill 映射（懒加载 + 缓存）。"""
    if _state.exploit_skill_map is None:
        _state.exploit_skill_map = _build_exploit_skill_map()
    return _state.exploit_skill_map


def find_exploit_skills_for_vuln(vuln_type: str) -> list[tuple[str, str]]:
    """根据漏洞类型查找对应的 exploit skill 内容。

    返回 [(skill_name, skill_content), ...] 列表。
    通常返回 1-2 个（特定类型 + 通用绕过）。

    Args:
        vuln_type: 漏洞类型（中文标准名，如 "SQL注入"、"IDOR越权"）

    Returns:
        [(skill_name, skill_body_content), ...]
    """
    mapping = get_exploit_skill_map()
    results: list[tuple[str, str]] = []

    # 1. 精确匹配
    skill_name = mapping.get(vuln_type)
    if skill_name:
        path = find_skill_path(skill_name)
        if path and path.exists():
            try:
                content = path.read_text(encoding="utf-8")
                # 去掉 frontmatter，只保留正文
                _, body = _parse_frontmatter(content)
                results.append((skill_name, body.strip()))
            except Exception:
                pass

    # 2. 模糊匹配（漏洞类型可能有别名）
    if not results:
        vt_lower = vuln_type.lower()
        for mapped_vt, sname in mapping.items():
            if mapped_vt.lower() in vt_lower or vt_lower in mapped_vt.lower():
                if sname != skill_name:  # 避免重复
                    path = find_skill_path(sname)
                    if path and path.exists():
                        try:
                            content = path.read_text(encoding="utf-8")
                            _, body = _parse_frontmatter(content)
                            results.append((sname, body.strip()))
                        except Exception:
                            pass
                break

    # 3. 始终附加通用绕过 skill（如果存在且不重复）
    universal_name = "exploit-universal-bypass"
    if universal_name not in [r[0] for r in results]:
        path = find_skill_path(universal_name)
        if path and path.exists():
            try:
                content = path.read_text(encoding="utf-8")
                _, body = _parse_frontmatter(content)
                results.append((universal_name, body.strip()))
            except Exception:
                pass

    return results


def reset_exploit_skill_map() -> None:
    """重置 exploit skill 映射缓存（热重载时调用）。"""
    _state.exploit_skill_map = None


# ---- 注册到 core.di 统一单例重置注册表（测试隔离用）----
register_resetter("skill_registry", reset_registry)
register_resetter("exploit_skill_map", reset_exploit_skill_map)
