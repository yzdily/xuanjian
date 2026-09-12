"""
Knowledge MCP — Skills 知识库检索服务

搜索和加载 SKILL.md 方法论，优先搜索 skills_my/（用户私有），
再搜索 knowledge/AboutSecurity/skills/（公共基座）。
"""

from __future__ import annotations

import os
import yaml
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("knowledge")

# 知识库搜索路径（优先级从高到低）
# playbooks/ 已合并进 skills_my/scenario/，统一扫描
SEARCH_PATHS = [
    Path(os.getenv("SKILLS_MY_PATH", "./skills_my")),
    Path(os.getenv("KNOWLEDGE_BASE_PATH", "./knowledge/AboutSecurity")) / "skills",
]


def _find_all_skills() -> list[dict]:
    """扫描所有 SKILL.md，提取 frontmatter 元数据。"""
    skills = []
    for base in SEARCH_PATHS:
        if not base.exists():
            continue
        for skill_file in base.rglob("SKILL.md"):
            try:
                content = skill_file.read_text(encoding="utf-8")
                meta = _parse_frontmatter(content)
                meta["_path"] = str(skill_file)
                meta["_source"] = "private" if "skills_my" in str(skill_file) else "public"
                skills.append(meta)
            except Exception:
                continue
    return skills


def _parse_frontmatter(content: str) -> dict:
    """解析 SKILL.md 的 YAML frontmatter。"""
    if not content.startswith("---"):
        return {"name": "unknown", "description": ""}
    parts = content.split("---", 2)
    if len(parts) < 3:
        return {"name": "unknown", "description": ""}
    try:
        meta = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        meta = {}
    return meta


def _get_authority_hint(content: str) -> str:
    """根据 SKILL 的 authority 字段返回 LLM 执行指引。"""
    meta = _parse_frontmatter(content)
    authority = ""
    if isinstance(meta.get("metadata"), dict):
        authority = meta["metadata"].get("authority", "")

    if authority == "expert":
        return (
            "\n> ⚡ **authority: expert** — 这是资深安全工程师的实战经验总结。\n"
            "> **必须严格按以下步骤和决策树执行，不要跳过、不要替换、不要自作主张改变顺序。**\n"
            "> **当决策树明确写了「满足 X 条件 → 标 vulnerable/not_vuln」时，必须按此判定，不得用自己的推理覆盖 SKILL 的结论。**\n"
            "> **例如：SKILL 写「排序参数可控 → ORDER BY 注入 → 立即 mark vulnerable」，你就必须标 vulnerable，不得降级为 needs_review 或 not_vuln。**\n"
        )
    elif authority == "reference":
        return (
            "\n> 📖 **authority: reference** — 这是通用参考方法论。\n"
            "> 可以参考方向和思路，也可以结合你自己的推理自主判断和扩展。\n"
        )
    else:
        return "\n"


@mcp.tool()
async def knowledge_search(query: str) -> str:
    """搜索 Skills 知识库，返回匹配的方法论列表。

    搜索范围：skill 名称、描述、tags。
    私有 skills (skills_my/) 优先于公共 skills。
    """
    skills = _find_all_skills()
    query_lower = query.lower()

    matches = []
    for s in skills:
        score = 0
        name = s.get("name", "")
        desc = s.get("description", "")
        tags = ""
        if isinstance(s.get("metadata"), dict):
            tags = s["metadata"].get("tags", "")

        searchable = f"{name} {desc} {tags}".lower()

        for word in query_lower.split():
            if word in searchable:
                score += 1
            if word in name.lower():
                score += 3  # 名称匹配权重更高

        # 私有 skill 加分
        if s.get("_source") == "private":
            score += 1

        if score > 0:
            matches.append((score, s))

    matches.sort(key=lambda x: -x[0])

    if not matches:
        return f"未找到与 '{query}' 相关的方法论。"

    output = [f"找到 {len(matches)} 个相关方法论：\n"]
    for score, s in matches[:10]:
        source_tag = "🔒私有" if s.get("_source") == "private" else "📚公共"
        authority = ""
        if isinstance(s.get("metadata"), dict):
            auth = s["metadata"].get("authority", "")
            if auth == "expert":
                authority = " ⚡严格遵循"
            elif auth == "reference":
                authority = " 📖参考扩展"
        output.append(f"- **{s.get('name', '?')}** [{source_tag}{authority}]")
        output.append(f"  {s.get('description', '')[:150]}")
        output.append(f"  → `knowledge_load_skill(\"{s.get('name')}\")`")
        output.append("")

    return "\n".join(output)


@mcp.tool()
async def knowledge_load_skill(skill_name: str) -> str:
    """加载一个完整的 SKILL.md 方法论到上下文。

    按优先级搜索：skills_my/ → knowledge/AboutSecurity/skills/

    支持子文件加载语法：
    - "sql-injection-methodology" → 加载 SKILL.md（主方法论）
    - "sql-injection-methodology/waf-bypass" → 加载 knowledge/waf-bypass.md（知识库子文件）
    """
    MAX_SKILL_CHARS = 20000  # Agent 主动加载时给完整版（预注入仍由 worker_agent.py 截断到 8KB）
    MAX_KNOWLEDGE_CHARS = 12000  # 知识库子文件允许更长（绕过库/案例库需要更多空间）

    # 解析子文件路径：skill_name/sub_file_name
    parts = skill_name.split("/", 1)
    base_skill_name = parts[0]
    sub_file_name = parts[1] if len(parts) > 1 else None

    for base in SEARCH_PATHS:
        if not base.exists():
            continue

        # 精确匹配目录名
        for skill_dir in base.rglob(base_skill_name):
            if not skill_dir.is_dir():
                continue

            # ── 子文件加载模式 ──
            if sub_file_name:
                # 搜索 knowledge/ 子目录
                sub_path = skill_dir / "knowledge" / f"{sub_file_name}.md"
                if sub_path.exists():
                    content = sub_path.read_text(encoding="utf-8")
                    if len(content) > MAX_KNOWLEDGE_CHARS:
                        content = content[:MAX_KNOWLEDGE_CHARS] + f"\n\n... (已截断，原文 {len(content)} 字符)"
                    return f"# 知识库: {base_skill_name}/{sub_file_name}\n\n{content}"
                # 兜底：直接在 skill 目录下找同名 md
                sub_path2 = skill_dir / f"{sub_file_name}.md"
                if sub_path2.exists():
                    content = sub_path2.read_text(encoding="utf-8")
                    if len(content) > MAX_KNOWLEDGE_CHARS:
                        content = content[:MAX_KNOWLEDGE_CHARS] + f"\n\n... (已截断，原文 {len(content)} 字符)"
                    return f"# 知识库: {base_skill_name}/{sub_file_name}\n\n{content}"
                # 列出可用的子文件
                knowledge_dir = skill_dir / "knowledge"
                if knowledge_dir.exists():
                    available = [f.stem for f in knowledge_dir.glob("*.md")]
                    if available:
                        return (
                            f"未找到子文件 '{sub_file_name}'。"
                            f"可用的知识库子文件：\n"
                            + "\n".join(f"  → `knowledge_load_skill(\"{base_skill_name}/{a}\")`" for a in available)
                        )
                return f"SKILL '{base_skill_name}' 没有 knowledge/ 子目录或子文件 '{sub_file_name}' 不存在。"

            # ── 主文件加载模式 ──
            skill_file = skill_dir / "SKILL.md"
            if skill_file.exists():
                content = skill_file.read_text(encoding="utf-8")
                authority_hint = _get_authority_hint(content)
                if len(content) > MAX_SKILL_CHARS:
                    content = content[:MAX_SKILL_CHARS] + f"\n\n... (已截断，原文 {len(content)} 字符，保留核心部分)"
                return f"# 已加载方法论: {base_skill_name}\n{authority_hint}\n{content}"

        # 模糊匹配（仅主文件）
        if not sub_file_name:
            for skill_file in base.rglob("SKILL.md"):
                if base_skill_name in str(skill_file):
                    content = skill_file.read_text(encoding="utf-8")
                    authority_hint = _get_authority_hint(content)
                    if len(content) > MAX_SKILL_CHARS:
                        content = content[:MAX_SKILL_CHARS] + f"\n\n... (已截断，原文 {len(content)} 字符，保留核心部分)"
                    return f"# 已加载方法论: {skill_file.parent.name}\n{authority_hint}\n{content}"

    return f"未找到名为 '{skill_name}' 的方法论。请用 knowledge_search 搜索。"


@mcp.tool()
async def knowledge_list_categories() -> str:
    """列出所有可用的方法论分类和数量。"""
    skills = _find_all_skills()
    categories: dict[str, int] = {}
    for s in skills:
        cat = "unknown"
        if isinstance(s.get("metadata"), dict):
            cat = s["metadata"].get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1

    output = ["可用方法论分类：\n"]
    for cat, count in sorted(categories.items()):
        output.append(f"  {cat}: {count} 个")

    total_private = sum(1 for s in skills if s.get("_source") == "private")
    total_public = sum(1 for s in skills if s.get("_source") == "public")
    output.append(f"\n总计: {len(skills)} 个方法论 ({total_private} 私有 + {total_public} 公共)")

    return "\n".join(output)


if __name__ == "__main__":
    mcp.run(transport="stdio")
