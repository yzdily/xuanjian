"""
Skill 管理 API。

URL 保持不变：/api/skills/*
设计：每个 SKILL 是一个目录 skills_my/<category>/<name>/SKILL.md
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, Request

from core import config as _config
from core.skill_registry import get_registry, reload_registry
from core.log import get_logger

log = get_logger("web.skills_api")

router = APIRouter()


_SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9][\w\-]{0,60}$")
# category 支持单层斜杠，例如 "discovery/personal"；每段必须是合法标识符，且总长 ≤ 60
_SKILL_CATEGORY_RE = re.compile(r"^[A-Za-z0-9][\w\-]{0,30}(/[A-Za-z0-9][\w\-]{0,30})?$")


def _validate_skill_name(name: str) -> tuple[bool, str]:
    if not name or not _SKILL_NAME_RE.match(name):
        return False, "name 只能含字母/数字/下划线/短横线，1-61 字符"
    return True, ""


def _resolve_skill_path(name: str) -> Path | None:
    """根据 name 查找现有 SKILL.md。"""
    skills_dir = Path("skills_my")
    if not skills_dir.exists():
        return None
    for p in skills_dir.rglob("SKILL.md"):
        if p.parent.name == name:
            return p
    return None


def _is_builtin_skill_path(p: Path) -> bool:
    """判定一个 SKILL.md 路径是否属于"系统内置区"。"""
    try:
        skills_root = Path("skills_my").resolve()
        rel_parts = p.resolve().relative_to(skills_root).parts
    except Exception:
        return False
    return len(rel_parts) >= 2 and rel_parts[0] == "discovery" and rel_parts[1] == "builtin"


def _toggle_skill_enabled_in_frontmatter(content: str, new_enabled: bool) -> str:
    """在 SKILL.md 的 YAML frontmatter 中设置 enabled 字段。"""
    val = "true" if new_enabled else "false"

    fm_match = re.match(r"^(---\s*\n)(.*?)(\n---\s*\n)", content, re.DOTALL)
    if not fm_match:
        return f"---\nenabled: {val}\n---\n\n{content}"

    head, fm_body, tail = fm_match.groups()
    end_idx = fm_match.end()
    rest = content[end_idx:]

    cleaned_fm = re.sub(
        r"^enabled\s*:\s*[^\n]*\n?",
        "",
        fm_body,
        flags=re.MULTILINE,
    )

    name_line = re.search(r"^name\s*:[^\n]*$", cleaned_fm, re.MULTILINE)
    if name_line:
        insert_pos = name_line.end()
        new_fm = cleaned_fm[:insert_pos] + f"\nenabled: {val}" + cleaned_fm[insert_pos:]
    else:
        new_fm = f"enabled: {val}\n" + cleaned_fm

    return head + new_fm + tail + rest


@router.get("/api/skills/list")
async def skills_list():
    """列出所有 SKILL（已合并 frontmatter 元数据 + 文件大小）。"""
    reg = get_registry()
    items = []
    builtin_skipped = 0
    for s in sorted(reg.skills.values(), key=lambda x: (x.category or "zzz", x.name)):
        if _is_builtin_skill_path(s.path):
            builtin_skipped += 1
            continue
        try:
            file_size = s.path.stat().st_size
            mtime = s.path.stat().st_mtime
        except Exception:
            file_size = 0
            mtime = 0
        items.append({
            "name": s.name,
            "description": s.description,
            "category": s.category,
            "enabled": s.enabled,
            "vuln_types": s.vuln_types,
            "triggers": s.triggers,
            "synonyms": s.synonyms,
            "priority": s.priority,
            "tags": s.tags,
            "path": s.relative_path,
            "file_size": file_size,
            "mtime": mtime,
            "body_size": s.body_size,
            "knowledge_files": s.knowledge_files,
        })
    return {
        "count": len(items),
        "enabled_count": reg.enabled_count,
        "builtin_skipped": builtin_skipped,
        "vuln_to_skill_total": len(reg.vuln_to_skill),
        "triggers_total": len(reg.feature_triggers),
        "synonyms_total": len(reg.vuln_synonyms),
        "errors": reg.errors,
        "skills": items,
    }


@router.get("/api/skills/get")
async def skill_get(name: str):
    """获取单个 SKILL 完整内容。"""
    ok, msg = _validate_skill_name(name)
    if not ok:
        return {"status": "error", "message": msg}
    p = _resolve_skill_path(name)
    if p is None:
        return {"status": "error", "message": f"SKILL 不存在: {name}"}
    try:
        content = p.read_text(encoding="utf-8")
        return {"status": "ok", "name": name, "path": str(p.relative_to(Path("skills_my"))),
                "content": content}
    except Exception as ex:
        return {"status": "error", "message": str(ex)}


@router.post("/api/skills/save")
async def skill_save(request: Request):
    """保存 SKILL.md 内容。"""
    body = await request.json()
    name = (body.get("name") or "").strip()
    content = body.get("content") or ""
    category = (body.get("category") or "user").strip()

    ok, msg = _validate_skill_name(name)
    if not ok:
        return {"status": "error", "message": msg}
    if not _SKILL_CATEGORY_RE.match(category):
        return {"status": "error", "message": "category 只能含字母/数字/下划线/短横线，可选单层斜杠（如 discovery/personal）"}
    if not content.strip():
        return {"status": "error", "message": "SKILL 内容不能为空"}

    if category == "discovery":
        category = "discovery/personal"

    if category.startswith("discovery/builtin"):
        return {"status": "error", "message": "discovery/builtin 是系统内置区，不允许在页面新增/修改"}

    existing = _resolve_skill_path(name)
    if existing:
        if _is_builtin_skill_path(existing):
            return {"status": "error", "message": f"{name} 是系统内置 SKILL，不允许修改"}
        target = existing
    else:
        target = Path("skills_my") / category / name / "SKILL.md"
        target.parent.mkdir(parents=True, exist_ok=True)

    try:
        tmp = target.with_suffix(".md.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(target)
        new_reg = reload_registry()
        _config.apply_skill_registry(new_reg)
        log.info("SKILL 已保存并热重载: %s (位于 %s)", name, target)
        return {"status": "ok", "name": name,
                "path": str(target.relative_to(Path("skills_my"))),
                "is_new": existing is None,
                "registry_count": new_reg.count}
    except Exception as ex:
        return {"status": "error", "message": str(ex)}


@router.post("/api/skills/delete")
async def skill_delete(request: Request):
    """删除一个 SKILL 目录。"""
    body = await request.json()
    name = (body.get("name") or "").strip()
    ok, msg = _validate_skill_name(name)
    if not ok:
        return {"status": "error", "message": msg}
    p = _resolve_skill_path(name)
    if p is None:
        return {"status": "error", "message": f"SKILL 不存在: {name}"}
    if _is_builtin_skill_path(p):
        return {"status": "error", "message": f"{name} 是系统内置 SKILL，不允许删除"}
    try:
        skill_dir = p.parent
        skills_root = Path("skills_my").resolve()
        if not str(skill_dir.resolve()).startswith(str(skills_root)):
            return {"status": "error", "message": "路径非法"}
        import shutil
        shutil.rmtree(skill_dir)
        new_reg = reload_registry()
        _config.apply_skill_registry(new_reg)
        log.info("SKILL 已删除: %s", name)
        return {"status": "ok", "name": name, "registry_count": new_reg.count}
    except Exception as ex:
        return {"status": "error", "message": str(ex)}


@router.post("/api/skills/toggle")
async def skill_toggle(request: Request):
    """启用/禁用一个 SKILL。"""
    body = await request.json()
    name = (body.get("name") or "").strip()
    new_enabled = bool(body.get("enabled", True))

    ok, msg = _validate_skill_name(name)
    if not ok:
        return {"status": "error", "message": msg}
    p = _resolve_skill_path(name)
    if p is None:
        return {"status": "error", "message": f"SKILL 不存在: {name}"}
    if _is_builtin_skill_path(p):
        return {"status": "error", "message": f"{name} 是系统内置 SKILL，不允许启用/禁用"}

    try:
        content = p.read_text(encoding="utf-8")
    except Exception as ex:
        return {"status": "error", "message": f"读取失败: {ex}"}

    from core.skill_registry import _parse_frontmatter
    cur_meta, _ = _parse_frontmatter(content)
    cur_enabled = bool(cur_meta.get("enabled", True)) if "enabled" in cur_meta else True

    new_content = _toggle_skill_enabled_in_frontmatter(content, new_enabled)

    if cur_enabled == new_enabled and new_content == content:
        return {"status": "ok", "name": name, "enabled": new_enabled,
                "message": f"已是 {new_enabled and '启用' or '禁用'} 状态"}

    try:
        tmp = p.with_suffix(".md.tmp")
        tmp.write_text(new_content, encoding="utf-8")
        tmp.replace(p)
        new_reg = reload_registry()
        _config.apply_skill_registry(new_reg)
        log.info("SKILL %s → %s", name, "启用" if new_enabled else "禁用")
        return {"status": "ok", "name": name, "enabled": new_enabled,
                "message": f"已{'启用' if new_enabled else '禁用'} {name}",
                "enabled_count": new_reg.enabled_count}
    except Exception as ex:
        return {"status": "error", "message": str(ex)}


@router.post("/api/skills/reload")
async def skills_reload():
    """从磁盘重新扫描 skills_my/，刷新 Registry 和 config 映射。"""
    try:
        new_reg = reload_registry()
        stats = _config.apply_skill_registry(new_reg)
        return {"status": "ok",
                "count": new_reg.count,
                "enabled_count": new_reg.enabled_count,
                "errors": new_reg.errors,
                **stats}
    except Exception as ex:
        return {"status": "error", "message": str(ex)}
