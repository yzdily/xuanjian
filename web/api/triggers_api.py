"""
触发规则（关键词→漏洞类型）管理 API。

URL 保持不变：/api/triggers/*
"""
from __future__ import annotations

from fastapi import APIRouter, Request

from core import config as _config
from core.skill_registry import reload_registry
from core.log import get_logger

log = get_logger("web.triggers_api")

router = APIRouter()


@router.get("/api/triggers/list")
async def triggers_list():
    """返回所有触发规则：默认（来自 config.py，只读）+ 自定义（来自 yaml，可编辑）。"""
    try:
        from core.user_triggers import list_user_triggers
        default_table = _config._DEFAULT_FEATURE_VULN_MAPPING or _config.FEATURE_VULN_MAPPING
        defaults = [{"keywords": list(kw), "vuln_types": list(vt),
                     "source": "default", "note": ""}
                    for kw, vt in default_table]
        users = [{**r, "source": "user"} for r in list_user_triggers()]
        known_vts = sorted(set(_config._DEFAULT_VULN_TO_SKILL or _config.VULN_TO_SKILL))
        return {
            "status": "ok",
            "default_count": len(defaults),
            "user_count": len(users),
            "rules": defaults + users,
            "known_vuln_types": known_vts,
        }
    except Exception as ex:
        return {"status": "error", "message": str(ex)}


@router.post("/api/triggers/save")
async def triggers_save(request: Request):
    """覆盖式保存所有用户自定义规则。"""
    try:
        body = await request.json()
        rules = body.get("rules") or []
        if not isinstance(rules, list):
            return {"status": "error", "message": "rules 必须是数组"}
        for i, r in enumerate(rules):
            kws = r.get("keywords") or []
            vts = r.get("vuln_types") or []
            if not kws:
                return {"status": "error", "message": f"规则 #{i+1} 缺少 keywords"}
            if not vts:
                return {"status": "error", "message": f"规则 #{i+1} 缺少 vuln_types"}

        from core.user_triggers import save_user_triggers
        save_user_triggers(rules)

        new_reg = reload_registry()
        stats = _config.apply_skill_registry(new_reg)
        log.info("用户触发规则已保存: %d 条，feature_triggers 总数=%d",
                 len(rules), stats["feature_triggers"])
        return {"status": "ok", "saved": len(rules), **stats}
    except Exception as ex:
        log.error("保存触发规则失败: %s", ex, exc_info=True)
        return {"status": "error", "message": str(ex)}


@router.post("/api/triggers/preview")
async def triggers_preview(request: Request):
    """预览一条规则会影响多少现有功能点。"""
    try:
        body = await request.json()
        kws = [str(k).strip().lower() for k in (body.get("keywords") or []) if str(k).strip()]
        if not kws:
            return {"status": "ok", "matched": 0, "samples": []}

        from pathlib import Path
        sites_dir = Path("data/sites")
        matched = 0
        samples: list[str] = []
        if sites_dir.exists():
            import json as _json
            for fp in sites_dir.glob("*/features.json"):
                try:
                    data = _json.loads(fp.read_text(encoding="utf-8"))
                except Exception:
                    continue
                feats = data.get("features") if isinstance(data, dict) else data
                if not isinstance(feats, list):
                    continue
                for f in feats:
                    name = str(f.get("name") or "")
                    url = str(f.get("url") or f.get("path") or "")
                    desc = str(f.get("description") or "")
                    haystack = (name + " " + url + " " + desc).lower()
                    if any(k in haystack for k in kws):
                        matched += 1
                        if len(samples) < 5:
                            label = name or url or "(unnamed)"
                            samples.append(label[:60])
        return {"status": "ok", "matched": matched, "samples": samples}
    except Exception as ex:
        return {"status": "error", "message": str(ex)}


@router.post("/api/triggers/reset")
async def triggers_reset():
    """清空所有用户自定义规则。"""
    try:
        from core.user_triggers import save_user_triggers
        save_user_triggers([])
        new_reg = reload_registry()
        stats = _config.apply_skill_registry(new_reg)
        log.info("用户触发规则已清空")
        return {"status": "ok", **stats}
    except Exception as ex:
        return {"status": "error", "message": str(ex)}
