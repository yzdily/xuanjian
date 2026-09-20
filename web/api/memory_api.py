"""
Memory API — Hermes 风格经验教训管理。

所有路由保持原 URL 不变：/api/memory/*
"""
from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/api/memory/list")
async def memory_list(scope: str = "", enabled: str = "all", limit: int = 0):
    from core import memory
    return {"items": memory.list_all(scope=scope, enabled=enabled, limit=limit),
            "stats": memory.stats()}


@router.get("/api/memory/get")
async def memory_get(id: str):
    from core import memory
    item = memory.get(id)
    if not item:
        return {"error": "not_found"}
    return item


@router.post("/api/memory/save")
async def memory_save(request: Request):
    """新增或更新一条经验。"""
    from core import memory
    body = await request.json()
    lid = (body.get("id") or "").strip()
    scope = (body.get("scope") or "global").strip()
    scope_value = (body.get("scope_value") or "").strip()
    trigger = (body.get("trigger") or "").strip()
    lesson = (body.get("lesson") or "").strip()
    evidence = (body.get("evidence") or "").strip()
    enabled = body.get("enabled", True)
    if not lesson:
        return {"error": "lesson 不能为空"}
    if scope not in memory.VALID_SCOPES:
        return {"error": f"scope 必须是 {memory.VALID_SCOPES} 之一"}
    if lid:
        ok = memory.update(lid, scope=scope, scope_value=scope_value,
                           trigger=trigger, lesson=lesson, evidence=evidence,
                           enabled=bool(enabled))
        if not ok:
            return {"error": "未找到该 ID"}
        return {"ok": True, "id": lid, "action": "updated"}
    item = memory.record(
        scope=scope, scope_value=scope_value, trigger=trigger,
        lesson=lesson, evidence=evidence, source="manual",
    )
    return {"ok": True, "id": item["id"], "action": "created"}


@router.post("/api/memory/toggle")
async def memory_toggle(request: Request):
    from core import memory
    body = await request.json()
    lid = (body.get("id") or "").strip()
    enabled = bool(body.get("enabled", True))
    if not lid:
        return {"error": "缺少 id"}
    ok = memory.toggle(lid, enabled)
    return {"ok": ok}


@router.post("/api/memory/delete")
async def memory_delete(request: Request):
    from core import memory
    body = await request.json()
    lid = (body.get("id") or "").strip()
    if not lid:
        return {"error": "缺少 id"}
    ok = memory.delete(lid)
    return {"ok": ok}


@router.post("/api/memory/reload")
async def memory_reload():
    from core import memory
    n = memory.reload()
    return {"ok": True, "total": n}
