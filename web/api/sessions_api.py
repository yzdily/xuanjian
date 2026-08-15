"""
会话管理 API + 全局动作（reset/stop/status/realtime/vulns）。

URL 保持不变：/api/sessions*, /api/reset, /api/stop, /api/status, /api/realtime/vulns
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from core.session import AgentSession
from core.log import get_logger

from web._state import (
    _pool,
    _sessions,
    STATE,
    get_session,
    _list_saved_sessions,
    _resolve_sitemap,
)
from web._security import validate_task_id

log = get_logger("web.sessions_api")

router = APIRouter()


@router.get("/api/sessions")
async def list_sessions():
    """列出所有会话（含活跃内存会话 + 磁盘历史会话）。"""
    saved = _list_saved_sessions()
    saved_ids = {s["task_id"] for s in saved}
    cur = STATE["current_session_id"]
    for sid, session in _sessions.items():
        if sid not in saved_ids:
            saved.insert(0, {
                "task_id": sid,
                "target": getattr(session, "target_url", ""),
                "features": len(session.sitemap.features) if session.sitemap else 0,
                "vulns": 0,
                "time": time.time(),
                "active": sid == cur,
            })
    return {"sessions": saved, "current": cur}


@router.post("/api/sessions/new")
async def new_session():
    """创建新会话并切换到它。旧会话继续在后台运行不中断。"""
    cur = STATE["current_session_id"]
    if cur and cur in _sessions:
        old = _sessions[cur]
        if old.sitemap:
            old.sitemap.save()
    session = AgentSession(llm=_pool.primary, skip_recover=True)
    _sessions[session.task_id] = session
    STATE["current_session_id"] = session.task_id
    log.info("新建会话: %s", session.task_id)
    return {"status": "ok", "task_id": session.task_id}


@router.post("/api/sessions/switch")
async def switch_session(request: Request):
    """切换到指定会话。旧会话继续在后台运行不中断。"""
    body = await request.json()
    target_id = body.get("task_id", "")

    # ★ S1 扩展：target_id 校验，防止路径穿越（data/tasks/{target_id}-sitemap.json）。
    if not validate_task_id(target_id):
        return {"error": "无效的 task_id"}

    cur = STATE["current_session_id"]
    if cur and cur in _sessions:
        old = _sessions[cur]
        if old.sitemap:
            old.sitemap.save()

    def _build_summary(session: AgentSession) -> dict:
        info: dict = {"status": "ok", "task_id": target_id}
        if session.sitemap:
            info["target"] = session.sitemap.target
            info["coverage"] = session.sitemap.get_coverage()
            info["summary"] = session.sitemap.to_summary()
            info["phase"] = session.phase
        return info

    if target_id in _sessions:
        STATE["current_session_id"] = target_id
        from core.log import bind_context
        session = _sessions[target_id]
        bind_context(session_id=target_id, phase=session.phase)
        return _build_summary(session)

    from core.sitemap import Sitemap
    sitemap_path = Path("data/tasks") / f"{target_id}-sitemap.json"
    if sitemap_path.exists():
        data = json.loads(sitemap_path.read_text(encoding="utf-8"))
        session = AgentSession(llm=_pool.primary, skip_recover=True)
        session.task_id = target_id
        sitemap = Sitemap(target=data.get("target", ""), task_id=target_id)
        if sitemap.load():
            session.sitemap = sitemap
            session.target_url = data.get("target", "")
            session.phase = "idle"
            session._sync_tool_executor()
        _sessions[target_id] = session
        STATE["current_session_id"] = target_id
        from core.log import bind_context
        bind_context(session_id=target_id, phase=session.phase)
        log.info("恢复会话: %s", target_id)
        result = _build_summary(session)
        result["recovered"] = True
        return result

    return {"error": f"会话不存在: {target_id}"}


@router.get("/api/sessions/{task_id}/history")
async def get_session_history(task_id: str):
    """获取指定会话的完整对话历史。"""
    # ★ S1 扩展：task_id 校验，防止路径穿越（data/tasks/{task_id}-chat.jsonl）。
    if not validate_task_id(task_id):
        return {"error": "无效的 task_id"}
    history = AgentSession.get_chat_history(task_id)
    return {"task_id": task_id, "events": history}


@router.post("/api/sessions/delete")
async def delete_session(request: Request):
    """删除一个会话（含活跃会话，删除后自动新建）。"""
    body = await request.json()
    target_id = body.get("task_id", "")

    if not validate_task_id(target_id):
        return {"error": "无效的 task_id"}

    session = _sessions.pop(target_id, None)
    if session is not None:
        bg = getattr(session, "_bg_task", None)
        if bg and not bg.done():
            bg.cancel()
        eq = getattr(session, "_event_queue", None)
        if eq:
            try:
                eq.put_nowait(None)
            except Exception:
                pass

    tasks_dir = Path("data/tasks").resolve()
    for f in tasks_dir.glob(f"{target_id}*"):
        if f.resolve().parent == tasks_dir or str(f.resolve()).startswith(str(tasks_dir)):
            if f.is_dir():
                import shutil
                shutil.rmtree(f, ignore_errors=True)
            else:
                f.unlink(missing_ok=True)
    reports_dir = Path("data/reports").resolve()
    for f in reports_dir.glob(f"{target_id}*"):
        if f.resolve().parent == reports_dir:
            if f.is_dir():
                import shutil
                shutil.rmtree(f, ignore_errors=True)
            else:
                f.unlink(missing_ok=True)

    if target_id == STATE["current_session_id"]:
        STATE["current_session_id"] = None
        get_session()
        return {"status": "ok", "new_session": True}

    return {"status": "ok"}


@router.get("/api/sessions/{task_id}/subscribe")
async def subscribe_session(task_id: str):
    """订阅一个正在运行的会话的实时事件流。"""
    if task_id not in _sessions:
        return {"error": "会话不存在或未在运行"}

    session = _sessions[task_id]
    bg = getattr(session, "_bg_task", None)
    eq = getattr(session, "_event_queue", None)

    if not bg or bg.done():
        return {"error": "该会话当前没有运行中的任务", "phase": session.phase}

    if not eq:
        return {"error": "事件队列不存在"}

    async def generate():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(eq.get(), timeout=15)
                    if event is None:
                        break
                    yield event
                except asyncio.TimeoutError:
                    if bg.done():
                        break
                    yield ": heartbeat\n\n"
        except (GeneratorExit, asyncio.CancelledError):
            pass

    return StreamingResponse(generate(), media_type="text/event-stream",
                            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/api/sessions/{task_id}/status")
async def session_status(task_id: str):
    """查询指定会话的运行状态。"""
    if task_id not in _sessions:
        return {"running": False, "phase": "unknown"}
    session = _sessions[task_id]
    bg = getattr(session, "_bg_task", None)
    running = bg is not None and not bg.done()
    return {
        "running": running,
        "phase": session.phase,
        "task_id": task_id,
    }


@router.post("/api/reset")
async def reset():
    """重置当前会话（新建一个）。"""
    return await new_session()


@router.post("/api/stop")
async def stop():
    """停止当前任务。"""
    session = get_session()
    _crawler = getattr(session, "_active_crawler", None)
    _crawl_task = getattr(session, "_active_crawl_task", None)

    if _crawler is not None:
        _crawler.request_stop(user_aborted=True)
        if _crawl_task is not None and not _crawl_task.done():
            _crawl_task.cancel()
        if session.sitemap:
            session.sitemap.save()
        return {"status": "crawler_stopped", "message": "爬虫已停止，任务将继续后续阶段"}
    else:
        _worker_tasks = getattr(session, "_active_worker_tasks", None)
        if _worker_tasks:
            for wid, wtask in list(_worker_tasks.items()):
                if wtask and not wtask.done():
                    wtask.cancel()
            _worker_tasks.clear()
        bg = getattr(session, "_bg_task", None)
        if bg and not bg.done():
            bg.cancel()
        if session.sitemap:
            session.sitemap.save()
        session.phase = "idle"
        return {"status": "ok", "message": "任务已停止"}


@router.get("/api/status")
async def status():
    from core.log import metrics as _metrics
    session = get_session()
    result = {
        "task_id": session.task_id,
        "started": session.started,
        "model": session.llm.config.model if session.llm else "未配置",
        "phase": session.phase,
        "scan_mode": getattr(session, "scan_mode", "batch"),
        "metrics": _metrics.snapshot(),
    }
    if session.sitemap:
        result["coverage"] = session.sitemap.get_coverage()
        result["target"] = session.sitemap.target
        result["recovered"] = not session.started and session.phase == "idle" and bool(session.sitemap)
    return result


@router.get("/api/realtime/vulns")
async def get_realtime_vulns(task_id: str = ""):
    """获取实时漏洞检测结果（实时模式下使用）。"""
    sitemap = _resolve_sitemap(task_id)
    if not sitemap:
        return {"status": "no_data", "vulns": [], "total": 0}

    from core.sitemap import CheckResult
    vulns = []
    for fp in sitemap.features.values():
        for c in fp.checklist:
            if c.result == CheckResult.VULNERABLE:
                vulns.append({
                    "feature_id": fp.id,
                    "feature_name": fp.name,
                    "module": fp.module or "",
                    "vuln_type": c.vuln_type,
                    "severity": c.severity,
                    "detail": c.detail[:500] if c.detail else "",
                    "skill_used": c.skill_used,
                    "tested_at": c.tested_at,
                })
    return {
        "status": "ok",
        "vulns": vulns,
        "total": len(vulns),
        "scan_mode": "realtime",
    }
