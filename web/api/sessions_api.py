"""
会话管理 API + 全局动作（reset/stop/status/realtime/vulns）。

URL 保持不变：/api/sessions*, /api/reset, /api/stop, /api/status, /api/realtime/vulns
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

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
from web._security import PROJECT_ROOT, validate_task_id
from web._paths import move_to_trash

log = get_logger("web.sessions_api")

router = APIRouter()

# ★ C1 四件套 + 回收区：路径统一从 web._security.PROJECT_ROOT 单源拼出。
TASKS_DIR = PROJECT_ROOT / "data" / "tasks"
REPORTS_DIR = PROJECT_ROOT / "data" / "reports"
ARTIFACTS_DIR = PROJECT_ROOT / "data" / "scan_artifacts"
# ⚠️ 回收区固定 data/_trash/，严禁放到 data/reports/ 或 data/tasks/ 下 ——
# 否则 reports_api._group_reports_by_task()（纯 iterdir + 后缀过滤）会把
# 回收区里的 .md 当成正常报告列出来（IMPACT R3）。
TRASH_DIR = PROJECT_ROOT / "data" / "_trash"


def _collect_task_assets(task_id: str) -> list[Path]:
    """收集该 task_id 的磁盘资产（tasks / reports / scan_artifacts）。"""
    assets: list[Path] = []
    if TASKS_DIR.exists():
        assets.extend(f for f in TASKS_DIR.glob(f"{task_id}*") if f.parent == TASKS_DIR)
    if REPORTS_DIR.exists():
        assets.extend(f for f in REPORTS_DIR.glob(f"{task_id}*") if f.parent == REPORTS_DIR)
    artifact_dir = ARTIFACTS_DIR / task_id
    if artifact_dir.exists():
        assets.append(artifact_dir)
    return assets


def _purge_task_assets(task_id: str) -> str:
    """删除会话的"四件套"：① tasks ② reports ③ scan_artifacts ④ scan_store 行。

    前三项**移动**到回收区（不是 unlink，误删可找回），第四项走 scan_store
    软删（``status='deleted'``，零 schema 变更）。

    Returns:
        回收目录路径（无资产可移时为空串）。
    """
    trashed_dir = move_to_trash(_collect_task_assets(task_id), TRASH_DIR)
    try:
        from core.scan_store import mark_scan_deleted, mark_vulns_deleted
        mark_scan_deleted(task_id)
        mark_vulns_deleted(task_id)
    except Exception as exc:                          # 绝不静默：DB 失败必须留痕
        log.warning("scan_store 软删失败 task_id=%s: %s", task_id, exc)
    return trashed_dir


def _disk_session_ids() -> list[str]:
    """扫描 data/tasks/ 得到历史会话 id（与 _list_saved_sessions 同一命名规则）。"""
    if not TASKS_DIR.exists():
        return []
    ids: set[str] = set()
    for f in TASKS_DIR.glob("task_*-sitemap.json"):
        ids.add(f.name.replace("-sitemap.json", ""))
    for f in TASKS_DIR.glob("task_*-chat.jsonl"):
        ids.add(f.name.replace("-chat.jsonl", ""))
    return sorted(ids)


def _is_empty_session(task_id: str) -> bool:
    """空会话判定：无 target 且 features==0 且无对话历史（chat.jsonl 不存在或为空）。

    与 ``_list_saved_sessions`` 下发的 ``empty`` 字段口径完全一致：空 chat 文件
    不算有历史。cleanup 据此决定是否可清理。
    """
    chat_file = TASKS_DIR / f"{task_id}-chat.jsonl"
    if chat_file.exists() and chat_file.stat().st_size > 0:
        return False                                   # 有对话历史 → 非空
    sitemap_file = TASKS_DIR / f"{task_id}-sitemap.json"
    if not sitemap_file.exists():
        return True                                    # 无 sitemap 且无 chat 内容 → 空
    try:
        data = json.loads(sitemap_file.read_text(encoding="utf-8"))
    except Exception:
        return False                                   # 读不动就不动它
    return not (data.get("target") or "").strip() and not (data.get("features") or {})


@router.get("/api/sessions")
async def list_sessions():
    """列出所有会话（含活跃内存会话 + 磁盘历史会话）。"""
    saved = _list_saved_sessions()
    saved_ids = {s["task_id"] for s in saved}
    cur = STATE["current_session_id"]
    for sid, session in _sessions.items():
        if sid not in saved_ids:
            bg = getattr(session, "_bg_task", None)
            saved.insert(0, {
                "task_id": sid,
                "target": getattr(session, "target_url", "") or "新会话",
                "raw_target": getattr(session, "target_url", ""),
                "title": "",
                "features": len(session.sitemap.features) if session.sitemap else 0,
                "vulns": 0,
                "time": time.time(),
                "active": sid == cur,
                "running": bool(bg is not None and not bg.done()),
                "phase": str(getattr(session, "phase", "") or ""),
                # ★ 阶段 4-E1 修复（既有 bug）：原读 `_current_credential`，该字段从未被赋值
                #   → 恒为 False，前端 🔑 角标从未显示。改为读真实的会话凭证字段。
                "has_credentials": bool(
                    getattr(session, "_inject_cookies", "")
                    or getattr(session, "_inject_auth", "")
                    or getattr(session, "has_credentials", False)
                ),
                # D3 CredScope：凭证作用域（修复后为会话级隔离，恒为 "session"）
                "cred_scope": "session" if (
                    getattr(session, "_inject_cookies", "")
                    or getattr(session, "_inject_auth", "")
                    or getattr(session, "has_credentials", False)
                ) else "",
                "empty": not getattr(session, "target_url", ""),
            })
    return {"sessions": saved, "current": cur}


@router.post("/api/sessions/rename")
async def rename_session(request: Request):
    """给会话设置别名（业务命名，如「某某公司某某系统URL测试」）。

    写入 sidecar `data/tasks/{task_id}-meta.json`，**不写进 sitemap** ——
    sitemap 参与 diff 快照与报告生成，写进去会污染对比基线。

    title 传空字符串表示清除别名（回退到自动标题/目标 URL）。
    """
    body = await request.json()
    task_id = str(body.get("task_id") or "").strip()
    raw_title = str(body.get("title") or "")

    # ★ validate_task_id 返回 bool（不抛异常）—— 本项目真实踩过的坑
    if not validate_task_id(task_id):
        return JSONResponse(status_code=400, content={"error": f"非法 task_id: {task_id!r}"})

    # 净化：剥换行/控制字符（别名会进报告标题与导出文件，防注入），限长 60
    title = re.sub(r"[\x00-\x1f\x7f]+", " ", raw_title).strip()[:60]

    meta_path = TASKS_DIR / f"{task_id}-meta.json"
    meta: dict = {}
    if meta_path.exists():
        try:
            loaded = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                meta = loaded
        except Exception:
            meta = {}
    if title:
        meta["title"] = title
    else:
        meta.pop("title", None)
    meta["updated_at"] = time.time()

    try:
        TASKS_DIR.mkdir(parents=True, exist_ok=True)
        tmp = meta_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(meta_path)                    # 原子替换，避免半写文件
    except Exception as exc:
        log.warning("会话别名写入失败 %s: %s", task_id, exc)
        return JSONResponse(status_code=500, content={"error": f"写入失败: {exc}"})

    log.info("会话别名已设置: %s -> %r", task_id, title)
    return {"status": "ok", "task_id": task_id, "title": title}


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
    """删除一个会话（含活跃会话，删除后自动新建）。

    ★ I1 护栏：会话后台任务未完成 → HTTP 409，除非显式 ``force=true``
    （保留内部调用能力）。护栏通过后才 ``bg.cancel()`` 并执行四件套清理。
    """
    body = await request.json()
    target_id = body.get("task_id", "")
    force = bool(body.get("force", False))

    if not validate_task_id(target_id):
        return JSONResponse(status_code=400, content={"error": "无效的 task_id"})

    session = _sessions.get(target_id)
    bg = getattr(session, "_bg_task", None) if session is not None else None
    if bg is not None and not bg.done() and not force:
        return JSONResponse(
            status_code=409,
            content={
                "error": "会话正在扫描，请先停止任务再删除",
                "task_id": target_id,
                "hint": "POST /api/stop 后可重试",
            },
        )

    _sessions.pop(target_id, None)
    if session is not None:
        if bg is not None and not bg.done():
            bg.cancel()
        eq = getattr(session, "_event_queue", None)
        if eq:
            try:
                eq.put_nowait(None)
            except Exception:
                pass

    trashed_dir = _purge_task_assets(target_id)

    if target_id == STATE["current_session_id"]:
        STATE["current_session_id"] = None
        get_session()
        return {"status": "ok", "new_session": True, "trashed_dir": trashed_dir}

    return {"status": "ok", "trashed_dir": trashed_dir}


@router.post("/api/sessions/cleanup")
async def cleanup_sessions():
    """批量清理"空会话"（无 target 且 features==0 且无 chat.jsonl）。

    判定集合**排除**运行中（``_bg_task`` 未 done）与当前会话（``_state`` 指针），
    被排除者进 ``skipped`` 并给出原因；其余走与单删一致的四件套 + 回收区。
    """
    cur = STATE["current_session_id"]
    removed_ids: list[str] = []
    skipped: list[dict] = []

    for tid in _disk_session_ids():
        session = _sessions.get(tid)
        bg = getattr(session, "_bg_task", None) if session is not None else None
        if bg is not None and not bg.done():
            skipped.append({"task_id": tid, "reason": "running"})
            continue
        if tid == cur:
            skipped.append({"task_id": tid, "reason": "current"})
            continue
        if not _is_empty_session(tid):
            continue
        _purge_task_assets(tid)
        _sessions.pop(tid, None)
        removed_ids.append(tid)

    log.info("清理空会话: removed=%d skipped=%d", len(removed_ids), len(skipped))
    return {
        "status": "ok",
        "removed": len(removed_ids),
        "removed_ids": removed_ids,
        "skipped": skipped,
    }


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
