"""
Burp 插件单包扫描 API。

URL 保持不变：/api/packet/scan*
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from core.session import AgentSession
from core.log import get_logger

from web._state import _pool, _sessions

log = get_logger("web.packet_api")

router = APIRouter()


# 并发控制：手动扫描（右键发送）优先级高于被动扫描（自动代理流量）
_burp_semaphore = asyncio.Semaphore(3)
_burp_passive_semaphore = asyncio.Semaphore(2)
_burp_passive_queue_count = 0
_BURP_PASSIVE_QUEUE_LIMIT = 15


async def _do_scan(session, eq, task_id, intent, packet, user_message):
    """执行实际的单包漏洞检测逻辑。"""
    terminal_events = {"done", "task_failed", "task_stuck", "task_aborted"}
    terminal_seen = False
    try:
        log.info("[burp][task:%s] 单包检测开始", task_id)
        async for event in session._run_packet_test_mode(intent, packet, user_message):
            await eq.put(event)
            if isinstance(event, str) and event.startswith("data: "):
                try:
                    payload = json.loads(event[6:].strip())
                    if payload.get("type") in terminal_events:
                        terminal_seen = True
                except Exception:
                    pass
        if not terminal_seen:
            try:
                await eq.put(session._event("done", "单包检测完成"))
            except Exception:
                pass
    except asyncio.CancelledError:
        try:
            await eq.put(session._event("task_aborted", json.dumps({
                "reason": "cancelled", "message": "检测被中断",
            }, ensure_ascii=False)))
        except Exception:
            pass
    except Exception as e:
        log.error("[burp][task:%s] 检测异常: %s", task_id, e, exc_info=True)
        try:
            await eq.put(session._event("task_failed", json.dumps({
                "reason": "uncaught_exception", "error": str(e)[:300],
            }, ensure_ascii=False)))
        except Exception:
            pass


@router.post("/api/packet/scan")
async def packet_scan(request: Request):
    """Burp 插件专用：直接对 HTTP 数据包跑漏洞检测。"""
    body = await request.json()
    raw_request = body.get("raw_request", "")
    notes = body.get("notes", "")
    priority = body.get("priority", "manual")

    if not raw_request.strip():
        return {"error": "raw_request 不能为空"}

    global _burp_passive_queue_count
    if priority == "passive":
        if _burp_passive_queue_count >= _BURP_PASSIVE_QUEUE_LIMIT:
            return {"error": "passive_queue_full", "message": "被动扫描排队已满，请稍后重试"}

    from core.intent import parse_http_request_packet, has_http_request_packet
    packet = None
    if has_http_request_packet(raw_request):
        packet = parse_http_request_packet(raw_request)
    else:
        return {"error": "无法解析 HTTP 数据包，请确认格式正确（Burp Raw 格式或完整 HTTP 请求）"}

    if not packet:
        return {"error": "数据包解析结果为空"}

    intent = {
        "has_target": True,
        "target_url": packet.get("url", "") or f"{packet.get('scheme', 'https')}://{packet.get('host', '')}",
        "credentials": [],
        "session_cookies": packet.get("cookies", ""),
        "auth_header": "",
        "extra_headers": {},
        "extra_scope": [],
        "test_mode": "",
        "special_notes": notes,
        "intent_kind": "packet",
        "packet": packet,
    }
    for k, v in (packet.get("headers") or {}).items():
        if k.lower() == "authorization":
            intent["auth_header"] = v
            break
    from core.intent import _filter_extra_headers
    intent["extra_headers"] = _filter_extra_headers(packet.get("headers") or {})

    session = AgentSession(llm=_pool.primary)
    _sessions[session.task_id] = session
    task_id = session.task_id
    log.info("[burp] 为单包检测创建独立 session: %s", task_id)

    session._event_queue = asyncio.Queue()
    eq = session._event_queue

    user_message = raw_request
    if notes:
        user_message = f"{notes}\n\n{raw_request}"

    async def producer():
        global _burp_passive_queue_count
        is_passive = (priority == "passive")

        if is_passive:
            _burp_passive_queue_count += 1

        try:
            await eq.put(session._event("init", json.dumps({
                "task_id": task_id,
            }, ensure_ascii=False)))

            need_wait = not _burp_semaphore._value > 0
            if is_passive:
                need_wait = need_wait or not _burp_passive_semaphore._value > 0
            if need_wait:
                queue_msg = "并发检测数已达上限，排队等待中..."
                if is_passive:
                    queue_msg = f"被动扫描排队中（当前排队 {_burp_passive_queue_count} 个）..."
                await eq.put(session._event("queued", json.dumps({
                    "position": max(0, 3 - _burp_semaphore._value),
                    "message": queue_msg,
                }, ensure_ascii=False)))

            if is_passive:
                async with _burp_passive_semaphore:
                    async with _burp_semaphore:
                        if need_wait:
                            await eq.put(session._event("dequeue", "开始检测"))
                        await _do_scan(session, eq, task_id, intent, packet, user_message)
            else:
                async with _burp_semaphore:
                    if need_wait:
                        await eq.put(session._event("dequeue", "开始检测"))
                    await _do_scan(session, eq, task_id, intent, packet, user_message)
        finally:
            if is_passive:
                _burp_passive_queue_count -= 1
            try:
                await eq.put(None)
            except Exception:
                pass

    bg_task = asyncio.create_task(producer())
    session._bg_task = bg_task

    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept:
        async def generate():
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(eq.get(), timeout=30)
                        if event is None:
                            break
                        yield event
                    except asyncio.TimeoutError:
                        if bg_task.done():
                            break
                        yield ": heartbeat\n\n"
            except (GeneratorExit, asyncio.CancelledError):
                pass

        return StreamingResponse(generate(), media_type="text/event-stream",
                                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
    else:
        return {"status": "started", "task_id": task_id,
                "message": "检测已启动，通过 SSE 或轮询获取结果"}


@router.get("/api/packet/scan/{task_id}/events")
async def packet_scan_events(task_id: str):
    """SSE 端点：连接后获取指定 task 的实时事件流。"""
    if task_id not in _sessions:
        return {"error": f"task {task_id} 不存在"}

    session = _sessions[task_id]
    if not hasattr(session, '_event_queue') or session._event_queue is None:
        return {"error": "该任务没有事件队列"}

    eq = session._event_queue

    async def generate():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(eq.get(), timeout=30)
                    if event is None:
                        break
                    yield event
                except asyncio.TimeoutError:
                    if hasattr(session, '_bg_task') and session._bg_task.done():
                        break
                    yield ": heartbeat\n\n"
        except (GeneratorExit, asyncio.CancelledError):
            pass

    return StreamingResponse(generate(), media_type="text/event-stream",
                            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/api/packet/scan/{task_id}/result")
async def packet_scan_result(task_id: str):
    """查询指定 task 的检测结果（从对话历史中提取）。"""
    if task_id not in _sessions:
        return {"error": f"task {task_id} 不存在"}

    session = _sessions[task_id]
    sitemap = session.sitemap

    if not sitemap or not sitemap.features:
        return {"status": "no_results", "task_id": task_id}

    vulns = []
    for fp in sitemap.features.values():
        for ci in fp.checklist:
            if ci.result and ci.result.value == "vulnerable":
                vulns.append({
                    "feature": fp.name,
                    "vuln_type": ci.vuln_type,
                    "severity": ci.severity or "high",
                    "evidence": ci.evidence_request or ci.detail or "",
                    "remediation": ci.fix_suggestion or "",
                })

    return {
        "status": "done" if vulns else "no_vulns",
        "task_id": task_id,
        "target": getattr(session, "target_url", ""),
        "total_features": len(sitemap.features),
        "total_checks": sum(len(fp.checklist) for fp in sitemap.features.values()),
        "vulnerabilities": vulns,
    }
