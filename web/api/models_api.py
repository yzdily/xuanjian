"""
模型管理 + LLM 用量监控 API。

URL 保持不变：/api/models/*, /api/llm/usage*
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, StreamingResponse

from core.llm import mask_api_key, LLMConfig
from core.log import get_logger

from web._state import (
    _pool,
    _sessions,
    get_session,
    _list_saved_sessions,
    _get_cached_llm_records,
)

log = get_logger("web.models_api")

router = APIRouter()


# ==================== 模型简易接口 ====================

@router.get("/api/models")
async def list_models():
    models = [{"name": c.name, "model": c.model, "provider": c.provider, "is_primary": c.is_primary} for c in _pool.configs]
    session = get_session()
    return {"models": models, "current": session.llm.config.name if session.llm else ""}


@router.get("/api/screenshot/{name}")
async def get_screenshot(name: str):
    """返回截图文件（data/reports/{name}.png）。"""
    if not re.match(r'^[\w\-]+$', name):
        return {"error": "invalid name"}
    path = Path("data/reports") / f"{name}.png"
    if not path.exists():
        return {"error": "not found"}
    return FileResponse(path, media_type="image/png")


@router.post("/api/screenshot/upload")
async def upload_screenshot(request: Request):
    """接收用户上传的截图。"""
    import uuid as _uuid
    import base64 as _base64

    upload_dir = Path("data/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)

    content_type = request.headers.get("content-type", "")

    if "multipart" in content_type:
        form = await request.form()
        file = form.get("file")
        if not file:
            return {"error": "未找到 file 字段"}
        ext = Path(file.filename).suffix or ".png"
        filename = f"upload_{_uuid.uuid4().hex[:8]}{ext}"
        filepath = upload_dir / filename
        content = await file.read()
        filepath.write_bytes(content)
    else:
        body = await request.json()
        image_base64 = body.get("image_base64", "")
        if not image_base64:
            return {"error": "未提供 image_base64"}
        ext = body.get("ext", ".png")
        filename = f"upload_{_uuid.uuid4().hex[:8]}{ext}"
        filepath = upload_dir / filename
        filepath.write_bytes(_base64.b64decode(image_base64))

    return {"path": str(filepath), "filename": filename}


@router.post("/api/focused-test/screenshot")
async def focused_test_with_screenshot(request: Request):
    """截图 + 指令的指定功能测试入口（SSE 流）。"""
    body = await request.json()
    target_url = body.get("target_url", "")
    screenshot_path = body.get("screenshot_path", "")
    instruction = body.get("instruction", "")
    task_id = body.get("task_id", "")

    if not target_url:
        return {"error": "target_url 不能为空"}
    if not screenshot_path or not Path(screenshot_path).exists():
        return {"error": "screenshot_path 无效或文件不存在"}

    if task_id and task_id in _sessions:
        session = _sessions[task_id]
    else:
        session = get_session()
        task_id = session.task_id

    intent = {
        "has_target": True,
        "target_url": target_url,
        "credentials": [],
        "session_cookies": body.get("session_cookies", ""),
        "auth_header": body.get("auth_header", ""),
        "extra_headers": body.get("extra_headers", {}),
        "test_mode": "",
        "special_notes": instruction,
        "intent_kind": "focused",
        "target_features": [],
    }

    if not hasattr(session, '_event_queue') or session._event_queue is None:
        session._event_queue = asyncio.Queue()
    eq = session._event_queue

    async def producer():
        try:
            async for event in session._run_screenshot_focused_test(
                intent, screenshot_path, instruction or "测试截图中的所有功能"
            ):
                await eq.put(event)
        except Exception as e:
            await eq.put(session._event("error", f"截图测试失败: {e}"))
        finally:
            await eq.put(None)

    asyncio.create_task(producer())

    async def event_stream():
        while True:
            event = await eq.get()
            if event is None:
                break
            yield event

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ==================== LLM 用量监控 ====================

@router.get("/api/llm/usage")
async def llm_usage(task_id: str = ""):
    """获取 LLM 调用监控统计。"""
    log_file = Path("data/logs/llm_usage.jsonl")
    file_records = _get_cached_llm_records(log_file)

    if task_id:
        recent = [r for r in file_records if r.get("task_id") == task_id]
        total_calls = len(recent)
        total_input = sum(r.get("input_tokens", 0) for r in recent)
        total_output = sum(r.get("output_tokens", 0) for r in recent)
        total_seconds = sum(r.get("elapsed_s", 0) for r in recent)
        started_at = min((r.get("timestamp", 0) for r in recent), default=0)
        last_at = max((r.get("timestamp", 0) for r in recent), default=0)

        by_caller_task: dict[str, dict] = {}
        by_model_task: dict[str, dict] = {}
        for r in recent:
            cl = r.get("caller", "") or "main"
            md = r.get("model", "")
            if cl not in by_caller_task:
                by_caller_task[cl] = {"calls": 0, "input_tokens": 0, "output_tokens": 0}
            by_caller_task[cl]["calls"] += 1
            by_caller_task[cl]["input_tokens"] += r.get("input_tokens", 0)
            by_caller_task[cl]["output_tokens"] += r.get("output_tokens", 0)
            if md:
                if md not in by_model_task:
                    by_model_task[md] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "seconds": 0.0}
                by_model_task[md]["calls"] += 1
                by_model_task[md]["input_tokens"] += r.get("input_tokens", 0)
                by_model_task[md]["output_tokens"] += r.get("output_tokens", 0)
                by_model_task[md]["seconds"] += r.get("elapsed_s", 0)
        return {
            "scope": "task",
            "task_id": task_id,
            "total_calls": total_calls,
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_tokens": total_input + total_output,
            "total_seconds": total_seconds,
            "started_at": started_at,
            "last_at": last_at,
            "by_model": by_model_task,
            "by_caller": by_caller_task,
        }

    total_calls = len(file_records)
    total_input = sum(r.get("input_tokens", 0) for r in file_records)
    total_output = sum(r.get("output_tokens", 0) for r in file_records)
    total_seconds = sum(r.get("elapsed_s", 0) for r in file_records)

    by_task: dict[str, dict] = {}
    by_model: dict[str, dict] = {}
    for r in file_records:
        tid = r.get("task_id", "unknown")
        md = r.get("model", "")
        if tid not in by_task:
            by_task[tid] = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                           "seconds": 0.0, "started_at": 0, "last_at": 0}
        by_task[tid]["calls"] += 1
        by_task[tid]["input_tokens"] += r.get("input_tokens", 0)
        by_task[tid]["output_tokens"] += r.get("output_tokens", 0)
        by_task[tid]["seconds"] += r.get("elapsed_s", 0)
        ts = r.get("timestamp", 0)
        if not by_task[tid]["started_at"] or ts < by_task[tid]["started_at"]:
            by_task[tid]["started_at"] = ts
        if ts > by_task[tid]["last_at"]:
            by_task[tid]["last_at"] = ts
        if md:
            if md not in by_model:
                by_model[md] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "seconds": 0.0}
            by_model[md]["calls"] += 1
            by_model[md]["input_tokens"] += r.get("input_tokens", 0)
            by_model[md]["output_tokens"] += r.get("output_tokens", 0)
            by_model[md]["seconds"] += r.get("elapsed_s", 0)

    summary = {
        "scope": "global",
        "total_calls": total_calls,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_tokens": total_input + total_output,
        "total_seconds": total_seconds,
        "by_model": by_model,
        "by_task": by_task,
    }

    try:
        saved = _list_saved_sessions()
        target_by_id = {s["task_id"]: s.get("target", "") for s in saved}
        for tid, stat in by_task.items():
            stat["target"] = target_by_id.get(tid, "")
    except Exception:
        pass

    return summary


@router.get("/api/llm/usage/detail")
async def llm_usage_detail(
    limit: int = 100,
    offset: int = 0,
    task_id: str = "",
    is_error: str = "",
    model: str = "",
    caller: str = "",
    keyword: str = "",
):
    """获取 LLM 调用明细（支持筛选 + 分页）。"""
    log_file = Path("data/logs/llm_usage.jsonl")
    if not log_file.exists():
        return {"records": [], "total": 0, "filtered": 0}
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()

    matched: list = []
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if task_id and rec.get("task_id") != task_id:
            continue
        if is_error == "true" and not rec.get("is_error"):
            continue
        if is_error == "false" and rec.get("is_error"):
            continue
        if model and rec.get("model") != model:
            continue
        if caller and rec.get("caller") != caller:
            continue
        if keyword:
            kw = keyword.lower()
            blob = (rec.get("req_summary", "") + rec.get("resp_summary", "") + rec.get("error", "")).lower()
            if kw not in blob:
                continue
        matched.append(rec)

    total_filtered = len(matched)
    page = matched[offset:offset + limit]
    all_models = sorted({r.get("model", "") for r in matched if r.get("model")})
    all_callers = sorted({r.get("caller", "") for r in matched if r.get("caller")})

    return {
        "records": page,
        "total": len(lines),
        "filtered": total_filtered,
        "limit": limit,
        "offset": offset,
        "models": all_models,
        "callers": all_callers,
    }


@router.get("/api/llm/usage/call/{call_id}")
async def llm_usage_one_call(call_id: str):
    """根据 call_id 获取单条调用详情。"""
    log_file = Path("data/logs/llm_usage.jsonl")
    if not log_file.exists():
        return {"error": "no log file"}
    for line in reversed(log_file.read_text(encoding="utf-8").splitlines()):
        try:
            rec = json.loads(line)
            if rec.get("call_id") == call_id:
                return rec
        except Exception:
            continue
    return {"error": "call_id not found"}


# ==================== 模型配置管理 ====================

@router.post("/api/models/switch")
async def switch_model(request: Request):
    body = await request.json()
    try:
        client = _pool.get(body.get("name", ""))
    except KeyError:
        return {"error": "模型不存在"}
    get_session().switch_model(client)
    return {"status": "ok", "model": client.config.model}


@router.get("/api/models/list")
async def models_list_full():
    """返回完整模型配置列表（api_key 已掩码），用于 WebUI 配置页。"""
    session = get_session()
    current_name = session.llm.config.name if session.llm else ""
    return {
        "current": current_name,
        "models": [
            {
                "name": c.name,
                "provider": c.provider,
                "base_url": c.base_url,
                "api_key_masked": mask_api_key(c.api_key),
                "model": c.model,
                "is_current": c.name == current_name,
                "is_primary": c.is_primary,
            }
            for c in _pool.configs
        ],
    }


@router.post("/api/models/save")
async def models_save(request: Request):
    """新增或更新模型配置。"""
    body = await request.json()
    is_primary_raw = body.get("is_primary")
    is_primary = None if is_primary_raw is None else bool(is_primary_raw)
    ok, msg = _pool.add_or_update(
        name=body.get("name", ""),
        provider=body.get("provider", ""),
        base_url=body.get("base_url", ""),
        api_key=body.get("api_key", ""),
        model=body.get("model", ""),
        is_primary=is_primary,
    )
    if not ok:
        return {"status": "error", "message": msg}
    return {"status": "ok", "message": msg, "total": _pool.count}


@router.post("/api/models/delete")
async def models_delete(request: Request):
    """删除模型配置。"""
    body = await request.json()
    name = body.get("name", "")
    _sess = get_session()
    current_name = _sess.llm.config.name if _sess.llm else ""
    ok, msg = _pool.delete(name, current_active=current_name)
    if not ok:
        return {"status": "error", "message": msg}
    return {"status": "ok", "message": msg, "total": _pool.count}


@router.post("/api/models/set-primary")
async def models_set_primary(request: Request):
    """设置某个模型为默认（primary）。"""
    body = await request.json()
    name = body.get("name", "")
    if not name or name not in _pool.clients:
        return {"status": "error", "message": "模型不存在"}
    target = next((c for c in _pool.configs if c.name == name), None)
    if not target:
        return {"status": "error", "message": "模型不存在"}
    if target.is_primary:
        return {"status": "ok", "message": f"{name} 已经是默认模型"}
    new_list = [
        LLMConfig(**{**c.__dict__, "is_primary": c.name == name})
        for c in _pool.configs
    ]
    from core.llm import save_llm_configs
    save_llm_configs(new_list)
    _pool.reload()
    return {"status": "ok", "message": f"已将 {name} 设为默认模型"}


@router.post("/api/models/test")
async def models_test(request: Request):
    """测试模型连通性。"""
    body = await request.json()
    name = body.get("name", "")
    loop = asyncio.get_event_loop()
    ok, msg = await loop.run_in_executor(None, _pool.test_connection, name)
    return {"status": "ok" if ok else "error", "message": msg}


@router.post("/api/models/reload")
async def models_reload():
    """从 data/llm_configs.json 重新加载，热更新现有 clients。"""
    try:
        result = _pool.reload()
        return {"status": "ok", **result}
    except Exception as ex:
        return {"status": "error", "message": str(ex)}
