"""
凭证注入 API 路由 — 手动登录凭证注入功能。

路由前缀：/api/credential-injection/*
- POST /api/credential-injection/login   启动 Playwright 登录自动化（SSE 流式返回状态）
- POST /api/credential-injection/cancel   取消正在进行的登录流程
- GET  /api/credential-injection/test     测试 Playwright 可用性

工作流程：
1. 前端调用 /login，传入 target_url / username / password / login_url
2. 后端启动 CredentialInjector，通过 SSE 推送实时状态（启动浏览器/填表/验证码/提交/捕获凭证）
3. 最终 success 事件携带捕获的 cookies / token / auth_header
4. 前端拿到凭证后构造扫描指令启动 /api/chat
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from core.log import get_logger

log = get_logger("web.credential_injection_api")

router = APIRouter()

# 全局注入器实例表（task_id → CredentialInjector），用于取消操作
_active_injectors: dict[str, Any] = {}


@router.post("/api/credential-injection/login")
async def credential_injection_login(request: Request):
    """启动 Playwright 登录自动化，通过 SSE 流式返回状态事件。

    请求体：
        {
            "target_url": "https://example.com",
            "username": "admin",
            "password": "123456",
            "login_url": "",            // 可选，登录页 URL
            "headless": false,          // 可选，是否无头模式
            "timeout": 180              // 可选，手动登录超时秒数
        }

    SSE 事件格式（data: JSON\n\n）：
        {"type": "status",  "message": "正在启动浏览器..."}
        {"type": "captcha", "message": "检测到验证码...", "data": {"kind": "image_captcha"}}
        {"type": "warning", "message": "..."}
        {"type": "error",   "message": "...", "data": {...}}
        {"type": "success", "message": "凭证捕获完成", "data": {
            "success": true,
            "cookies": [...],
            "cookie_string": "session=xxx; token=yyy",
            "local_storage": {...},
            "auth_header": "Bearer eyJ...",
            "final_url": "https://example.com/dashboard",
            "login_method": "form_login",
            "duration_seconds": 12.5
        }}
        {"type": "done"}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "error": "请求体必须是 JSON"})

    target_url = (body.get("target_url") or "").strip()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    login_url = (body.get("login_url") or "").strip()
    headless = bool(body.get("headless", False))
    timeout = int(body.get("timeout", 180))

    if not target_url:
        return JSONResponse(status_code=400, content={"ok": False, "error": "target_url 不能为空"})
    if not username or not password:
        return JSONResponse(status_code=400, content={"ok": False, "error": "username 和 password 不能为空"})

    from core.credential_injector import CredentialInjector

    injector = CredentialInjector(headless=headless, timeout=timeout)

    # 生成 task_id 用于取消
    import uuid
    task_id = str(uuid.uuid4())[:8]
    _active_injectors[task_id] = injector

    async def event_stream():
        try:
            async for event in injector.login(target_url, username, password, login_url):
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                if event.get("type") in ("error", "success"):
                    yield f"data: {json.dumps({'type': 'done', 'task_id': task_id}, ensure_ascii=False)}\n\n"
                    break
        except Exception as e:
            log.exception("凭证注入 SSE 流异常")
            yield f"data: {json.dumps({'type': 'error', 'message': f'服务器异常: {e}'}, ensure_ascii=False)}\n\n"
            yield f"data: {json.dumps({'type': 'done', 'task_id': task_id}, ensure_ascii=False)}\n\n"
        finally:
            _active_injectors.pop(task_id, None)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/api/credential-injection/cancel")
async def credential_injection_cancel(request: Request):
    """取消正在进行的登录流程。

    请求体：
        {"task_id": "abc12345"}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "error": "请求体必须是 JSON"})

    task_id = (body.get("task_id") or "").strip()
    injector = _active_injectors.get(task_id)
    if injector:
        injector.cancel()
        log.info("用户取消了凭证注入任务: %s", task_id)
        return {"ok": True, "message": "已发送取消信号"}
    return JSONResponse(status_code=404, content={"ok": False, "error": "任务不存在或已完成"})


@router.get("/api/credential-injection/check")
async def credential_injection_check():
    """检查 Playwright 是否可用。

    返回：
        {
            "ok": true,
            "playwright_installed": true,
            "browser_path": "C:\\Users\\...\\chrome.exe",
            "headless_supported": true
        }
    """
    try:
        import playwright  # noqa: F401
        pw_installed = True
    except ImportError:
        pw_installed = False

    browser_path = None
    if pw_installed:
        try:
            from core.browser_resolver import get_launch_executable_path
            browser_path = get_launch_executable_path()
        except Exception:
            pass

    return {
        "ok": True,
        "playwright_installed": pw_installed,
        "browser_path": browser_path or "",
        "browser_available": bool(browser_path),
    }
