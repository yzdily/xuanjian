"""
认证 API 路由 — 登录 / 注册 / 登出 / 当前用户信息。

所有路由前缀：/api/auth/*
- POST /api/auth/login    登录（用户名 + 密码），返回 token
- POST /api/auth/register 注册新用户
- POST /api/auth/logout   登出（前端清除 token；服务端无状态，仅记录日志）
- GET  /api/auth/me       获取当前登录用户信息（需带 token）

中间件：
- require_auth(request) — 从 Authorization 头提取 token 并校验，
  返回 (payload, None) 或 (None, error_response)。
"""
from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core import auth
from core.log import get_logger

log = get_logger("web.auth_api")

router = APIRouter()

# ★ S8 安全加固：注册接口 IP 级限流（每 IP 60 秒最多 3 次）
_register_attempts: dict[str, list[float]] = {}
_REGISTER_RATE_LIMIT = 3
_REGISTER_RATE_WINDOW = 60.0


def _check_register_rate_limit(client_ip: str) -> bool:
    """检查注册限流，返回 True 表示允许。"""
    now = time.time()
    attempts = _register_attempts.get(client_ip, [])
    # 清理过期记录
    attempts = [t for t in attempts if now - t < _REGISTER_RATE_WINDOW]
    if len(attempts) >= _REGISTER_RATE_LIMIT:
        _register_attempts[client_ip] = attempts
        return False
    attempts.append(now)
    _register_attempts[client_ip] = attempts
    return True


def _security_headers(response: JSONResponse) -> JSONResponse:
    """★ S7: 为敏感 API 响应添加安全头和缓存控制。"""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# ============================================================
# 中间件：require_auth
# ============================================================

def _extract_token(request: Request) -> str:
    """从请求中提取 token，仅从 Authorization 头提取。

    ★ S3 安全加固：不再从 query.token 和 cookie.token 提取（URL/cookie 泄露风险）。
    """
    auth_header = request.headers.get("Authorization", "") or ""
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return ""


def require_auth(request: Request):
    """强制鉴权中间件：校验 token，返回 (payload, None) 或 (None, error_response)。

    用法：
        payload, err = require_auth(request)
        if err:
            return err
        # payload["username"] 可用
    """
    token = _extract_token(request)
    payload = auth.verify_token(token)
    if not payload:
        return None, JSONResponse(
            status_code=401,
            content={"ok": False, "error": "未登录或 token 已失效", "code": "UNAUTHORIZED"},
        )
    return payload, None


def try_auth(request: Request) -> Optional[dict]:
    """可选鉴权：返回 payload 或 None，不抛错。供「未登录可访问但记录身份」的接口使用。"""
    token = _extract_token(request)
    return auth.verify_token(token)


# ============================================================
# 路由
# ============================================================

@router.post("/api/auth/login")
async def login(request: Request):
    """登录接口：接收 {username, password}，返回 token。"""
    try:
        body = await request.json()
    except Exception:
        return _security_headers(JSONResponse(status_code=400, content={"ok": False, "error": "请求体必须是 JSON"}))
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    result = auth.login(username, password)
    if result.get("ok"):
        return _security_headers(JSONResponse(content=result))
    return _security_headers(JSONResponse(status_code=401, content=result))


@router.post("/api/auth/register")
async def register(request: Request):
    """注册接口：接收 {username, password}，创建新用户并返回 token。"""
    # ★ S8: 注册限流
    client_ip = request.client.host if request.client else "unknown"
    if not _check_register_rate_limit(client_ip):
        return _security_headers(JSONResponse(
            status_code=429,
            content={"ok": False, "error": "注册请求过于频繁，请稍后再试", "code": "RATE_LIMITED"},
        ))
    try:
        body = await request.json()
    except Exception:
        return _security_headers(JSONResponse(status_code=400, content={"ok": False, "error": "请求体必须是 JSON"}))
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    result = auth.register(username, password)
    if result.get("ok"):
        return _security_headers(JSONResponse(content=result))
    return _security_headers(JSONResponse(status_code=400, content=result))


@router.post("/api/auth/logout")
async def logout(request: Request):
    """登出接口。

    本系统 token 为无状态 JWT-like 结构，服务端不维护会话表，
    登出由前端清除本地 token 即可。此处仅记录日志并返回成功。
    """
    payload = try_auth(request)
    if payload:
        log.info("用户登出: %s", payload.get("username"))
    return {"ok": True, "message": "已登出，请清除前端 token"}


@router.get("/api/auth/me")
async def me(request: Request):
    """获取当前登录用户信息（需要有效 token）。"""
    payload, err = require_auth(request)
    if err:
        return err
    username = payload.get("username", "")
    user = auth.get_user(username)
    if not user:
        return JSONResponse(
            status_code=401,
            content={"ok": False, "error": "用户不存在", "code": "USER_NOT_FOUND"},
        )
    return {"ok": True, "user": user}
