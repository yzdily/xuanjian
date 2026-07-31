"""
OOB Callback Receiver — 盲打 XSS 回调接收。

URL 保持不变：/api/oob/*
"""
from __future__ import annotations

from fastapi import APIRouter, Request

from core.log import get_logger

log = get_logger("web.oob_api")

router = APIRouter()


@router.get("/api/oob/callback/{token}")
@router.post("/api/oob/callback/{token}")
async def oob_callback(token: str, request: Request):
    """接收盲打 XSS 回调。

    使用方式：
        在 WebUI 配置 OOB URL 为：http://<your-server>:8000/api/oob/callback
        盲打 payload 内会自动拼成 /api/oob/callback?t=<token>

    安全提示：
        - 这个端点不需要鉴权（受害者浏览器直接命中）
        - 仅记录基本信息（UA / Referer / IP），不存敏感数据
        - 生产部署建议反代 + 限流
    """
    try:
        from core.xss import get_global_oob_receiver
        receiver = get_global_oob_receiver() if get_global_oob_receiver else None
        if not receiver:
            return {"status": "noop", "reason": "OOB module unavailable"}
        actual_token = token
        if not actual_token or actual_token == "callback":
            actual_token = request.query_params.get("t", "") or ""
        if not actual_token:
            return {"status": "noop", "reason": "no token"}
        hit_info = {
            "ip": request.client.host if request.client else "",
            "user_agent": request.headers.get("user-agent", ""),
            "referer": request.headers.get("referer", ""),
            "method": request.method,
            "query": dict(request.query_params),
        }
        await receiver.record_hit(actual_token, hit_info)
        log.info("OOB callback hit: token=%s ua=%s", actual_token,
                 hit_info["user_agent"][:80])
        return {"status": "ok"}
    except Exception as e:
        log.warning("OOB callback error: %s", e)
        return {"status": "error", "message": str(e)[:120]}


@router.get("/api/oob/hits")
async def oob_hits(token: str = ""):
    """查询所有 OOB 回调命中记录（用于 WebUI 显示）。"""
    try:
        from core.xss import get_global_oob_receiver
        receiver = get_global_oob_receiver() if get_global_oob_receiver else None
        if not receiver:
            return {"hits": {}}
        if token:
            return {"token": token, "hits": await receiver.get_hits(token)}
        return {"hits": await receiver.get_all_hits()}
    except Exception as e:
        return {"error": str(e)[:120]}


@router.get("/api/oob/url")
async def oob_url(request: Request):
    """返回当前实例可用的 OOB callback URL（供 WebUI 自动填充）。"""
    host = request.headers.get("host", "127.0.0.1:8000")
    scheme = request.headers.get("x-forwarded-proto", "http")
    return {
        "url": f"{scheme}://{host}/api/oob/callback",
        "hint": "把这个 URL 填入'盲打 OOB 回调'输入框；扫描器会自动给每个写入点生成 token",
    }
