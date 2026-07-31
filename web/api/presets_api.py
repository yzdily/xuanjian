"""
扫描预设模板 API — 创建/管理可复用的扫描配置模板。

预设包含：扫描策略、认证方式、Cookie、请求头、备注等。
用户可直接选择预设快速扫描，避免重复填写参数。
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from threading import Lock

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.log import get_logger

log = get_logger("web.presets_api")

router = APIRouter()

_PRESETS_FILE = Path("data/scan_presets.json")
_PRESETS_LOCK = Lock()
_PRESETS_CACHE: list[dict] | None = None

_DEFAULT_PRESETS = [
    {
        "id": "preset_quick",
        "name": "⚡ 快速巡检",
        "description": "仅测高危漏洞，适合快速安全体检",
        "scan_mode": "fast",
        "auth_type": "none",
        "cookie": "",
        "headers": {},
        "notes": "重点关注 SQL注入、SSRF、未授权访问",
        "builtin": True,
    },
    {
        "id": "preset_standard",
        "name": "🔍 标准检测",
        "description": "全量漏洞检测，包含 OWASP Top 10",
        "scan_mode": "standard",
        "auth_type": "none",
        "cookie": "",
        "headers": {},
        "notes": "",
        "builtin": True,
    },
    {
        "id": "preset_deep",
        "name": "🧬 深度渗透",
        "description": "含业务逻辑测试、越权检测、复杂流程",
        "scan_mode": "deep",
        "auth_type": "none",
        "cookie": "",
        "headers": {},
        "notes": "开启全量检测，耗时较长",
        "builtin": True,
    },
    {
        "id": "preset_login",
        "name": "🔐 登录态扫描",
        "description": "带 Cookie 的认证后全量扫描",
        "scan_mode": "standard",
        "auth_type": "cookie",
        "cookie": "",
        "headers": {},
        "notes": "请填写有效的 Cookie",
        "builtin": True,
    },
    {
        "id": "preset_api",
        "name": "🔌 API 安全检测",
        "description": "针对 REST/GraphQL 接口的安全测试",
        "scan_mode": "deep",
        "auth_type": "header",
        "cookie": "",
        "headers": {"Content-Type": "application/json"},
        "notes": "重点关注未授权访问、IDOR、SQL注入",
        "builtin": True,
    },
]


def _load() -> list[dict]:
    global _PRESETS_CACHE
    if _PRESETS_CACHE is not None:
        return _PRESETS_CACHE
    _PRESETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    items: list[dict] = []
    if _PRESETS_FILE.exists():
        try:
            data = json.loads(_PRESETS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                items = [d for d in data if isinstance(d, dict)]
        except Exception as e:
            log.error("读取 presets 失败: %s", e)
    if not items:
        items = [dict(p) for p in _DEFAULT_PRESETS]
        _flush(items)
    _PRESETS_CACHE = items
    return _PRESETS_CACHE


def _flush(items: list[dict] | None = None) -> None:
    if items is None:
        items = _load()
    _PRESETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PRESETS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, _PRESETS_FILE)


@router.get("/api/presets")
async def list_presets():
    """列出所有扫描预设模板。"""
    with _PRESETS_LOCK:
        items = _load()
    return {"presets": items, "total": len(items)}


@router.post("/api/presets")
async def create_preset(request: Request):
    """创建新预设。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "error": "请求体必须是 JSON"})
    name = (body.get("name") or "").strip()
    if not name:
        return JSONResponse(status_code=400, content={"ok": False, "error": "名称不能为空"})
    preset = {
        "id": f"preset_{int(time.time())}_{uuid.uuid4().hex[:6]}",
        "name": name,
        "description": (body.get("description") or "").strip(),
        "scan_mode": body.get("scan_mode", "standard"),
        "auth_type": body.get("auth_type", "none"),
        "cookie": body.get("cookie", ""),
        "headers": body.get("headers", {}),
        "notes": body.get("notes", ""),
        "builtin": False,
    }
    with _PRESETS_LOCK:
        items = _load()
        items.append(preset)
        _flush(items)
    log.info("创建预设: %s (%s)", preset["id"], name)
    return {"ok": True, "preset": preset}


@router.put("/api/presets/{preset_id}")
async def update_preset(preset_id: str, request: Request):
    """更新预设。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "error": "请求体必须是 JSON"})
    with _PRESETS_LOCK:
        items = _load()
        for item in items:
            if item.get("id") == preset_id:
                if item.get("builtin"):
                    return JSONResponse(status_code=400, content={"ok": False, "error": "内置预设不可修改"})
                for k in ("name", "description", "scan_mode", "auth_type", "cookie", "headers", "notes"):
                    if k in body:
                        item[k] = body[k]
                _flush(items)
                return {"ok": True, "preset": item}
    return JSONResponse(status_code=404, content={"ok": False, "error": f"预设不存在: {preset_id}"})


@router.delete("/api/presets/{preset_id}")
async def delete_preset(preset_id: str):
    """删除预设。"""
    with _PRESETS_LOCK:
        items = _load()
        before = len(items)
        items[:] = [it for it in items if it.get("id") != preset_id and not it.get("builtin")]
        after = len(items)
        if before == after:
            return JSONResponse(status_code=404, content={"ok": False, "error": f"预设不存在或为内置: {preset_id}"})
        _flush(items)
    return {"ok": True, "message": "预设已删除"}
