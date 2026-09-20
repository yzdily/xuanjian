"""
web/api/crypto_api.py — 加密接口模板管理 HTTP API
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from core.crypto_replay import (
    AlgorithmType,
    CryptoTemplate,
    EncryptedField,
    delete_template,
    encrypt_field,
    learn_from_capture,
    list_templates,
    load_template,
    save_template,
)
from web._security import WEB_ROOT

router = APIRouter()


@router.get("/crypto-templates", response_class=HTMLResponse)
def page_crypto() -> HTMLResponse:
    page = WEB_ROOT / "crypto_templates.html"
    if not page.exists():
        return HTMLResponse("<h1>crypto_templates.html 缺失</h1>", status_code=500)
    return HTMLResponse(page.read_text(encoding="utf-8"))


@router.get("/api/crypto/templates")
def api_list() -> JSONResponse:
    return JSONResponse({"templates": list_templates()})


@router.get("/api/crypto/template")
def api_get(host: str = Query(...)) -> JSONResponse:
    tpl = load_template(host)
    if tpl is None:
        raise HTTPException(status_code=404, detail="模板不存在")
    return JSONResponse(tpl.to_dict())


@router.post("/api/crypto/templates/delete")
def api_delete(host: str = Query(...)) -> JSONResponse:
    if delete_template(host):
        return JSONResponse({"ok": True})
    raise HTTPException(status_code=404, detail="模板不存在")


class LearnReq(BaseModel):
    host: str
    url: str = ""
    field: str
    algorithm: str
    mode: str = "CBC"
    key: str = ""
    iv: str = ""
    encoding: str = "base64"
    location: str = "body"
    sample_plaintext: str = ""
    sample_ciphertext: str = ""


@router.post("/api/crypto/learn")
def api_learn(req: LearnReq) -> JSONResponse:
    """手动喂入一条捕获记录学习模板。

    （除了通过 events.bus 自动学习，也允许 UI 手工录入。）
    """
    ok = learn_from_capture(req.model_dump())
    if not ok:
        raise HTTPException(status_code=400, detail="学习失败")
    tpl = load_template(req.host)
    return JSONResponse({"ok": True, "template": tpl.to_dict() if tpl else None})


class TestReq(BaseModel):
    host: str
    field: str
    plaintext: str


@router.post("/api/crypto/test")
def api_test(req: TestReq) -> JSONResponse:
    """对模板做一次试加密，返回密文。"""
    cipher = encrypt_field(req.host, req.field, req.plaintext)
    return JSONResponse({
        "ok": True,
        "plaintext": req.plaintext,
        "ciphertext": cipher,
        "encrypted": cipher != req.plaintext,
    })


__all__ = ["router"]
