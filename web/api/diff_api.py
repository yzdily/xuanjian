"""
web/api/diff_api.py — Sitemap Diff + 增量回归 的 HTTP API

挂载方式：在 web/server.py 启动时
    from web.api.diff_api import router as diff_router
    app.include_router(diff_router)

所有路由前缀 /api/diff/*，HTML 页面 /sitemap-diff
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from core.diff import diff_snapshots, list_snapshots, load_snapshot
from core.diff.regression import build_regression_plan, save_regression_plan
from core.diff.snapshot import delete_snapshot, take_snapshot
from web._security import WEB_ROOT

router = APIRouter()


# ============================================================
# HTML 页面
# ============================================================

@router.get("/sitemap-diff", response_class=HTMLResponse)
def page_sitemap_diff() -> HTMLResponse:
    page = WEB_ROOT / "sitemap_diff.html"
    if not page.exists():
        return HTMLResponse("<h1>sitemap_diff.html 缺失</h1>", status_code=500)
    return HTMLResponse(page.read_text(encoding="utf-8"))


# ============================================================
# Snapshot 管理
# ============================================================

@router.get("/api/diff/snapshots")
def api_list_snapshots(host: str = "") -> JSONResponse:
    return JSONResponse({"snapshots": list_snapshots(host)})


class TakeSnapshotReq(BaseModel):
    task_id: str
    tag: str = ""
    note: str = ""


@router.post("/api/diff/snapshots/take")
def api_take_snapshot(req: TakeSnapshotReq) -> JSONResponse:
    if not req.task_id:
        raise HTTPException(status_code=400, detail="task_id 必填")
    meta = take_snapshot(task_id=req.task_id, tag=req.tag, note=req.note)
    if meta is None:
        raise HTTPException(
            status_code=404,
            detail=f"找不到 task_id={req.task_id} 的 sitemap.json",
        )
    return JSONResponse({"ok": True, "snapshot": meta.to_dict()})


@router.post("/api/diff/snapshots/delete")
def api_delete_snapshot(host: str = Query(...), tag: str = Query(...)) -> JSONResponse:
    ok = delete_snapshot(host, tag)
    if not ok:
        raise HTTPException(status_code=404, detail="快照不存在")
    return JSONResponse({"ok": True})


# ============================================================
# Diff
# ============================================================

@router.get("/api/diff/compare")
def api_compare(
    host: str = Query(...),
    tag_a: str = Query(..., description="旧版本"),
    tag_b: str = Query(..., description="新版本"),
) -> JSONResponse:
    snap_a = load_snapshot(host, tag_a)
    snap_b = load_snapshot(host, tag_b)
    if snap_a is None:
        raise HTTPException(status_code=404, detail=f"快照不存在: {tag_a}")
    if snap_b is None:
        raise HTTPException(status_code=404, detail=f"快照不存在: {tag_b}")

    result = diff_snapshots(snap_a, snap_b, tag_a=tag_a, tag_b=tag_b)
    return JSONResponse({
        "target": result.target,
        "snapshot_a": result.snapshot_a,
        "snapshot_b": result.snapshot_b,
        "summary": result.summary,
        "pages": [_change_to_dict(c) for c in result.pages],
        "endpoints": [_change_to_dict(c) for c in result.endpoints],
        "features": [_change_to_dict(c) for c in result.features],
    })


def _change_to_dict(change: Any) -> dict:
    """把 dataclass change 转为可 JSON 序列化的 dict（处理 ChangeKind 枚举）。"""
    d = asdict(change)
    # ChangeKind 是 str Enum，asdict 会保留枚举对象，FastAPI 也能序列化但前端拿到是 'ChangeKind.ADDED'
    # 显式转一下保证拿到字符串
    if "kind" in d and hasattr(change.kind, "value"):
        d["kind"] = change.kind.value
    return d


# ============================================================
# 回归测试方案
# ============================================================

@router.post("/api/diff/regression/plan")
def api_build_regression_plan(
    host: str = Query(...),
    tag_a: str = Query(...),
    tag_b: str = Query(...),
    save: bool = Query(False),
) -> JSONResponse:
    snap_a = load_snapshot(host, tag_a)
    snap_b = load_snapshot(host, tag_b)
    if snap_a is None or snap_b is None:
        raise HTTPException(status_code=404, detail="快照不存在")
    diff = diff_snapshots(snap_a, snap_b, tag_a=tag_a, tag_b=tag_b)
    plan = build_regression_plan(diff)
    saved_to = ""
    if save:
        saved_to = str(save_regression_plan(plan))
    return JSONResponse({
        "ok": True,
        "saved_to": saved_to,
        "plan": plan.to_dict(),
    })


__all__ = ["router"]
