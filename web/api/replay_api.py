"""
web/api/replay_api.py — Replay Theater HTTP API
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from core.replay import (
    delete_run,
    list_runs,
    load_script,
    mine_lessons_from_script,
)
from core.replay.miner import write_back_to_memory

router = APIRouter()
WEB_ROOT = Path(__file__).parent.parent


@router.get("/replay-theater", response_class=HTMLResponse)
def page_replay_theater() -> HTMLResponse:
    page = WEB_ROOT / "replay_theater.html"
    if not page.exists():
        return HTMLResponse("<h1>replay_theater.html 缺失</h1>", status_code=500)
    return HTMLResponse(page.read_text(encoding="utf-8"))


@router.get("/replay-advanced", response_class=HTMLResponse)
def page_replay_advanced() -> HTMLResponse:
    """高级可视化页：力导图 / 攻击树 / 辐射图 + 一键导出。"""
    page = WEB_ROOT / "replay_advanced.html"
    if not page.exists():
        return HTMLResponse("<h1>replay_advanced.html 缺失</h1>", status_code=500)
    return HTMLResponse(page.read_text(encoding="utf-8"))


@router.get("/api/replay/runs")
def api_list_runs(limit: int = 200) -> JSONResponse:
    return JSONResponse({"runs": list_runs(limit=limit)})


@router.get("/api/replay/script")
def api_get_script(run_id: str = Query(...)) -> JSONResponse:
    frames, meta = load_script(run_id)
    if not frames and not meta:
        raise HTTPException(status_code=404, detail="run 不存在或为空")
    return JSONResponse({
        "meta": meta,
        "frames": [f.to_dict() for f in frames],
    })


@router.post("/api/replay/delete")
def api_delete_run(run_id: str = Query(...)) -> JSONResponse:
    if delete_run(run_id):
        return JSONResponse({"ok": True})
    raise HTTPException(status_code=404, detail="run 不存在")


class MineReq(BaseModel):
    run_id: str
    write_back: bool = False
    min_total: int = 3
    selected_indices: list[int] | None = None


@router.post("/api/replay/mine")
def api_mine(req: MineReq) -> JSONResponse:
    """从某个 run 抽取经验。可选写回 memory。"""
    frames, _ = load_script(req.run_id)
    if not frames:
        raise HTTPException(status_code=404, detail="run 不存在或为空")
    lessons = mine_lessons_from_script(frames, min_total=req.min_total)
    written = 0
    if req.write_back and lessons:
        selected = lessons
        if req.selected_indices:
            selected = [lessons[i] for i in req.selected_indices if 0 <= i < len(lessons)]
        if selected:
            written = write_back_to_memory(selected)
    return JSONResponse({
        "ok": True,
        "candidates": [ls.to_dict() for ls in lessons],
        "written": written,
    })


# ========================================================================
# 跨 run 聚合：按功能点 / 任务 维度查询所有相关 frames
# 用于"流量管理页"内嵌「决策回放」tab 的数据源
# ========================================================================
@router.get("/api/replay/by_feature")
def api_replay_by_feature(
    feature_name: str = Query("", description="功能点名称，子串匹配"),
    feature_id: str = Query("", description="功能点 ID，精确匹配"),
    task_id: str = Query("", description="可选，限定到某个 task"),
    limit_runs: int = Query(50, description="最多扫描多少个最近 run"),
) -> JSONResponse:
    """
    跨所有 run 聚合某个功能点的 frames，按时间排序返回。

    匹配规则（任一即命中）：
      - feature_id 精确等于（优先级最高）
      - feature_name 子串匹配（不区分大小写）
    """
    if not feature_name and not feature_id:
        return JSONResponse({"frames": [], "runs": [], "total": 0})

    runs_meta = list_runs(limit=limit_runs)
    matched_frames: list[dict[str, Any]] = []
    matched_runs: list[dict[str, Any]] = []

    fname_lc = (feature_name or "").lower()

    for meta in runs_meta:
        rid = meta.get("run_id", "")
        if task_id and meta.get("task_id", "") != task_id:
            continue
        if not rid:
            continue
        try:
            frames, _ = load_script(rid)
        except Exception:
            continue
        hit_in_run = 0
        for fr in frames:
            ok = False
            if feature_id and fr.feature_id == feature_id:
                ok = True
            elif fname_lc and fname_lc in (fr.feature_name or "").lower():
                ok = True
            if ok:
                d = fr.to_dict()
                d["_run_id"] = rid
                matched_frames.append(d)
                hit_in_run += 1
        if hit_in_run > 0:
            matched_runs.append({
                "run_id": rid,
                "target": meta.get("target", ""),
                "ended_at_human": meta.get("ended_at_human", ""),
                "hit_count": hit_in_run,
            })

    # 按时间升序排列（剧本回放需要时间正序）
    matched_frames.sort(key=lambda x: x.get("timestamp", 0))
    return JSONResponse({
        "frames": matched_frames,
        "runs": matched_runs,
        "total": len(matched_frames),
    })


__all__ = ["router"]
