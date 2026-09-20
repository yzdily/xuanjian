"""LOOP 深挖链只读 API（E3-1 · 阶段 1「链可见」）。

数据来源
--------
Phase 2.7（`core/loops/deep_dive.py`）在报告阶段之前执行 depth_chain，
并把每条链的**完整路径 + 终止状态 + 产出**写入：

    data/tasks/{task_id}-loops.json

本模块只负责把它读出来给前端 —— 不做任何写入，也不触发链执行
（触发由扫描流程控制，避免"点一下页面就开始打目标"）。

空态设计（重要）
----------------
前端 ChainTimeline 的**空态必须能解释"为什么没有链"**，否则用户会以为功能坏了。
因此无数据时返回：

  - `empty: true`
  - `enabled_triggers`：当前开关启用了哪些 trigger（环境变量）
  - `trigger_catalog`：矩阵里全部 trigger（本系统具备的深挖能力）
  - `hint`：一句人话解释（何时才会产生链数据）

对应设计文档 D1 的要求："空态也要说清检查了哪些 trigger 但没命中"。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from core.log import get_logger
from web._security import PROJECT_ROOT as _PROJECT_ROOT, validate_task_id

log = get_logger("web.loops_api")

router = APIRouter()

TASKS_DIR = _PROJECT_ROOT / "data" / "tasks"


# ================================================================
# 矩阵概览（静态，注意：必须先于 /api/loops/{task_id} 注册）
# ================================================================
@router.get("/api/loops/matrix")
async def loops_matrix():
    """矩阵里全部 trigger 的概览 —— 前端用来展示"本系统具备哪些深挖能力"。"""
    try:
        from core.loops.loop_controller import LoopController
        ctrl = LoopController()
    except Exception as exc:
        log.warning("矩阵加载失败: %s", exc)
        return JSONResponse({"triggers": [], "error": str(exc)[:200]})

    triggers = []
    for name, entry in ctrl.matrix.items():
        chain = entry.get("depth_chain", []) or []
        triggers.append({
            "trigger": name,
            "description": entry.get("description", ""),
            "steps": [s.get("step") for s in chain],
            "step_count": len(chain),
            "termination": entry.get("termination", []),
            "max_steps": entry.get("max_steps"),
        })
    return {
        "triggers": triggers,
        "total": len(triggers),
        "enabled_triggers": _enabled_triggers(),
        "loop_enabled": os.getenv("XJ_LOOP_ENABLED", "1").strip() != "0",
    }


def _enabled_triggers() -> list[str]:
    """与 deep_dive._enabled_triggers 保持同一语义（这里只做展示）。"""
    if os.getenv("XJ_LOOP_ENABLED", "1").strip() == "0":
        return []
    raw = os.getenv("XJ_LOOP_TRIGGERS", "").strip()
    if not raw:
        return ["actuator_exposure"]
    wanted = sorted({t.strip() for t in raw.split(",") if t.strip()})
    return ["*"] if "all" in wanted else wanted


# ================================================================
# 某任务的链数据
# ================================================================
@router.get("/api/loops/{task_id}")
async def get_task_loops(task_id: str):
    """读取某次扫描任务的 LOOP 深挖链（只读）。"""
    # ★ S1 加固：路径穿越防线（web._security 单源）。
    #   注意 validate_task_id 返回 bool（不抛异常）—— 早期版本误用 try/except 导致校验被绕过。
    if not validate_task_id(task_id):
        return JSONResponse(status_code=400, content={"error": f"非法 task_id: {task_id!r}"})

    path = TASKS_DIR / f"{task_id}-loops.json"
    base = {
        "task_id": task_id,
        "enabled_triggers": _enabled_triggers(),
        "loop_enabled": os.getenv("XJ_LOOP_ENABLED", "1").strip() != "0",
    }

    if not path.exists():
        base.update({
            "chains": [],
            "empty": True,
            "hint": (
                "本次任务没有产生深挖链。链数据在「报告阶段前」由 Phase 2.7 写入，"
                "需要同时满足：① `XJ_LOOP_ENABLED` 未关闭；② 存在已确认漏洞且其类型命中"
                "启用的 trigger（当前：%s）；③ 目标存在对应特征（如 /actuator 端点暴露）。"
                % ("、".join(base["enabled_triggers"]) or "无（已关闭）")
            ),
        })
        return base

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("链数据解析失败 %s: %s", path, exc)
        base.update({"chains": [], "empty": True, "hint": f"链数据文件损坏：{str(exc)[:120]}"})
        return base

    chains = payload.get("chains", []) or []
    base.update({
        "chains": chains,
        "empty": not chains,
        "updated_at": payload.get("updated_at"),
        "summary": {
            "chains": len(chains),
            "completed": sum(1 for c in chains if c.get("status") == "completed"),
            "findings": sum(len(c.get("findings") or []) for c in chains),
            "written_back": sum(int(c.get("written_back") or 0) for c in chains),
            "missing_handlers": sorted({
                h for c in chains for h in (c.get("missing_handlers") or [])
            }),
        },
    })
    return base
