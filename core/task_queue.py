"""
TaskQueue — 后台扫描任务队列

提供异步任务队列管理：
- submit_task: 提交扫描任务，立即返回 task_id
- cancel_task: 取消指定任务
- get_task_status: 查询任务状态
- list_tasks: 列出所有任务

每个任务在独立 session 中执行，不阻塞 Web UI。
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Optional

from core.llm import LLMPool
from core.log import get_logger
from core.scan_store import upsert_scan, finish_scan, upsert_vuln

log = get_logger("task_queue")

_pool: Optional[LLMPool] = None
_tasks: dict[str, dict] = {}
# ★ #17 修复：所有 asyncio 原语改为懒构造，避免在模块导入/同步启动阶段
# 绑定到"幽灵事件循环"导致后续 "Event loop is closed" / 跨循环访问错误。
_queue: Optional[asyncio.Queue] = None
_concurrent = 3
_worker_task: Optional[asyncio.Task] = None
_semaphore: Optional[asyncio.Semaphore] = None


def _get_queue() -> asyncio.Queue:
    """懒构造 asyncio.Queue，确保绑定到当前运行的事件循环。"""
    global _queue
    if _queue is None:
        _queue = asyncio.Queue()
    return _queue


def _get_semaphore() -> asyncio.Semaphore:
    """懒构造 asyncio.Semaphore，确保绑定到当前运行的事件循环。"""
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(_concurrent)
    return _semaphore


def init(pool: LLMPool, max_concurrent: int = 3):
    """初始化任务队列配置（纯 Python 赋值，不创建 asyncio 原语）。

    asyncio 原语（Queue/Semaphore）的创建推迟到首次在运行中的事件循环里
    被调用时（见 _get_queue / _get_semaphore），避免模块导入阶段绑定到
    不存在的"幽灵事件循环"。
    """
    global _pool, _concurrent
    _pool = pool
    _concurrent = max_concurrent
    # ★ 不在此创建 Semaphore —— 推迟到首次 _execute_task 调用时


def start_worker():
    """启动后台 worker。

    ★ 必须在运行中的事件循环里调用（FastAPI startup 钩子 / async 上下文）。
    若在无运行循环的同步上下文调用，会显式关闭未消费的 coroutine 并记录警告，
    避免 "coroutine '_worker_loop' was never awaited" 警告。
    """
    global _worker_task
    if _worker_task is not None and not _worker_task.done():
        return
    # 必须先确认有运行中的事件循环，否则 create_task 会抛 RuntimeError
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        log.warning("start_worker 在无运行事件循环的上下文被调用，已忽略；"
                    "应在 FastAPI startup 钩子或 async 上下文中调用")
        return
    coro = _worker_loop()
    try:
        _worker_task = loop.create_task(coro)
        log.info("任务队列 worker 已启动 (concurrent=%d)", _concurrent)
    except RuntimeError:
        # 显式关闭未消费的 coroutine，避免 "coroutine was never awaited" 警告
        coro.close()
        log.warning("任务队列 worker 启动失败：无法创建 task")
        raise


async def _worker_loop():
    while True:
        task_id = await _get_queue().get()
        if task_id is None:
            break
        task_info = _tasks.get(task_id)
        if not task_info:
            continue
        task_info["status"] = "running"
        task_info["started_at"] = time.time()
        try:
            await _execute_task(task_id, task_info)
            task_info["status"] = "done"
            task_info["finished_at"] = time.time()
            log.info("[task_queue] 任务完成: %s", task_id)
        except asyncio.CancelledError:
            task_info["status"] = "cancelled"
            log.info("[task_queue] 任务已取消: %s", task_id)
        except Exception as e:
            task_info["status"] = "failed"
            task_info["error"] = str(e)[:200]
            log.error("[task_queue] 任务失败: %s, error=%s", task_id, e)
        finally:
            _get_queue().task_done()


async def _execute_task(task_id: str, task_info: dict):
    # ★ 懒构造 Semaphore，确保绑定到当前运行的事件循环
    async with _get_semaphore():
        await _do_scan(task_id, task_info)


async def _do_scan(task_id: str, task_info: dict):
    from core.session import AgentSession

    target_url = task_info.get("url", "")
    scan_mode = task_info.get("scan_mode", "standard")

    if not _pool:
        raise RuntimeError("LLMPool 未初始化")

    session = AgentSession(llm=_pool.primary, skip_recover=True)
    session.task_id = task_id
    session.set_scan_mode("batch")

    upsert_scan(task_id, target_url, status="running", scan_mode=scan_mode)

    user_message = target_url
    if task_info.get("notes"):
        user_message = f"{target_url} ({task_info['notes']})"

    async for event in session.chat(user_message):
        if isinstance(event, str) and event.startswith("data: "):
            try:
                payload = json.loads(event[6:].strip())
                event_type = payload.get("type", "")
                if event_type in ("done", "task_failed", "task_aborted"):
                    break
            except Exception:
                pass

    if session.sitemap:
        metrics = {
            "features": len(session.sitemap.features),
            "total_checks": sum(len(fp.checklist) for fp in session.sitemap.features.values()),
            "vulns": 0,
        }
        from core.sitemap import CheckResult
        for fp in session.sitemap.features.values():
            for c in fp.checklist:
                if c.result == CheckResult.VULNERABLE:
                    metrics["vulns"] += 1
                    upsert_vuln(
                        task_id, fp.id, c.vuln_type,
                        feature_name=fp.name, severity=c.severity or "medium",
                        url=c.evidence_request or "",
                        detail=c.detail or "",
                    )
        session.sitemap.save()
        finish_scan(task_id, metrics)

    task_info["result"] = {"features": len(session.sitemap.features) if session.sitemap else 0}


def submit_task(url: str, scan_mode: str = "standard", cookie: str = "",
                username: str = "", password: str = "", notes: str = "") -> str:
    task_id = f"batch_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    _tasks[task_id] = {
        "task_id": task_id,
        "url": url,
        "scan_mode": scan_mode,
        "cookie": cookie,
        "username": username,
        "password": password,
        "notes": notes,
        "status": "queued",
        "created_at": time.time(),
        "started_at": None,
        "finished_at": None,
        "error": None,
        "result": None,
    }
    _get_queue().put_nowait(task_id)
    upsert_scan(task_id, url, status="queued", scan_mode=scan_mode)
    log.info("[task_queue] 提交任务: %s, url=%s, mode=%s", task_id, url, scan_mode)
    start_worker()
    return task_id


def cancel_task(task_id: str) -> bool:
    if task_id not in _tasks:
        return False
    _tasks[task_id]["status"] = "cancelled"
    return True


def get_task_status(task_id: str) -> Optional[dict]:
    return _tasks.get(task_id)


def list_tasks(limit: int = 50) -> list[dict]:
    items = sorted(_tasks.values(), key=lambda x: x.get("created_at", 0), reverse=True)
    return items[:limit]


def submit_batch_targets(targets: list[dict]) -> list[dict]:
    results = []
    for t in targets:
        tid = submit_task(
            url=t.get("url", ""),
            scan_mode=t.get("scan_mode", "standard"),
            cookie=t.get("cookie", ""),
            username=t.get("username", ""),
            password=t.get("password", ""),
            notes=t.get("notes", ""),
        )
        results.append({"task_id": tid, "url": t.get("url", ""), "status": "queued"})
    return results
