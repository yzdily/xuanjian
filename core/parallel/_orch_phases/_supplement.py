# 补测协同函数（原样搬迁自 orchestrator.py）。

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import AsyncGenerator, TYPE_CHECKING

import httpx as _httpx

from core.config import (
    MAX_WORKERS, WORKER_EVENT_TIMEOUT, WORKER_STUCK_TIMEOUT,
    FAST_SCAN_MAX_WORKERS, LLM_SCAN_MAX_WORKERS,
    SKIP_META_ANALYSIS, SKIP_BUSINESS_UNDERSTANDING,
    FAST_MODE_TIMEOUTS,
)
from core.prompts.phases import PHASE_TEST_PROMPT, PHASE_REPORT_PROMPT
from core.sitemap import TestStatus, CheckResult
from core.log import get_logger, bind_context, metrics

if TYPE_CHECKING:
    from core.session import AgentSession

log = get_logger("parallel.orchestrator")


from core.parallel._orchestrator_helpers import (
    _check_mitmproxy_health,
    _try_restart_mitmproxy,
    _check_stuck_workers,
    _run_fast_scanner_core,
    _write_fast_scanner_results,
    _apply_skill_routing,
    _run_scripted_scan_core,
    _write_scripted_scan_results,
    _run_llm_preparation,
)

async def _run_supplementary_test(
    session: "AgentSession",
    session_info: dict,
    effective_max_workers: int | None = None,
) -> AsyncGenerator[str, None]:
    """对覆盖检查新增的功能点跑一轮子 Agent 补测。"""
    from core.parallel.grouping import _group_features_by_api_prefix

    if not session.sitemap:
        return

    untested = session.sitemap.get_untested_features()
    worker_features = [fp for fp in untested if fp.get_http_pending()]
    if not worker_features:
        return

    # 补测沿用主流程的并发上限；未传入时回退到默认值，避免 NameError 崩溃
    if effective_max_workers is None:
        effective_max_workers = MAX_WORKERS

    yield session._event("phase", f"Phase 2a+: 补测 {len(worker_features)} 个新发现功能点")

    from core.worker_agent import WorkerAgent

    # 补测用代码分组（数量少，不需要 LLM 分组）
    feature_groups = _group_features_by_api_prefix(worker_features)
    queue = list(feature_groups)
    active_workers: dict[str, asyncio.Task] = {}
    event_queue: asyncio.Queue = asyncio.Queue()
    worker_idx = 100  # 补测从 w100 开始编号
    supp_last_event: dict[str, float] = {}  # ★ 卡死检测

    async def _run_worker(worker: WorkerAgent):
        try:
            async for evt in worker.run():
                await event_queue.put(evt)
        except Exception as e:
            await event_queue.put({"type": "worker_error", "worker": worker.worker_id,
                                   "feature": worker.group_name, "error": str(e)})

    while queue and len(active_workers) < effective_max_workers:
        group_name, group_fps = queue.pop(0)
        worker_idx += 1
        for fp in group_fps:
            session.sitemap.start_test(fp.id)
        worker = WorkerAgent(worker_id=f"w{worker_idx}", llm=session.llm,
                             features=group_fps, group_name=group_name,
                             sitemap=session.sitemap, session_info=session_info)
        task = asyncio.create_task(_run_worker(worker))
        active_workers[worker.worker_id] = task
        supp_last_event[worker.worker_id] = time.time()
        yield session._event("system", f"🔄 补测 [{worker.worker_id}] 组「{group_name}」: {len(group_fps)} 个功能点")

    while active_workers:
        try:
            evt = await asyncio.wait_for(event_queue.get(), timeout=WORKER_EVENT_TIMEOUT)
        except asyncio.TimeoutError:
            # ★ 卡死检测：取消长时间无事件的补测 Worker
            stuck_ids = _check_stuck_workers(active_workers, supp_last_event)
            for sid in stuck_ids:
                yield session._event("system",
                    f"🛑 补测 [{sid}] 卡死（{WORKER_STUCK_TIMEOUT}s 无事件），已强制取消")
                if sid in active_workers:
                    del active_workers[sid]
                if sid in supp_last_event:
                    del supp_last_event[sid]
                if queue:
                    group_name, group_fps = queue.pop(0)
                    worker_idx += 1
                    for fp in group_fps:
                        session.sitemap.start_test(fp.id)
                    worker = WorkerAgent(worker_id=f"w{worker_idx}", llm=session.llm,
                                         features=group_fps, group_name=group_name,
                                         sitemap=session.sitemap, session_info=session_info)
                    task = asyncio.create_task(_run_worker(worker))
                    active_workers[worker.worker_id] = task
                    supp_last_event[worker.worker_id] = time.time()
                    yield session._event("system", f"🔄 补测 [{worker.worker_id}] 替补组「{group_name}」")
            if stuck_ids:
                continue
            done_ids = [wid for wid, t in active_workers.items() if t.done()]
            for wid in done_ids:
                del active_workers[wid]
                if wid in supp_last_event:
                    del supp_last_event[wid]
            continue

        wid = evt.get("worker", "?")
        if wid != "?":
            supp_last_event[wid] = time.time()
        if evt["type"] == "worker_done":
            metrics.inc("features_tested", evt.get("features_done", 0))
            yield session._event("system", f"✅ 补测 [{wid}] 完成组「{evt['group']}」")
            if wid in active_workers:
                del active_workers[wid]
            if wid in supp_last_event:
                del supp_last_event[wid]
            if queue:
                group_name, group_fps = queue.pop(0)
                worker_idx += 1
                for fp in group_fps:
                    session.sitemap.start_test(fp.id)
                worker = WorkerAgent(worker_id=f"w{worker_idx}", llm=session.llm,
                                     features=group_fps, group_name=group_name,
                                     sitemap=session.sitemap, session_info=session_info)
                task = asyncio.create_task(_run_worker(worker))
                active_workers[worker.worker_id] = task
                supp_last_event[worker.worker_id] = time.time()
                yield session._event("system", f"🔄 补测 [{worker.worker_id}] 组「{group_name}」")
        elif evt["type"] == "worker_error":
            yield session._event("system", f"❌ 补测 [{wid}] 出错: {evt.get('error', '')[:80]}")
            if wid in active_workers:
                del active_workers[wid]
            if wid in supp_last_event:
                del supp_last_event[wid]
            # ★ 补测出错也要补派
            if queue:
                group_name, group_fps = queue.pop(0)
                worker_idx += 1
                for fp in group_fps:
                    session.sitemap.start_test(fp.id)
                worker = WorkerAgent(worker_id=f"w{worker_idx}", llm=session.llm,
                                     features=group_fps, group_name=group_name,
                                     sitemap=session.sitemap, session_info=session_info)
                task = asyncio.create_task(_run_worker(worker))
                active_workers[worker.worker_id] = task
                supp_last_event[worker.worker_id] = time.time()
                yield session._event("system", f"🔄 补测 [{worker.worker_id}] 替补组「{group_name}」")
        elif evt["type"] == "worker_tool":
            tool_brief = evt.get("tool_brief", evt.get("tool", ""))
            tool_full = evt.get("tool_full", evt.get("tool", ""))
            yield session._event("tool_call",
                f"[{wid}/{evt.get('feature','')[:12]}] {tool_brief}",
                full=f"[{wid}/{evt.get('feature','')}] {tool_full}")
        elif evt["type"] == "worker_screenshot":
            ss_name = evt.get("name", "screenshot")
            yield session._event("screenshot", f"/api/screenshot/{ss_name}")
        elif evt["type"] == "worker_message":
            yield session._event("message",
                f"**[{wid}]** {evt.get('content', '')}")

    yield session._event("system", "补测完成")


# ============================================================
# F13 (0903) — 假设链 spawner（hypothesis chaining）
# 漏洞链接接：每个 finding 都可 spawn 子 agent 继续验证
# 落到现有 Phase 2.5 补测阶段，而非另起 agent 模型
# ============================================================

FINDING_SPAWN_PATTERNS: dict[str, str] = {
    "actuator_exposure": "validation_agent",
    "shiro_remmeberme_active": "validation_agent",
    "heapdump_leak": "validation_agent",
    "actuator_env_leak": "validation_agent",
    "param_config_leak": "validation_agent",
    "vertical_privilege_escalation": "validation_agent",
}


def should_spawn_for_finding(finding: dict) -> str | None:
    """根据 finding 的 vuln_type 决定是否 spawn 子 agent。

    返回 spawn_pattern 或 None。
    """
    vuln_type = finding.get("vuln_type", "")
    return FINDING_SPAWN_PATTERNS.get(vuln_type)


async def _spawn_hypothesis_agent(
    session: "AgentSession",
    finding: dict,
    session_info: dict,
) -> list[str]:
    """F13: 为 finding spawn 验证子 agent（漏洞链下游补测）。

    利用现有 run_supplementary_test 框架做漏洞链下游补测。
    关键纪律：Reporting + Fixing 是 ONE step（Strix 经验）。
    """
    spawn_pattern = should_spawn_for_finding(finding)
    if not spawn_pattern:
        return []

    vuln_type = finding.get("vuln_type", "unknown")
    finding_id = finding.get("id", "?")
    tasks: list[str] = []

    if spawn_pattern == "validation_agent":
        task_desc = (
            f"验证漏洞 {finding_id} ({vuln_type}) 并确认可利用性。"
            f"上下文: {finding.get('detail', {})}"
        )
        tasks.append(task_desc)
    elif spawn_pattern == "reporting_agent":
        task_desc = (
            f"为漏洞 {finding_id} ({vuln_type}) 生成报告（含修复建议）。"
            f"上下文: {finding.get('detail', {})}"
        )
        tasks.append(task_desc)

    return tasks


