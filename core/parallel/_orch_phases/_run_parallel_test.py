# Phase 2 主调度函数（从 orchestrator.py 原样搬迁，逻辑零改动）。
# 公开名经 core.parallel.orchestrator 再导出，调用点零改动（D6/A5）。

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
from ._report_phase import _enter_report_phase

async def run_parallel_test(session: "AgentSession") -> AsyncGenerator[str, None]:
    """Phase 2 核心：FastScanner + LLM WorkerAgent 双路径并行。"""
    from core.parallel.session_info import get_session_info
    from core.parallel.batch_test import _batch_test_unauth
    from core.llm import set_current_task

    set_current_task(getattr(session, "task_id", "") or "")
    if not session.sitemap:
        return

    # ★ Phase 2 开始前：mitmproxy 健康检查 + 自动重启
    # 确保 Phase 2 期间产生的流量被正确记录到 flows.jsonl，供 Phase 2.55 补测使用
    _p2_proxy_port = int(os.getenv("PROXY_PORT", "18080"))
    if not _check_mitmproxy_health(_p2_proxy_port):
        log.warning("Phase 2 开始: mitmproxy 代理不可用（端口 %d），尝试自动重启", _p2_proxy_port)
        _p2_restart_ok = _try_restart_mitmproxy(_p2_proxy_port)
        if _p2_restart_ok:
            yield session._event("system",
                f"✅ Phase 2: mitmproxy 代理已自动重启（端口 {_p2_proxy_port}）")
        else:
            # ★ 缓存重启失败状态：Phase 2.55 不再重复尝试（同一次扫描内重启原因相同）
            session._mitmproxy_restart_failed = True
            # ★ 降级透明化：在 sitemap 上持久化标记，供报告渲染醒目横幅
            _degraded_reason = (
                f"Phase 2: mitmproxy 代理不可用且重启失败（端口 {_p2_proxy_port}），"
                "流量记录依赖 Playwright 降级写入，flows.jsonl 可能不完整。"
            )
            try:
                session.sitemap.traffic_degraded = True
                session.sitemap.traffic_degraded_reason = _degraded_reason
            except Exception:
                pass
            # ★ 详细降级日志：记录失败原因供后续排查
            log.error("mitmproxy 降级原因: 端口 %d 不可用且自动重启失败", _p2_proxy_port)
            log.error("  影响范围: 流量抓包不可用，flows.jsonl 由 Playwright 降级写入（可能缺失 WebSocket/部分 XHR）")
            log.error("  补偿机制: CDP 流量捕获 (get_cdp_flows) 可作为备选数据源")
            log.error("  排查建议: 1) 检查 mitmdump 是否安装  2) 检查端口 %d 是否被占用  3) 查看上方重启日志", _p2_proxy_port)
            yield session._event("system",
                f"⚠️ Phase 2: mitmproxy 代理不可用且重启失败，"
                f"流量记录将依赖 Playwright 降级写入")

    untested = session.sitemap.get_untested_features()
    if not untested:
        async for evt in _enter_report_phase(session):
            yield evt
        return

    # ---- Step 0.5: 过滤幽灵端点（404 的 API 不参与后续测试） ----
    try:
        ghost_result = await session.sitemap.filter_phantom_features(max_workers=10)
        if ghost_result.get("ghost_found", 0) > 0:
            yield session._event("system",
                f"👻 幽灵端点过滤: 发现 {ghost_result['ghost_found']} 个 404 端点，已跳过")
            # 重新获取 untested（过滤后状态可能变化）
            untested = session.sitemap.get_untested_features()
            if not untested:
                async for evt in _enter_report_phase(session):
                    yield evt
                return
    except Exception as e:
        log.warning("幽灵端点过滤异常（不影响主流程）: %s", e)

    # ---- Step 1: deferred 功能点批量测未授权访问（纯代码，极快） ----
    deferred_fps = [fp for fp in untested if fp.deferred and len(fp.checklist) == 1
                    and fp.checklist[0].vuln_type == "未授权访问"]
    if deferred_fps:
        yield session._event("system",
            f"⚡ 批量 deferred 未授权访问: {len(deferred_fps)} 个")
        batch_result = await _batch_test_unauth(session, deferred_fps)
        yield session._event("system",
            f"⚡ deferred 完成: {batch_result['tested']} 已测, "
            f"{batch_result['accessible']} 可未授权访问, {batch_result['blocked']} 需认证")
        tested_ids = {fp.id for fp in deferred_fps}
        untested = [fp for fp in untested if fp.id not in tested_ids]

    if not untested:
        async for evt in _enter_report_phase(session):
            yield evt
        return

    # ---- Step 2: 解析扫描策略 ----
    from core.scan_strategies import ScanMode, get_scan_strategy
    scan_cfg = get_scan_strategy(getattr(session, "user_scan_mode", "standard"))
    _effective_max_workers = LLM_SCAN_MAX_WORKERS if scan_cfg.llm_max_workers > 0 else MAX_WORKERS
    _fast_mode = scan_cfg.mode == ScanMode.FAST
    _is_packet_mode = getattr(session, 'target_info', '').startswith('单包测试')

    # ---- Step 3: 获取 Session 信息（FastScanner + LLM 都需要） ----
    if _is_packet_mode:
        import json as _json
        _headers = {}
        for k in ("PENTEST_INJECT_COOKIES", "PENTEST_INJECT_AUTH", "PENTEST_INJECT_HEADERS"):
            v = os.environ.get(k, "")
            if k == "PENTEST_INJECT_COOKIES" and v:
                _headers["Cookie"] = v
            elif k == "PENTEST_INJECT_AUTH" and v:
                _headers["Authorization"] = v
            elif k == "PENTEST_INJECT_HEADERS" and v:
                try:
                    _extra = _json.loads(v)
                    if isinstance(_extra, dict):
                        _headers.update(_extra)
                except Exception:
                    pass
        session_info = {"headers": _headers} if _headers else {}
    else:
        yield session._event("system", "正在获取 Session 信息...")
        session_info = await get_session_info()

    # ---- Step 4: FastScanner 先行 → LLM 准备基于更小的待测项 ----
    # ★ 优化（原设计为双路径并行）：原设计 FastScanner 与 LLM 准备同时启动，
    #   导致 LLM 元分析/智能分组基于原始 untested，包含 FastScanner 即将确认的项，
    #   浪费 LLM token 且决策质量下降。
    #   改为串行：FastScanner 先跑完写回结果，LLM 准备阶段基于过滤后的 remaining。
    #   超时降级：FastScanner 超过 lead_time 仍未完成则放弃等待，回退到原并行逻辑
    #   （保证总时长不劣化；FastScanner 仍在后台继续跑完，Step 5 再收尾）。
    enable_fast = scan_cfg.enable_fast_scanner
    enable_llm = not _fast_mode

    scripted_task = None
    if os.getenv("XUANJIAN_SCRIPTED_SCAN_CMD", "").strip():
        yield session._event("system", "🧪 脚本广扫层: 导出 API 清单并后台执行")
        scripted_task = asyncio.create_task(
            _run_scripted_scan_core(session.sitemap, session_info)
        )

    fast_findings: list = []
    fast_stats: dict = {}
    _fast_done = False
    fast_task = None
    if enable_fast:
        from core.config import FAST_MODE_TIMEOUTS as _FST
        _lead_time = _FST.get("lead_time", 120.0)
        _hard_timeout = _FST.get("hard_timeout", 600.0)
        yield session._event("system",
            f"🚀 FastScanner 先行: 本地规则引擎检测（LLM 准备阶段待其完成，超时 {_lead_time:.0f}s）")
        _fast_start_time = time.monotonic()
        fast_task = asyncio.create_task(
            _run_fast_scanner_core(untested, session_info, sitemap=session.sitemap)
        )
        # ★ 用 asyncio.wait 而非 wait_for：超时不取消 task，让其继续后台跑（Step 5 收尾）
        done, _pending = await asyncio.wait({fast_task}, timeout=_lead_time)
        if fast_task in done:
            try:
                fast_findings, fast_stats = fast_task.result()
                session._fast_scanner_stats = fast_stats
                hit_count = _write_fast_scanner_results(fast_findings, untested, session.sitemap)
                if scan_cfg.enable_skill_routing:
                    _apply_skill_routing(fast_findings, session.sitemap, scan_cfg.skill_routing_top_n)
                yield session._event("system",
                    f"⚡ FastScanner 完成: {len(fast_findings)} 条命中, {hit_count} 个功能点已标记")
                _fast_done = True
                fast_task = None  # 已完成，释放引用
            except Exception as e:
                log.warning("FastScanner 异常: %s", e)
                yield session._event("system", f"⚠️ FastScanner 异常（不影响 LLM 路径）: {str(e)[:120]}")
                fast_task = None
        else:
            yield session._event("system",
                f"⏱️ FastScanner 超时（>{_lead_time:.0f}s），回退并行模式")
            # fast_task 保留（仍在 pending），后台继续跑，Step 5 收尾
    else:
        if enable_llm:
            yield session._event("system", "🚀 LLM 准备阶段（FastScanner 已跳过）")

    # ---- Step 4b: 重新计算待测项（仅当 FastScanner 已完成时才有效）----
    # FastScanner 已完成 → remaining_for_llm 排除已确认项（更小，省 LLM token）
    # FastScanner 超时/跳过 → remaining_for_llm = 原始 untested（回退原逻辑）
    if _fast_done:
        remaining_for_llm = [fp for fp in untested if fp.get_http_pending()]
    else:
        remaining_for_llm = untested

    llm_result = None
    if enable_llm and not remaining_for_llm:
        yield session._event("system", "⚡ FastScanner 已覆盖全部 HTTP 项，跳过 LLM 准备阶段")
    elif enable_llm:
        llm_result = []
        async for evt in _run_llm_preparation(session, remaining_for_llm, scan_cfg, _effective_max_workers):
            yield evt
            llm_result.append(evt)
    else:
        yield session._event("system", "快速模式: 跳过 LLM 分析")

    # ---- Step 5: 等待 FastScanner 后台完成（仅超时降级路径）----
    if fast_task is not None:
        # ★ 硬超时：从 FastScanner 启动算起的总预算，超过则取消 task 避免无限拖慢
        _elapsed = time.monotonic() - _fast_start_time
        _remaining = max(1.0, _hard_timeout - _elapsed)
        try:
            fast_findings, fast_stats = await asyncio.wait_for(fast_task, timeout=_remaining)
            session._fast_scanner_stats = fast_stats
            hit_count = _write_fast_scanner_results(fast_findings, untested, session.sitemap)
            if scan_cfg.enable_skill_routing:
                _apply_skill_routing(fast_findings, session.sitemap, scan_cfg.skill_routing_top_n)
            yield session._event("system",
                f"⚡ FastScanner 后台完成: {len(fast_findings)} 条命中, {hit_count} 个功能点已标记")
        except asyncio.TimeoutError:
            fast_task.cancel()
            log.warning("FastScanner 硬超时（>%ds），取消后台任务，放弃剩余扫描结果",
                        int(_hard_timeout))
            yield session._event("system",
                f"⏱️ FastScanner 硬超时（>{int(_hard_timeout)}s），已取消，使用 LLM 路径结果")
        except Exception as e:
            log.warning("FastScanner 后台异常: %s", e)
            yield session._event("system", f"⚠️ FastScanner 异常（不影响 LLM 路径）: {str(e)[:120]}")

    scripted_findings = []
    scripted_stats = {}
    if scripted_task:
        try:
            scripted_findings, scripted_stats = await scripted_task
            session._scripted_scan_stats = scripted_stats
            if session.sitemap:
                session.sitemap._scripted_scan_stats = scripted_stats
            scripted_hit_count = _write_scripted_scan_results(scripted_findings, untested, session.sitemap)
            yield session._event("system",
                f"🧪 脚本广扫完成: {len(scripted_findings)} 条疑似, {scripted_hit_count} 个功能点已标记待验证")
        except Exception as e:
            log.warning("脚本广扫异常: %s", e)
            yield session._event("system", f"⚠️ 脚本广扫异常（不影响主流程）: {str(e)[:120]}")

    # ---- Step 6: 快速模式直接进报告 ----
    if _fast_mode:
        from core.sitemap import CheckResult
        # ★ OPT2: FAST 模式保底清单 — 5 项检测已由 FastScanner 本地规则执行，
        # 不应标记为"跳过"，而应标记为"FastScanner 保底检测"。
        # 英文规则名 → 中文 vuln_type 映射（与 fast_scanner.py 中 vuln_type 一致）
        _minimal_vuln_types: set[str] = set()
        _RULE_TO_VULN_TYPE = {
            "sql_injection": {"SQL注入"},
            "unauthorized_access": {"未授权访问", "IDOR"},
            "info_disclosure": {"信息泄露"},
            "weak_password": {"弱口令"},
            "cors": {"CORS配置错误"},
        }
        for _rule in (getattr(scan_cfg, 'fast_minimal_checks', None) or []):
            _minimal_vuln_types.update(_RULE_TO_VULN_TYPE.get(_rule, set()))

        _minimal_kept = 0
        for fp in untested:
            for c in fp.checklist:
                if c.result == CheckResult.PENDING:
                    if c.vuln_type in _minimal_vuln_types:
                        # 保底检测项：FastScanner 已执行但无命中
                        c.result = CheckResult.NOT_VULN
                        c.detail = "FastScanner 保底检测（本地规则已执行，无命中）"
                        _minimal_kept += 1
                    else:
                        c.result = CheckResult.SKIPPED
                        c.detail = "快速模式跳过 LLM"
            if fp.test_status == TestStatus.NOT_TESTED:
                fp.test_status = TestStatus.TESTED
        if _minimal_kept > 0:
            yield session._event("system",
                f"⚡ FAST 保底检测: {_minimal_kept} 项已由 FastScanner 本地规则执行")
        if session.sitemap:
            session.sitemap.phase_status = "fast_mode"
            session.sitemap.termination_reason = "快速模式：仅运行 FastScanner 部分规则，跳过所有 LLM 深度分析。"
            session.sitemap.save()
        yield session._event("system", "快速模式完成，进入报告")
        async for evt in _enter_report_phase(session):
            yield evt
        return

    # ---- Step 7: 过滤 FastScanner 已测完项，剩余交 LLM ----
    remaining = [fp for fp in untested if fp.get_http_pending()]
    if not remaining:
        yield session._event("system", "FastScanner + 初筛已覆盖全部项，跳过 LLM WorkerAgent")
        async for evt in _enter_report_phase(session):
            yield evt
        return

    # ---- Step 8: 分类并提取分组（从 LLM 准备结果或 fallback） ----
    worker_features = [fp for fp in remaining if fp.get_http_pending()]
    browser_features = [fp for fp in remaining if fp.get_browser_pending()]

    # 如果 LLM 准备阶段完成了智能分组，复用该结果；否则按 API 前缀分组。
    # 复用时必须重新过滤 pending，因为初筛/脚本批测/FastScanner 可能已改写 checklist 状态。
    from core.parallel.grouping import _group_features_by_api_prefix
    llm_groups = getattr(session, "_llm_feature_groups", None) or []
    if llm_groups:
        worker_ids = {fp.id for fp in worker_features}
        assigned_ids: set[str] = set()
        feature_groups = []
        for group_name, group_fps in llm_groups:
            filtered = [fp for fp in group_fps if fp.id in worker_ids and fp.get_http_pending()]
            if filtered:
                feature_groups.append((group_name, filtered))
                assigned_ids.update(fp.id for fp in filtered)
        missing = [fp for fp in worker_features if fp.id not in assigned_ids]
        if missing:
            feature_groups.extend(_group_features_by_api_prefix(missing))
        if not feature_groups:
            feature_groups = _group_features_by_api_prefix(worker_features)
    else:
        feature_groups = _group_features_by_api_prefix(worker_features)

    from core.config import MAX_FEATURES_PER_GROUP
    split_groups = []
    for name, fps in feature_groups:
        if len(fps) <= MAX_FEATURES_PER_GROUP:
            split_groups.append((name, fps))
        else:
            for i in range(0, len(fps), MAX_FEATURES_PER_GROUP):
                chunk = fps[i:i + MAX_FEATURES_PER_GROUP]
                split_groups.append((f"{name}({i // MAX_FEATURES_PER_GROUP + 1})", chunk))
    feature_groups = split_groups

    # ========== 阶段 A: 子 Agent 并行测试 HTTP 项 ==========
    if worker_features:
        yield session._event("phase",
            f"Phase 2a: 子 Agent 并行测试 ({len(worker_features)} 个功能点, {len(feature_groups)} 组)")

        from core.worker_agent import WorkerAgent

        # ★ 改为按组分配：每个 worker 接收一组功能点，串行测试（共享上下文）
        queue = list(feature_groups)  # [(group_name, [fp, ...])]
        active_workers: dict[str, asyncio.Task] = {}
        event_queue: asyncio.Queue = asyncio.Queue()
        worker_idx = 0
        worker_last_event: dict[str, float] = {}  # ★ 卡死检测：记录每个 worker 最后事件时间

        async def _run_worker(worker: WorkerAgent):
            try:
                async for evt in worker.run():
                    await event_queue.put(evt)
            except Exception as e:
                await event_queue.put({"type": "worker_error", "worker": worker.worker_id,
                                       "feature": worker.group_name, "error": str(e)})

        # 启动初始批次
        # ★ 注册 active_workers 到 session，供 /api/stop 取消所有子 Agent
        session._active_worker_tasks = active_workers
        while queue and len(active_workers) < _effective_max_workers:
            group_name, group_fps = queue.pop(0)
            worker_idx += 1
            for fp in group_fps:
                session.sitemap.start_test(fp.id)
            worker = WorkerAgent(
                worker_id=f"w{worker_idx}",
                llm=session.llm,
                features=group_fps,
                group_name=group_name,
                sitemap=session.sitemap,
                session_info=session_info,
            )
            task = asyncio.create_task(_run_worker(worker))
            active_workers[worker.worker_id] = task
            worker_last_event[worker.worker_id] = time.time()  # ★ 卡死检测起点
            fp_count = len(group_fps)
            checks_count = sum(len(fp.get_http_pending()) for fp in group_fps)
            yield session._event("system",
                f"🚀 子 Agent [{worker.worker_id}] 开始测试组「{group_name}」"
                f"({fp_count} 个功能点, {checks_count} 项 checklist)")

        # 事件循环
        while active_workers:
            try:
                evt = await asyncio.wait_for(event_queue.get(), timeout=WORKER_EVENT_TIMEOUT)
            except asyncio.TimeoutError:
                # ★ 卡死检测：取消长时间无事件的 Worker
                stuck_ids = _check_stuck_workers(active_workers, worker_last_event)
                for sid in stuck_ids:
                    yield session._event("system",
                        f"🛑 子 Agent [{sid}] 卡死（{WORKER_STUCK_TIMEOUT}s 无事件），已强制取消")
                    if sid in active_workers:
                        del active_workers[sid]
                    if sid in worker_last_event:
                        del worker_last_event[sid]
                    if queue:
                        group_name, group_fps = queue.pop(0)
                        worker_idx += 1
                        for fp in group_fps:
                            session.sitemap.start_test(fp.id)
                        worker = WorkerAgent(
                            worker_id=f"w{worker_idx}",
                            llm=session.llm,
                            features=group_fps,
                            group_name=group_name,
                            sitemap=session.sitemap,
                            session_info=session_info,
                        )
                        task = asyncio.create_task(_run_worker(worker))
                        active_workers[worker.worker_id] = task
                        worker_last_event[worker.worker_id] = time.time()
                        yield session._event("system",
                            f"🔄 子 Agent [{worker.worker_id}] 替补启动（卡死替换）组「{group_name}」")
                if stuck_ids:
                    continue
                done_ids = [wid for wid, t in active_workers.items() if t.done()]
                for wid in done_ids:
                    del active_workers[wid]
                    if wid in worker_last_event:
                        del worker_last_event[wid]
                if not done_ids:
                    yield session._event("system", "子 Agent 超时，继续等待...")
                continue

            wid = evt.get("worker", "?")
            # ★ 更新 Worker 最后事件时间（卡死检测）
            if wid != "?":
                worker_last_event[wid] = time.time()

            if evt["type"] == "worker_done":
                metrics.inc("features_tested", evt["features_done"])
                metrics.inc("checklist_completed", evt["completed"])
                metrics.inc("vulns_found", evt["vulns"])
                yield session._event("system",
                    f"✅ 子 Agent [{wid}] 完成组「{evt['group']}」: "
                    f"{evt['features_done']}/{evt['features_total']} 功能点, "
                    f"{evt['completed']}/{evt['total']} checklist, "
                    f"{evt['vulns']} 个漏洞")
                if wid in active_workers:
                    del active_workers[wid]
                if wid in worker_last_event:
                    del worker_last_event[wid]
                # 从队列中取下一组
                if queue:
                    group_name, group_fps = queue.pop(0)
                    worker_idx += 1
                    for fp in group_fps:
                        session.sitemap.start_test(fp.id)
                    worker = WorkerAgent(
                        worker_id=f"w{worker_idx}",
                        llm=session.llm,
                        features=group_fps,
                        group_name=group_name,
                        sitemap=session.sitemap,
                        session_info=session_info,
                    )
                    task = asyncio.create_task(_run_worker(worker))
                    active_workers[worker.worker_id] = task
                    worker_last_event[worker.worker_id] = time.time()
                    fp_count = len(group_fps)
                    checks_count = sum(len(fp.get_http_pending()) for fp in group_fps)
                    yield session._event("system",
                        f"🚀 子 Agent [{worker.worker_id}] 开始测试组「{group_name}」"
                        f"({fp_count} 个功能点, {checks_count} 项 checklist)")

            elif evt["type"] == "worker_error":
                yield session._event("system", f"❌ 子 Agent [{wid}] 出错: {evt.get('error', '')[:100]}")
                if wid in active_workers:
                    del active_workers[wid]
                if wid in worker_last_event:
                    del worker_last_event[wid]
                # ★ 错误退出后也要从队列取下一组启动新 worker（否则剩余任务被跳过）
                if queue:
                    group_name, group_fps = queue.pop(0)
                    worker_idx += 1
                    for fp in group_fps:
                        session.sitemap.start_test(fp.id)
                    worker = WorkerAgent(
                        worker_id=f"w{worker_idx}",
                        llm=session.llm,
                        features=group_fps,
                        group_name=group_name,
                        sitemap=session.sitemap,
                        session_info=session_info,
                    )
                    task = asyncio.create_task(_run_worker(worker))
                    active_workers[worker.worker_id] = task
                    worker_last_event[worker.worker_id] = time.time()
                    fp_count = len(group_fps)
                    checks_count = sum(len(fp.get_http_pending()) for fp in group_fps)
                    yield session._event("system",
                        f"🔄 子 Agent [{worker.worker_id}] 替补启动组「{group_name}」"
                        f"({fp_count} 个功能点, {checks_count} 项 checklist)")

            elif evt["type"] == "worker_tool":
                tool_brief = evt.get("tool_brief", evt.get("tool", ""))
                tool_full = evt.get("tool_full", evt.get("tool", ""))
                yield session._event("tool_call",
                    f"[{wid}/{evt['feature'][:12]}] {tool_brief}",
                    full=f"[{wid}/{evt['feature']}] {tool_full}")

            elif evt["type"] == "worker_screenshot":
                # ★ 实时展示子 Agent 的浏览器截图
                ss_name = evt.get("name", "screenshot")
                yield session._event("screenshot", f"/api/screenshot/{ss_name}")

            elif evt["type"] == "worker_message":
                # 子 Agent 的文字输出（测试过程描述）
                yield session._event("message",
                    f"**[{wid}]** {evt.get('content', '')}")

            elif evt["type"] == "worker_thinking":
                # 每 2 轮推一次"在思考"心跳（避免 LLM 调用期间前端长时间无事件）
                if evt.get("round", 0) % 2 == 1:
                    yield session._event("thinking", f"[{wid}] {evt['feature']} — 第 {evt['round']} 轮")

        yield session._event("system", "所有子 Agent 完成 HTTP 项测试")

    # ★ 回收被占坑但实际未测试的 API 计数，释放被截断的功能点
    if session.sitemap:
        reclaim = session.sitemap.reclaim_unused_api_slots()
        if reclaim.get("reactivated_features", 0) > 0:
            yield session._event("system",
                f"🔄 回收未测试坑位: {reclaim['reclaimed_apis']} 个 API 计数已校正, "
                f"{reclaim['reactivated_features']} 个功能点重新激活")

    # ========== 接力测试：检查是否还有未测完的功能点 ==========
    # ★ #20: 接力轮数可配置（环境变量 PENTEST_RELAY_MAX_ROUNDS）
    #   默认 2 轮（兼顾覆盖率和 Token 预算），用户可在 .env 里调大调小：
    #   - 0 = 禁用接力（一次失败就跳过）
    #   - 1~3 = 常规配置（默认 2）
    #   - >5 = 不推荐（容易死循环烧 Token）
    try:
        MAX_RETRY_ROUNDS = max(0, int(os.getenv("PENTEST_RELAY_MAX_ROUNDS", "2")))
    except (ValueError, TypeError):
        MAX_RETRY_ROUNDS = 2
    if MAX_RETRY_ROUNDS == 0:
        yield session._event("system",
            f"⏭️ 接力测试已禁用（PENTEST_RELAY_MAX_ROUNDS=0），未测完的功能点将保留 NOT_TESTED 状态")
    for retry_round in range(MAX_RETRY_ROUNDS):
        if not session.sitemap:
            break
        # 找出还有 PENDING checklist 项的功能点（HTTP 项）
        # ★ 包含 NOT_TESTED 和 IN_PROGRESS（子 Agent 出错中断的功能点停在 IN_PROGRESS）
        retry_fps = [fp for fp in session.sitemap.features.values()
                     if fp.test_status in (TestStatus.NOT_TESTED, TestStatus.IN_PROGRESS)
                     and fp.get_http_pending()
                     and not fp.deferred]
        if not retry_fps:
            break

        pending_count = sum(len(fp.get_http_pending()) for fp in retry_fps)
        yield session._event("system",
            f"🔄 接力轮 {retry_round + 1}: 发现 {len(retry_fps)} 个功能点还有 {pending_count} 项未测完，重新分配子 Agent")

        # 重新分组（每组不超过 MAX_FEATURES_PER_GROUP）
        from core.config import MAX_FEATURES_PER_GROUP
        retry_groups: list[tuple[str, list]] = []
        for i in range(0, len(retry_fps), MAX_FEATURES_PER_GROUP):
            chunk = retry_fps[i:i + MAX_FEATURES_PER_GROUP]
            retry_groups.append((f"接力{retry_round+1}-{i//MAX_FEATURES_PER_GROUP+1}", chunk))

        # 启动新一轮子 Agent
        from core.worker_agent import WorkerAgent
        retry_queue = list(retry_groups)
        retry_active: dict[str, asyncio.Task] = {}
        retry_event_queue: asyncio.Queue = asyncio.Queue()
        retry_last_event: dict[str, float] = {}  # ★ 卡死检测

        async def _run_retry_worker(w: WorkerAgent):
            try:
                async for evt in w.run():
                    await retry_event_queue.put(evt)
            except Exception as e:
                await retry_event_queue.put({"type": "worker_error", "worker": w.worker_id,
                                             "feature": w.group_name, "error": str(e)})

        while retry_queue and len(retry_active) < _effective_max_workers:
            gname, gfps = retry_queue.pop(0)
            worker_idx += 1
            for fp in gfps:
                session.sitemap.start_test(fp.id)
            w = WorkerAgent(
                worker_id=f"w{worker_idx}",
                llm=session.llm,
                features=gfps,
                group_name=gname,
                sitemap=session.sitemap,
                session_info=session_info,
            )
            t = asyncio.create_task(_run_retry_worker(w))
            retry_active[w.worker_id] = t
            retry_last_event[w.worker_id] = time.time()
            yield session._event("system",
                f"🚀 接力 Agent [{w.worker_id}] 测试 {len(gfps)} 个功能点")

        # ★ 注册接力 worker tasks 到 session，供 /api/stop 取消
        session._active_worker_tasks = retry_active

        while retry_active:
            try:
                evt = await asyncio.wait_for(retry_event_queue.get(), timeout=WORKER_EVENT_TIMEOUT)
            except asyncio.TimeoutError:
                # ★ 卡死检测
                stuck_ids = _check_stuck_workers(retry_active, retry_last_event)
                for sid in stuck_ids:
                    yield session._event("system",
                        f"🛑 接力 Agent [{sid}] 卡死（{WORKER_STUCK_TIMEOUT}s 无事件），已强制取消")
                    if sid in retry_active:
                        del retry_active[sid]
                    if sid in retry_last_event:
                        del retry_last_event[sid]
                if stuck_ids:
                    continue
                done_ids = [wid for wid, t in retry_active.items() if t.done()]
                for wid in done_ids:
                    del retry_active[wid]
                    if wid in retry_last_event:
                        del retry_last_event[wid]
                continue

            wid = evt.get("worker", "?")
            if wid != "?":
                retry_last_event[wid] = time.time()
            if evt["type"] == "worker_done":
                metrics.inc("features_tested", evt.get("features_done", 0))
                yield session._event("system", f"✅ 接力 Agent [{wid}] 完成")
                if wid in retry_active:
                    del retry_active[wid]
                if wid in retry_last_event:
                    del retry_last_event[wid]
                if retry_queue:
                    gname, gfps = retry_queue.pop(0)
                    worker_idx += 1
                    for fp in gfps:
                        session.sitemap.start_test(fp.id)
                    w = WorkerAgent(
                        worker_id=f"w{worker_idx}",
                        llm=session.llm,
                        features=gfps,
                        group_name=gname,
                        sitemap=session.sitemap,
                        session_info=session_info,
                    )
                    t = asyncio.create_task(_run_retry_worker(w))
                    retry_active[w.worker_id] = t
                    retry_last_event[w.worker_id] = time.time()
                    yield session._event("system",
                        f"🚀 接力 Agent [{w.worker_id}] 测试 {len(gfps)} 个功能点")
            elif evt["type"] == "worker_error":
                yield session._event("system", f"❌ 接力 Agent [{wid}] 出错: {evt.get('error', '')[:100]}")
                if wid in retry_active:
                    del retry_active[wid]
                if wid in retry_last_event:
                    del retry_last_event[wid]
                # ★ 接力轮出错也要补派
                if retry_queue:
                    gname, gfps = retry_queue.pop(0)
                    worker_idx += 1
                    for fp in gfps:
                        session.sitemap.start_test(fp.id)
                    w = WorkerAgent(
                        worker_id=f"w{worker_idx}",
                        llm=session.llm,
                        features=gfps,
                        group_name=gname,
                        sitemap=session.sitemap,
                        session_info=session_info,
                    )
                    t = asyncio.create_task(_run_retry_worker(w))
                    retry_active[w.worker_id] = t
                    retry_last_event[w.worker_id] = time.time()
                    yield session._event("system",
                        f"🔄 接力 Agent [{w.worker_id}] 替补 {len(gfps)} 个功能点")
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

        yield session._event("system", f"接力轮 {retry_round + 1} 完成")

    # ========== 覆盖检查：补齐遗漏的功能点 ==========
    if session.sitemap:
        api_cov = session.sitemap.check_api_coverage()
        uncovered = api_cov.get("uncovered", [])
        if uncovered:
            yield session._event("system",
                f"⚠️ API 覆盖检查: {api_cov['covered']}/{api_cov['total_apis']} 已覆盖, "
                f"发现 {len(uncovered)} 个未覆盖 API")
            # 自动为未覆盖的 API 创建功能点
            for api in uncovered[:20]:  # 最多补 20 个，防止爆炸
                session.sitemap.report_discovery(
                    f"{api['method']} {api['url']}",
                    description=f"覆盖检查发现的未测试接口",
                )
            # report_discovery 只入 pending_discoveries，需调 merge_discoveries 真正创建功能点
            merge_result = session.sitemap.merge_discoveries()
            new_count = merge_result.get("new", 0)
            merged_count = merge_result.get("merged", 0)
            if new_count > 0:
                log.info("覆盖检查补建 %d 个新功能点, 归并 %d 个到已有功能点", new_count, merged_count)
                yield session._event("system", f"✅ 自动补建 {new_count} 个功能点，启动追加测试...")
                # 递归调用：对新功能点再跑一轮并行测试
                session.sitemap.save()
                async for evt in _run_supplementary_test(session, session_info, _effective_max_workers):
                    yield evt
        else:
            yield session._event("system", f"✅ API 覆盖检查通过: {api_cov['total_apis']} 个 API 全部被功能点覆盖")

    # ========== 阶段 B: 主 Agent 串行测试浏览器项 ==========
    # ★ 2026-05-28 修复：单包模式下跳过浏览器测试（单包只测 HTTP 项，不需要浏览器）
    if _is_packet_mode:
        log.info("单包模式: 跳过 Phase 2b 浏览器测试")
        # 将浏览器项标记为 skipped（不影响报告）
        if session.sitemap:
            from core.sitemap_models import CheckResult
            all_untested = session.sitemap.get_untested_features()
            for fp in all_untested:
                for c in fp.get_browser_pending():
                    c.result = CheckResult.SKIPPED
                    c.detail = "单包模式跳过浏览器测试（仅测 HTTP 项）"
            session.sitemap.save()
        async for evt in _enter_report_phase(session):
            yield evt
    else:
        # 重新收集浏览器项（可能有新增的功能点）
        if session.sitemap:
            all_untested = session.sitemap.get_untested_features()
            browser_features = [fp for fp in all_untested if fp.get_browser_pending()]
            total_browser = sum(len(fp.get_browser_pending()) for fp in browser_features)

        if browser_features:
            yield session._event("phase", f"Phase 2b: 主 Agent 浏览器测试 ({total_browser} 项)")
            session._browser_test_queue = list(browser_features)
            async for evt in start_browser_feature_test(session):
                yield evt
        else:
            async for evt in _enter_report_phase(session):
                yield evt


