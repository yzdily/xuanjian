# 报告阶段收口函数（原样搬迁自 orchestrator.py）。

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


async def _execute_gap_tasks(new_tasks: list[dict]) -> list[dict]:
    """对每个补齐任务起一个最小子 Agent 执行。

    纯函数（零局部捕获），从 ``_enter_report_phase`` 内 hoist 到模块级，
    以便测试与生产代码统一引用（保持 ``test_a_grade_hoists`` 的导入契约）。
    """
    if not new_tasks:
        return []
    results: list[dict] = []
    for task in new_tasks:
        if not isinstance(task, dict):
            results.append({"status": "skipped", "summary": "非 dict"})
            continue
        title = task.get("title", "") or task.get("id", "GAP")
        role = task.get("role", "")
        url = task.get("target_url", "")
        param = task.get("param_to_modify", "") or task.get("param", "")
        method = task.get("test_method", "")
        expected_safe = task.get("expected_if_safe", "")
        expected_vuln = task.get("expected_if_vuln", "")
        vtype = task.get("vulnerability_type", "")
        summary = (
            f"任务已识别并记录在报告。\n"
            f"执行建议: 用角色「{role}」对 `{url}` 的参数 `{param}` "
            f"执行「{method}」,若返回 `{expected_safe}` 则安全,"
            f"返回 `{expected_vuln}` 则确认 {vtype}。"
        )
        results.append({
            "status": "已记录待执行",
            "summary": summary,
        })
    return results


async def _enter_report_phase(session: "AgentSession") -> AsyncGenerator[str, None]:
    """进入 Phase 3 汇总报告。"""
    # ★ 等待 XSS 后台扫描完成（如果还在跑）并 drain 所有积压事件
    xss_task = getattr(session, "_xss_task", None)
    xss_queue = getattr(session, "_xss_events_queue", None)
    if xss_task and xss_queue:
        yield session._event("system", "⏳ 等待 XSS 专项扫描完成...")
        # 先 drain 已有事件
        drained = 0
        while not xss_queue.empty():
            try:
                evt = xss_queue.get_nowait()
                if evt.get("type") == "_xss_internal_done":
                    continue
                msg = evt.get("data", "")
                if msg:
                    yield session._event("system", f"[XSS] {msg}")
                drained += 1
            except asyncio.QueueEmpty:
                break
        if drained:
            log.info("XSS pre-wait drained %d events", drained)
        # 等待 XSS task 完成（含 timeout 兜底）
        try:
            heartbeat = 0
            while not xss_task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(xss_task), timeout=5)
                except asyncio.TimeoutError:
                    heartbeat += 5
                    # 顺便 drain 一下
                    while not xss_queue.empty():
                        try:
                            evt = xss_queue.get_nowait()
                            if evt.get("type") == "_xss_internal_done":
                                continue
                            msg = evt.get("data", "")
                            if msg:
                                yield session._event("system", f"[XSS] {msg}")
                        except asyncio.QueueEmpty:
                            break
                    if heartbeat % 30 == 0:
                        yield session._event("system",
                            f"  ⏳ XSS 扫描进行中... ({heartbeat}s)")
                except asyncio.CancelledError:
                    break
                except Exception:
                    log.debug("XSS 扫描 heartbeat 中断", exc_info=True)
                    break
            # 最后再 drain 一次
            while not xss_queue.empty():
                try:
                    evt = xss_queue.get_nowait()
                    if evt.get("type") == "_xss_internal_done":
                        continue
                    msg = evt.get("data", "")
                    if msg:
                        yield session._event("system", f"[XSS] {msg}")
                except asyncio.QueueEmpty:
                    break
            # 汇总 XSS 结果
            scanner = getattr(session, "_xss_scanner", None)
            if scanner and scanner.findings:
                from core.xss.models import FindingStatus
                confirmed = [f for f in scanner.findings if f.status == FindingStatus.CONFIRMED]
                review = [f for f in scanner.findings if f.status == FindingStatus.NEEDS_REVIEW]
                yield session._event("system",
                    f"🛡️ XSS 扫描汇总: 确认 {len(confirmed)} 个, 待复核 {len(review)} 个")
                # 把 confirmed 漏洞作为 sitemap.findings 注入（被 Phase 3 报告引用）
                if confirmed and session.sitemap:
                    try:
                        for f in confirmed:
                            # 把对应 feature 的 XSS checklist 项标记为 vulnerable
                            if f.feature_id and f.feature_id in session.sitemap.features:
                                fp = session.sitemap.features[f.feature_id]
                                for item in fp.checklist:
                                    if item.vuln_type in ("XSS", "反射型XSS", "DOM XSS"):
                                        # ★ CheckResult/TestStatus 已在模块顶部导入，
                                        # 此处不再局部 import，避免 UnboundLocalError。
                                        from core.sitemap_models import Severity as SitemapSev
                                        item.result = CheckResult.VULNERABLE
                                        item.detail = f.description or f.title
                                        item.severity = f.severity.value
                                        item.reproduce_steps = f.reproduce_steps
                                        item.fix_suggestion = f.fix_suggestion
                                        item.evidence_request = f.candidate.request_packet
                                        item.evidence_response = f.candidate.response_packet[:5000]
                                        fp.test_status = TestStatus.VULN_FOUND
                                        break
                        session.sitemap.save()
                    except (KeyError, ValueError, AttributeError, OSError) as e:
                        log.warning("merge xss confirmed to sitemap features failed: %s", e)
        except Exception as e:
            yield session._event("system", f"⚠️ 等待 XSS 扫描时出错: {str(e)[:120]}")

    # Phase 2 结束：统一合并动态发现的 API/功能点
    if session.sitemap and session.sitemap.pending_discoveries:
        merge_result = session.sitemap.merge_discoveries()
        merged = merge_result["merged"]
        new = merge_result["new"]
        discarded = merge_result["discarded"]
        log.info("动态发现合并完成: 归并 %d 个, 新增 %d 个, 丢弃 %d 个", merged, new, discarded)
        yield session._event("system",
            f"📋 Phase 2 动态发现整合: 归并到已有功能点 {merged} 个, "
            f"新增功能点 {new} 个, 丢弃 {discarded} 个")
        if merge_result["details"]:
            detail_text = "\n".join(f"  - {d}" for d in merge_result["details"][:20])
            yield session._event("system", f"合并详情:\n{detail_text}")

    # ★ Phase 2.5: 业务对账 + Top 缺口补齐
    bu_result = getattr(session.sitemap, "business_understanding", None) or {}
    if session.sitemap and bu_result and bu_result.get("status") == "ok" and not SKIP_BUSINESS_UNDERSTANDING:
        yield session._event("phase", "Phase 2.5: 业务对账 — AI 总监审计测试覆盖")
        try:
            from core.reconcile import reconcile_loop

            # 进度回调
            _reconcile_events: list[str] = []

            def _on_reconcile_event(msg: str):
                _reconcile_events.append(msg)

            # 补齐任务执行器：使用模块级纯函数 _execute_gap_tasks（见文件下方定义）

            rec_started = time.time()
            rec_result = await reconcile_loop(
                sitemap=session.sitemap,
                bu_result=bu_result,
                llm=session.llm,
                execute_new_tasks=_execute_gap_tasks,
                max_rounds=2,
                on_event=_on_reconcile_event,
                timeout_per_round=90.0,
            )

            # 输出对账事件
            for msg in _reconcile_events:
                yield session._event("system", f"[对账] {msg}")

            session.sitemap.reconcile_result = rec_result
            try:
                session.sitemap.save()
            except OSError as e:
                log.warning("Phase 2.5 sitemap save 失败: %s", e)

            if rec_result.get("status") == "ok":
                rec_data = rec_result.get("reconcile_data", {}) or {}
                cov = rec_data.get("coverage_summary", {}) or {}
                new_tasks = rec_data.get("new_tasks", []) or []
                rec_elapsed = time.time() - rec_started
                yield session._event("system",
                    f"✅ Phase 2.5 对账完成 (耗时 {rec_elapsed:.1f}s, "
                    f"{rec_result.get('rounds', 0)} 轮):\n"
                    f"  - 承诺覆盖: {cov.get('promises_covered', '?')}/{cov.get('promises_total', '?')}\n"
                    f"  - 综合置信度: {cov.get('overall_confidence', '?')}\n"
                    f"  - Top 缺口: {len(new_tasks)} 个\n"
                    f"  - 总评: {cov.get('verdict', '?')}\n"
                    f"  - 详情已写入报告 1.3 章节")
            else:
                yield session._event("system",
                    f"⚠️ Phase 2.5 对账失败: {rec_result.get('error', '未知')[:200]}\n"
                    f"  不影响主报告生成,只是缺少能力补齐分析")
        except Exception as e:
            log.warning("Phase 2.5 reconcile crashed: %s", e)
            yield session._event("system", f"⚠️ Phase 2.5 异常: {str(e)[:200]}")
    elif bu_result:
        # 业务理解未完成,跳过对账
        bu_status = bu_result.get("status", "missing")
        if bu_status != "ok":
            yield session._event("system",
                f"ℹ️ 业务理解状态为 {bu_status},跳过 Phase 2.5 对账")

    # ★ 代理健康检查 + 自动重启：Phase 2.55 补测前检测 mitmproxy 是否可用
    # 代理不可用时尝试自动重启；重启失败则使用降级方案：
    #   1. Playwright 降级写入 flows.jsonl（crawler_core.py）
    #   2. 主动目录爆破发现新 API（supplemental_test_agent.py）
    _proxy_port = int(os.getenv("PROXY_PORT", "18080"))
    # ★ Phase 2 已缓存重启失败状态时，跳过重复尝试（避免 4 条重复日志）
    if getattr(session, "_mitmproxy_restart_failed", False):
        if not _check_mitmproxy_health(_proxy_port):
            yield session._event("system",
                f"⚠️ mitmproxy 代理（端口 {_proxy_port}）仍未恢复，补测依赖主动目录爆破 + Playwright 降级写入。"
                f"flows.jsonl 可能不完整。")
            log.warning("Phase 2.55: mitmproxy 仍不可用（Phase 2 重启已失败，跳过重复尝试）")
            # ★ 降级透明化：确保 sitemap 标记已设置（Phase 2 已设，此处兜底）
            try:
                session.sitemap.traffic_degraded = True
            except Exception:
                pass
    elif not _check_mitmproxy_health(_proxy_port):
        yield session._event("system",
            f"⚠️ mitmproxy 代理（端口 {_proxy_port}）未运行，尝试自动重启...")
        log.warning("Phase 2.55: mitmproxy 代理不可用（端口 %d），尝试自动重启", _proxy_port)

        _restart_ok = _try_restart_mitmproxy(_proxy_port)
        if _restart_ok:
            yield session._event("system",
                f"✅ mitmproxy 代理已自动重启成功（端口 {_proxy_port}）")
        else:
            yield session._event("system",
                f"⚠️ mitmproxy 代理自动重启失败，补测将依赖主动目录爆破 + Playwright 降级写入。"
                f"flows.jsonl 可能不完整。")
            log.warning("Phase 2.55: mitmproxy 重启失败，使用降级模式")
            # ★ 降级透明化：Phase 2.55 独立重启失败时也设置 sitemap 标记
            try:
                session.sitemap.traffic_degraded = True
                session.sitemap.traffic_degraded_reason = (
                    f"Phase 2.55: mitmproxy 代理重启失败（端口 {_proxy_port}），"
                    "补测依赖主动目录爆破 + Playwright 降级写入，flows.jsonl 可能不完整。"
                )
            except Exception:
                pass

    # ★ Phase 2.55: 补测 Agent (2026-05-22)
    # ★ P2-A: FAST 模式不再完全跳过补测，改用本地规则版（FastScanner 替代 WorkerAgent）
    _fast_mode = getattr(session, "user_scan_mode", "smart") == "fast"
    if session.sitemap and not _fast_mode:
        try:
            from core.supplemental_test_agent import run_supplemental_test
            yield session._event("phase",
                "Phase 2.55: 补测 Agent — 扫描 Phase 2 新发现 API 并补测")
            supp_started = time.time()
            async for supp_evt in run_supplemental_test(session):
                etype = supp_evt.get("type", "")
                if etype == "info":
                    yield session._event("system", f"[补测] {supp_evt.get('msg', '')}")
                elif etype == "warn":
                    yield session._event("system", f"[补测] ⚠️ {supp_evt.get('msg', '')}")
                elif etype == "error":
                    yield session._event("system", f"[补测] ❌ {supp_evt.get('msg', '')}")
                elif etype == "worker_event":
                    inner = supp_evt.get("evt", {})
                    inner_type = inner.get("type", "")
                    wid = inner.get("worker", "supp?")
                    if inner_type == "worker_tool":
                        tb = inner.get("tool_brief", inner.get("tool", ""))
                        tf = inner.get("tool_full", inner.get("tool", ""))
                        feat = inner.get("feature", "")[:12]
                        yield session._event("tool_call",
                            f"[{wid}/{feat}] {tb}",
                            full=f"[{wid}/{inner.get('feature', '')}] {tf}")
                    elif inner_type == "worker_message":
                        yield session._event("system",
                            f"[{wid}] {inner.get('content', '')}")
                    elif inner_type == "worker_done":
                        yield session._event("system",
                            f"✅ 补测 Agent [{wid}] 完成: {inner.get('summary', '')}")
                    elif inner_type == "worker_error":
                        yield session._event("system",
                            f"❌ 补测 Agent [{wid}] 出错: {inner.get('error', '')[:200]}")
                elif etype == "done":
                    s = supp_evt.get("summary", {}) or {}
                    session._supplemental_summary = s
                    elapsed = s.get("elapsed", time.time() - supp_started)
                    if s.get("error"):
                        yield session._event("system",
                            f"⚠️ Phase 2.55 补测完成（含异常）: 耗时 {elapsed:.1f}s, "
                            f"错误原因: {s['error']}")
                    else:
                        yield session._event("system",
                            f"✅ Phase 2.55 补测完成 (耗时 {elapsed:.1f}s):\n"
                            f"  - 扫描发现新 API: {s.get('discovered', 0)} 个\n"
                            f"  - 新建 feature: {s.get('new_features', 0)} 个 "
                            f"(挂到现有 feature: {s.get('attached_features', 0)} 个)\n"
                            f"  - 已测试: {s.get('tested_features', 0)} 个 "
                            f"(跳过: {s.get('skipped_features', 0)} 个)")
        except Exception as e:
            log.warning("Phase 2.55 supplemental crashed: %s", e, exc_info=True)
            yield session._event("system",
                f"⚠️ Phase 2.55 异常（{type(e).__name__}: {str(e)[:200]}）\n"
                f"  原因: 补测 Agent 启动失败，不影响后续 Phase 2.6/3")

    # ★ P2-A: FAST 模式本地规则版补测（不依赖 LLM，用 FastScanner 补覆盖缺口）
    elif session.sitemap and _fast_mode:
        try:
            from core.supplemental_test_agent import run_supplemental_test_local
            yield session._event("phase",
                "Phase 2.55: 本地规则补测 — 扫描新发现 API 并用 FastScanner 测试")
            supp_started = time.time()
            async for supp_evt in run_supplemental_test_local(session):
                etype = supp_evt.get("type", "")
                if etype == "info":
                    yield session._event("system", f"[补测] {supp_evt.get('msg', '')}")
                elif etype == "warn":
                    yield session._event("system", f"[补测] ⚠️ {supp_evt.get('msg', '')}")
                elif etype == "error":
                    yield session._event("system", f"[补测] ❌ {supp_evt.get('msg', '')}")
                elif etype == "done":
                    s = supp_evt.get("summary", {})
                    session._supplemental_summary = s
                    supp_elapsed = s.get("elapsed", time.time() - supp_started)
                    if s.get("error") or s.get("warning"):
                        _alert = s.get("error") or s.get("warning")
                        yield session._event("system",
                            f"⚠️ Phase 2.55 本地补测完成（含提示，耗时 {supp_elapsed:.1f}s）:\n"
                            f"  - 原因: {_alert}\n"
                            f"  - 发现新 API: {s.get('discovered', 0)} 个\n"
                            f"  - 新建 feature: {s.get('new_features', 0)} 个\n"
                            f"  - 测试 feature: {s.get('tested_features', 0)} 个\n"
                            f"  - 发现漏洞: {s.get('vulns_found', 0)} 个")
                    else:
                        yield session._event("system",
                            f"✅ Phase 2.55 本地补测完成 (耗时 {supp_elapsed:.1f}s):\n"
                            f"  - 发现新 API: {s.get('discovered', 0)} 个\n"
                            f"  - 新建 feature: {s.get('new_features', 0)} 个\n"
                            f"  - 测试 feature: {s.get('tested_features', 0)} 个\n"
                            f"  - 发现漏洞: {s.get('vulns_found', 0)} 个")
        except Exception as e:
            log.warning("Phase 2.55 local supplemental crashed: %s", e, exc_info=True)
            yield session._event("system",
                f"⚠️ Phase 2.55 本地补测异常（{type(e).__name__}: {str(e)[:200]}）\n"
                f"  不影响后续阶段")

    # ★ Phase 2.6: 漏洞危害验证 (SRC/赏金平台审核员视角)
    # ★ FAST 模式跳过危害验证（validate_harm 依赖 LLM）
    if session.sitemap and not _fast_mode:
        try:
            from core.harm_validation import validate_harm
            yield session._event("phase",
                "Phase 2.6: 漏洞危害验证 — 专业安全人员视角二次研判 + 真实 PoC 复现")
            hv_started = time.time()
            hv_result = await validate_harm(
                sitemap=session.sitemap,
                llm=session.llm,
                timeout=600.0,  # 带工具的多轮调用更耗时，给 10 分钟
                tool_executor=getattr(session, "tool_executor", None),
                max_rounds=8,
            )
            session.sitemap.harm_validation = hv_result
            try:
                session.sitemap.save()
            except OSError as e:
                log.warning("Phase 2.6 sitemap save 失败: %s", e)

            hv_status = hv_result.get("status")
            if hv_status == "ok":
                stats = hv_result.get("stats", {}) or {}
                hv_elapsed = time.time() - hv_started
                yield session._event("system",
                    f"✅ Phase 2.6 危害验证完成 (耗时 {hv_elapsed:.1f}s):\n"
                    f"  - 接受 (达到收录标准): {stats.get('accepted', 0)} 个\n"
                    f"  - 边缘 (需人工复核): {stats.get('borderline', 0)} 个\n"
                    f"  - 拒收 (形式漏洞): {stats.get('rejected', 0)} 个\n"
                    f"  - 详情已写入报告第 5 章节")
                summary = hv_result.get("summary", "")
                if summary:
                    yield session._event("system", f"📝 审核员总评: {summary[:300]}")
            elif hv_status == "no_vulns":
                yield session._event("system", "ℹ️ 无已发现漏洞,跳过危害验证")
            else:
                err = hv_result.get("error", "未知")
                yield session._event("system",
                    f"⚠️ Phase 2.6 危害验证失败 ({hv_status}): {err[:200]}\n"
                    f"  不影响主报告,只是缺少 SRC 收录裁决")
        except Exception as e:
            log.warning("Phase 2.6 harm validation crashed: %s", e)
            yield session._event("system",
                f"⚠️ Phase 2.6 异常: {str(e)[:200]}")

    session.phase = "report"
    # 持久化扫描完成状态
    from core.scan_store import finish_scan as _finish_scan, upsert_vuln
    _finish_scan(session.task_id, metrics=metrics.snapshot())
    # 同步漏洞到 scan_store
    if session.sitemap:
        for fp in session.sitemap.features.values():
            for c in fp.checklist:
                if c.result and c.result.name in ("VULNERABLE", "CONFIRMED"):
                    upsert_vuln(
                        session.task_id, fp.id, c.vuln_type,
                        feature_name=fp.name, severity=getattr(c, "severity", "medium"),
                        url=", ".join(fp.related_apis[:3]) if fp.related_apis else "",
                        detail=(c.detail or "")[:500],
                    )
    cov = session.sitemap.get_coverage() if session.sitemap else {"coverage": 0, "vulns": 0}

    # ★ 记录 Phase 状态与终止原因到 sitemap
    if session.sitemap:

        # ★ 收集补测状态，让终止原因体现补测是否成功
        supp_status = getattr(session, "_supplemental_summary", None) or {}
        supp_info = ""
        if supp_status:
            supp_err = supp_status.get("error") or supp_status.get("warning")
            if supp_err:
                supp_info = f" 补测异常: {str(supp_err)[:80]};"
            else:
                supp_disc = supp_status.get("discovered", 0)
                supp_info = f" 补测发现 {supp_disc} 个新 API;"

        # ★ 收集 harm_validation 状态
        hv_result = getattr(session.sitemap, "harm_validation", None) or {}
        hv_info = ""
        if hv_result:
            candidates = len(hv_result.get("vulnerabilities", []) or [])
            confirmed = sum(1 for v in (hv_result.get("verdicts", []) or [])
                           if isinstance(v, dict) and v.get("verdict") == "accepted")
            rejected = sum(1 for v in (hv_result.get("verdicts", []) or [])
                          if isinstance(v, dict) and v.get("verdict") == "rejected")
            hv_info = f" 危害验证: {candidates} 候选→{confirmed} 确认/{rejected} 拒收;"

        # ★ 收集未测项数量
        checks_total = cov.get("checks_total", 0)
        checks_done = cov.get("checks_done", 0)
        pending = checks_total - checks_done
        session.sitemap.phase_status = "partial" if pending > 0 else "completed"

        scan_issue = getattr(session, "_scan_health_issue", None) or {}
        traffic_health = getattr(session, "_traffic_health", None) or {}
        has_assets = bool(getattr(session.sitemap, "features", None) or getattr(session.sitemap, "apis", None))

        if not cov.get("vulns", 0) and not cov.get("checks_done", 0) and not has_assets:
            if scan_issue.get("type") == "zero_assets_after_crawl":
                target_flows = (traffic_health or scan_issue.get("traffic") or {}).get("target_flows", 0)
                flow_count = (traffic_health or scan_issue.get("traffic") or {}).get("flow_count", 0)
                problem = (traffic_health or scan_issue.get("traffic") or {}).get("problem", "")
                traffic_hint = (
                    f"抓包文件共 {flow_count} 条流量，但目标站点流量 {target_flows} 条"
                    if problem == "target_flow_zero"
                    else "流量文件不存在或抓包健康检查失败"
                )
                session.sitemap.termination_reason = (
                    "扫描未产生有效结果：Phase 0 未抓到页面、API 或有效点击，"
                    f"{traffic_hint}。可能原因是目标页面加载超时、浏览器代理/mitmproxy 未生效、"
                    "或当前硬超时过短；未进入有效功能点测试。"
                )
            else:
                session.sitemap.termination_reason = (
                    "扫描未产生有效结果：未发现可测试的功能点或 API，"
                    "FastScanner 未发现匹配目标，报告仅展示空结果。"
                )
        elif cov.get("vulns", 0) == 0:
            pending_str = f" {pending} 项未测;" if pending > 0 else ""
            # ★ P1-2: 低覆盖时不再称"扫描完成"，避免误导
            _rc = session._compute_real_completion() if hasattr(session, "_compute_real_completion") else {}
            _real_rate = _rc.get("real_rate", 0.0)
            _valid_rate = _rc.get("validated_rate", 0.0)
            if _real_rate < 10.0:
                _status_prefix = f"部分完成 / 覆盖不足（真实完成率 {_real_rate}%）"
            elif _valid_rate < 10.0 and _rc.get("speculative_total", 0) > 0:
                _status_prefix = f"部分完成（已确认项 {_valid_rate}%，另有推测项 {_rc.get('speculative_total', 0)} 项）"
            else:
                _status_prefix = "扫描完成"
            session.sitemap.termination_reason = (
                f"{_status_prefix}：{checks_done}/{checks_total} 项测试完成，"
                f"未发现漏洞。{pending_str}{supp_info}{hv_info}"
            ).strip()
        else:
            pending_str = f" {pending} 项未测;" if pending > 0 else ""
            # ★ P1-2: 有漏洞但低覆盖时也标注
            _rc = session._compute_real_completion() if hasattr(session, "_compute_real_completion") else {}
            _real_rate = _rc.get("real_rate", 0.0)
            _status_prefix = "部分完成 / 覆盖不足" if _real_rate < 10.0 else "扫描完成"
            session.sitemap.termination_reason = (
                f"{_status_prefix}：{cov.get('vulns', 0)} 个漏洞已确认。"
                f"{pending_str}{supp_info}{hv_info}"
            ).strip()
        try:
            session.sitemap.save()
        except OSError:
            pass

    yield session._event("phase", f"Phase 3: 汇总报告 — 覆盖率 {cov['coverage']}%, 发现 {cov['vulns']} 个漏洞")
    session.current_context = session._new_context_for_phase(PHASE_REPORT_PROMPT)
    session.current_context.add_user(
        "所有功能点已测试完成，请生成最终渗透测试报告。\n"
        "使用 note_add type=result 记录完整报告，然后调用 done 结束。"
    )
