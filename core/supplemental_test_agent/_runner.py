"""SupplementalTestAgent — 主入口与本地规则版补测。

包含 run_supplemental_test（Phase 2.55 LLM 版补测主流程）、
_run_worker_with_timeout（worker 超时控制）、run_supplemental_test_local
（FAST 模式本地规则版补测，不依赖 LLM）。
从原 core/supplemental_test_agent.py 抽取，行为不变。
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, AsyncGenerator

from core.log import get_logger

from ._constants import FEATURES_PER_WORKER, PER_API_TIMEOUT_S, TOTAL_BUDGET_S
from ._discovery import discover_apis_from_dirscan, discover_new_apis_from_flows
from ._attach import attach_apis_to_sitemap, _normalize_related_api_for_scan

log = get_logger("supplemental")


# ============================================================
# 主入口：运行 Phase 2.55 补测 Agent
# ============================================================

async def run_supplemental_test(
    session: "Any",
) -> AsyncGenerator[dict, None]:
    """运行 Phase 2.55 补测 Agent。

    yield 字典格式的事件，由调用方（parallel.py）转成 session._event 推送给前端。

    事件类型：
      - {"type": "info", "msg": ...}        — 一般信息
      - {"type": "warn", "msg": ...}        — 警告（继续）
      - {"type": "error", "msg": ...}       — 失败但已兜底（跳过补测）
      - {"type": "worker_event", "evt": ..} — 子 Agent 产生的事件（透传给前端）
      - {"type": "done", "summary": {...}}  — 全部完成
    """
    started = time.time()
    summary: dict[str, Any] = {
        "discovered": 0,
        "new_features": 0,
        "attached_features": 0,
        "tested_features": 0,
        "skipped_features": 0,
        "elapsed": 0.0,
        "error": None,
    }

    try:
        # ---- Step 1: 获取关键参数 ----
        sitemap = getattr(session, "sitemap", None)
        if sitemap is None:
            yield {"type": "error", "msg": "sitemap 未初始化，跳过补测"}
            summary["error"] = "sitemap 未初始化"
            yield {"type": "done", "summary": summary}
            return

        target_url = getattr(session, "target_url", "") or ""
        phase2_started_at = getattr(session, "_phase2_started_at", 0.0) or 0.0
        if phase2_started_at <= 0:
            yield {
                "type": "warn",
                "msg": "未记录 Phase 2 起点时间戳，将扫描全部 flows.jsonl（可能包含 Phase 0/1 流量）",
            }
            phase2_started_at = 0.0

        # ---- Step 2: 扫描新 API ----
        try:
            # ★ 2026-05-29: 传入 task_id 过滤，避免读到其他并发任务的流量
            current_task_id = getattr(session, "task_id", None) or ""
            apis, scan_stats = discover_new_apis_from_flows(
                sitemap=sitemap,
                target_url=target_url,
                phase2_started_at=phase2_started_at,
                task_id=current_task_id or None,
            )
        except Exception as e:
            yield {
                "type": "error",
                "msg": f"扫描 flows.jsonl 失败（{type(e).__name__}: {str(e)[:120]}），跳过补测",
            }
            summary["error"] = f"scan_failed: {e}"
            yield {"type": "done", "summary": summary}
            return

        summary["discovered"] = len(apis)
        summary["scan_stats"] = scan_stats

        # ★ 检测补测扫描阶段是否发生异常（IO 错误或非预期错误）
        # 即使返回了部分结果，也要把错误记录到 summary，供下游报告体现
        if scan_stats.get("io_error") or scan_stats.get("unexpected_error"):
            err_msg = scan_stats.get("unexpected_error") or scan_stats.get("io_error")
            summary["warning"] = f"flows_scan_partial: {err_msg}"
            yield {
                "type": "warn",
                "msg": f"扫描 flows.jsonl 过程中发生异常（已收集部分结果）: {err_msg[:120]}",
            }

        yield {
            "type": "info",
            "msg": (
                f"扫描完成: 共 {scan_stats['total_scanned']} 条流量, "
                f"保留 {scan_stats['kept']} 个新 API "
                f"(scope外 {scan_stats['out_of_scope']}, 第三方 {scan_stats['third_party']}, "
                f"非2xx {scan_stats['not_2xx']}, 已知 {scan_stats['already_known']}, "
                f"非业务 {scan_stats['non_business']}, 重复 {scan_stats['duplicate']})"
            ),
        }

        # ★ SEC-5: 补测告警语义修正 — 流量被大量过滤但 total>0 时不应用 ✅ 伪装正常
        # zhenduan 诊断②：total_scanned>0 但 kept=0 且非2xx 占比高 → 应输出 ⚠️ 而非 ✅
        if scan_stats['total_scanned'] > 0 and scan_stats['kept'] == 0:
            _sec5_total = scan_stats['total_scanned']
            _sec5_not2xx = scan_stats['not_2xx']
            _sec5_not2xx_ratio = _sec5_not2xx / _sec5_total if _sec5_total else 0
            if _sec5_not2xx_ratio > 0.5:
                yield {
                    "type": "warn",
                    "msg": (
                        f"⚠️ 流量大量被过滤: 非2xx 占比 {round(_sec5_not2xx_ratio*100, 1)}% "
                        f"({_sec5_not2xx}/{_sec5_total})，可能目标对未知路径返回错误状态码，"
                        f"建议检查指纹基线或补测 Agent 的过滤策略"
                    ),
                }
            else:
                yield {
                    "type": "warn",
                    "msg": (
                        f"⚠️ 抓到 {_sec5_total} 条流量但 0 新 API，"
                        f"可能登录接口已由 Phase 2 覆盖，或检查代理是否抓到登录 POST"
                    ),
                }

        # ---- Step 2b: 主动目录爆破发现新 API（不依赖 mitmproxy 流量） ----
        auth_headers = {}
        cookies = getattr(session, "_inject_cookies", "") or ""
        if cookies:
            auth_headers["Cookie"] = cookies
        inject_headers = getattr(session, "_inject_headers", {}) or {}
        auth_headers.update(inject_headers)

        try:
            dirscan_apis, dirscan_stats = await discover_apis_from_dirscan(
                sitemap=sitemap,
                target_url=target_url,
                auth_headers=auth_headers or None,
                existing_apis=apis,
            )
            summary["dirscan_stats"] = dirscan_stats

            if dirscan_apis:
                yield {
                    "type": "info",
                    "msg": (
                        f"目录爆破发现 {len(dirscan_apis)} 个新 API "
                        f"(请求 {dirscan_stats.get('dirscan_total', 0)}, "
                        f"敏感泄露 {dirscan_stats.get('dirscan_sensitive', 0)})"
                    ),
                }
                apis.extend(dirscan_apis)
                summary["discovered"] = len(apis)
        except Exception as e:
            yield {"type": "warn", "msg": f"目录爆破失败（非致命）: {type(e).__name__}: {str(e)[:120]}"}

        if not apis:
            # ★ 区分"真的没有新 API"和"因异常导致结果为空"
            if scan_stats.get("io_error") or scan_stats.get("unexpected_error"):
                err_msg = scan_stats.get("unexpected_error") or scan_stats.get("io_error")
                yield {
                    "type": "error",
                    "msg": f"扫描 flows.jsonl 异常导致未发现新 API，Phase 2.55 补测失败: {err_msg[:120]}",
                }
                summary["error"] = f"flows_scan_failed: {err_msg}"
            else:
                yield {"type": "info", "msg": "未发现需要补测的新 API，跳过 Phase 2.55"}
            summary["elapsed"] = time.time() - started
            yield {"type": "done", "summary": summary}
            return

        # ---- Step 3: 挂载到 sitemap ----
        try:
            new_features, attached_features = attach_apis_to_sitemap(sitemap, apis)
        except Exception as e:
            yield {
                "type": "error",
                "msg": f"挂载新 API 到 sitemap 失败（{type(e).__name__}: {str(e)[:120]}），跳过补测",
            }
            summary["error"] = f"attach_failed: {e}"
            yield {"type": "done", "summary": summary}
            return

        summary["new_features"] = len(new_features)
        summary["attached_features"] = len(attached_features)

        yield {
            "type": "info",
            "msg": (
                f"挂载完成: 新建 {len(new_features)} 个 feature, "
                f"挂到现有 feature {len(attached_features)} 个 API"
            ),
        }

        # ---- Step 4: 整理待测 feature 列表 ----
        # 新建的 feature 一定要测；挂到现有 feature 的 API 不重新测（避免重复）
        features_to_test = [fp for fp in new_features if fp.checklist]

        if not features_to_test:
            yield {
                "type": "info",
                "msg": "所有新 API 都挂到了现有 feature 上（或新 feature 无 checklist），无需启动补测 Agent",
            }
            summary["elapsed"] = time.time() - started
            yield {"type": "done", "summary": summary}
            return

        yield {
            "type": "info",
            "msg": f"准备启动补测 Agent 测试 {len(features_to_test)} 个新 feature",
        }

        # ---- Step 5: 启动 WorkerAgent 进行测试 ----
        # 按 FEATURES_PER_WORKER 分组，每组一个 worker
        try:
            from core.worker_agent import WorkerAgent
            from core.parallel import get_session_info
        except Exception as e:
            yield {
                "type": "error",
                "msg": f"导入 WorkerAgent 失败（{type(e).__name__}: {e}），跳过补测",
            }
            summary["error"] = f"import_failed: {e}"
            yield {"type": "done", "summary": summary}
            return

        try:
            session_info = await get_session_info()
        except Exception as e:
            yield {
                "type": "warn",
                "msg": f"获取 session_info 失败（{type(e).__name__}），使用空配置继续",
            }
            session_info = {}

        # 分组
        groups: list[list] = []
        for i in range(0, len(features_to_test), FEATURES_PER_WORKER):
            groups.append(features_to_test[i:i + FEATURES_PER_WORKER])

        # 标记测试开始
        for fp in features_to_test:
            try:
                sitemap.start_test(fp.id)
            except Exception:
                pass

        # 总预算控制
        budget_deadline = started + TOTAL_BUDGET_S

        for idx, group in enumerate(groups):
            remaining = budget_deadline - time.time()
            if remaining < 30:
                # 时间不够了，剩余 feature 标记为 skipped
                skipped = sum(len(g) for g in groups[idx:])
                summary["skipped_features"] = skipped
                yield {
                    "type": "warn",
                    "msg": f"⏱️ 补测总预算 {TOTAL_BUDGET_S/60:.0f}min 即将耗尽，跳过剩余 {skipped} 个 feature",
                }
                for g in groups[idx:]:
                    for fp in g:
                        try:
                            fp.test_status = sitemap.features[fp.id].test_status
                            from core.sitemap import TestStatus
                            sitemap.features[fp.id].test_status = TestStatus.SKIPPED
                        except Exception:
                            pass
                break

            group_name = f"补测组_{idx+1}"
            try:
                worker = WorkerAgent(
                    worker_id=f"supp{idx+1}",
                    llm=session.llm,
                    features=group,
                    group_name=group_name,
                    sitemap=sitemap,
                    session_info=session_info,
                )
            except Exception as e:
                yield {
                    "type": "warn",
                    "msg": f"创建补测 Agent {group_name} 失败（{type(e).__name__}: {str(e)[:100]}），跳过该组",
                }
                summary["skipped_features"] += len(group)
                continue

            yield {
                "type": "info",
                "msg": f"🚀 启动补测 Agent [{worker.worker_id}] 测试 {len(group)} 个新 feature（{group_name}）",
            }

            # 单组超时 = 单 API 预算 × feature 数
            group_timeout = min(
                PER_API_TIMEOUT_S * len(group) * 3,  # 给 worker 多轮工具调用预留时间
                remaining,
            )

            try:
                async for evt in _run_worker_with_timeout(worker, group_timeout):
                    # 透传给前端
                    yield {"type": "worker_event", "evt": evt}
                summary["tested_features"] += len(group)
            except asyncio.TimeoutError:
                yield {
                    "type": "warn",
                    "msg": f"⏱️ 补测组 {group_name} 超时（{group_timeout:.0f}s），标记为已部分测试",
                }
                summary["tested_features"] += len(group)  # 部分测过也算
            except Exception as e:
                yield {
                    "type": "warn",
                    "msg": f"⚠️ 补测组 {group_name} 异常（{type(e).__name__}: {str(e)[:120]}），跳过该组",
                }
                summary["skipped_features"] += len(group)
                continue

        summary["elapsed"] = time.time() - started
        yield {"type": "done", "summary": summary}

    except Exception as e:
        # 终极兜底：任何异常都不能影响 Phase 2.6
        log.warning("supplemental: 顶层异常: %s", e, exc_info=True)
        summary["error"] = f"top_level: {type(e).__name__}: {str(e)[:200]}"
        summary["elapsed"] = time.time() - started
        yield {
            "type": "error",
            "msg": f"补测 Agent 顶层异常（{type(e).__name__}: {str(e)[:160]}），已跳过",
        }
        yield {"type": "done", "summary": summary}


async def _run_worker_with_timeout(
    worker,
    timeout_s: float,
) -> AsyncGenerator[dict, None]:
    """运行 worker 并加超时控制。"""
    queue: asyncio.Queue = asyncio.Queue()
    done_flag = asyncio.Event()

    async def _drain():
        try:
            async for evt in worker.run():
                await queue.put(evt)
        except Exception as e:
            await queue.put({"type": "worker_error", "error": str(e)})
        finally:
            done_flag.set()

    drain_task = asyncio.create_task(_drain())
    deadline = asyncio.get_event_loop().time() + timeout_s

    try:
        while not done_flag.is_set():
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            try:
                evt = await asyncio.wait_for(queue.get(), timeout=min(remaining, 5.0))
                yield evt
            except asyncio.TimeoutError:
                if asyncio.get_event_loop().time() >= deadline:
                    raise
                continue
        # done 后 drain 队列里残留事件
        while not queue.empty():
            yield queue.get_nowait()
    finally:
        if not drain_task.done():
            drain_task.cancel()
            try:
                await drain_task
            except (asyncio.CancelledError, Exception):
                pass


# ============================================================
# P2-A: 本地规则版补测（FAST 模式专用，不依赖 LLM）
# ============================================================

async def run_supplemental_test_local(
    session: "Any",
) -> AsyncGenerator[dict, None]:
    """Phase 2.55 本地规则版补测（FAST 模式专用）。

    与 run_supplemental_test 的区别：
    - L1 发现新 API：相同（纯本地规则）
    - L2 挂载到 sitemap：相同（纯本地规则）
    - L3 测试新 feature：用 FastScanner 替代 WorkerAgent（不依赖 LLM）

    这样 FAST 模式也能覆盖爬取后新发现的 API，不增加 LLM 成本。
    """
    started = time.time()
    summary: dict[str, Any] = {
        "discovered": 0,
        "new_features": 0,
        "attached_features": 0,
        "tested_features": 0,
        "vulns_found": 0,
        "elapsed": 0.0,
        "error": None,
        "mode": "local",
    }

    try:
        sitemap = getattr(session, "sitemap", None)
        if sitemap is None:
            yield {"type": "error", "msg": "sitemap 未初始化，跳过补测"}
            summary["error"] = "sitemap 未初始化"
            yield {"type": "done", "summary": summary}
            return

        target_url = getattr(session, "target_url", "") or ""
        phase2_started_at = getattr(session, "_phase2_started_at", 0.0) or 0.0

        # ---- L1: 扫描新 API（纯本地规则） ----
        current_task_id = getattr(session, "task_id", None) or ""
        apis, scan_stats = discover_new_apis_from_flows(
            sitemap=sitemap,
            target_url=target_url,
            phase2_started_at=phase2_started_at,
            task_id=current_task_id or None,
        )

        summary["discovered"] = len(apis)
        summary["scan_stats"] = scan_stats

        if scan_stats.get("flow_file_missing"):
            summary["error"] = f"flow_file_missing: {scan_stats.get('flow_file', '')}"
            yield {
                "type": "error",
                "msg": f"[本地补测] flows.jsonl 不存在: {scan_stats.get('flow_file', '')}",
            }
        elif scan_stats.get("io_error") or scan_stats.get("unexpected_error"):
            err_msg = scan_stats.get("unexpected_error") or scan_stats.get("io_error")
            summary["warning"] = f"flows_scan_partial: {err_msg}"
            yield {
                "type": "warn",
                "msg": f"[本地补测] 扫描 flows.jsonl 过程中发生异常（已收集部分结果）: {err_msg[:120]}",
            }

        yield {
            "type": "info",
            "msg": (
                f"[本地补测] 扫描完成: {scan_stats.get('total_scanned', 0)} 条流量, "
                f"保留 {len(apis)} 个新 API "
                f"(早于Phase2 {scan_stats.get('before_phase2', 0)}, "
                f"其他任务 {scan_stats.get('other_task', 0)}, "
                f"scope外 {scan_stats.get('out_of_scope', 0)}, "
                f"第三方 {scan_stats.get('third_party', 0)}, "
                f"非2xx {scan_stats.get('not_2xx', 0)}, "
                f"已知 {scan_stats.get('already_known', 0)}, "
                f"非业务 {scan_stats.get('non_business', 0)}, "
                f"重复 {scan_stats.get('duplicate', 0)})"
            ),
        }
        if scan_stats.get("total_scanned", 0) == 0 and not scan_stats.get("flow_file_missing"):
            summary["warning"] = "no_phase2_flows"
            yield {
                "type": "warn",
                "msg": (
                    "[本地补测] 没有可分析的新流量（flows.jsonl 为空），"
                    "将启动主动目录爆破补充发现。"
                ),
            }

        # ---- L1b: 主动目录爆破发现新 API（不依赖 mitmproxy 流量） ----
        auth_headers = {}
        cookies = getattr(session, "_inject_cookies", "") or ""
        if cookies:
            auth_headers["Cookie"] = cookies
        inject_headers = getattr(session, "_inject_headers", {}) or {}
        auth_headers.update(inject_headers)

        dirscan_apis, dirscan_stats = await discover_apis_from_dirscan(
            sitemap=sitemap,
            target_url=target_url,
            auth_headers=auth_headers or None,
            existing_apis=apis,
        )
        summary["dirscan_stats"] = dirscan_stats

        if dirscan_apis:
            yield {
                "type": "info",
                "msg": (
                    f"[本地补测] 目录爆破发现 {len(dirscan_apis)} 个新 API "
                    f"(请求 {dirscan_stats.get('dirscan_total', 0)}, "
                    f"敏感泄露 {dirscan_stats.get('dirscan_sensitive', 0)}, "
                    f"已知 {dirscan_stats.get('dirscan_already_known', 0)})"
                ),
            }
            apis.extend(dirscan_apis)
            summary["discovered"] = len(apis)
        elif dirscan_stats.get("dirscan_total", 0) > 0:
            yield {
                "type": "info",
                "msg": (
                    f"[本地补测] 目录爆破完成: {dirscan_stats.get('dirscan_total', 0)} 次请求, "
                    f"未发现新 API（已知 {dirscan_stats.get('dirscan_already_known', 0)}, "
                    f"敏感 {dirscan_stats.get('dirscan_sensitive', 0)}）"
                ),
            }

        if not apis:
            if summary.get("error"):
                yield {"type": "error", "msg": "[本地补测] 未获得可补测 API，补测失败但不阻塞后续阶段"}
            elif scan_stats.get("io_error") or scan_stats.get("unexpected_error"):
                err_msg = scan_stats.get("unexpected_error") or scan_stats.get("io_error")
                summary["error"] = f"flows_scan_failed: {err_msg}"
                yield {
                    "type": "error",
                    "msg": f"[本地补测] 扫描异常导致未发现新 API: {err_msg[:120]}",
                }
            else:
                yield {"type": "info", "msg": "[本地补测] 未发现新 API，跳过"}
            summary["elapsed"] = time.time() - started
            yield {"type": "done", "summary": summary}
            return

        # ---- L2: 挂载到 sitemap（纯本地规则） ----
        new_features, attached_features = attach_apis_to_sitemap(sitemap, apis)
        summary["new_features"] = len(new_features)
        summary["attached_features"] = len(attached_features)

        yield {
            "type": "info",
            "msg": (
                f"[本地补测] 挂载完成: 新建 {len(new_features)} 个 feature, "
                f"挂到现有 feature {len(attached_features)} 个 API"
            ),
        }

        features_to_test = [fp for fp in new_features if fp.checklist]
        if not features_to_test:
            yield {"type": "info", "msg": "[本地补测] 无需测试的新 feature"}
            summary["elapsed"] = time.time() - started
            yield {"type": "done", "summary": summary}
            return

        # ---- L3: FastScanner 本地规则测试（替代 WorkerAgent） ----
        from core.fast_scanner import FastScanner, ScanTarget, convert_findings_to_checklist_results
        from core.sitemap import CheckResult

        # 收集认证头
        auth_headers = {}
        cookies = getattr(session, "_inject_cookies", "") or ""
        if cookies:
            auth_headers["Cookie"] = cookies
        inject_headers = getattr(session, "_inject_headers", {}) or {}
        auth_headers.update(inject_headers)

        # ★ 共享一个 FastScanner 实例，使 WAF/超时封禁状态跨 URL/feature 持续生效。
        # 原逻辑每次 quick_scan() 创建新 scanner，_waf_blocked 每个 URL 重置，
        # 导致 WAF 已封禁后下一个 URL 仍从头触发封禁（日志中 "WAF 已封禁" 重复出现）。
        scanner = FastScanner(max_workers=5)
        waf_blocked_global = False

        total_vulns = 0
        for fp in features_to_test:
            # 收集该 feature 的所有 API URL
            api_targets: list[tuple[str, str]] = []
            for api_path in getattr(fp, "related_apis", []) or []:
                normalized = _normalize_related_api_for_scan(api_path, target_url)
                if normalized:
                    api_targets.append(normalized)

            if not api_targets:
                yield {
                    "type": "warn",
                    "msg": f"[本地补测] {fp.name} 没有可解析的 API URL，跳过",
                }
                continue

            # ★ 截断日志：超 10 个 URL 时提示被跳过的数量（原逻辑静默截断）
            scan_urls = api_targets[:10]
            if len(api_targets) > 10:
                yield {
                    "type": "warn",
                    "msg": (
                        f"[本地补测] {fp.name} 有 {len(api_targets)} 个 URL，"
                        f"超过单 feature 上限 10，仅测试前 10 个，跳过 {len(api_targets) - 10} 个"
                    ),
                }

            yield {
                "type": "info",
                "msg": f"[本地补测] FastScanner 测试 {fp.name}: {len(scan_urls)} 个 URL",
            }

            # 对每个 URL 跑 FastScanner（共享 scanner 实例）
            for method, url in scan_urls:
                # ★ WAF/超时全局封禁后跳过剩余 URL
                if waf_blocked_global:
                    yield {
                        "type": "warn",
                        "msg": f"[本地补测] WAF/超时已封禁，跳过 {fp.name} 剩余 URL",
                    }
                    break

                try:
                    target = ScanTarget(
                        url=url,
                        method=method,
                        auth_headers=auth_headers or {},
                    )
                    result = await scanner.scan_target(target)
                    # ★ 检查本次扫描是否触发 WAF 或超时熔断
                    scan_stats = scanner.get_accumulated_stats()
                    if scan_stats.get("waf_blocked") or scan_stats.get("timeout_blocked"):
                        reason = "WAF 封禁" if scan_stats.get("waf_blocked") else "超时熔断"
                        waf_blocked_global = True
                        yield {
                            "type": "warn",
                            "msg": f"[本地补测] {url} 触发{reason}，后续 URL 将被跳过",
                        }
                    if result.vuln_count > 0:
                        total_vulns += result.vuln_count
                        # 回写 checklist
                        cl_results = convert_findings_to_checklist_results(result.findings)
                        for finding in cl_results:
                            vuln_type = finding.get("vuln_type", "")
                            # 匹配 checklist 中的对应项
                            for c in fp.checklist:
                                if c.result == CheckResult.PENDING and vuln_type in c.vuln_type:
                                    c.result = CheckResult.VULN
                                    c.detail = finding.get("detail", "")
                                    c.evidence = finding.get("evidence", "")
                                    c.fix_suggestion = finding.get("fix_suggestion", "")
                                    c.source = "fast_scanner_supplemental"
                                    break
                except Exception as e:
                    log.warning("[本地补测] FastScanner 扫描 %s 失败: %s", url, e)

            summary["tested_features"] += 1

        # 清理共享 scanner 的 HTTP 客户端
        try:
            await scanner._close()
        except Exception:
            pass

        summary["vulns_found"] = total_vulns
        summary["elapsed"] = time.time() - started

        if total_vulns > 0:
            yield {
                "type": "info",
                "msg": f"[本地补测] 完成: 测试 {summary['tested_features']} 个 feature, "
                       f"发现 {total_vulns} 个漏洞",
            }
        else:
            yield {
                "type": "info",
                "msg": f"[本地补测] 完成: 测试 {summary['tested_features']} 个 feature, 未发现漏洞",
            }

        # 保存 sitemap
        try:
            sitemap.save()
        except Exception:
            pass

        yield {"type": "done", "summary": summary}

    except Exception as e:
        log.warning("supplemental_local: 顶层异常: %s", e, exc_info=True)
        summary["error"] = f"top_level: {type(e).__name__}: {str(e)[:200]}"
        summary["elapsed"] = time.time() - started
        yield {
            "type": "error",
            "msg": f"[本地补测] 异常（{type(e).__name__}: {str(e)[:160]}），已跳过",
        }
        yield {"type": "done", "summary": summary}
