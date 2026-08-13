"""
orchestrator — Phase 2 顶层调度

- run_parallel_test: Phase 2 核心，并行调度子 Agent + 主 Agent
- _run_fast_scanner_core: FastScanner 纯异步执行（无 yield，可 create_task）
- _write_fast_scanner_results: FastScanner 结果回写 sitemap
- _run_llm_preparation: LLM 准备阶段（初筛/元分析/智能分组）
- _run_supplementary_test: 覆盖检查新增功能点补测
- start_browser_feature_test: 主 Agent 串行测试浏览器项
- _enter_report_phase: 进入 Phase 3 汇总报告
"""

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


# ============================================================
# mitmproxy 健康检查 + 自动重启
# ============================================================

def _check_mitmproxy_health(port: int | None = None) -> bool:
    """检测 mitmproxy 代理端口是否在监听。

    Returns:
        True 如果端口可连接，False 如果不可连接。
    """
    import socket
    _port = port or int(os.getenv("PROXY_PORT", "18080"))
    try:
        _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _sock.settimeout(1.0)
        _ok = _sock.connect_ex(("127.0.0.1", _port)) == 0
        _sock.close()
        return _ok
    except Exception:
        return False


def _try_restart_mitmproxy(port: int | None = None) -> bool:
    """尝试重启 mitmproxy 代理（在后台启动新的 mitmdump 进程）。

    策略：
    1. 检查端口是否已在监听（可能已自恢复）
    2. 查找 mitmdump 可执行文件
    3. 启动新进程，带 addon 脚本
    4. 轮询等待端口就绪（最多 15 秒）

    Returns:
        True 如果重启成功且端口就绪，False 如果失败。
    """
    import socket
    import subprocess
    import threading
    import sys
    from pathlib import Path as _Path

    _port = port or int(os.getenv("PROXY_PORT", "18080"))

    # 1. 先检查是否已自恢复
    if _check_mitmproxy_health(_port):
        log.info("mitmproxy 代理（端口 %d）已恢复可用", _port)
        return True

    log.warning("mitmproxy 代理（端口 %d）不可用，尝试自动重启...", _port)

    # 2. 查找 mitmdump
    import shutil
    project_dir = _Path(os.getenv("PROJECT_DIR", os.getcwd()))
    addon_path = project_dir / "mcp_servers" / "mitm_addon.py"
    if not addon_path.exists():
        # 打包模式：尝试 bundle 目录
        bundle_dir = _Path(getattr(sys, '_MEIPASS', project_dir))
        addon_path = bundle_dir / "mcp_servers" / "mitm_addon.py"

    # ★ addon 脚本不存在时仍可启动代理（只是没有流量记录功能）
    if not addon_path.exists():
        log.warning("mitmproxy addon 脚本不存在 (%s)，代理仍可启动但流量记录不可用", addon_path)
        addon_arg = None
    else:
        addon_arg = str(addon_path)

    mitmdump_path = None
    candidates = [
        _Path(sys.executable).parent / "mitmdump",
        _Path(sys.executable).parent / "Scripts" / "mitmdump.exe",  # Windows venv
        _Path(sys.executable).parent.parent.parent.parent / "bin" / "mitmdump",
    ]
    try:
        import sysconfig
        scripts_dir = sysconfig.get_path("scripts")
        if scripts_dir:
            candidates.append(_Path(scripts_dir) / "mitmdump")
            if os.name == "nt":
                candidates.append(_Path(scripts_dir) / "mitmdump.exe")
    except Exception:
        pass

    # ★ conda 环境
    conda_prefix = os.getenv("CONDA_PREFIX")
    if conda_prefix:
        if os.name == "nt":
            candidates.append(_Path(conda_prefix) / "Scripts" / "mitmdump.exe")
        else:
            candidates.append(_Path(conda_prefix) / "bin" / "mitmdump")

    for cand in candidates:
        if cand and cand.exists():
            mitmdump_path = cand
            break

    # 构建命令
    base_cmd = ["-p", str(_port), "--set", "stream_large_bodies=10m",
                "--set", "connection_strategy=lazy", "--quiet"]
    if addon_arg:
        base_cmd = ["-s", addon_arg] + base_cmd

    if mitmdump_path:
        mitm_cmd = [str(mitmdump_path)] + base_cmd
    elif shutil.which("mitmdump"):
        mitm_cmd = ["mitmdump"] + base_cmd
    else:
        # ★ 兜底：用 python 调用 mitmdump 入口
        try:
            import mitmproxy as _mitm_check
        except ImportError:
            log.error("mitmproxy 重启失败: 未找到 mitmdump 可执行文件，且 mitmproxy 包未安装")
            return False
        mitm_cmd = [sys.executable, "-c",
                     "from mitmproxy.tools.main import mitmdump; mitmdump()"] + base_cmd
        log.info("mitmproxy 重启: 使用 python -c fallback（mitmdump 可执行文件未找到）")

    # 3. 启动新进程
    try:
        kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.PIPE,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(mitm_cmd, **kwargs)
        log.info("mitmproxy 重启进程已启动 (PID: %d)", proc.pid)
    except FileNotFoundError as e:
        log.error("mitmproxy 重启失败: mitmdump 可执行文件未找到 — %s", e)
        return False
    except PermissionError as e:
        log.error("mitmproxy 重启失败: 权限不足 — %s", e)
        return False
    except Exception as e:
        log.error("mitmproxy 重启失败: %s", e)
        return False

    # ★ 启动 stderr 消费线程（防管道缓冲区满导致进程阻塞）
    _stderr_lines: list[str] = []

    def _drain_stderr(p: subprocess.Popen):
        try:
            for line in iter(p.stderr.readline, b""):
                text = line.decode("utf-8", errors="replace").rstrip()
                if text and len(_stderr_lines) < 50:
                    _stderr_lines.append(text)
        except Exception:
            pass

    _drain_t = threading.Thread(target=_drain_stderr, args=(proc,), daemon=True)
    _drain_t.start()

    # 4. 轮询等待端口就绪（最多 15 秒，原 10 秒不够）
    for attempt in range(15):
        if proc.poll() is not None:
            # 进程已退出
            stderr_out = "\n".join(_stderr_lines[:10]) if _stderr_lines else ""
            log.error("mitmproxy 重启进程已退出 (code=%s): %s", proc.returncode, stderr_out[:500])
            # ★ 诊断
            if stderr_out:
                _sl = stderr_out.lower()
                if "address already in use" in _sl:
                    log.error("  诊断: 端口 %d 被占用，可能有残留 mitmdump 进程", _port)
                elif "no module named" in _sl or "importerror" in _sl:
                    log.error("  诊断: mitmproxy 依赖缺失，请 pip install --force-reinstall mitmproxy")
                elif "permission denied" in _sl:
                    log.error("  诊断: 权限不足，请以管理员身份运行或更换端口")
            return False
        import time as _time
        _time.sleep(1)
        if _check_mitmproxy_health(_port):
            log.info("mitmproxy 重启成功 (PID: %d, 端口: %d)", proc.pid, _port)
            return True

    # ★ 端口未就绪但进程还活着：输出 stderr 辅助诊断
    stderr_snippet = "\n".join(_stderr_lines[:5]) if _stderr_lines else "(无 stderr 输出)"
    log.warning("mitmproxy 重启后 15s 内端口未就绪 (PID=%d)，stderr: %s", proc.pid, stderr_snippet[:300])
    return False


def _check_stuck_workers(
    active_workers: dict[str, asyncio.Task],
    worker_last_event: dict[str, float],
) -> list[str]:
    """检测并取消卡死的 Worker（长时间无事件）。

    返回被取消的 worker_id 列表。
    """
    import time as _time
    now = _time.time()
    stuck_ids = []
    for wid, task in list(active_workers.items()):
        last_evt = worker_last_event.get(wid, 0)
        if last_evt == 0:
            continue
        silent_for = now - last_evt
        if silent_for > WORKER_STUCK_TIMEOUT:
            log.warning("Worker %s 已 %ds 无事件，强制取消（防 LLM 挂起）",
                        wid, int(silent_for))
            task.cancel()
            stuck_ids.append(wid)
    return stuck_ids


# ============================================================
# FastScanner 纯异步执行核（无 yield，可 create_task 后台运行）
# ============================================================

async def _run_fast_scanner_core(
    untested: list,
    session_info: dict | None,
    sitemap=None,
) -> tuple[list, dict]:
    """运行 FastScanner 并返回 (findings, stats)，不 yield 任何事件。

    可在后台 asyncio.create_task 运行，与 LLM 准备阶段并行。
    """
    from core.fast_scanner import FastScanner
    from core.config import FAST_SCAN_MAX_WORKERS, FAST_SCAN_RATE_LIMIT, FAST_MODE_TIMEOUTS

    scanner = FastScanner(
        max_workers=FAST_SCAN_MAX_WORKERS,
        timeout=FAST_MODE_TIMEOUTS.get("request", 6.0),
        request_rate_limit=FAST_SCAN_RATE_LIMIT,
    )
    findings = await scanner.scan_sitemap_features(
        untested, session_info=session_info, sitemap=sitemap
    )
    stats = scanner.get_accumulated_stats()
    return findings, stats


def _write_fast_scanner_results(
    findings: list,
    untested: list,
    sitemap,
) -> int:
    """将 FastScanner 的发现回写到 sitemap checklist。

    返回命中（vulnerable）的功能点数。
    未匹配到现有功能点的发现会被记录到 sitemap 的 _fast_scanner_orphan_findings 中，
    确保扫描结果不会丢失。
    """
    # ★ 已在模块顶部 import TestStatus, CheckResult，此处不再局部 import，
    # 避免 Python 把它们当作局部变量导致 UnboundLocalError。
    hit_count = 0
    orphan_findings: list[dict] = []
    for finding in findings:
        finding_url = (finding.url or "").lower().rstrip("/")
        if not finding_url:
            continue
        matched_fp = False
        for fp in untested:
            matched = False
            for api in (fp.related_apis or []):
                api_url = api.split(" ", 1)[-1].lower().rstrip("/") if " " in api else api.lower().rstrip("/")
                if finding_url == api_url or finding_url in api_url or api_url in finding_url:
                    # ★ 将 evidence_quality 追加到 evidence_response 末尾，
                    #    供 harm_validation collect_vulnerabilities 解析（无需改 mark_check 接口）
                    eq = getattr(finding, "evidence_quality", "") or ""
                    ev = getattr(finding, "evidence", "") or ""
                    if eq:
                        ev = f"{ev}\n[evidence_quality={eq}]"
                    marked = fp.mark_check(
                        vuln_type=finding.vuln_type,
                        result=CheckResult.VULNERABLE,
                        detail=finding.detail,
                        severity=finding.severity,
                        evidence_request=getattr(finding, "payload", ""),
                        evidence_response=ev,
                        fix_suggestion=getattr(finding, "fix_suggestion", ""),
                    )
                    if marked:
                        fp.test_status = TestStatus.VULN_FOUND
                        hit_count += 1
                        matched = True
                        matched_fp = True
                        break
            if matched:
                break
        # 未匹配到任何功能点的 finding 记录为 orphan，不丢失
        if not matched_fp:
            orphan_findings.append({
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "url": finding.url,
                "method": finding.method,
                "detail": finding.detail,
                "evidence": (finding.evidence or "")[:500],
                "payload": finding.payload,
                "fix_suggestion": finding.fix_suggestion,
                # ★ 证据质量（header_only/body_confirmed/content_match）
                "evidence_quality": getattr(finding, "evidence_quality", "") or "",
                # ★ 优化.md 建议6：溯源 ID + 规则标签
                "trace_id": getattr(finding, "trace_id", "") or "",
                "rule_tag": getattr(finding, "rule_tag", "") or "",
            })

    # 将 orphan findings 存入 sitemap，确保不丢失
    if orphan_findings and sitemap:
        existing = getattr(sitemap, "_fast_scanner_orphan_findings", None) or []
        existing.extend(orphan_findings)
        sitemap._fast_scanner_orphan_findings = existing

    if sitemap:
        sitemap.save()
    return hit_count


def _apply_skill_routing(findings: list, sitemap, top_n: int = 3) -> None:
    """Fast 模式 skill 引导（确定性，零 LLM）：给 FastScanner 发现打 skill 标签 + 挂 skill_routes 到 sitemap。

    仅做 VULN_TO_SKILL 查表（经 core.skill_router），不调用 LLM、不消耗 API。
    供报告展示「每个发现由哪个 SKILL 治理」，以及 top-N 最相关 SKILL 指引。
    异常安全：失败只记日志，绝不阻断主流程。
    """
    if not findings:
        return
    vuln_types = {getattr(f, "vuln_type", "") for f in findings if getattr(f, "vuln_type", "")}
    if not vuln_types:
        return
    try:
        from core.skill_router import build_vuln_to_skill_routes, route_vuln_types_to_skills

        lookup = build_vuln_to_skill_routes(vuln_types)
        for f in findings:
            vt = getattr(f, "vuln_type", "")
            route = lookup.get(vt)
            if route:
                f.skill = route.skill_name
                f.skill_path = route.skill_path

        top_routes = route_vuln_types_to_skills(vuln_types, top_n=top_n)
        if sitemap is not None:
            sitemap.skill_routes = {
                "enabled": True,
                "zero_llm": True,
                "routes": [r.to_dict() for r in top_routes],
            }
            # orphan findings 也补打标，避免 skill 溯源信息丢失
            orphans = getattr(sitemap, "_fast_scanner_orphan_findings", None) or []
            for o in orphans:
                vt = o.get("vuln_type", "")
                route = lookup.get(vt)
                if route:
                    o["skill"] = route.skill_name
                    o["skill_path"] = route.skill_path
    except Exception as e:
        log.warning("skill 路由标注失败（不影响主流程）: %s", e)


async def _run_scripted_scan_core(sitemap, session_info: dict | None) -> tuple[list[dict], dict]:
    """运行可选脚本广扫层，返回归一化 findings。"""
    from core.scripted_scan import run_scripted_scan

    return await run_scripted_scan(sitemap, session_info=session_info)


def _write_scripted_scan_results(
    findings: list[dict],
    untested: list,
    sitemap,
) -> int:
    """将脚本广扫发现按 suspected 写回 sitemap，并保存孤儿发现。"""
    hit_count = 0
    orphan_findings: list[dict] = []
    for finding in findings:
        finding_url = (finding.get("url") or "").lower().rstrip("/")
        if not finding_url:
            continue
        matched_fp = False
        for fp in untested:
            matched = False
            for api in (fp.related_apis or []):
                api_url = api.split(" ", 1)[-1].lower().rstrip("/") if " " in api else api.lower().rstrip("/")
                if finding_url == api_url or finding_url in api_url or api_url in finding_url:
                    marked = fp.mark_check(
                        vuln_type=finding.get("vuln_type", "未知"),
                        result=CheckResult.NEEDS_REVIEW,
                        detail=finding.get("detail", ""),
                        severity=finding.get("severity_original", "medium"),
                        evidence_request=finding.get("evidence_request", ""),
                        evidence_response=finding.get("evidence_response", ""),
                        fix_suggestion=finding.get("fix_suggestion", ""),
                    )
                    if marked:
                        fp.test_status = TestStatus.VULN_FOUND
                        hit_count += 1
                        matched = True
                        matched_fp = True
                        break
            if matched:
                break
        if not matched_fp:
            orphan_findings.append(finding)

    if sitemap:
        if orphan_findings:
            existing = getattr(sitemap, "_scripted_scan_findings", None) or []
            existing.extend(orphan_findings)
            sitemap._scripted_scan_findings = existing
        sitemap.save()
    return hit_count


# ============================================================
# LLM 准备阶段：初筛 → 元分析 → 智能分组（含 event yield）
# ============================================================

async def _run_llm_preparation(
    session: "AgentSession",
    untested: list,
    scan_cfg,
    _effective_max_workers: int,
) -> AsyncGenerator[str, None]:
    """LLM 准备阶段：初筛 → 元分析 → 智能分组。

    与 FastScanner 并行运行（FastScanner 在后台 task 中同时执行）。
    """
    from core.parallel.grouping import _smart_group_features
    from core.parallel.batch_test import (
        _batch_prelim_test,
        _meta_analyze_checklist, _execute_script_batch,
    )

    # 初筛
    yield session._event("system", "⚡ 脚本化初筛: 信息泄露/CORS/未授权访问规则检测...")
    prelim_result = await _batch_prelim_test(session, untested)
    if prelim_result["cleared"] > 0:
        yield session._event("system",
            f"⚡ 初筛完成: 检测 {prelim_result['tested']} 项, "
            f"确认安全 {prelim_result['cleared']} 项")
    else:
        yield session._event("system", "⚡ 初筛完成: 无可直接排除的项")

    # 元分析
    remaining_pending = sum(len(fp.get_http_pending()) for fp in untested)
    _skip_meta = SKIP_META_ANALYSIS or scan_cfg.skip_meta_analysis
    if remaining_pending > 20 and not _skip_meta:
        yield session._event("system",
            f"🧠 LLM 元分析: 分析 {remaining_pending} 项待测 checklist...")
        meta_task = asyncio.create_task(_meta_analyze_checklist(
            untested, llm=session.llm,
            business_type=session.sitemap.business_summary if session.sitemap else "",
            tech_stack=session.sitemap.tech_stack if session.sitemap else "",
        ))
        heartbeat_sec = 0
        while not meta_task.done():
            try:
                await asyncio.wait_for(asyncio.shield(meta_task), timeout=5)
            except asyncio.TimeoutError:
                heartbeat_sec += 5
                yield session._event("system", f"  🧠 LLM 元分析中... ({heartbeat_sec}s)")
            except asyncio.CancelledError:
                break
            except Exception:
                break
        meta_result = meta_task.result() if meta_task.done() and not meta_task.exception() else {}
        script_batch = meta_result.get("script_batch", [])
        if script_batch:
            script_items = sum(len(g.get("feature_ids", [])) for g in script_batch)
            yield session._event("system",
                f"🧠 元分析决策: {len(script_batch)} 类可脚本化 ({script_items} 个功能点)")
            yield session._event("system", "⚡ 执行脚本化批量检测...")
            batch_task = asyncio.create_task(_execute_script_batch(session, script_batch, untested))
            hb = 0
            while not batch_task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(batch_task), timeout=5)
                except asyncio.TimeoutError:
                    hb += 5
                    yield session._event("system", f"  ⚡ 脚本批量处理中... ({hb}s)")
                except asyncio.CancelledError:
                    break
                except Exception:
                    break
            batch_result = batch_task.result() if batch_task.done() and not batch_task.exception() else {"cleared": 0}
            if batch_result["cleared"] > 0:
                yield session._event("system", f"⚡ 脚本批量处理完成: {batch_result['cleared']} 项已标记")
        else:
            yield session._event("system", "🧠 元分析: 所有项需 LLM 深入分析")
    else:
        yield session._event("system", f"待测项 {remaining_pending} 个（≤20），跳过元分析")

    # 分类
    worker_features = [fp for fp in untested if fp.get_http_pending()]
    browser_features = [fp for fp in untested if fp.get_browser_pending()]

    # 智能分组
    yield session._event("system", "🔗 智能分组功能点...")
    group_task = asyncio.create_task(_smart_group_features(
        worker_features, llm=session.llm,
        target=getattr(session, "target_url", ""),
        business_type=session.sitemap.business_summary if session.sitemap else "",
        tech_stack=session.sitemap.tech_stack if session.sitemap else "",
    ))
    hb = 0
    while not group_task.done():
        try:
            await asyncio.wait_for(asyncio.shield(group_task), timeout=5)
        except asyncio.TimeoutError:
            hb += 5
            yield session._event("system", f"  🔗 智能分组中... ({hb}s)")
        except asyncio.CancelledError:
            break
        except Exception:
            break
    feature_groups = group_task.result() if group_task.done() and not group_task.exception() else []

    # 拆分超大组
    from core.config import MAX_FEATURES_PER_GROUP
    split_groups: list[tuple[str, list]] = []
    for name, fps in feature_groups:
        if len(fps) <= MAX_FEATURES_PER_GROUP:
            split_groups.append((name, fps))
        else:
            for i in range(0, len(fps), MAX_FEATURES_PER_GROUP):
                chunk = fps[i:i + MAX_FEATURES_PER_GROUP]
                sub_name = f"{name}({i // MAX_FEATURES_PER_GROUP + 1})"
                split_groups.append((sub_name, chunk))
    if len(split_groups) != len(feature_groups):
        log.info("分组拆分: %d 组 → %d 组", len(feature_groups), len(split_groups))
    feature_groups = split_groups
    session._llm_feature_groups = feature_groups

    total_http = sum(len(fp.get_http_pending()) for fp in worker_features)
    group_lines = []
    for name, fps in feature_groups:
        names = ", ".join(fp.name[:15] for fp in fps[:5])
        if len(fps) > 5:
            names += f"... (+{len(fps)-5})"
        group_lines.append(f"  - 「{name}」: {len(fps)} 个 ({names})")
    yield session._event("system",
        f"任务分配:\n"
        f"- HTTP: {len(worker_features)} 个 → {len(feature_groups)} 组\n"
        + "\n".join(group_lines) + "\n"
        f"- HTTP checklist: {total_http} 项\n"
        f"- 浏览器: {len(browser_features)} 个\n"
        f"- 最大并行: {min(len(feature_groups), _effective_max_workers)}")

    # 分组结果已通过 yield event 展示给前端
    # 实际调用方（run_parallel_test）会用自己的逻辑重新分组


# ============================================================
# Phase 2 主入口
# ============================================================

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
    scan_cfg = get_scan_strategy(getattr(session, "user_scan_mode", "batch"))
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


async def start_browser_feature_test(session: "AgentSession") -> AsyncGenerator[str, None]:
    """主 Agent 串行测试浏览器专属 checklist 项。"""
    if not session.sitemap:
        return

    from core.config import VULN_TO_SKILL

    queue = getattr(session, "_browser_test_queue", [])

    while queue:
        fp = queue.pop(0)
        browser_pending = fp.get_browser_pending()
        if not browser_pending:
            continue

        session.current_feature_id = fp.id
        session.tool_executor.current_feature_id = fp.id
        bind_context(feature_id=fp.id)
        if fp.test_status == TestStatus.NOT_TESTED:
            session.sitemap.start_test(fp.id)

        yield session._event("feature_start",
            f"🌐 主 Agent 浏览器测试: {fp.name} ({len(browser_pending)} 项)")

        session.current_context = session._new_context_for_phase(PHASE_TEST_PROMPT)

        # 自动注入浏览器测试项对应的 SKILL 方法论
        injected_skills: set[str] = set()
        skills_dir = Path("skills_my")
        for c in browser_pending:
            skill_name = VULN_TO_SKILL.get(c.vuln_type, "")
            if skill_name and skill_name not in injected_skills:
                for skill_md in skills_dir.rglob("SKILL.md"):
                    if skill_md.parent.name == skill_name:
                        content = skill_md.read_text(encoding="utf-8")
                        if len(content) > 4000:
                            content = content[:4000] + "\n\n... (方法论截断，按以上步骤执行)"
                        session.current_context.add_system(
                            f"## 方法论：{c.vuln_type}\n"
                            f"**必须按此步骤执行**：\n\n{content}"
                        )
                        injected_skills.add(skill_name)
                        log.info("主 Agent 注入 SKILL: %s → %s", c.vuln_type, skill_name)
                        break

        from core.test_templates import generate_browser_test_steps

        browser_checklist_lines = []
        for c in browser_pending:
            browser_checklist_lines.append(f"⬜ **{c.vuln_type}**")
            steps = generate_browser_test_steps(
                vuln_type=c.vuln_type,
                page_url=fp.page_url,
                feature_id=fp.id,
            )
            browser_checklist_lines.append(steps)
            browser_checklist_lines.append("")
        browser_checklist = "\n".join(browser_checklist_lines)

        session.current_context.add_user(
            f"## 浏览器专属测试: {fp.name}\n\n"
            f"- 页面: {fp.page_url}\n"
            f"- 优先级: {fp.priority.value}\n\n"
            f"### 待测项（浏览器专属，含具体操作步骤）\n\n{browser_checklist}\n\n"
            f"## 工作流程\n\n"
            f"1. 用 `browser_goto` 访问页面\n"
            f"2. **按上面每个待测项的 Step 执行**\n"
            f"3. 每测完一项调用 `checklist_mark` 记录结论\n"
            f"4. 全部测完后调用 `phase_complete`\n\n"
            f"⛔ 只测上面列出的浏览器项，HTTP 项已由子 Agent 完成。\n"
            f"⛔ **严格按步骤执行**，不要自由发挥。"
        )
        return

    # 所有浏览器项测完
    async for evt in _enter_report_phase(session):
        yield evt


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

            # 构造补齐任务执行器(每个 task 直接当一个最小 checklist 项跑)
            async def _execute_gap_tasks(new_tasks: list[dict]) -> list[dict]:
                """对每个补齐任务起一个最小子 Agent 执行。"""
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
