"""
_orchestrator_helpers — 从 orchestrator.py 机械拆分出的辅助函数。

包含：
- mitmproxy 健康检查 + 自动重启
- FastScanner 纯异步执行核
- 脚本广扫
- LLM 准备阶段

这些函数原位于 core.parallel.orchestrator，为降低单文件体积而迁出，
逻辑与行为保持完全一致（机械 relocation，无任何改动）。
"""

from __future__ import annotations

import asyncio
import os
from typing import AsyncGenerator, TYPE_CHECKING

from core.config import WORKER_STUCK_TIMEOUT, SKIP_META_ANALYSIS
from core.sitemap import TestStatus, CheckResult
from core.log import get_logger

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
        hard_timeout=FAST_MODE_TIMEOUTS.get("hard_timeout", 600.0),
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
