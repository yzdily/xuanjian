"""
Web Server — FastAPI 主入口（已拆分版）。

只保留：
1. FastAPI app 实例化与启动配置
2. 全局子路由挂载（traffic / diff / replay / crypto + 9 个新拆分 router）
3. SKILL registry 启动初始化
4. 静态 HTML 页面入口
5. 核心 /api/chat（深度依赖 session/SSE，留在主文件不拆）

所有业务路由按职责拆分到 web/api/*.py，全局共享状态在 web/_state.py。
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from core.log import get_logger
from core import config as _config
from core.skill_registry import get_registry

# ★ 共享状态（_pool / _sessions / get_session / ...）
from web._state import _pool, _sessions, STATE, get_session  # noqa: F401

log = get_logger("server")

# ★ 启动消息缓冲：收集模块级初始化结果，最终输出一条摘要日志
# 原逻辑每个子模块挂载都输出一条 INFO，每次重启产生 15+ 行重复日志
_startup_msgs: list[str] = []

app = FastAPI(title="玄鉴 XuanJian 智能安全扫描器")


# ★ P1: 任务队列配置加载（仅赋值，不创建 asyncio 原语）
# worker 的启动推迟到 FastAPI startup 钩子（此时 uvicorn 事件循环已运行），
# 避免模块导入阶段调用 create_task 触发 "no running event loop" /
# "coroutine was never awaited" 警告。
try:
    from core.task_queue import init as _init_task_queue
    _init_task_queue(_pool, max_concurrent=3)
    _startup_msgs.append("任务队列=3")
except Exception as _ex:
    log.warning("任务队列配置加载失败（非致命）: %s", _ex)


@app.on_event("startup")
async def _startup_task_queue_worker():
    """FastAPI startup 钩子：uvicorn 事件循环已运行，安全启动 worker。"""
    try:
        from core.task_queue import start_worker
        start_worker()
        log.debug("后台任务队列 worker 已通过 startup 钩子启动")
    except Exception as _ex:
        log.warning("任务队列 worker 启动失败（非致命）: %s", _ex)


# ============================================================
# 子路由挂载区
# ============================================================

# 旧有：流量管理路由（/traffic 页面 + /api/traffic/* 接口）
try:
    from web.traffic_api import traffic_router, register_session_accessor
    app.include_router(traffic_router)
    _startup_msgs.append("traffic")
except Exception as _ex:
    log.warning("流量管理路由加载失败: %s", _ex)

# 旧有：Sitemap Diff 路由
try:
    from web.api.diff_api import router as _diff_router
    from core.diff.register import attach as _attach_diff_events
    app.include_router(_diff_router)
    _attach_diff_events()
    _startup_msgs.append("diff")
except Exception as _ex:
    log.warning("Sitemap Diff 路由加载失败: %s", _ex)

# 旧有：Replay Theater 路由
try:
    from web.api.replay_api import router as _replay_router
    from core.replay.register import attach as _attach_replay_events
    app.include_router(_replay_router)
    _attach_replay_events()
    _startup_msgs.append("replay")
except Exception as _ex:
    log.warning("Replay Theater 路由加载失败: %s", _ex)

# 旧有：Crypto Replay 路由
try:
    from web.api.crypto_api import router as _crypto_router
    from core.crypto_replay.register import attach as _attach_crypto_events
    app.include_router(_crypto_router)
    _attach_crypto_events()
    _startup_msgs.append("crypto")
except Exception as _ex:
    log.warning("Crypto Replay 路由加载失败: %s", _ex)


# ★ 新拆分的 9 个业务路由（顺序无关，FastAPI 内部按精确路径匹配；
# 但同一 router 内的路由先后顺序保持原样，避免 path 变量截获问题）
try:
    from web.api.memory_api import router as _memory_router
    from web.api.triggers_api import router as _triggers_router
    from web.api.reports_api import router as _reports_router
    from web.api.skills_api import router as _skills_router
    from web.api.models_api import router as _models_router
    from web.api.templates_api import router as _templates_router
    from web.api.packet_api import router as _packet_router
    from web.api.oob_api import router as _oob_router
    from web.api.system_api import router as _system_router
    from web.api.sessions_api import router as _sessions_router
    from web.api.auth_api import router as _auth_router
    from web.api.presets_api import router as _presets_router
    from web.api.dashboard_api import router as _dashboard_router
    from web.api.credential_injection_api import router as _cred_inject_router

    app.include_router(_memory_router)
    app.include_router(_triggers_router)
    app.include_router(_reports_router)
    app.include_router(_skills_router)
    app.include_router(_models_router)
    app.include_router(_templates_router)
    app.include_router(_packet_router)
    app.include_router(_oob_router)
    app.include_router(_system_router)
    app.include_router(_sessions_router)
    app.include_router(_auth_router)
    app.include_router(_presets_router)
    app.include_router(_dashboard_router)
    app.include_router(_cred_inject_router)
    _startup_msgs.append("14 routers")
except Exception as _ex:
    log.error("业务 router 挂载失败: %s", _ex, exc_info=True)


# ============================================================
# 认证模块：启动时初始化默认用户（admin/admin）
# ★ 鉴权策略（v2 安全加固）：
#   - 静态 HTML 页面与 /api/auth/* 完全免认证
#   - 若配置了 XUANJIAN_API_KEY，则所有 /api/ 业务接口强制认证
#     （Bearer Token 或 X-API-Key），消除"安全工具自身无认证"的矛盾
#   - 若未配置 XUANJIAN_API_KEY，回退到可选认证模式（兼容本地开发）
# ============================================================
try:
    from core import auth as _auth
    _auth.init_default_user()
    _startup_msgs.append("auth=ok")
except Exception as _ex:
    log.warning("认证模块初始化失败（非致命）: %s", _ex)


@app.on_event("startup")
async def _startup_init_default_user():
    """app 启动事件：再次确保默认用户已创建（兼容多 worker / 重启场景）。"""
    try:
        from core import auth as _auth
        _auth.init_default_user()
    except Exception as _ex:
        log.warning("startup 初始化默认用户失败（非致命）: %s", _ex)


# ★ 启动时把 SKILL.md frontmatter 合并到 config 全局映射
try:
    _stats = _config.apply_skill_registry(get_registry())
    _startup_msgs.append(f"skills={_stats['vuln_to_skill']}")
except Exception as _ex:
    log.warning("SKILL registry 合并失败（将使用默认映射）: %s", _ex)


# ★ v4.2: 注入 session 访问器给 traffic_api，使其能读取内存中的实时 sitemap
try:
    register_session_accessor(  # type: ignore[name-defined]
        lambda: _sessions.get(STATE["current_session_id"]) if STATE["current_session_id"] else None
    )
except Exception as e:
    log.warning("注册 session 访问器失败: %s", e)


# ★ 启动时自动恢复最近一次未完成的会话
try:
    from web._state import _restore_session
    recovered = _restore_session()
    if recovered:
        _startup_msgs.append(f"恢复会话={recovered.task_id}")
    else:
        _startup_msgs.append("无待恢复会话")
except Exception as _ex:
    log.warning("自动恢复会话异常（非致命）: %s", _ex)

# ★ 输出启动摘要：将原本 15+ 行 INFO 合并为一条
log.info("服务启动完成 | %s", " | ".join(_startup_msgs))


# ============================================================
# ★ P0: 全局 API 鉴权中间件（白名单 + Bearer Token / API Key）
# ============================================================

_AUTH_WHITELIST = {
    "/api/auth/login", "/api/auth/register", "/api/auth/logout",
    "/api/health", "/",
    "/favicon.svg", "/logo.png",
    "/llm-monitor", "/skill-manager", "/reports", "/memory",
    "/traffic", "/replay-theater", "/sitemap-diff", "/crypto-templates",
}

_API_KEY = os.getenv("XUANJIAN_API_KEY", "")

# ★ SSE 连接数限制：防止过多 SSE 连接耗尽服务器资源
_MAX_SSE_CONNECTIONS = int(os.getenv("XUANJIAN_MAX_SSE_CONNECTIONS", "10"))
_sse_connection_count = 0


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    path = request.url.path

    if path in _AUTH_WHITELIST or path.startswith("/api/auth/"):
        return await call_next(request)

    if path.startswith("/api/"):
        token = ""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        if not token:
            token = request.headers.get("X-API-Key", "")
        if not token:
            token = request.query_params.get("api_key", "")

        if _API_KEY:
            # ★ 安全加固：配置了 API Key 时强制认证
            if token and hmac.compare_digest(token, _API_KEY):
                return await call_next(request)

            if token:
                from core import auth as _auth_mod
                payload = _auth_mod.verify_token(token)
                if payload:
                    request.state.user = payload.get("username", "unknown")
                    return await call_next(request)

            return JSONResponse(
                status_code=401,
                content={"ok": False, "error": "请先登录或在请求头添加 X-API-Key", "code": "UNAUTHORIZED"},
            )
        else:
            # 未配置 API Key：可选认证模式（兼容本地开发），有 token 则校验
            if token:
                from core import auth as _auth_mod
                payload = _auth_mod.verify_token(token)
                if payload:
                    request.state.user = payload.get("username", "unknown")
            return await call_next(request)


# ============================================================
# 静态 HTML 页面入口
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = Path(__file__).parent / "index.html"
    return HTMLResponse(
        html_path.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"},
    )


@app.get("/llm-monitor", response_class=HTMLResponse)
async def llm_monitor_page():
    """LLM 用量详细监控页 — 独立页面，含表格、筛选器、诊断详情。"""
    html_path = Path(__file__).parent / "llm_monitor.html"
    if not html_path.exists():
        return HTMLResponse("<h2>LLM Monitor page not found</h2>", status_code=404)
    return HTMLResponse(
        html_path.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/skill-manager", response_class=HTMLResponse)
async def skill_manager_page():
    """SKILL 管理独立页面 — 列表/编辑/启用-禁用/上传/Markdown 预览。"""
    html_path = Path(__file__).parent / "skill_manager.html"
    if not html_path.exists():
        return HTMLResponse("<h2>Skill Manager page not found</h2>", status_code=404)
    return HTMLResponse(
        html_path.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/reports", response_class=HTMLResponse)
async def reports_page():
    """报告管理独立页面 — 列出所有 task 的 .md 报告。"""
    html_path = Path(__file__).parent / "reports.html"
    if not html_path.exists():
        return HTMLResponse("<h2>Reports page not found</h2>", status_code=404)
    return HTMLResponse(
        html_path.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/memory", response_class=HTMLResponse)
async def memory_page():
    """记忆管理独立页面 — Hermes 风格经验教训管理。"""
    html_path = Path(__file__).parent / "memory_manager.html"
    if not html_path.exists():
        return HTMLResponse("<h2>Memory Manager page not found</h2>", status_code=404)
    return HTMLResponse(
        html_path.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    """安全仪表盘页面 — 漏洞统计、趋势、分布图表。"""
    html_path = Path(__file__).parent / "dashboard.html"
    if not html_path.exists():
        return HTMLResponse("<h2>Dashboard page not found</h2>", status_code=404)
    return HTMLResponse(
        html_path.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/logo.png")
async def logo():
    logo_path = Path(__file__).parent / "logo.png"
    if logo_path.exists():
        return FileResponse(logo_path, media_type="image/png")
    return HTMLResponse("", status_code=404)


@app.get("/favicon.svg")
async def favicon():
    svg_path = Path(__file__).parent / "favicon.svg"
    if svg_path.exists():
        return FileResponse(svg_path, media_type="image/svg+xml",
                            headers={"Cache-Control": "public, max-age=3600"})
    return HTMLResponse("", status_code=404)


# ============================================================
# 核心 Chat API（与 session 深度耦合，保留在主文件）
# ============================================================

@app.post("/api/chat")
async def chat(request: Request):
    body = await request.json()
    user_message = body.get("message", "")
    task_id = body.get("task_id", "")
    # 可选：OOB callback URL（盲打 XSS 回调）
    oob_callback_url = (body.get("oob_callback_url") or "").strip()
    # ★ 扫描模式：fast | standard | deep | smart | batch | realtime
    scan_mode = (body.get("scan_mode") or "smart").strip().lower()
    if scan_mode not in ("batch", "realtime", "smart", "fast", "standard", "deep"):
        scan_mode = "smart"
    # ★ 内联图片附件（CodeBuddy 风格）
    screenshot_paths = body.get("screenshot_paths", []) or []

    if not user_message.strip() and not screenshot_paths:
        return {"error": "消息不能为空"}

    # 用 task_id 绑定到具体 session
    if task_id and task_id in _sessions:
        session = _sessions[task_id]
    else:
        session = get_session()
        task_id = session.task_id

    # ★ 设置扫描模式（仅在新任务时生效，已有 session 不覆盖）
    # ★ "fast"/"quick" 模式：执行策略用 batch（并行批处理），深度模式标记为 fast（跳过 LLM）
    _exec_mode = scan_mode
    if scan_mode in ("fast", "quick"):
        _exec_mode = "batch"
    if session.phase == "idle" and _exec_mode in ("batch", "realtime") and _exec_mode != session.scan_mode:
        session.set_scan_mode(_exec_mode)
        log.info("[task:%s] 执行模式设置为: %s (深度模式: %s)", task_id, _exec_mode, scan_mode)
    # ★ 记录用户选择的原始模式（含 smart/fast），供 chat_loop 判断是否跳过 LLM
    # ★ 统一归一化：quick → fast，下游只需检查 == "fast"
    session.user_scan_mode = "fast" if scan_mode in ("fast", "quick") else scan_mode

    # 设置 OOB callback URL（在 XSS scanner 启动前）
    if oob_callback_url:
        session.oob_callback_url = oob_callback_url
        log.info("[task:%s] OOB callback URL 已配置: %s", task_id, oob_callback_url)

    # ★ session 级事件队列（生命周期跟 session 走，不跟 SSE 连接走）
    if not hasattr(session, '_event_queue') or session._event_queue is None:
        session._event_queue = asyncio.Queue()

    # ★ 注入 event_queue 到 RealtimeStrategy（让实时测试事件推送到 SSE）
    if session.scan_mode == "realtime" and hasattr(session, '_strategy') and session._strategy:
        from core.strategy_base import RealtimeStrategy
        if isinstance(session._strategy, RealtimeStrategy):
            session._strategy.set_event_queue(session._event_queue)

    eq = session._event_queue

    async def producer():
        # ★ 跟踪 chat() 是否已显式发出过结束事件（done / task_failed / task_stuck / task_aborted）
        terminal_events = {"done", "task_failed", "task_stuck", "task_aborted"}
        terminal_seen = False

        try:
            log.info("[task:%s] 后台任务开始", task_id)

            # ★ 如果有截图附件，走截图测试流程
            if screenshot_paths:
                import re as _re_url
                url_match = _re_url.search(r'https?://[^\s,]+', user_message)
                target_url = url_match.group(0) if url_match else ""

                intent = {
                    "has_target": bool(target_url),
                    "target_url": target_url,
                    "credentials": [],
                    "session_cookies": "",
                    "auth_header": "",
                    "extra_headers": {},
                    "test_mode": "",
                    "special_notes": user_message,
                    "intent_kind": "focused",
                    "target_features": [],
                }

                screenshot_path = screenshot_paths[0]
                async for event in session._run_screenshot_focused_test(
                    intent, screenshot_path, user_message or "测试截图中的所有功能"
                ):
                    await eq.put(event)
                    if isinstance(event, str) and event.startswith("data: "):
                        try:
                            payload = json.loads(event[6:].strip())
                            if payload.get("type") in terminal_events:
                                terminal_seen = True
                        except Exception:
                            pass
            else:
                async for event in session.chat(user_message):
                    await eq.put(event)
                    if isinstance(event, str) and event.startswith("data: "):
                        try:
                            payload = json.loads(event[6:].strip())
                            if payload.get("type") in terminal_events:
                                terminal_seen = True
                        except Exception:
                            pass
            log.info("[task:%s] 后台任务正常结束 (terminal=%s)", task_id, terminal_seen)
            in_report_followup = (
                hasattr(session, 'phase') and session.phase == "report"
                and not terminal_seen
            )
            if not terminal_seen and not in_report_followup:
                try:
                    await eq.put(session._event("done", "任务流程结束"))
                except Exception as e:
                    log.warning("[task:%s] 发送 done 事件失败: %s", task_id, e)
        except asyncio.CancelledError:
            log.info("[task:%s] 后台任务被停止", task_id)
            try:
                await eq.put(session._event("system", "任务已停止"))
                await eq.put(session._event("task_aborted", json.dumps({
                    "reason": "user_aborted",
                    "message": "任务已被用户中断，发送消息可继续",
                }, ensure_ascii=False)))
            except Exception as e:
                log.warning("[task:%s] 发送 task_aborted 事件失败: %s", task_id, e)
        except Exception as e:
            log.error("[task:%s] 后台任务异常: %s", task_id, e, exc_info=True)
            try:
                await eq.put(session._event("system", f"错误: {e}"))
                await eq.put(session._event("task_failed", json.dumps({
                    "reason": "uncaught_exception",
                    "error": str(e)[:300],
                    "message": "后台任务异常，发送消息可重试",
                }, ensure_ascii=False)))
            except Exception as eq_err:
                log.warning("[task:%s] 发送 task_failed 事件失败: %s", task_id, eq_err)
        finally:
            try:
                await eq.put(None)  # 结束信号
            except Exception as e:
                log.warning("[task:%s] 发送结束信号失败: %s", task_id, e)

    # 启动后台任务（session 级，不受 SSE 连接生命周期影响）
    bg_task = asyncio.create_task(producer())
    session._bg_task = bg_task

    # ★ SSE 连接数限制
    global _sse_connection_count
    if _sse_connection_count >= _MAX_SSE_CONNECTIONS:
        return JSONResponse(
            status_code=429,
            content={"ok": False, "error": f"SSE 连接数已达上限 ({_MAX_SSE_CONNECTIONS})，请稍后重试", "code": "TOO_MANY_CONNECTIONS"},
        )
    _sse_connection_count += 1
    log.info("[sse] 连接建立 (当前活跃: %d/%d)", _sse_connection_count, _MAX_SSE_CONNECTIONS)

    async def generate():
        """SSE 流：只是从 session 的事件队列中读取并推送给前端。断开不影响后台任务。"""
        try:
            while True:
                try:
                    event = await asyncio.wait_for(eq.get(), timeout=15)
                    if event is None:
                        break
                    yield event
                except asyncio.TimeoutError:
                    if bg_task.done():
                        break
                    yield ": heartbeat\n\n"
        except (GeneratorExit, asyncio.CancelledError):
            log.info("[sse:%s] 前端断开，后台任务继续运行 (done=%s)", task_id, bg_task.done())
        finally:
            global _sse_connection_count
            _sse_connection_count -= 1
            log.info("[sse] 连接关闭 (当前活跃: %d/%d)", _sse_connection_count, _MAX_SSE_CONNECTIONS)

    return StreamingResponse(generate(), media_type="text/event-stream",
                            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
