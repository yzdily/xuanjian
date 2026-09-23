"""
Session Base — AgentSession 基类定义。

包含：__init__、字段声明、_try_recover、switch_model、_reset_for_new_task、
_load_base_prompt、_new_context_for_phase、_sync_tool_executor、_event、get_chat_history。
这些是所有 Mixin 共享的核心状态和工具方法。
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from pathlib import Path
from typing import AsyncGenerator

from core.llm import LLMClient, Message
from core.context import ContextManager
from core.sitemap import Sitemap, TestStatus, Priority, CheckResult
from core.config import MAX_TOOL_RESULT, CONTEXT_BATCH_SIZE, MAIN_MAX_ROUNDS, REPEAT_TOOL_THRESHOLD
from core.tools import ALL_MAIN_TOOLS
from core.tool_executor import ToolExecutor
from core.intent import parse_user_intent
from core.log import get_logger, bind_context, clear_context
from core.prompts.phases import (
    PHASE_EXPLORE_PROMPT, PHASE_ANALYZE_PROMPT,
    PHASE_TEST_PROMPT, PHASE_REPORT_PROMPT,
)

log = get_logger("session")

# ★ T14 (0923 v2)：事件镜像白名单 —— 只镜像"用户可见结论类"事件。
#   刻意不含 message / thinking / tool_call 等高频流式输出，避免 events.jsonl 爆炸。
_MIRROR_EVENT_TYPES = frozenset({
    "system", "error", "phase", "vuln", "findings", "screenshot",
    "report_reply_done",
    "done", "task_partial", "task_unreachable", "task_failed", "task_aborted",
    "task_stuck",
})

# 单行上限：events.jsonl 是 append-only 审计流，单行过大拖慢事后 grep / 解析
_MIRROR_MAX_LINE = 4000


def mirror_serialize(record: dict, max_line: int = _MIRROR_MAX_LINE) -> str:
    """把镜像记录序列化成**一行合法 JSON**（T14 / P16）。

    ★ 不能对 ``json.dumps(...)`` 的结果直接切片：切出来的行不是合法 JSON，
    事后用 ``json.loads`` 审计时整行报废 —— 等于把审计记录写废，
    与 P16「未通过校验的发现不丢数据、可事后复核」直接冲突。
    正确做法是把超长部分压到 ``data`` 字段上，保证整行始终可解析。

    Args:
        record: 待写入记录（``ts`` / ``task_id`` / ``phase`` / ``type`` / ``data``）。
        max_line: 单行字符上限。

    Returns:
        一行 JSON 文本（不含换行符）。
    """
    payload = json.dumps(record, ensure_ascii=False, default=str)
    if len(payload) <= max_line:
        return payload
    rec = dict(record)
    rec["truncated"] = True
    _over = len(payload) - max_line
    _d = rec.get("data")
    if isinstance(_d, str):
        _keep = max(0, len(_d) - _over - 64)   # 预留截断标记与转义开销
        rec["data"] = _d[:_keep] + "…[truncated]"
    else:
        rec["data"] = str(_d)[:512] + "…[truncated]"
    payload = json.dumps(rec, ensure_ascii=False, default=str)
    if len(payload) > max_line:                # 其它字段本身超长的兜底
        rec["data"] = "…[truncated]"
        payload = json.dumps(rec, ensure_ascii=False, default=str)
    return payload


class AgentSessionBase:
    """分阶段渗透 Agent 会话 — 基类（核心状态 + 通用方法）。"""

    def __init__(self, llm: "LLMClient | None" = None, skip_recover: bool = False):
        self.task_id = f"task_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        bind_context(session_id=self.task_id)
        self.llm = llm  # ★ 可为 None（fast/无 LLM 模式）
        self.sitemap: Sitemap | None = None
        self.started = False

        self.current_context = ContextManager(llm=self.llm)
        self._phase = "idle"  # idle → explore → analyze → test → report
        self.current_feature_id: str | None = None
        self.has_credentials: bool = False

        self.tool_executor = ToolExecutor()
        self._browser_test_queue: list = []

        # 报告增量更新：记录上次生成报告时的关键指标快照
        # 结构：{"vulns": int, "tested": int, "total": int, "vuln_keys": set[str]}
        # 用于在 phase == "report" 阶段判断追问后是否需要重新生成报告
        self._last_report_snapshot: dict | None = None

        # 凭证注入（实例字段副本，下游仍以 env 为准；用于可观察 + 排查）
        self._inject_cookies: str = ""
        self._inject_auth: str = ""
        self._inject_headers: dict = {}
        self._inject_target_url: str = ""

        # ★ 扫描模式：batch（默认批处理）| realtime（实时扫描）
        self.scan_mode: str = "batch"
        # ★ 用户选择的原始模式（含 smart），供 chat_loop 判断是否需要自动切换
        self.user_scan_mode: str = "smart"
        # ★ P1-A: 模式升降级追踪
        self._original_user_scan_mode: str | None = None  # 首次升降级前的原始模式
        self._mode_escalated: bool = False                 # 是否发生过升降级
        # ★ 扫描策略实例（惰性创建，scan_mode 变更时重建）
        self._strategy = None

        # ★ 2026-05-29: 活跃爬虫引用（供 /api/stop 直接通知爬虫退出）
        self._active_crawler = None
        self._active_crawl_task = None
        # ★ 2026-05-31: 活跃 worker tasks 引用（供 /api/stop 取消所有子 Agent）
        self._active_worker_tasks: dict = {}

        self._load_base_prompt()

        # 尝试恢复上次崩溃的会话（仅首次启动时，新建会话跳过）
        if not skip_recover:
            self._try_recover()

    # ---- phase 属性：自动同步结构化日志上下文 ----
    @property
    def phase(self) -> str:
        return self._phase

    @phase.setter
    def phase(self, value: str) -> None:
        self._phase = value
        bind_context(phase=value)

    def _try_recover(self) -> None:
        """启动时检查是否有上次未完成的 sitemap，自动恢复。"""
        tasks_dir = Path("data/tasks")
        if not tasks_dir.exists():
            return
        # 找最近的 sitemap 文件
        sitemap_files = sorted(tasks_dir.glob("task_*-sitemap.json"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not sitemap_files:
            return
        latest = sitemap_files[0]
        try:
            import json as _json
            data = _json.loads(latest.read_text(encoding="utf-8"))
            # 只恢复 30 分钟内的会话（太旧的可能是上一次完全跑完的）
            import time as _time
            mtime = latest.stat().st_mtime
            if _time.time() - mtime > 1800:
                return
            task_id = latest.name.replace("-sitemap.json", "")
            sitemap = Sitemap(target=data.get("target", ""), task_id=task_id)
            if sitemap.load():
                # 检查是否有未完成的测试（至少有 pending 的 checklist 项）
                has_pending = False
                for fp in sitemap.features.values():
                    for c in fp.checklist:
                        if c.result == CheckResult.PENDING:
                            has_pending = True
                            break
                    if has_pending:
                        break
                if has_pending:
                    self.sitemap = sitemap
                    self.task_id = task_id
                    self.target_url = data.get("target", "")
                    # ★ 恢复凭证状态（从 sitemap 持久化字段中读取）
                    self._inject_cookies = getattr(sitemap, "_inject_cookies", "") or ""
                    self._inject_auth = getattr(sitemap, "_inject_auth", "") or ""
                    self._inject_headers = getattr(sitemap, "_inject_headers", {}) or {}
                    self.has_credentials = getattr(sitemap, "_has_credentials", False)
                    # ★ 阶段 4-E1：恢复到**会话级作用域**（让爬虫能复用登录凭证），
                    #   不再写进程级 os.environ —— 那是并行会话互相清除凭证的根源。
                    from core.session import cred_scope as _cs
                    _cs.set_scope(_cs.CredScope(
                        cookies=self._inject_cookies or "",
                        auth=self._inject_auth or "",
                        headers=dict(self._inject_headers or {}),
                        target_url=self.target_url or "",
                        source=_cs.SOURCE_PRESET,
                        session_key=self.task_id,
                    ))
                    log.info("恢复上次未完成的会话: task_id=%s, target=%s, features=%d, has_credentials=%s",
                             task_id, sitemap.target, len(sitemap.features), self.has_credentials)
        except Exception as e:
            log.warning("恢复会话失败: %s", e)

    def switch_model(self, llm: LLMClient) -> None:
        self.llm = llm
        self.current_context.llm = llm

    @property
    def strategy(self):
        """惰性创建扫描策略实例。"""
        if self._strategy is None:
            from core.strategy_base import create_strategy
            self._strategy = create_strategy(self.scan_mode)
        return self._strategy

    def set_scan_mode(self, mode: str) -> None:
        """设置扫描模式，重建策略实例。"""
        if mode not in ("batch", "realtime", "smart"):
            mode = "batch"
        # smart 模式在策略层等同于 batch（由意图识别决定是否走 packet/focused 等路径）
        self.scan_mode = mode if mode != "smart" else "batch"
        self._strategy = None  # 惰性重建

    def _reset_for_new_task(self) -> None:
        # ★ 通知旧策略做清理
        if self._strategy is not None:
            try:
                import asyncio
                # ★ D10：get_event_loop() 在无运行循环时已弃用；优先取运行循环，
                # 否则新建并在 finally 中关闭，避免事件循环泄漏。
                try:
                    loop = asyncio.get_running_loop()
                    loop_running = True
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    loop_running = False
                if loop_running:
                    asyncio.ensure_future(self._strategy.on_task_done(self))
                else:
                    try:
                        loop.run_until_complete(self._strategy.on_task_done(self))
                    finally:
                        loop.close()
            except Exception as e:
                log.warning("策略清理失败 (非致命): %s", e)
        if self.sitemap:
            self.sitemap.save()
        # ★ 方案 C：释放**本会话**的浏览器 context —— 每会话一个独立 context，
        #   不回收会随会话数累积泄漏（实测每个约 1.4 MB，长跑会堆起来）。
        try:
            from mcp_servers.browser_mcp import release_session
            _prev_task = self.task_id
            _loop = asyncio.get_event_loop()
            if _loop.is_running():
                _loop.create_task(release_session(_prev_task))
            else:
                _loop.run_until_complete(release_session(_prev_task))
        except Exception as _rel_err:
            log.debug("释放浏览器 context 失败（非致命）: %s", _rel_err)
        self.task_id = f"task_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        self.sitemap = None
        self.current_context = ContextManager(llm=self.llm)
        self.current_feature_id = None
        self.tool_executor = ToolExecutor()
        self._load_base_prompt()
        # ★ 清理 Cookie/Auth 注入（避免新任务沾染旧任务的凭证）
        #   阶段 4-E1：凭证已迁移到**会话级作用域**（contextvar）——
        #   这里把作用域置空，并清掉进程级遗留 env（env 不再是写入路径，但可能残留旧值）。
        from core.session import cred_scope as _cs
        # session_key 必须带上：即使本会话暂无凭证，浏览器层也要靠它选对独立 context
        _cs.set_scope(_cs.CredScope(session_key=self.task_id))
        _cs.clear_env_injections()
        # 同步清理实例字段
        self._inject_cookies = ""
        self._inject_auth = ""
        self._inject_headers = {}
        self._inject_target_url = ""
        # 重置策略
        self._strategy = None

    def _load_base_prompt(self):
        prompts_dir = Path(__file__).parent.parent / "prompts"
        solver_prompt = (prompts_dir / "solver.md").read_text(encoding="utf-8")
        self.current_context.add_system(solver_prompt)

    def _new_context_for_phase(self, phase_prompt: str) -> ContextManager:
        """为指定 Phase 创建新 context（含 skill 注入 + 历史经验）。"""
        ctx = ContextManager(llm=self.llm)
        ctx.add_system(phase_prompt)

        # ★ SKILL 注入：根据 phase 加载对应 SKILL.md
        core_dir = Path(__file__).parent.parent
        skills_dir = Path(os.getenv("SKILLS_MY_PATH", core_dir.parent / "skills_my"))

        # Phase 1 注入业务逻辑分析方法论
        if self.phase == "analyze":
            biz_path = skills_dir / "business-analysis" / "business-logic-analysis" / "SKILL.md"
            if biz_path.exists():
                ctx.add_system(biz_path.read_text(encoding="utf-8"))

        # Phase 2 注入采样推断策略
        if self.phase == "test":
            sampling_path = core_dir / "sampling-inference" / "SKILL.md"
            if sampling_path.exists():
                ctx.add_system(sampling_path.read_text(encoding="utf-8"))

        # 无凭证时注入快速测试约束
        if not self.has_credentials:
            quick_path = core_dir / "no-auth-quick-test" / "SKILL.md"
            if quick_path.exists():
                ctx.add_system(quick_path.read_text(encoding="utf-8"))

        # 注入历史经验（跨任务的知识沉淀）
        self._inject_memories(ctx)

        # ★ 阶段 5-E2：阶段接力（本任务的进度/证据）
        #   原实现只在 phase == "test" 时注入 sitemap 摘要，其它阶段边界**什么都不带** ——
        #   新阶段不知道上阶段做到哪、还有什么没测、已确认哪些漏洞，于是重复劳动或漏测。
        self._inject_phase_handoff(ctx)

        return ctx

    def _inject_phase_handoff(self, ctx: ContextManager) -> None:
        """注入阶段接力物：未完成项列表 + 关键证据引用（不含报文全文）。

        数据源是 **sitemap**（结构化且持久化），不依赖 LLM 摘要 ——
        上下文压缩怎么切都不会丢样本结论。摘要只是辅助记忆。
        """
        if not self.sitemap:
            return
        try:
            from core.session.phase_handoff import build_handoff
        except Exception as e:                                  # pragma: no cover
            log.warning("导入阶段接力模块失败: %s", e)
            return

        to_phase = str(getattr(self, "phase", "") or "")
        from_phase = str(getattr(self, "_handoff_from_phase", "") or "")

        # 与上下文预算联动：已接近上限时收紧接力物体量
        try:
            budget = 8000 if ctx.budget_allows_injection() else 2500
        except Exception:
            budget = 8000

        try:
            text, stats = build_handoff(
                self.sitemap,
                to_phase=to_phase,
                from_phase=from_phase,
                budget_chars=budget,
            )
        except Exception as e:
            log.warning("构建阶段接力物失败: %s", e)
            return

        self._handoff_from_phase = to_phase      # 供下一次阶段边界使用

        if not text:
            return
        ctx.add_system(text)
        self._last_handoff = stats.as_dict()
        self._handoff_count = int(getattr(self, "_handoff_count", 0) or 0) + 1
        log.info("阶段接力注入: %s → %s, 未完成项 %d, 已确认漏洞 %d%s",
                 from_phase or "-", to_phase, stats.features_pending,
                 stats.confirmed_vulns, "（已截断）" if stats.truncated else "")

    def _sync_tool_executor(self) -> None:
        """同步 sitemap 到 tool executor（让 sitemap_get_coverage 等工具能访问）。"""
        self.tool_executor.set_session(self)

    def _event(self, event_type: str, data, full: str = "") -> str:
        # ============================================================
        # ★ T9 + T14 (0923 v2)：终态语义分流 + 事件镜像
        #   这里是**唯一**的事件出口，所以两个横切关注点都收在这一处，
        #   避免在 5 个 `yield self._event("done", ...)` 站点各改一遍。
        # ============================================================
        event_type = self._normalize_terminal_event(event_type)
        event = {"type": event_type, "data": data}
        if full:
            event["full"] = full
        payload = json.dumps(event, ensure_ascii=False)
        # 持久化对话历史（追加写入 jsonl）
        try:
            history_path = Path("data/tasks") / f"{self.task_id}-chat.jsonl"
            history_path.parent.mkdir(parents=True, exist_ok=True)
            with open(history_path, "a", encoding="utf-8") as f:
                f.write(payload + "\n")
        except Exception as e:
            log.warning("持久化对话历史失败 (task=%s): %s", self.task_id, e)
        # ★ T14 (0923 v2)：服务端事件镜像。
        #   修正前的裂缝：终端里"看得见"的发现（如「主动目录爆破发现 5 个
        #   敏感信息泄露」）只推 SSE，agent.log 里出现 0 次 → 事后无法审计
        #   "到底给用户看过什么"。0923 那次报告丢数据，若不是用户截图，
        #   根本无从发现（那是运气，不是设计）。
        #   镜像走 append-only jsonl，失败绝不影响主流程。
        self._mirror_event(event)
        return f"data: {payload}\n\n"

    # 终态事件名（五态）—— 与 web/server.py::terminal_events 保持一致
    TERMINAL_EVENT_MAP = {
        "done": "done",                       # completed
        "task_partial": "task_partial",       # partial（有组未完成/覆盖有洞）
        "task_unreachable": "task_unreachable",  # unreachable
        "task_failed": "task_failed",         # failed
        "task_aborted": "task_aborted",       # aborted
    }

    def _normalize_terminal_event(self, event_type: str) -> str:
        """把 ``done`` 收窄成五态之一（T9 / 修 B4）。

        修正前的问题：无论"扫完且确实没漏洞"还是"目标压根不可达"，最后都输出
        ``DONE 扫描完成`` —— 两个语义在产品和 UI 上完全同形，
        用户无法判断 `0 漏洞` 是真的干净还是根本没测。

        规则：
        - 目标不可达（``_target_unreachable``）→ ``task_unreachable``，且**不发 done**
        - 有子 Agent 组未完成（``_browse_stuck_groups``）→ ``task_partial``
        - 其余 → ``done``

        只改写 ``done``，其他事件原样通过（避免误伤 task_failed/aborted）。
        """
        if event_type != "done":
            return event_type
        if getattr(self, "_target_unreachable", False):
            return "task_unreachable"
        if getattr(self, "_browse_stuck_groups", None):
            return "task_partial"
        return "done"

    def _mirror_event(self, event: dict) -> None:
        """把事件追加写入 ``data/logs/events.jsonl``（T14）。

        只镜像"用户可见结论类"事件（system/vuln/error/终态），避免把
        message/thinking 这类高频流式输出也灌进去导致文件爆炸。
        """
        try:
            _etype = str(event.get("type", ""))
            if _etype not in _MIRROR_EVENT_TYPES:
                return
            mirror_path = Path("data/logs") / "events.jsonl"
            mirror_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "ts": time.time(),
                "task_id": getattr(self, "task_id", ""),
                "phase": getattr(self, "phase", ""),
                "type": _etype,
                "data": event.get("data"),
            }
            with open(mirror_path, "a", encoding="utf-8") as f:
                f.write(mirror_serialize(record) + "\n")
        except Exception:
            # 镜像失败绝不影响主流程；但也不能完全静默 —— 打一条 debug 级日志
            try:
                log.debug("事件镜像写入失败 (task=%s)", getattr(self, "task_id", ""),
                          exc_info=True)
            except Exception:
                pass

    @staticmethod
    def get_chat_history(task_id: str) -> list[dict]:
        """从文件加载完整对话历史。"""
        history_path = Path("data/tasks") / f"{task_id}-chat.jsonl"
        if not history_path.exists():
            return []
        events = []
        for line in history_path.read_text(encoding="utf-8").strip().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events
