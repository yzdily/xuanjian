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
                    log.info("恢复上次未完成的会话: task_id=%s, target=%s, features=%d",
                             task_id, sitemap.target, len(sitemap.features))
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
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self._strategy.on_task_done(self))
                else:
                    loop.run_until_complete(self._strategy.on_task_done(self))
            except Exception:
                pass
        if self.sitemap:
            self.sitemap.save()
        self.task_id = f"task_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        self.sitemap = None
        self.current_context = ContextManager(llm=self.llm)
        self.current_feature_id = None
        self.tool_executor = ToolExecutor()
        self._load_base_prompt()
        # ★ 清理 Cookie/Auth 注入环境变量（避免新任务沾染旧任务的凭证）
        for k in ("PENTEST_INJECT_COOKIES", "PENTEST_INJECT_AUTH", "PENTEST_INJECT_HEADERS", "PENTEST_INJECT_LOCAL_STORAGE", "PENTEST_TARGET_URL"):
            os.environ.pop(k, None)
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

        # 注入历史经验
        self._inject_memories(ctx)

        # Phase 2 开始时，注入 sitemap 摘要
        if self.phase == "test" and self.sitemap:
            ctx.add_system(f"## 当前站点地图\n\n{self.sitemap.to_summary()}")

        return ctx

    def _sync_tool_executor(self) -> None:
        """同步 sitemap 到 tool executor（让 sitemap_get_coverage 等工具能访问）。"""
        self.tool_executor.set_session(self)

    def _event(self, event_type: str, data, full: str = "") -> str:
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
        except Exception:
            pass
        return f"data: {payload}\n\n"

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
