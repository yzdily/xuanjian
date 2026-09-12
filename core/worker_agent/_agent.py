"""
WorkerAgent — Phase 2 并行测试子 Agent

每个 WorkerAgent 负责测试**一组**功能点的 HTTP checklist 项。
同组功能点共享上下文（业务关联、Session 信息），串行测试。

- 独立 LLM 上下文（独立 token 消耗）
- 只用 HTTP 工具（proxy_send_request/proxy_replay），不用浏览器
- checklist_mark 写入共享 Sitemap（线程安全）
- 主 Agent 分发 Cookie/Token，子 Agent 携带发请求
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncGenerator, Callable

from core.llm import LLMClient, Message, parse_tool_call_arguments, ContextLimitError
from core.context import ContextManager
from core.sitemap import Sitemap, FeaturePoint, CheckResult, TestStatus
from core.config import WORKER_MAX_ROUNDS
from core.tools import build_worker_tools
from core.tool_executor import ToolExecutor
from core.log import get_logger
from core.worker_agent._helpers import _WorkerAgentHelpers

log = get_logger("worker")

# ★ 2026-08-05：Worker 专用压缩阈值，比默认 30 更激进
# Worker 的静态 prompt（任务组+API样本）可达 24K+，每轮重发浪费严重；
# 15 轮后压缩可把历史摘要化，后续轮次只发摘要+近期对话。
WORKER_COMPRESS_THRESHOLD = 15

# ★ 2026-08-05：高 skip 率熔断阈值
# 当 skip 比例超过此值且未发现漏洞时，提前终止 worker 避免空转烧 token
WORKER_SKIP_CIRCUIT_BREAKER_RATIO = 0.5
WORKER_SKIP_CIRCUIT_BREAKER_MIN_ROUNDS = 3


class WorkerAgent(_WorkerAgentHelpers):
    """测试一组功能点的子 Agent。

    同组功能点共享上下文（认证信息、SKILL 方法论），串行逐个测试。
    支持向后兼容：如果传入单个 feature（旧调用方式），自动包装为列表。
    """

    def __init__(
        self,
        worker_id: str,
        llm: LLMClient,
        sitemap: Sitemap,
        session_info: dict,
        # 新参数：一组功能点
        features: list[FeaturePoint] | None = None,
        group_name: str = "",
        # 兼容旧参数：单个功能点
        feature: FeaturePoint | None = None,
        on_event: Callable | None = None,
    ):
        self.worker_id = worker_id
        self.llm = llm
        self.sitemap = sitemap
        self.session_info = session_info
        self.on_event = on_event

        # 兼容：旧代码传 feature=单个功能点
        if features:
            self.features = features
        elif feature:
            self.features = [feature]
        else:
            self.features = []

        self.group_name = group_name or (self.features[0].name if self.features else "未知组")

        # 当前正在测试的功能点索引
        self._current_idx = 0
        self.feature = self.features[0] if self.features else None  # 兼容旧属性

        self.context = ContextManager(llm=self.llm)
        self._init_context()

        self.completed = False
        self.error: str | None = None
        self._done_reject_count = 0

        # ★ 反内卷保护：跟踪同一接口连续测试次数 + 连续轮数无 checklist_mark
        self._url_method_streak: dict[str, int] = {}  # key="METHOD path", value=连续测试次数
        self._last_url_method_key: str = ""           # 上一次测试的 key
        self._rounds_without_mark: int = 0            # 连续多少轮没 checklist_mark
        self._anti_loop_warned: bool = False          # 是否已发过反内卷警告（防重复）
        self._vuln_nudge_sent: bool = False           # 是否已发过"漏洞证据未 mark"强提示（防重复）

        # ★ 必须传入 task_id，否则 note_add/note_read 会写到 default-*.md，
        # 导致子 Agent 的 info/infer/result 笔记与漏洞报告全部丢失。
        self.tool_executor = ToolExecutor(
            sitemap=sitemap,
            has_credentials=True,
            task_id=getattr(sitemap, "task_id", "default"),
        )

        # ★ 决策剧场：缓存 task_id / target，emit 时统一带上
        self._replay_task_id: str = getattr(sitemap, "task_id", "") or ""
        self._replay_target: str = getattr(sitemap, "target", "") or ""

    @property
    def current_feature(self) -> FeaturePoint | None:
        if 0 <= self._current_idx < len(self.features):
            return self.features[self._current_idx]
        return None

    async def run(self) -> AsyncGenerator[dict, None]:
        """运行子 Agent 直到所有功能点测试完成或出错。"""
        round_num = 0
        tools = build_worker_tools()
        # 增加 max_rounds：多功能点组需要更多轮次
        max_rounds = WORKER_MAX_ROUNDS * max(len(self.features), 1)

        # ★ 跟踪当前正在测试的功能点，切换时压缩上下文
        _prev_feature_id = self.features[0].id if self.features else None

        while round_num < max_rounds and not self.completed:
            round_num += 1

            # 更新当前功能点引用
            self.feature = self.current_feature

            # ★ 功能点切换检测 → 强制压缩上下文（释放前一个功能点的对话历史）
            curr_fid = self.feature.id if self.feature else None
            if curr_fid and curr_fid != _prev_feature_id:
                log.info("[%s] 功能点切换: %s → %s，压缩上下文",
                         self.worker_id, _prev_feature_id, curr_fid)
                self.context.compress()
                _prev_feature_id = curr_fid

            yield {"type": "worker_thinking", "worker": self.worker_id,
                   "feature": self.feature.name if self.feature else self.group_name,
                   "round": round_num}

            # ★ LLM 调用超时保护：asyncio.wait_for 兜底，防止 API 挂起导致 Worker 永久卡死
            # SDK 层已设 120s timeout，这里 180s 兜底（给 SDK 先抛出有意义的错误）
            _LLM_CALL_TIMEOUT = 180
            try:
                messages = self.context.get_messages()
                # ★ max_retries=3：内层 LLMClient.chat() 负责 3 次指数退避重试
                response = await asyncio.wait_for(
                    asyncio.to_thread(self.llm.chat, messages, tools, caller=f"worker:{self.worker_id}", max_retries=3),
                    timeout=_LLM_CALL_TIMEOUT,
                )
            except ContextLimitError as cle:
                # ★ Token 预检超限 → 自动压缩上下文后重试一次
                log.warning("[%s] 上下文超限，自动压缩后重试: 估算 %d tokens > 窗口 %d",
                            self.worker_id, cle.estimated_tokens, cle.context_window)
                self.context.compress()
                messages = self.context.get_messages()
                try:
                    response = await asyncio.wait_for(
                        asyncio.to_thread(self.llm.chat, messages, tools, caller=f"worker:{self.worker_id}", max_retries=3),
                        timeout=_LLM_CALL_TIMEOUT,
                    )
                except Exception as e_inner:
                    log.error("[%s] 压缩后重试仍失败: %s", self.worker_id, e_inner)
                    self.error = str(e_inner)
                    yield {"type": "worker_error", "worker": self.worker_id,
                           "feature": self.group_name, "error": f"上下文超限: {e_inner}"}
                    break
            except Exception as e:
                # ★ asyncio.TimeoutError → 转成可读消息，走重试逻辑
                if isinstance(e, asyncio.TimeoutError):
                    e = TimeoutError(f"LLM 调用超时（{_LLM_CALL_TIMEOUT}s），可能 API 挂起或模型无响应")
                # ★ 自动重试：网络错误/限流/5xx 最多重试 5 次（间隔递增），避免偶发抖动直接退出
                err_str = str(e).lower()
                err_type = type(e).__name__.lower()
                is_network_err = (
                    "connection error" in err_str or "connecterror" in err_type
                    or "timeout" in err_type or "dns" in err_type
                    or "could not resolve" in err_str or "nodename nor servname" in err_str
                    or "name or service not known" in err_str
                    or "connection refused" in err_str or "connection reset" in err_str
                    or "network is unreachable" in err_str
                    # ★ 限流与服务端临时错误（与 LLMClient._RETRYABLE_ERROR_KEYWORDS 对齐）
                    or "429" in err_str or "rate limit" in err_str or "rate_limit" in err_str
                    or "too many requests" in err_str
                    or "500" in err_str or "502" in err_str or "503" in err_str or "504" in err_str
                    or "overloaded" in err_str or "server_error" in err_str
                )
                _retried_ok = False
                if is_network_err:
                    for _retry in range(1, 6):
                        _wait = _retry * 5
                        log.info("Worker %s LLM 网络异常，重试 %d/5（等待 %ds）: %s",
                                 self.worker_id, _retry, _wait, e)
                        await asyncio.sleep(_wait)
                        try:
                            messages = self.context.get_messages()
                            # ★ max_retries=0：外层重试时内层不再重试，避免三层叠加（3×5=15 次→最多 3+5=8 次）
                            response = await asyncio.wait_for(
                                asyncio.to_thread(self.llm.chat, messages, tools, caller=f"worker:{self.worker_id}", max_retries=0),
                                timeout=_LLM_CALL_TIMEOUT,
                            )
                            _retried_ok = True
                            break
                        except Exception:
                            continue
                if not _retried_ok:
                    self.error = str(e)
                    yield {"type": "worker_error", "worker": self.worker_id,
                           "feature": self.group_name, "error": str(e)}
                    break

            self.context.add_assistant(response)

            if response.content:
                # ★ 过滤无意义的推理文本（"Let me examine..." / "I'll work through..." 等）
                # 只在有实质内容时才推送，避免前端被废话刷屏
                _content = response.content.strip()
                _is_boilerplate = any(
                    _content.lower().startswith(p)
                    for p in ("let me ", "i'll ", "i will ", "now let me ", "first, let me ")
                ) and len(_content) < 150
                if not _is_boilerplate:
                    yield {"type": "worker_message", "worker": self.worker_id,
                           "feature": self.feature.name if self.feature else self.group_name,
                           "content": _content[:800]}

            if response.tool_calls:
                # ★ 反内卷跟踪：本轮是否有 checklist_mark
                this_round_has_mark = False
                for tc in response.tool_calls:
                    func_name = tc["function"]["name"]
                    args, args_failed = parse_tool_call_arguments(
                        tc["function"]["arguments"], caller=f"worker:{self.worker_id}")

                    # ★ tool_call arguments 解析失败时，不要用空 args 继续执行
                    # （会导致工具用默认参数跑、行为不可预期），而是回填错误让 LLM 重发。
                    if args_failed:
                        _err_hint = (
                            f"⚠️ 工具 `{func_name}` 的 arguments 解析失败，"
                            f"无法识别参数。请重新调用该工具，arguments 必须是合法 JSON "
                            f"（如 {chr(123)}\"url\": \"...\", \"method\": \"GET\"{chr(125)}）。"
                        )
                        try:
                            self.context.add_tool_result(tc["id"], _err_hint)
                        except Exception:
                            pass
                        log.warning("[%s] tool_call %s args 解析失败，已回填提示 LLM 重发",
                                    self.worker_id, func_name)
                        continue

                    # ★ 反内卷：跟踪同一接口连续测试次数
                    if func_name in ("proxy_send_request", "proxy_replay", "proxy_batch_send"):
                        try:
                            from urllib.parse import urlparse as _up
                            url_arg = args.get("url") or args.get("base_url") or ""
                            method_arg = (args.get("method") or "GET").upper()
                            if url_arg:
                                parsed = _up(url_arg)
                                # 只取 host+path，去掉 query 和 fragment
                                _key = f"{method_arg} {parsed.netloc}{parsed.path}"
                                if _key == self._last_url_method_key:
                                    self._url_method_streak[_key] = self._url_method_streak.get(_key, 0) + 1
                                else:
                                    self._url_method_streak[_key] = 1
                                self._last_url_method_key = _key
                        except Exception as _e:
                            log.debug("[%s] 反内卷 URL 跟踪失败: %s", self.worker_id, _e)
                    if func_name == "checklist_mark":
                        this_round_has_mark = True
                        # mark 后重置该 URL 的内卷计数（因为已经下结论了）
                        self._url_method_streak.clear()
                        self._last_url_method_key = ""

                    # 摘要：隐藏 headers/Cookie，只显示关键参数
                    args_full_str = json.dumps(args, ensure_ascii=False)
                    brief_args = {k: ("{...}" if k.lower() in ("headers", "cookie") else
                                      (v[:60] + "..." if isinstance(v, str) and len(v) > 60 else v))
                                  for k, v in args.items()}
                    args_brief_str = json.dumps(brief_args, ensure_ascii=False)[:150]

                    yield {"type": "worker_tool", "worker": self.worker_id,
                           "feature": self.feature.name if self.feature else self.group_name,
                           "tool_brief": f"{func_name}({args_brief_str})",
                           "tool_full": f"{func_name}({args_full_str})"}

                    # ★ 决策剧场：每个 tool_call 都是一次"LLM 决策"
                    # 注意：checklist_mark 走 HARM_VALIDATED 帧（在 tool_executor 里 emit），这里不重复
                    if func_name != "checklist_mark":
                        try:
                            from core.replay import emit_decision as _ed
                            # vuln_type 推断：args 里有 vuln_type 直接用，否则从当前 feature 取第一个 pending
                            _vt = args.get("vuln_type", "") if isinstance(args, dict) else ""
                            if not _vt and self.current_feature:
                                _pending = self.current_feature.get_http_pending()
                                if _pending:
                                    _vt = _pending[0].vuln_type
                            # LLM 思考摘要：本次 response.content / reasoning_content
                            _summary = (response.content or "")[:1500]
                            if not _summary and getattr(response, "reasoning_content", ""):
                                _summary = (response.reasoning_content or "")[:1500]
                            # target_url 优先从 args 里抠
                            _turl = ""
                            if isinstance(args, dict):
                                _turl = args.get("url") or args.get("base_url") or ""
                            _ed(
                                task_id=self._replay_task_id,
                                worker_id=self.worker_id,
                                feature_id=self.current_feature.id if self.current_feature else "",
                                feature_name=self.current_feature.name if self.current_feature else self.group_name,
                                vuln_type=_vt,
                                skill_used=func_name,
                                payload=args_brief_str,
                                target_url=_turl or self._replay_target,
                                llm_summary=_summary,
                                track="llm",
                                round=round_num,
                            )
                        except Exception as _e:
                            log.debug("[%s] 决策剧场 emit 失败: %s", self.worker_id, _e)

                    try:
                        # 传入当前功能点（checklist_mark 需要 feature 上下文）
                        result, is_completed, self._done_reject_count = \
                            await self._execute_tool(func_name, args)
                    except Exception as e:
                        result = f"工具执行出错: {e}"
                        is_completed = False

                    # ★ 截图工具：实时向前端推送截图事件
                    if func_name == "browser_screenshot" and isinstance(result, str) \
                            and "截图已保存" in result:
                        ss_name = args.get("name", "screenshot") if isinstance(args, dict) else "screenshot"
                        yield {"type": "worker_screenshot", "worker": self.worker_id,
                               "feature": self.feature.name if self.feature else self.group_name,
                               "name": ss_name}

                    if len(result) > 6000:
                        result = result[:6000] + "\n... (截断)"

                    self.context.add_tool_result(tc["id"], result)

                    if is_completed:
                        self.completed = True
                        break

                # ★ 反内卷判定（在 tool_calls 循环结束后做一次）
                if not self.completed:
                    self._rounds_without_mark = 0 if this_round_has_mark else (self._rounds_without_mark + 1)
                    streak_max = max(self._url_method_streak.values(), default=0)

                    # 触发条件：①同一接口连续 ≥ 30 次  或  ②连续 ≥ 30 轮没 mark
                    # 2026-05-23: no_mark 阈值从 10 放宽到 20（单个漏洞类型正常探测需 5-8 轮）
                    # 2026-05-29: no_mark 阈值从 20 放宽到 30（复杂漏洞深度测试需更多轮次）
                    should_warn = (streak_max >= 30) or (self._rounds_without_mark >= 30)

                    # ★ 2026-05-20 修复（A）：漏洞验证豁免
                    # 如果最近几轮 LLM 输出里已经出现明确的"发现漏洞/泄露"证据，
                    # 但还没来得及 checklist_mark，反内卷应该让步给 LLM 完成验证标记。
                    # 否则会出现"发现 SQL 注入但被强制收尾，最终 0 漏洞"的严重 bug。
                    if should_warn:
                        vuln_evidence = self._detect_vuln_evidence_in_history()
                        if vuln_evidence:
                            # 不触发反内卷，但插入一条强提醒：立刻 mark
                            if not getattr(self, "_vuln_nudge_sent", False):
                                self.context.add_system(
                                    "## 🚨 检测到漏洞证据但未 mark — 立即固化\n\n"
                                    f"你最近的输出里出现了漏洞证据关键词：**{vuln_evidence}**。\n"
                                    "**强制要求：你的下一个动作必须是 `checklist_mark`**：\n"
                                    "- `result=\"vulnerable\"` + 详细 `detail`（payload / 响应特征 / 影响）\n"
                                    "- 或 `result=\"needs_review\"` + 复现步骤（如果还需补一两个 payload 才能盖章）\n\n"
                                    "**禁止继续发新 payload 探测**——证据已经够了，先固化再说。"
                                )
                                self._vuln_nudge_sent = True
                                log.warning("[%s] 反内卷豁免: 检测到漏洞证据 [%s]，已强提示 LLM mark",
                                            self.worker_id, vuln_evidence)
                                yield {"type": "worker_message", "worker": self.worker_id,
                                       "feature": self.feature.name if self.feature else self.group_name,
                                       "content": f"🛡️ 反内卷豁免：检测到漏洞证据「{vuln_evidence}」，已强提示 LLM 立即固化"}
                            # 给 LLM 5 轮额外时间完成 mark（reset 计数，不让反内卷立刻再触发）
                            self._url_method_streak.clear()
                            self._last_url_method_key = ""
                            # _rounds_without_mark 不重置：如果给了豁免还不 mark，下一轮该触发还得触发
                            should_warn = False  # 跳过本轮 nudge

                    if should_warn and not self._anti_loop_warned:
                        # 找到最热的 URL（仅用于提示）
                        hot_key = max(self._url_method_streak.items(), key=lambda x: x[1])[0] \
                            if self._url_method_streak else "(无)"
                        nudge = (
                            "## ⚠️ 反内卷强制收尾\n\n"
                            f"检测到你在同一接口反复测试无进展：\n"
                            f"- 最热接口：`{hot_key}` 已连续测试 {streak_max} 次\n"
                            f"- 连续 {self._rounds_without_mark} 轮未调用 checklist_mark\n\n"
                            "**立即执行以下二选一：**\n"
                            "1. 如果你已得出结论 → 调用 `checklist_mark` 给当前 checklist 项打分"
                            "（result=`not_vuln` / `skipped` / `vulnerable`，附 detail 简述判断依据），"
                            "然后切到下一个测试方向；\n"
                            "2. 如果该接口确实没有可测点 → 直接对当前功能点的所有未测项标 `skipped` "
                            "（reason=\"接口无回显/参数不影响响应/已穷举无可疑点\"），然后调用 `worker_done` 收尾。\n\n"
                            "⚠️ **如果你已发现可疑漏洞（如 SQL 错误、堆栈泄露、敏感数据回显），"
                            "请立即 `checklist_mark vulnerable` 并把证据写到 detail 里——不要再换 payload 试**！\n\n"
                            "⛔ 不允许继续在同一接口换载荷试探，浪费预算。"
                        )
                        self.context.add_system(nudge)
                        log.warning("[%s] 反内卷触发: hot=%s streak=%d no_mark=%d",
                                    self.worker_id, hot_key, streak_max, self._rounds_without_mark)
                        yield {"type": "worker_message", "worker": self.worker_id,
                               "feature": self.feature.name if self.feature else self.group_name,
                               "content": f"⚠️ 反内卷触发：同接口连测 {streak_max} 次或连续 {self._rounds_without_mark} 轮未 mark — 已强制提示收尾"}
                        self._anti_loop_warned = True
                        # 重置计数：给 LLM 一次机会响应，没响应再触发一次升级
                        self._url_method_streak.clear()
                        self._last_url_method_key = ""
                        self._rounds_without_mark = 0
                    elif should_warn and self._anti_loop_warned:
                        # 第二次触发 → 直接给所有未测项标 skipped + 强制 worker_done
                        # ★ 2026-05-20 修复（A）：强制收尾前抢救漏洞证据
                        # 如果历史里有未 mark 的漏洞证据，自动写一个 needs_review 项保留线索
                        log.warning("[%s] 反内卷二次触发 → 强制收尾", self.worker_id)
                        from core.sitemap import CheckResult as _CR
                        salvage_evidence = self._detect_vuln_evidence_in_history()
                        salvaged_count = 0
                        if salvage_evidence:
                            # 尝试找一个相关的 pending checklist 项标 needs_review
                            for fp in self.features:
                                for c in fp.checklist:
                                    if c.result == _CR.PENDING:
                                        # 优先把最相关的 vuln_type 标 needs_review（粗略匹配）
                                        if any(kw in c.vuln_type.lower() for kw in
                                               (salvage_evidence.lower(), "注入" if "sql" in salvage_evidence.lower() else "")):
                                            c.result = _CR.NEEDS_REVIEW
                                            c.detail = (
                                                f"⚠️ 反内卷强制收尾前抢救保留：worker 输出包含漏洞证据「{salvage_evidence}」"
                                                f"但未完成 checklist_mark，请人工复测验证。"
                                            )
                                            salvaged_count += 1
                                            break  # 只标第一个匹配项
                                if salvaged_count > 0:
                                    break
                        forced_skip_count = 0
                        for fp in self.features:
                            for c in fp.checklist:
                                if c.result == _CR.PENDING:
                                    c.result = _CR.SKIPPED
                                    # ★ 补全 detail：标注反内卷触发条件，让报告可追溯
                                    c.detail = (
                                        f"反内卷强制收尾：worker 在同一接口连续测试 {streak_max} 次 "
                                        f"且连续 {self._rounds_without_mark} 轮无 checklist_mark，"
                                        f"未得出明确结论，建议人工补测。"
                                    )
                                    forced_skip_count += 1
                        self.completed = True
                        salvage_msg = f"，⚠️ 抢救保留 {salvaged_count} 项 needs_review（检测到证据「{salvage_evidence}」）" if salvaged_count else ""
                        yield {"type": "worker_message", "worker": self.worker_id,
                               "feature": self.group_name,
                               "content": f"🛑 反内卷强制收尾：自动跳过 {forced_skip_count} 个未结论项{salvage_msg}"}
            else:
                break

            # ★ 2026-08-05 优化1：Worker 专用压缩阈值（15 轮，比默认 30 更激进）
            # Worker 静态 prompt（任务组+API样本）可达 24K+，每轮重发浪费严重
            # ★ 2026-08-07：增加 token 触发——当 token 估算超阈值时也压缩
            if self.context.turn_count >= WORKER_COMPRESS_THRESHOLD or self.context.should_compress_by_tokens():
                self.context.compress()

            # ★ 2026-08-05 优化3：高 skip 率熔断
            # 当 skip 比例超过 50% 且未发现漏洞时，提前终止避免空转烧 token
            if round_num >= WORKER_SKIP_CIRCUIT_BREAKER_MIN_ROUNDS:
                _total_checks = sum(len(fp.checklist) for fp in self.features)
                _skip_count = sum(
                    1 for fp in self.features for c in fp.checklist
                    if c.result == CheckResult.SKIPPED
                )
                _vuln_count = sum(
                    1 for fp in self.features for c in fp.checklist
                    if c.result == CheckResult.VULNERABLE
                )
                if (_total_checks > 0
                        and _skip_count / _total_checks >= WORKER_SKIP_CIRCUIT_BREAKER_RATIO
                        and _vuln_count == 0):
                    log.warning("[%s] skip 率熔断: %d/%d 项已 skip (%.0f%%)，0 漏洞，第 %d 轮提前终止",
                                self.worker_id, _skip_count, _total_checks,
                                _skip_count / _total_checks * 100, round_num)
                    # 将剩余 pending 项标记为 skipped
                    _circuit_skip = 0
                    for fp in self.features:
                        for c in fp.checklist:
                            if c.result == CheckResult.PENDING:
                                c.result = CheckResult.SKIPPED
                                c.detail = "skip 率熔断：worker 高 skip 率提前终止，建议人工补测"
                                _circuit_skip += 1
                    self.completed = True
                    yield {"type": "worker_message", "worker": self.worker_id,
                           "feature": self.group_name,
                           "content": f"🛑 skip 率熔断：{_skip_count}/{_total_checks} 项已 skip，0 漏洞，提前终止（跳过 {_circuit_skip} 个未测项）"}

            # ★ 2026-08-05 优化6：无进展熔断
            # 连续 20 轮没有新的 checklist 进展（无 VULNERABLE/needs_review 变更），提前终止
            # 此前任务组「other」1 功能点跑满 100 轮（183 次调用），纯空转烧 token
            if round_num >= 20 and round_num % 10 == 0:
                _done_now = sum(
                    1 for fp in self.features for c in fp.checklist
                    if c.result in (CheckResult.VULNERABLE, CheckResult.NOT_VULN, CheckResult.NEEDS_REVIEW)
                )
                if _done_now == getattr(self, "_last_done_count", -1) and _done_now > 0:
                    # 与 10 轮前相比无进展
                    log.warning("[%s] 无进展熔断: %d 轮无新 checklist 进展（%d 项已完成），提前终止",
                                self.worker_id, 10, _done_now)
                    for fp in self.features:
                        for c in fp.checklist:
                            if c.result == CheckResult.PENDING:
                                c.result = CheckResult.SKIPPED
                                c.detail = "无进展熔断：worker 长时间无新进展，建议人工补测"
                    self.completed = True
                    yield {"type": "worker_message", "worker": self.worker_id,
                           "feature": self.group_name,
                           "content": f"🛑 无进展熔断：连续 10 轮无新进展，提前终止"}
                    break
                self._last_done_count = _done_now

        # 完成后标记所有功能点状态
        # ★ 根据 worker 退出原因区分 normal/error/anti_loop，
        # 让报告能区分"正常结束未覆盖" vs "worker 崩溃漏测"
        exit_reason = "normal"
        if self.error:
            exit_reason = "error"
        elif getattr(self, "_anti_loop_warned", False):
            exit_reason = "anti_loop"
        for fp in self.features:
            if fp.test_status in (TestStatus.NOT_TESTED, TestStatus.IN_PROGRESS):
                self.sitemap.finish_test(fp.id, reason=exit_reason)
        self.sitemap.save()

        # 汇总统计
        total_vulns = sum(
            1 for fp in self.features for c in fp.checklist
            if c.result == CheckResult.VULNERABLE
        )
        total_completed = sum(
            1 for fp in self.features for c in fp.checklist
            if c.result != CheckResult.PENDING
        )
        total_checks = sum(len(fp.checklist) for fp in self.features)
        features_done = sum(
            1 for fp in self.features
            if fp.test_status in (TestStatus.TESTED, TestStatus.VULN_FOUND)
        )

        yield {"type": "worker_done", "worker": self.worker_id,
               "group": self.group_name,
               "features_done": features_done,
               "features_total": len(self.features),
               "vulns": total_vulns,
               "completed": total_completed,
               "total": total_checks}

    async def _execute_tool(self, func_name: str, args: dict) -> tuple[str, bool, int]:
        """执行工具调用，处理 checklist_mark 的 feature_id 路由。

        对于 checklist_mark，需要根据 feature_id 找到正确的功能点。
        对于 worker_done，检查是否所有功能点都已测完。
        """
        if func_name == "worker_done":
            # 检查是否所有功能点的 checklist 都已标记
            all_pending = []
            for fp in self.features:
                pending = [c for c in fp.checklist if c.result == CheckResult.PENDING and not c.needs_browser]
                if pending:
                    all_pending.append((fp, [c for c in pending]))

            if all_pending and self._done_reject_count < 3:
                self._done_reject_count += 1
                detail = "\n".join(
                    f"- {fp.name} ({fp.id}): {', '.join(c.vuln_type for c in checks)}"
                    for fp, checks in all_pending
                )

                if self._done_reject_count <= 2:
                    # 前 2 次：明确告诉 LLM 还有哪些没测，要求补测
                    return (
                        f"⛔ 拒绝完成（第 {self._done_reject_count}/3 次）：\n"
                        f"还有 {len(all_pending)} 个功能点共 "
                        f"{sum(len(checks) for _, checks in all_pending)} 个未测项：\n{detail}\n\n"
                        f"**请对每个未测项执行测试并 checklist_mark，或标记 skipped（附说明原因）。**\n"
                        f"⚠️ 不允许直接跳过未测项！每个 checklist 项必须有结论。",
                        False, self._done_reject_count
                    )
                else:
                    # 第 3 次：自动把遗漏项标为 skipped，然后放行（防止死循环）
                    auto_skipped = 0
                    for fp, checks in all_pending:
                        for c in checks:
                            c.result = CheckResult.SKIPPED
                            # ★ 补全 detail：明确标注是 worker_done 拒绝后强制 skip，
                            # 让报告能区分"LLM 主动跳过" vs "系统强制兜底"
                            c.detail = (
                                "⚠️ 子 Agent 多次拒绝完成（worker_done 被拒 3 次），"
                                "系统强制标记 skipped。该项未实际测试，建议人工补测。"
                            )
                            auto_skipped += 1
                    log.warning("[%s] worker_done 第3次拒绝后自动 skip %d 个未测项",
                                self.worker_id, auto_skipped)
                    return (
                        f"⚠️ 强制完成：{auto_skipped} 个未测项已自动标记为 skipped（漏检）。\n"
                        f"这些项会在报告中标注为「子 Agent 未覆盖」。",
                        True, self._done_reject_count
                    )
            else:
                return "✅ 所有功能点测试完成", True, self._done_reject_count

        if func_name == "checklist_mark":
            # 如果 args 中没有 feature_id，尝试推断
            if "feature_id" not in args and self.current_feature:
                args["feature_id"] = self.current_feature.id

        # 根据 feature_id 找到组内正确的功能点
        target_feature = self.current_feature or (self.features[0] if self.features else None)
        if "feature_id" in args:
            fid = args["feature_id"]
            for fp in self.features:
                if fp.id == fid:
                    target_feature = fp
                    break

        # 委托给 ToolExecutor
        result, is_completed, reject_count = await self.tool_executor.execute_for_worker(
            func_name, args, target_feature, self._done_reject_count
        )

        # 如果是 worker_done 从 execute_for_worker 返回的 complete 信号
        if is_completed and func_name == "worker_done":
            return result, True, reject_count

        # ★ checklist_mark 后检测：当前功能点是否所有 HTTP 项都完成了？
        # 如果完成 → 自动递增 _current_idx 推进到下一个功能点
        if func_name == "checklist_mark" and self.current_feature:
            curr_pending = self.current_feature.get_http_pending()
            if not curr_pending:
                # 当前功能点所有 HTTP 项已完成
                old_idx = self._current_idx
                if self._current_idx < len(self.features) - 1:
                    self._current_idx += 1
                    next_fp = self.features[self._current_idx]
                    log.info("[%s] 功能点 %s 全部完成，推进到 %s (idx %d→%d)",
                             self.worker_id, self.current_feature.name if old_idx < len(self.features) else "?",
                             next_fp.name, old_idx, self._current_idx)
                    # 在结果中提示 LLM 继续下一个功能点
                    result += f"\n\n✅ 当前功能点已全部测完。请继续测试下一个功能点：{next_fp.name} ({next_fp.id})"

        return result, False, reject_count
