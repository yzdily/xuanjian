"""
RealtimeWorker — 实时扫描模式核心组件。

包含：
- FlowWatcher: 后台守护线程，轮询 mitmproxy FlowStore，识别功能型 API 包并触发即时测试
- RealtimeWorker: 单轮快速测试器，针对单个功能点执行漏洞检测
- test_single_feature: 独立测试函数，供 FlowWatcher 和 strategy 调用

设计要点：
- FlowWatcher 监控 Phase 0 + Phase 1 的全部流量（统一监控点）
- 最大并发 3 个 RealtimeWorker
- 30 秒 debounce 防止对同一功能点的重复测试
- 测试结果实时写入 Sitemap.checklist 并推送 SSE 事件
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import AsyncGenerator, TYPE_CHECKING
from urllib.parse import urlparse

from core.context import ContextManager
from core.sitemap import CheckResult, FeaturePoint
from core.config import WORKER_MAX_ROUNDS
from core.tools import build_worker_tools
from core.llm import parse_tool_call_arguments
from core.tool_executor import ToolExecutor
from core.prompts.phases import WORKER_SYSTEM_PROMPT
from core.log import get_logger

if TYPE_CHECKING:
    from core.session import AgentSession
    from core.llm import LLMClient

log = get_logger("realtime_worker")

# ---- 配置常量 ----
MAX_CONCURRENT_WORKERS = 3       # 最大并发 RealtimeWorker 数
DEBOUNCE_SECONDS = 30            # 同一功能点去重时间窗口
FLOW_POLL_INTERVAL = 5           # FlowWatcher 轮询间隔（秒）
MAX_FEATURE_QUEUE_SIZE = 50      # 待测功能点队列上限
STATIC_EXTENSIONS = frozenset({
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.mp4',
    '.mp3', '.wav', '.flv', '.avi', '.zip', '.tar', '.gz',
})
# 功能型 API 判定关键词（非静态、非追踪类）
FEATURE_API_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class RealtimeWorker:
    """单功能点快速测试器。

    与 WorkerAgent 的区别：
    - 只测试一个功能点（WorkerAgent 测试一组）
    - 单轮 LLM 交互（WorkerAgent 多轮）
    - 专注 HTTP 工具测试，不需要浏览器
    - 更轻量的 context 初始化
    """

    def __init__(
        self,
        worker_id: str,
        llm: "LLMClient",
        session_info: dict,
        feature: FeaturePoint,
        sitemap,  # Sitemap
    ):
        self.worker_id = worker_id
        self.llm = llm
        self.session_info = session_info
        self.feature = feature
        self.sitemap = sitemap

        self.context = ContextManager(llm=self.llm)
        self._init_context()
        self.tool_executor = ToolExecutor(sitemap=self.sitemap, task_id=self.sitemap.task_id, realtime_mode=True)
        self.tool_executor.current_feature_id = self.feature.id

        self.completed = False
        self.error: str | None = None

    def _init_context(self) -> None:
        """初始化 Worker 上下文。"""
        self.context.add_system(WORKER_SYSTEM_PROMPT)

        # 注入 SKILL 方法论
        core_dir = Path(__file__).parent
        skills_dir = Path(core_dir / "no-auth-quick-test" / "SKILL.md")
        if skills_dir.exists():
            self.context.add_system(skills_dir.read_text(encoding="utf-8"))

        # ★ Hermes 风格历史经验注入：按本功能点的 vuln_type 精准召回
        self._inject_lessons_by_vuln_type()

        # 注入功能点信息
        check_items = []
        for c in self.feature.checklist:
            status = "⏳" if c.result == CheckResult.PENDING else (
                "✅" if c.result == CheckResult.VULN else "❌"
            )
            check_items.append(f"  [{status}] {c.vuln_type}")

        feature_prompt = (
            f"## 功能点：{self.feature.name}\n\n"
            f"描述：{self.feature.description}\n\n"
            f"模块：{self.feature.module or '未知'}\n\n"
            f"页面：{self.feature.page_url or '未知'}\n\n"
            f"### Checklist（{len(self.feature.checklist)} 项）\n"
            + "\n".join(check_items)
            + "\n\n"
        )

        # 注入关联 API 样本
        if self.feature.related_apis:
            feature_prompt += "### 关联 API\n\n"
            for api_ref in self.feature.related_apis[:10]:
                # 从 sitemap.api_samples 中获取完整请求样本
                sample = self.sitemap.api_samples.get(api_ref)
                if sample:
                    feature_prompt += (
                        f"**{api_ref}**\n"
                        f"  请求头: {json.dumps(sample.get('headers', {}), ensure_ascii=False)[:300]}\n"
                        f"  请求体: {sample.get('body', '')[:500]}\n"
                        f"  响应码: {sample.get('status_code', 0)}\n"
                        f"  响应体: {sample.get('response_body', '')[:300]}\n\n"
                    )
                else:
                    feature_prompt += f"- `{api_ref}`（无样本）\n"

        # 注入认证信息
        if self.session_info.get("headers"):
            auth_info = "### 认证信息\n\n"
            for k, v in self.session_info["headers"].items():
                if k.lower() in ("cookie", "authorization"):
                    val_preview = v[:80] + "..." if len(v) > 80 else v
                    auth_info += f"- {k}: {val_preview}\n"
            feature_prompt += auth_info

        self.context.add_user(
            feature_prompt + "\n\n"
            "请快速对以上功能点进行漏洞检测。每个 checklist 项测完后用 `checklist_mark` 记录结果。\n"
            "测试完成后调用 `done` 工具。\n"
            "⚠️ 只测 HTTP 接口，不使用浏览器。注意控制测试轮次（最多 5 轮）。"
        )

    async def run(self) -> AsyncGenerator[dict, None]:
        """执行单功能点测试，yield 事件字典。"""
        from core.llm import set_current_task
        worker_tools = build_worker_tools()
        max_rounds = min(5, WORKER_MAX_ROUNDS)

        for round_num in range(1, max_rounds + 1):
            try:
                messages = self.context.get_messages()
                response = await asyncio.to_thread(
                    self.llm.chat, messages, worker_tools
                )
            except Exception as e:
                self.error = str(e)
                yield {"type": "realtime_worker_error", "worker_id": self.worker_id,
                       "error": str(e), "feature": self.feature.name}
                break

            self.context.add_assistant(response)

            if response.content:
                yield {
                    "type": "realtime_worker_message",
                    "worker_id": self.worker_id,
                    "content": response.content[:500],
                    "feature": self.feature.name,
                    "round": round_num,
                }

            if not response.tool_calls:
                break

            # 确保 tool_executor 的 sitemap 和 feature_id 保持同步
            self.tool_executor.sitemap = self.sitemap
            self.tool_executor.current_feature_id = self.feature.id

            for tc in response.tool_calls:
                func_name = tc["function"]["name"]
                args, _args_failed = parse_tool_call_arguments(
                    tc["function"]["arguments"], caller=f"realtime:{getattr(self, 'worker_id', '?')}")

                if func_name == "done":
                    self.completed = True
                    yield {"type": "realtime_worker_done", "worker_id": self.worker_id,
                           "feature": self.feature.name, "rounds": round_num}
                    return

                yield {"type": "realtime_worker_tool", "worker_id": self.worker_id,
                       "tool": f"{func_name}({json.dumps(args, ensure_ascii=False)[:100]})"}

                # ★ 决策剧场：实时模式的 LLM 决策也录入
                if func_name != "checklist_mark":
                    try:
                        from core.replay import emit_decision as _ed
                        _vt = args.get("vuln_type", "") if isinstance(args, dict) else ""
                        if not _vt and self.feature:
                            _pending = [c for c in self.feature.checklist if c.result == CheckResult.PENDING]
                            if _pending:
                                _vt = _pending[0].vuln_type
                        _summary = (response.content or "")[:1500] if response.content else ""
                        _turl = ""
                        if isinstance(args, dict):
                            _turl = args.get("url") or args.get("base_url") or ""
                        _ed(
                            task_id=getattr(self.sitemap, "task_id", "") or "",
                            worker_id=self.worker_id,
                            feature_id=self.feature.id,
                            feature_name=self.feature.name,
                            vuln_type=_vt,
                            skill_used=func_name,
                            payload=json.dumps(args, ensure_ascii=False)[:500],
                            target_url=_turl or getattr(self.sitemap, "target", "") or "",
                            llm_summary=_summary,
                            track="llm",
                            mode="realtime",
                            round=round_num,
                        )
                    except Exception:
                        pass

                try:
                    result = await self.tool_executor.execute(func_name, args)
                except Exception as e:
                    result = f"工具执行出错: {e}"

                if len(result) > 2000:
                    result = result[:2000] + "\n... (截断)"

                self.context.add_tool_result(tc["id"], result)

                yield {"type": "realtime_worker_tool_result", "worker_id": self.worker_id,
                       "content": result[:300], "feature": self.feature.name}

        self.completed = True
        yield {"type": "realtime_worker_done", "worker_id": self.worker_id,
               "feature": self.feature.name, "rounds": max_rounds}

    def _inject_lessons_by_vuln_type(self) -> None:
        """按本功能点的 vuln_type 精准召回历史教训并注入上下文。

        与 WorkerAgent._inject_lessons_by_vuln_type 逻辑一致，
        区别是 RealtimeWorker 只测一个功能点，所以只从 self.feature 收集 vuln_type。
        """
        try:
            from core import memory
        except Exception as e:
            log.warning("[%s] 加载 memory 模块失败，跳过历史经验注入: %s", self.worker_id, e)
            return

        # 收集本功能点涉及的 vuln_type
        vuln_types: list[str] = []
        seen: set[str] = set()
        for c in self.feature.checklist:
            if c.vuln_type and c.vuln_type not in seen:
                seen.add(c.vuln_type)
                vuln_types.append(c.vuln_type)
        if not vuln_types:
            return

        target_url = getattr(self.sitemap, "target", "") or ""
        all_lessons: list[dict] = []
        seen_ids: set[str] = set()

        for vt in vuln_types:
            try:
                lessons = memory.recall(
                    target_url=target_url,
                    vuln_type=vt,
                    query=vt,
                    limit=3,
                )
            except Exception as e:
                log.warning("[%s] memory.recall(%s) 失败: %s", self.worker_id, vt, e)
                continue
            for ls in lessons:
                lid = ls.get("id", "")
                if lid and lid not in seen_ids:
                    seen_ids.add(lid)
                    all_lessons.append(ls)
                    if len(all_lessons) >= 12:
                        break
            if len(all_lessons) >= 12:
                break

        if not all_lessons:
            return

        try:
            block = memory.format_for_prompt(all_lessons)
        except Exception as e:
            log.warning("[%s] format_for_prompt 失败: %s", self.worker_id, e)
            return

        if not block:
            return

        self.context.add_system(block)
        log.info("[%s] 注入 %d 条历史经验（覆盖 %d 个 vuln_type）",
                 self.worker_id, len(all_lessons), len(vuln_types))


class _SessionProxy:
    """轻量 Session 代理，只暴露 sitemap 给 ToolExecutor。

    用于 checklist_mark 等工具访问共享 sitemap，无需完整 AgentSession。
    """

    def __init__(self, sitemap):
        self.sitemap = sitemap
        self.task_id = sitemap.task_id
        self.phase = "test"
        self.current_feature_id = None


class FlowWatcher:
    """流量监控守护线程。

    轮询 mitmproxy FlowStore，识别功能型 API 包，
    匹配或创建功能点，触发 RealtimeWorker 即时测试。

    同时支持直接调用 test_feature_now() 对已知功能点即时测试
    （用于 Phase 0 generate_atomic_features 产生的功能点）。
    """

    def __init__(
        self,
        session: "AgentSession",
        event_queue: asyncio.Queue[str] | None = None,
    ):
        self.session = session
        self.event_queue = event_queue
        self._running = False
        self._task: asyncio.Task | None = None
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_WORKERS)
        self._active_workers: dict[str, asyncio.Task] = {}
        self._feature_queue: asyncio.Queue[FeaturePoint] = asyncio.Queue(
            maxsize=MAX_FEATURE_QUEUE_SIZE
        )
        # 去重：feature_id → 最近测试时间
        self._tested_features: dict[str, float] = {}
        # 记录每个功能点测试时的 related_apis 数量（用于检测新 API 补测）
        self._tested_api_count: dict[str, int] = {}
        # 已知的 flow id（避免重复处理）
        self._seen_flow_ids: set[str] = set()
        # 最后一次轮询时间
        self._last_poll_time = 0.0

    async def start(self) -> None:
        """启动 FlowWatcher。"""
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        # 同时启动消费协程
        asyncio.create_task(self._consume_loop())
        log.info("FlowWatcher 已启动 (session=%s)", self.session.task_id)

    async def stop(self) -> None:
        """停止 FlowWatcher。"""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("FlowWatcher 已停止 (session=%s)", self.session.task_id)

    async def stop_and_flush(self) -> AsyncGenerator[str, None]:
        """停止 FlowWatcher 并等待所有活跃 Worker 完成。"""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

        # 等待活跃 Worker 完成
        if self._active_workers:
            yield self.session._event(
                "system",
                f"⚡ 等待 {len(self._active_workers)} 个实时测试完成..."
            )
            done, _ = await asyncio.wait(
                self._active_workers.values(),
                timeout=60,
            )
            for t in done:
                if t.exception():
                    log.warning("Worker 完成异常: %s", t.exception())

        yield self.session._event(
            "system",
            f"⚡ FlowWatcher 已停止，已完成 {len(self._tested_features)} 个功能点的实时测试"
        )

    async def test_feature_now(self, feature: FeaturePoint) -> AsyncGenerator[str, None]:
        """对指定功能点立即触发实时测试（供 RealtimeStrategy.on_feature_discovered 调用）。"""
        if not self._should_test(feature.id):
            return
        async for evt in self._dispatch_test(feature):
            yield evt

    # ---- 内部方法 ----

    def _should_test(self, feature_id: str) -> bool:
        """检查功能点是否需要测试（去重 + debounce + 新API补测）。"""
        now = time.time()
        last_tested = self._tested_features.get(feature_id, 0)
        if now - last_tested < DEBOUNCE_SECONDS:
            return False

        # 检查功能点是否已有非 PENDING 的测试结果（已测过的跳过）
        if self.session.sitemap:
            fp = self.session.sitemap.features.get(feature_id)
            if fp and fp.checklist:
                tested = any(c.result != CheckResult.PENDING for c in fp.checklist)
                if tested:
                    # ★ 新 API 补测：如果 related_apis 数量比上次测试时增加了，
                    # 说明 Agent 点击产生了新的 API 流量丰富了该功能点，允许再测一轮
                    current_api_count = len(fp.related_apis) if fp.related_apis else 0
                    last_api_count = self._tested_api_count.get(feature_id, 0)
                    if current_api_count > last_api_count:
                        log.info(
                            "功能点 %s 发现新 API（%d → %d），触发补测",
                            fp.name, last_api_count, current_api_count
                        )
                        return True
                    return False

        return True

    async def _poll_loop(self) -> None:
        """轮询 mitmproxy FlowStore，发现功能型 API 时入队。"""
        while self._running:
            try:
                new_features = self._scan_new_flows()
                for feat in new_features:
                    try:
                        self._feature_queue.put_nowait(feat)
                    except asyncio.QueueFull:
                        log.warning("功能点队列已满，跳过: %s", feat.name)
            except Exception as e:
                log.warning("FlowWatcher 轮询异常: %s", e)

            await asyncio.sleep(FLOW_POLL_INTERVAL)

    async def _consume_loop(self) -> None:
        """消费功能点队列，分发测试任务。"""
        while self._running:
            try:
                feature = await asyncio.wait_for(
                    self._feature_queue.get(), timeout=FLOW_POLL_INTERVAL
                )
                if not self._should_test(feature.id):
                    continue
                async for evt in self._dispatch_test(feature):
                    # 事件通过 event_queue 传递给 SSE 流
                    if self.event_queue and evt:
                        try:
                            self.event_queue.put_nowait(evt)
                        except asyncio.QueueFull:
                            log.warning("事件队列已满，丢弃事件")
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.warning("消费协程异常: %s", e)

    def _scan_new_flows(self) -> list[FeaturePoint]:
        """扫描 mitmproxy FlowStore 中新增的功能型流量，匹配/创建功能点。"""
        if not self.session.sitemap:
            return []

        try:
            from mcp_servers.proxy_mcp import _store, _load_new_flows
            _load_new_flows()
        except Exception:
            return []

        target_host = ""
        if hasattr(self.session, "target_url") and self.session.target_url:
            target_host = urlparse(self.session.target_url).netloc

        new_features = []
        for flow_id in list(_store._order):
            if flow_id in self._seen_flow_ids:
                continue
            self._seen_flow_ids.add(flow_id)

            flow = _store.get(flow_id)
            if not flow:
                continue

            # 过滤：只关注目标站点的功能型 API
            if target_host and target_host not in flow.url:
                continue

            parsed = urlparse(flow.url)
            path_lower = parsed.path.lower()

            # 跳过静态资源
            if any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
                continue

            # 跳过 GET 请求（功能型 API 通常是增删改操作）
            if flow.method not in FEATURE_API_METHODS:
                continue

            # 尝试匹配已有功能点
            matched_feature = self._match_flow_to_feature(flow)
            if matched_feature:
                new_features.append(matched_feature)

        return new_features

    def _match_flow_to_feature(self, flow) -> "FeaturePoint | None":
        """将流量记录匹配到已有功能点。

        匹配逻辑：
        1. 先找 related_apis 中包含该 METHOD + path 的功能点
        2. 再找 page_url 中包含该 path 前缀的功能点
        3. 都没匹配到则创建新的原子功能点
        """
        if not self.session.sitemap:
            return None

        method = flow.method
        parsed = urlparse(flow.url)
        api_key = f"{method} {parsed.path}"

        # 1. 精确匹配 related_apis
        for fp in self.session.sitemap.features.values():
            if fp.deferred:
                continue
            for api_ref in (fp.related_apis or []):
                if api_ref == api_key or api_ref == f"{method} {flow.url}":
                    return fp

        # 2. 模糊匹配 page_url 前缀
        path_prefix = "/".join(parsed.path.split("/")[:3])  # 取前 3 段
        for fp in self.session.sitemap.features.values():
            if fp.deferred:
                continue
            if fp.page_url and path_prefix in fp.page_url:
                return fp

        # 3. 创建新的原子功能点
        try:
            from core.sitemap import Priority
            feature_name = f"{method} {parsed.path}"
            # 简短描述
            desc = f"自动发现的功能型 API：{method} {parsed.path}"
            if flow.request_body:
                desc += f"\n请求体: {flow.request_body[:200]}"

            fp = self.session.sitemap.add_feature(
                name=feature_name,
                description=desc,
                page_url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                priority=Priority.MEDIUM,
                related_apis=[f"{method} {parsed.path}"],
                requires_auth=True,
                deferred=False,
            )
            if fp:
                # 将流量样本添加到 sitemap
                self.session.sitemap.add_api_sample(
                    method=method,
                    url=flow.url,
                    headers=flow.request_headers,
                    body=flow.request_body,
                    status_code=flow.status_code,
                    discovered_by="flow_watcher",
                    response_body=flow.response_body,
                    response_headers=flow.response_headers,
                    content_type=flow.content_type,
                    flow_id=getattr(flow, "id", ""),
                    trigger_context={"tool": "flow_watcher"},
                )
                self.session.sitemap.save()
                return fp
        except Exception as e:
            log.warning("创建功能点失败: %s", e)

        return None

    async def _dispatch_test(self, feature: FeaturePoint) -> AsyncGenerator[str, None]:
        """分发一个功能点到 RealtimeWorker。"""
        async with self._semaphore:
            self._tested_features[feature.id] = time.time()
            # ★ 记录本次测试时的 API 数量，用于后续新 API 补测判断
            self._tested_api_count[feature.id] = len(feature.related_apis) if feature.related_apis else 0

            worker_id = f"rt_{feature.id[:8]}"
            yield self.session._event(
                "system",
                f"⚡ 实时测试开始: {feature.name} ({len(feature.checklist)} 项 checklist)"
            )

            try:
                # 获取 session 认证信息
                session_info = await self._get_session_info()

                worker = RealtimeWorker(
                    worker_id=worker_id,
                    llm=self.session.llm,
                    session_info=session_info,
                    feature=feature,
                    sitemap=self.session.sitemap,
                )

                # 设置 task_id 用于 LLM 监控
                from core.llm import set_current_task
                set_current_task(self.session.task_id)

                async for evt in worker.run():
                    # 将 worker 事件转化为 SSE 事件
                    evt_type = evt.get("type", "")

                    if evt_type == "realtime_worker_message":
                        yield self.session._event(
                            "realtime_test",
                            json.dumps({
                                "feature": feature.name,
                                "content": evt.get("content", ""),
                                "round": evt.get("round", 0),
                            }, ensure_ascii=False)
                        )

                    elif evt_type == "realtime_worker_tool":
                        yield self.session._event(
                            "tool_call",
                            f"[⚡{worker_id}] {evt.get('tool', '')}"
                        )

                    elif evt_type == "realtime_worker_tool_result":
                        yield self.session._event(
                            "realtime_result",
                            json.dumps({
                                "feature": feature.name,
                                "result_preview": evt.get("content", "")[:200],
                            }, ensure_ascii=False)
                        )

                    elif evt_type == "realtime_worker_done":
                        # 更新 sitemap 并推送事件
                        if self.session.sitemap:
                            self.session.sitemap.save()
                        # ★ 从 sitemap 中实际统计漏洞数（而非不可靠的文本匹配）
                        vuln_found = 0
                        if self.session.sitemap and feature.id in self.session.sitemap.features:
                            fp = self.session.sitemap.features[feature.id]
                            from core.sitemap import CheckResult as _CR
                            vuln_found = sum(1 for c in fp.checklist if c.result == _CR.VULNERABLE)
                        yield self.session._event(
                            "realtime_done",
                            json.dumps({
                                "feature": feature.name,
                                "feature_id": feature.id,
                                "rounds": evt.get("rounds", 0),
                                "vulns_found": vuln_found,
                            }, ensure_ascii=False)
                        )

                    elif evt_type == "realtime_worker_error":
                        yield self.session._event(
                            "system",
                            f"⚠️ 实时测试出错 [{feature.name}]: {evt.get('error', '')[:200]}"
                        )

            except Exception as e:
                log.error("RealtimeWorker 异常: %s", e, exc_info=True)
                yield self.session._event(
                    "system",
                    f"⚠️ 实时测试异常 [{feature.name}]: {str(e)[:200]}"
                )

    async def _get_session_info(self) -> dict:
        """获取当前 session 的认证信息（复用 parallel.py 的逻辑）。"""
        try:
            from core.parallel import get_session_info
            return await get_session_info()
        except Exception:
            # 降级：从环境变量获取
            import os
            headers = {}
            cookies = os.getenv("PENTEST_INJECT_COOKIES", "")
            auth = os.getenv("PENTEST_INJECT_AUTH", "")
            if cookies:
                headers["Cookie"] = cookies
            if auth:
                headers["Authorization"] = auth
            return {"headers": headers} if headers else {}
