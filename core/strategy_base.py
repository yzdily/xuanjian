"""
Strategy Base — 扫描策略抽象层。

两种模式：
- BatchStrategy（批处理）：爬虫 → checklist → 统一并行测试 → 报告（原有流程）
- RealtimeStrategy（实时）：爬虫/Agent 点击 → 发现功能包即测 → 实时更新报告

策略通过 session.scan_mode 字段选择，在 Phase 推进时自动分支。
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import AsyncGenerator, TYPE_CHECKING

from core.log import get_logger

if TYPE_CHECKING:
    from core.session import AgentSession
    from core.sitemap import FeaturePoint

log = get_logger("strategy")


class ScanStrategy(ABC):
    """扫描策略抽象基类。"""

    @abstractmethod
    async def on_crawl_complete(
        self, session: "AgentSession", crawl_result: dict
    ) -> AsyncGenerator[str, None]:
        """Phase 0 爬取完成后的回调。"""
        ...

    @abstractmethod
    async def on_feature_discovered(
        self, session: "AgentSession", feature: "FeaturePoint"
    ) -> AsyncGenerator[str, None]:
        """发现新功能点时的回调（实时模式在此触发即时测试）。"""
        ...

    @abstractmethod
    async def on_phase1_complete(
        self, session: "AgentSession", summary: str
    ) -> AsyncGenerator[str, None]:
        """Phase 1 完成后的回调（批处理模式在此触发并行测试）。"""
        ...

    @abstractmethod
    async def on_task_done(self, session: "AgentSession") -> None:
        """任务结束时的清理。"""
        ...


class BatchStrategy(ScanStrategy):
    """批处理模式 — 原有全流程。

    Phase 0 → Phase 1 → Phase 2 并行测试 → Phase 3 报告
    所有功能点在 Phase 2 统一并行测试，不在发现时单独测试。
    """

    async def on_crawl_complete(
        self, session: "AgentSession", crawl_result: dict
    ) -> AsyncGenerator[str, None]:
        # 批处理模式：爬取完成后不做额外处理，交给后续 Phase
        return
        yield  # noqa: unreachable — 使方法成为 generator

    async def on_feature_discovered(
        self, session: "AgentSession", feature: "FeaturePoint"
    ) -> AsyncGenerator[str, None]:
        # 批处理模式：发现功能点时只记录，不立即测试
        return
        yield

    async def on_phase1_complete(
        self, session: "AgentSession", summary: str
    ) -> AsyncGenerator[str, None]:
        # 批处理模式：Phase 1 完成后走原有 _advance_phase 逻辑
        # （并行测试由 AdvancePhaseMixin._advance_phase 触发）
        return
        yield

    async def on_task_done(self, session: "AgentSession") -> None:
        pass


class RealtimeStrategy(ScanStrategy):
    """实时模式 — 发现即测。

    Phase 0 爬取完成后即启动 FlowWatcher + BrowseWorker 联动：
    - FlowWatcher 监控 mitmproxy 流量，发现功能型 API 立即触发 RealtimeWorker 测试
    - BrowseWorker 串行操作菜单页面，产生新流量供 FlowWatcher 捕获
    - 每操作一个菜单组，FlowWatcher 自动捕获新流量并即时测试，实时输出漏洞结果
    Phase 1 完成后跳过 Phase 2 并行测试（已测过的不再重测），直接进入报告。
    """

    def __init__(self):
        self._watcher: "FlowWatcher | None" = None
        self._event_queue: asyncio.Queue[str] | None = None
        self._browse_task: asyncio.Task | None = None

    def set_event_queue(self, queue: asyncio.Queue[str]) -> None:
        """设置事件队列，用于向 SSE 流推送实时测试结果。"""
        self._event_queue = queue

    async def on_crawl_complete(
        self, session: "AgentSession", crawl_result: dict
    ) -> AsyncGenerator[str, None]:
        # 1. 启动 FlowWatcher 监控后续流量
        if self._watcher is None:
            from core.realtime_worker import FlowWatcher
            self._watcher = FlowWatcher(
                session=session,
                event_queue=self._event_queue,
            )
            await self._watcher.start()
            yield session._event("system", "⚡ 实时模式已启动 — FlowWatcher 正在监控流量")

        # 2. 解析菜单树，启动 BrowseWorker 串行操作（边点边测）
        from core.browse_worker import parse_menu_tree, group_menus_by_tab_weight
        menu_tree = parse_menu_tree(crawl_result) if crawl_result else None
        menu_groups = group_menus_by_tab_weight(menu_tree, crawl_result) if menu_tree else []

        if menu_groups and len(menu_groups) >= 1:
            total_pages = sum(g["page_count"] for g in menu_groups)
            total_tabs = sum(g["tab_count"] for g in menu_groups)
            yield session._event("system",
                f"⚡ 实时模式 — 启动 BrowseWorker 联动（{len(menu_groups)} 组, "
                f"{total_pages} 页面, {total_tabs} Tab）\n"
                f"  每操作一个菜单 → FlowWatcher 捕获流量 → 即时漏洞检测 → 实时输出结果")

            # 串行执行每组 BrowseWorker，操作期间 FlowWatcher 自动捕获新流量并测试
            from core.browse_worker import BrowseWorker
            for i, group in enumerate(menu_groups):
                yield session._event("phase",
                    f"⚡ 实时操作 [{i+1}/{len(menu_groups)}]「{group['name']}」"
                    f"（{group['page_count']} 页面, {group['tab_count']} Tab）")

                worker = BrowseWorker(
                    worker_id=f"rt_browse_{i+1}",
                    llm=session.llm,
                    sitemap=session.sitemap,
                    group=group,
                    target_info=session.target_info,
                    has_credentials=session.has_credentials,
                    extra_scope=crawl_result.get("extra_scope", []) if crawl_result else [],
                )

                async for evt in worker.run():
                    evt_type = evt.get("type", "")
                    if evt_type == "browse_worker_message":
                        yield session._event("message",
                            f"[{worker.worker_id}] {evt.get('content', '')}")
                    elif evt_type == "browse_worker_tool":
                        yield session._event("tool_call",
                            f"[{worker.worker_id}] {evt.get('tool', '')}")
                    elif evt_type == "browse_worker_tool_result":
                        content = evt.get('content', '')
                        if content:
                            yield session._event("system",
                                f"[{worker.worker_id}] {content}")
                    elif evt_type == "browse_worker_screenshot":
                        ss_name = evt.get('name', 'screenshot')
                        yield session._event("screenshot",
                            f"/api/screenshot/{ss_name}")
                    elif evt_type == "browse_worker_reasoning":
                        content = evt.get('content', '')
                        if any(kw in content for kw in
                            ('✅', '❌', '页面', 'Tab', '菜单', '按钮',
                             'API', 'proxy_get_traffic', '完成', '下一个')):
                            yield session._event("thinking",
                                f"[{worker.worker_id}] {content}")
                    elif evt_type == "browse_worker_error":
                        yield session._event("system",
                            f"⚠️ [{worker.worker_id}] 出错: {evt.get('error', '')}")
                    elif evt_type == "browse_worker_done":
                        rounds = evt.get("rounds", 0)
                        yield session._event("system",
                            f"✅ [{worker.worker_id}]「{group['name']}」完成"
                            f"（{rounds} 轮）")

                # 每组操作完后，给 FlowWatcher 一点时间处理新流量
                await asyncio.sleep(3)

            api_count = len(session.sitemap.apis) if session.sitemap else 0
            tested_count = len(self._watcher._tested_features) if self._watcher else 0
            yield session._event("system",
                f"🎯 实时模式 BrowseWorker 全部完成 — "
                f"共抓取 {api_count} 个 API，已即时测试 {tested_count} 个功能点")
        else:
            yield session._event("system",
                "⚡ 实时模式 — 未发现菜单树，FlowWatcher 将被动监控后续流量")

    async def on_feature_discovered(
        self, session: "AgentSession", feature: "FeaturePoint"
    ) -> AsyncGenerator[str, None]:
        # 实时模式：发现功能点时立即触发单轮测试
        if self._watcher:
            async for evt in self._watcher.test_feature_now(feature):
                yield evt

    async def on_phase1_complete(
        self, session: "AgentSession", summary: str
    ) -> AsyncGenerator[str, None]:
        # 实时模式：Phase 1 完成后停止 FlowWatcher
        # 已测过的功能点跳过，未测的补测一次
        if self._watcher:
            async for evt in self._watcher.stop_and_flush():
                yield evt
        yield session._event("system", "⚡ 实时模式 — 已测试功能点跳过并行测试，直接生成报告")

    async def on_task_done(self, session: "AgentSession") -> None:
        if self._watcher:
            await self._watcher.stop()
            self._watcher = None


def create_strategy(scan_mode: str) -> ScanStrategy:
    """根据 scan_mode 创建对应策略实例。"""
    if scan_mode == "realtime":
        return RealtimeStrategy()
    return BatchStrategy()
