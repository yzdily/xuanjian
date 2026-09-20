"""core.workflow.agent — Agent 抽象（长期 L2）。

按 XUANJIAN_ROADMAP_LONG_TERM §3.3 落地。
- Agent 通过 OSEventBus 订阅 topic，执行 run(ctx)，发布 {name}.done
- 子类只实现 run(ctx)
- 缺业务委托模块时 stub 化（XUANJIAN_AGENT_DISABLED=1 整体关）

零外部依赖。
回滚：XUANJIAN_AGENT_DISABLED=1 退回 v1.6 线性编排。
"""
from __future__ import annotations

import os
from typing import Any

from core.os.event_bus import OSEventBus


class Agent:
    """Agent 基类：订阅 topic → run(ctx) → publish {name}.done。"""

    def __init__(self, name: str, topics: list[str], bus: OSEventBus):
        self.name = name
        self.bus = bus
        self._disabled = os.environ.get("XUANJIAN_AGENT_DISABLED") == "1"
        for t in topics:
            bus.subscribe(t, self._on_event)

    def _on_event(self, payload: dict) -> None:
        """事件回调：调 run，发布结果。"""
        if self._disabled:
            return
        try:
            result = self.run(payload)
        except Exception as e:  # noqa: BLE001
            self.bus.publish(f"{self.name}.failed", {"error": str(e)[:200]})
            return
        self.bus.publish(f"{self.name}.done", result or {})

    def run(self, ctx: dict) -> dict:
        """子类必须实现：ctx → 新 ctx。"""
        raise NotImplementedError(f"{self.__class__.__name__}.run 未实现")


__all__ = ["Agent"]
