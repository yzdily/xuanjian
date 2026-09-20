"""core.os — AI-native 安全 OS 三件套（长期 L1）。

按 XUANJIAN_ROADMAP_LONG_TERM §2.3 落地：
- scheduler.py: Task/Scheduler 优先级队列 + 依赖等待
- resource_pool.py: CPU/内存/网络配额（Semaphore）
- event_bus.py: 复用 v1.6 core.events.EventBus，叠加 dispatch_timeout + dropped 统计

零外部依赖。
回滚：XUANJIAN_OS_DISABLED=1 退回 v1.6 同步调度。
"""
from __future__ import annotations

from core.os.event_bus import OSEventBus
from core.os.resource_pool import ResourcePool
from core.os.scheduler import Scheduler, Task

__all__ = ["Scheduler", "Task", "ResourcePool", "OSEventBus"]
