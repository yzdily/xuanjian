"""core.os.event_bus — L1 事件总线（薄包装 + dispatch_timeout + dropped 统计）。

按 XUANJIAN_ROADMAP_LONG_TERM §2.3 落地。
- 复用 v1.6 core.events.EventBus（不重复造轮子，保持 5 个标准事件名兼容）
- 叠加 dispatch_timeout（默认 5s）+ dropped/delivered 统计

零外部依赖。
"""
from __future__ import annotations

import concurrent.futures
import threading
from typing import Any, Callable

from core.events import EventBus as _CoreEventBus


class OSEventBus:
    """L1 事件总线：包装 v1.6 EventBus，加超时 + 统计。"""

    def __init__(self, *, dispatch_timeout: float = 5.0, max_workers: int = 32):
        self._bus = _CoreEventBus()
        self._dispatch_timeout = dispatch_timeout
        self._max_workers = max_workers
        self._stats = {
            "published": 0,
            "delivered": 0,
            "dropped_timeout": 0,
            "dropped_error": 0,
        }
        self._stats_lock = threading.Lock()

    def subscribe(self, event: str, fn: Callable[[dict], Any]) -> Callable[[], None]:
        """订阅（取消订阅函数返回）。"""
        return self._bus.on(event, fn)

    def publish(self, event: str, payload: dict | None = None) -> None:
        """发布；handler 在子线程里跑，超时记 dropped。"""
        payload = payload or {}
        handlers = []
        # 拿一份快照避免迭代时修改
        with self._bus._lock:
            handlers = list(self._bus._handlers.get(event, []))
        if not handlers:
            with self._stats_lock:
                self._stats["published"] += 1
            return
        with self._stats_lock:
            self._stats["published"] += 1
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self._max_workers, len(handlers)),
            thread_name_prefix=f"bus-{event}",
        ) as ex:
            futs = {ex.submit(h, payload): h for h in handlers}
            for fut in futs:
                try:
                    fut.result(timeout=self._dispatch_timeout)
                    with self._stats_lock:
                        self._stats["delivered"] += 1
                except concurrent.futures.TimeoutError:
                    with self._stats_lock:
                        self._stats["dropped_timeout"] += 1
                except Exception:  # noqa: BLE001
                    with self._stats_lock:
                        self._stats["dropped_error"] += 1

    def stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    # 透传
    def disable(self) -> None:
        self._bus.set_disabled(True)

    def enable(self) -> None:
        self._bus.set_disabled(False)


__all__ = ["OSEventBus"]
