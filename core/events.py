"""
events.py — 极简事件总线（零侵入扩展的地基）

## 目的
让新增特性（replay / diff / crypto_replay 等）能够订阅旧代码中的关键时刻，
而不需要修改旧代码的业务逻辑。旧代码只需要在关键节点 `bus.emit(name, payload)`，
新模块自己 `bus.on(name, handler)` 订阅即可。

## 设计原则
- **同步分发**：handler 串行执行，避免引入异步复杂度
- **异常隔离**：handler 抛错只 log，不影响主流程（safety > completeness）
- **可一键关闭**：通过环境变量 `EVENTS_DISABLED=1` 全局关闭，便于回滚
- **零依赖**：标准库实现，没有任何第三方依赖

## 标准事件名（按特性分组）
- crawl.snapshot.done   — 爬取完成，sitemap 可拍快照
- worker.decision       — Worker 选择 SKILL / payload，剧场录制
- harm.validated        — 危害验证产出结论
- crypto.captured       — 抓到加密包，可学习模板
- lesson.candidate      — 抽取到候选经验

事件名采用点分命名空间，便于后续按前缀通配订阅。
"""

from __future__ import annotations

import os
import threading
from collections import defaultdict
from typing import Any, Callable

from core.log import get_logger

log = get_logger("events")

# Handler 签名：接收一个 dict payload，返回值忽略
Handler = Callable[[dict[str, Any]], Any]


class EventBus:
    """线程安全的极简事件总线。"""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._lock = threading.RLock()
        self._disabled = os.getenv("EVENTS_DISABLED", "").strip() in ("1", "true", "yes")

    # ------------------------------------------------------------
    # 订阅
    # ------------------------------------------------------------

    def on(self, event: str, handler: Handler) -> Callable[[], None]:
        """订阅事件。返回一个取消订阅的函数。"""
        if not callable(handler):
            raise TypeError(f"handler 必须可调用，得到 {type(handler)}")
        with self._lock:
            self._handlers[event].append(handler)
        log.debug("事件订阅: %s -> %s", event, getattr(handler, "__name__", handler))

        def _off() -> None:
            self.off(event, handler)
        return _off

    def off(self, event: str, handler: Handler) -> bool:
        """取消订阅。返回是否成功移除。"""
        with self._lock:
            handlers = self._handlers.get(event, [])
            try:
                handlers.remove(handler)
                return True
            except ValueError:
                return False

    # ------------------------------------------------------------
    # 发布
    # ------------------------------------------------------------

    def emit(self, event: str, payload: dict[str, Any] | None = None) -> int:
        """发布事件，同步串行调用所有 handler。

        返回成功执行的 handler 数量（异常的不计入）。
        emit 永远不抛异常，对调用方零侵入。
        """
        if self._disabled:
            return 0

        payload = payload or {}
        # 复制一份 handler 列表，避免在迭代时被订阅/取消订阅修改
        with self._lock:
            handlers = list(self._handlers.get(event, []))

        if not handlers:
            return 0

        ok_count = 0
        for h in handlers:
            try:
                h(payload)
                ok_count += 1
            except Exception as e:  # noqa: BLE001  ——  事件 handler 必须不能影响主流程
                log.warning("事件 handler 异常 event=%s handler=%s: %s",
                            event, getattr(h, "__name__", h), e)
        return ok_count

    # ------------------------------------------------------------
    # 调试 / 内省
    # ------------------------------------------------------------

    def stats(self) -> dict[str, int]:
        """返回 {event_name: handler_count} 的快照。"""
        with self._lock:
            return {ev: len(hs) for ev, hs in self._handlers.items() if hs}

    def clear(self) -> None:
        """清空所有订阅（仅测试用）。"""
        with self._lock:
            self._handlers.clear()

    @property
    def disabled(self) -> bool:
        return self._disabled

    def set_disabled(self, value: bool) -> None:
        """运行时切换开关（用于测试或紧急止血）。"""
        self._disabled = bool(value)


# ------------------------------------------------------------
# 全局单例
# ------------------------------------------------------------

bus = EventBus()


# ------------------------------------------------------------
# 标准事件名常量（避免拼写错误）
# ------------------------------------------------------------

class Events:
    CRAWL_SNAPSHOT_DONE = "crawl.snapshot.done"
    WORKER_DECISION = "worker.decision"
    HARM_VALIDATED = "harm.validated"
    CRYPTO_CAPTURED = "crypto.captured"
    LESSON_CANDIDATE = "lesson.candidate"


__all__ = ["bus", "EventBus", "Events", "Handler"]
