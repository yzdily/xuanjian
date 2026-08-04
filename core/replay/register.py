"""
core/replay/register.py — 把 replay recorder 挂到事件总线
"""

from __future__ import annotations

from core.events import bus
from core.log import get_logger
from core.replay.recorder import EVENT_HANDLERS

log = get_logger("replay.register")

_attached = False
_handlers_attached: list = []


def attach() -> None:
    """把 replay 录制 handler 全部挂到 events bus。幂等。"""
    global _attached
    if _attached:
        return
    for event_name, handler in EVENT_HANDLERS.items():
        bus.on(event_name, handler)
        _handlers_attached.append((event_name, handler))
    _attached = True
    log.debug("Replay recorder 已挂载 %d 个事件 handler", len(EVENT_HANDLERS))


def detach() -> None:
    """取消订阅，仅测试用。"""
    global _attached
    for event_name, handler in _handlers_attached:
        bus.off(event_name, handler)
    _handlers_attached.clear()
    _attached = False


__all__ = ["attach", "detach"]
