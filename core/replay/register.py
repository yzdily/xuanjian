"""
core/replay/register.py — 把 replay recorder 挂到事件总线
"""

from __future__ import annotations

from dataclasses import dataclass

from core.events import bus
from core.log import get_logger
from core.replay.recorder import EVENT_HANDLERS
from core.di import register_resetter

log = get_logger("replay.register")


@dataclass
class _ReplayRegisterState:
    attached: bool = False


_state = _ReplayRegisterState()
_handlers_attached: list = []


def attach() -> None:
    """把 replay 录制 handler 全部挂到 events bus。幂等。"""
    if _state.attached:
        return
    for event_name, handler in EVENT_HANDLERS.items():
        bus.on(event_name, handler)
        _handlers_attached.append((event_name, handler))
    _state.attached = True
    log.debug("Replay recorder 已挂载 %d 个事件 handler", len(EVENT_HANDLERS))


def detach() -> None:
    """取消订阅，仅测试用。"""
    for event_name, handler in _handlers_attached:
        bus.off(event_name, handler)
    _handlers_attached.clear()
    _state.attached = False


__all__ = ["attach", "detach"]


# ★ DI 收敛（D7/A4）：注册单例重置钩子，供 reset_singletons() 在测试间统一重置
def _reset_core_replay_register__attached() -> None:
    _state.attached = False

register_resetter("core_replay_register__attached", _reset_core_replay_register__attached)
