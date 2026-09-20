"""
core/crypto_replay/register.py — 把 learner 挂到事件总线
"""

from __future__ import annotations

from dataclasses import dataclass

from core.events import Events, bus
from core.log import get_logger
from core.crypto_replay.learner import learn_from_capture
from core.di import register_resetter

log = get_logger("crypto_replay.register")


@dataclass
class _CryptoReplayRegisterState:
    attached: bool = False


_state = _CryptoReplayRegisterState()


def _on_crypto_captured(payload: dict) -> None:
    learn_from_capture(payload)


def attach() -> None:
    """订阅 crypto.captured 事件。幂等。"""
    if _state.attached:
        return
    bus.on(Events.CRYPTO_CAPTURED, _on_crypto_captured)
    _state.attached = True
    log.debug("CryptoReplay learner 已挂载到事件总线")


def detach() -> None:
    """仅测试用。"""
    bus.off(Events.CRYPTO_CAPTURED, _on_crypto_captured)
    _state.attached = False


__all__ = ["attach", "detach"]


# ★ DI 收敛（D7/A4）：注册单例重置钩子，供 reset_singletons() 在测试间统一重置
def _reset_core_crypto_replay_register__attached() -> None:
    _state.attached = False

register_resetter("core_crypto_replay_register__attached", _reset_core_crypto_replay_register__attached)
