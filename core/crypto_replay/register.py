"""
core/crypto_replay/register.py — 把 learner 挂到事件总线
"""

from __future__ import annotations

from core.events import Events, bus
from core.log import get_logger
from core.crypto_replay.learner import learn_from_capture

log = get_logger("crypto_replay.register")

_attached = False


def _on_crypto_captured(payload: dict) -> None:
    learn_from_capture(payload)


def attach() -> None:
    """订阅 crypto.captured 事件。幂等。"""
    global _attached
    if _attached:
        return
    bus.on(Events.CRYPTO_CAPTURED, _on_crypto_captured)
    _attached = True
    log.debug("CryptoReplay learner 已挂载到事件总线")


def detach() -> None:
    """仅测试用。"""
    global _attached
    bus.off(Events.CRYPTO_CAPTURED, _on_crypto_captured)
    _attached = False


__all__ = ["attach", "detach"]
