"""
test_events.py — core/events.py 的单测。
"""

from __future__ import annotations

import pytest

from core.events import EventBus, Events, bus as global_bus


@pytest.fixture()
def bus() -> EventBus:
    b = EventBus()
    return b


def test_emit_no_handler_returns_zero(bus: EventBus) -> None:
    assert bus.emit("nobody.listening", {"x": 1}) == 0


def test_subscribe_and_emit(bus: EventBus) -> None:
    received: list[dict] = []
    bus.on("foo", lambda p: received.append(p))
    n = bus.emit("foo", {"a": 1})
    assert n == 1
    assert received == [{"a": 1}]


def test_multiple_handlers_all_called(bus: EventBus) -> None:
    calls: list[str] = []
    bus.on("foo", lambda _: calls.append("h1"))
    bus.on("foo", lambda _: calls.append("h2"))
    bus.on("foo", lambda _: calls.append("h3"))
    assert bus.emit("foo") == 3
    assert calls == ["h1", "h2", "h3"]


def test_handler_exception_isolated(bus: EventBus) -> None:
    """一个 handler 抛错不应影响其他 handler 和 emit 的返回。"""
    calls: list[str] = []

    def bad(_: dict) -> None:
        raise RuntimeError("boom")

    bus.on("foo", bad)
    bus.on("foo", lambda _: calls.append("ok"))
    n = bus.emit("foo")
    # 抛错的 handler 不计入成功数；好的 handler 仍然被调用
    assert n == 1
    assert calls == ["ok"]


def test_off_unsubscribe(bus: EventBus) -> None:
    calls: list[int] = []
    h = lambda _: calls.append(1)
    bus.on("foo", h)
    assert bus.emit("foo") == 1
    assert bus.off("foo", h) is True
    assert bus.emit("foo") == 0


def test_on_returns_unsubscribe_fn(bus: EventBus) -> None:
    calls: list[int] = []
    off = bus.on("foo", lambda _: calls.append(1))
    bus.emit("foo")
    off()
    bus.emit("foo")
    assert calls == [1]


def test_disabled_swallows_emit(bus: EventBus) -> None:
    calls: list[int] = []
    bus.on("foo", lambda _: calls.append(1))
    bus.set_disabled(True)
    assert bus.emit("foo") == 0
    assert calls == []


def test_stats(bus: EventBus) -> None:
    bus.on("a", lambda _: None)
    bus.on("a", lambda _: None)
    bus.on("b", lambda _: None)
    assert bus.stats() == {"a": 2, "b": 1}


def test_emit_during_iteration_is_safe(bus: EventBus) -> None:
    """handler 在执行过程中订阅新的 handler，不应破坏当前迭代。"""
    calls: list[str] = []

    def on_first(_: dict) -> None:
        calls.append("first")
        # 在 emit 期间动态新增 handler
        bus.on("foo", lambda _: calls.append("late"))

    bus.on("foo", on_first)
    bus.emit("foo")
    # 当次 emit 只应该调用原有 handler（first）
    assert calls == ["first"]
    # 下一次 emit 才会调用新增的 late
    bus.emit("foo")
    assert "late" in calls


def test_event_name_constants_unique() -> None:
    names = [
        Events.CRAWL_SNAPSHOT_DONE,
        Events.WORKER_DECISION,
        Events.HARM_VALIDATED,
        Events.CRYPTO_CAPTURED,
        Events.LESSON_CANDIDATE,
    ]
    assert len(names) == len(set(names)), "事件名必须唯一"


def test_global_bus_is_singleton() -> None:
    from core.events import bus as bus_again
    assert global_bus is bus_again
