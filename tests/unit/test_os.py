"""tests/unit/test_os.py — 长期 L1 验收。

按 XUANJIAN_ROADMAP_LONG_TERM §2.3 4 断言：
1. Scheduler 并发上限
2. 依赖等齐（A → B）
3. ResourcePool CPU 配额（5 任务抢 2 核）
4. OSEventBus pub/sub + dropped 统计
"""
from __future__ import annotations

import threading
import time

import pytest

from core.os.event_bus import OSEventBus
from core.os.resource_pool import ResourcePool
from core.os.scheduler import Scheduler, Task


def test_scheduler_concurrent_limit():
    """max_concurrent=2 时，5 个慢任务在任意瞬间 running <= 2。"""
    s = Scheduler(max_concurrent=2)

    def slow():
        time.sleep(0.15)
        return "done"

    ids = [s.submit(slow) for _ in range(5)]
    time.sleep(0.05)  # 给 worker 起来的机会
    assert s.running <= 2
    # 等全部完成（pending 或 running 都算未完）
    deadline = time.time() + 3
    while time.time() < deadline and any(s.get(i).status in ("pending", "running") for i in ids):
        time.sleep(0.05)
    for i in ids:
        assert s.get(i).status == "done", f"task {i} status={s.get(i).status}"


def test_scheduler_deps_wait():
    """B 依赖 A；A 没完成前 B 不应 done。"""
    s = Scheduler(max_concurrent=4)
    order: list[str] = []

    a = s.submit(lambda: (order.append("A"), time.sleep(0.1))[1], name="A")
    b = s.submit(lambda: (order.append("B"), "x")[1], name="B", deps=[a])
    # 等 50ms：A 应该已经 running 或 done
    time.sleep(0.05)
    assert "A" in order, f"A 未开始: order={order}"
    # B 不应在 A 之前完
    if "B" in order:
        assert order.index("A") < order.index("B")

    # 等到全部完成
    deadline = time.time() + 3
    while time.time() < deadline and s.get(b).status in ("pending", "running"):
        time.sleep(0.05)
    assert s.get(a).status == "done"
    assert s.get(b).status == "done"


def test_resource_pool_cpu_limit():
    """5 线程抢 2 CPU 槽：峰值并发活跃 = 2。"""
    p = ResourcePool(max_cpu=2)
    active = [0]
    peak = [0]
    cv_lock = threading.Lock()

    def hold():
        with p.acquire(cpu=1, mem_mb=64, net=1):
            with cv_lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.1)
        with cv_lock:
            active[0] -= 1

    ts = [threading.Thread(target=hold) for _ in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=3)
    assert peak[0] <= 2, f"峰值并发 {peak[0]} 超过 max_cpu=2"


def test_event_bus_pubsub_and_stats():
    """OSEventBus pub/sub + stats 字段全有。"""
    bus = OSEventBus(dispatch_timeout=2.0)
    received: list[dict] = []
    bus.subscribe("scan.done", lambda p: received.append(p))
    bus.publish("scan.done", {"id": "F-1"})
    time.sleep(0.1)
    assert received == [{"id": "F-1"}]
    s = bus.stats()
    assert "published" in s
    assert "delivered" in s
    assert "dropped_timeout" in s
    assert "dropped_error" in s
    assert s["published"] >= 1


def test_event_bus_dropped_on_timeout():
    """handler sleep > dispatch_timeout → dropped_timeout 计数。"""
    bus = OSEventBus(dispatch_timeout=0.1)

    def slow(p):
        time.sleep(0.5)  # 必然超时

    bus.subscribe("slow.evt", slow)
    bus.publish("slow.evt", {"x": 1})
    time.sleep(0.3)
    s = bus.stats()
    assert s["dropped_timeout"] >= 1, f"expected dropped_timeout, got {s}"


def test_task_dataclass_defaults():
    """Task 字段默认值。"""
    t = Task()
    assert t.status == "pending"
    assert t.priority == 1
    assert t.deps == []
    assert t.result is None
