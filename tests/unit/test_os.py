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


def _wait_all_done(s: Scheduler, ids: list[str], timeout: float = 5.0) -> None:
    """确定性等待：轮询到所有任务离开 pending/running，而不是固定 sleep 赌时长。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all((s.get(i) or Task()).status not in ("pending", "running") for i in ids):
            return
        time.sleep(0.01)


def test_scheduler_concurrent_limit():
    """max_concurrent=2 时，5 个慢任务在任意瞬间 running <= 2。

    ★ 924 修复：原实现 `time.sleep(0.05)` 后断言 `s.running <= 2` —— 若线程尚未启动，
    `running` 为 0，断言平凡通过，其实没验证任何东西。改为在任务体内用锁统计**峰值并发**，
    确定性验证不变量。
    """
    s = Scheduler(max_concurrent=2)
    lock = threading.Lock()
    active = [0]
    peak = [0]

    def slow():
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.15)
        with lock:
            active[0] -= 1
        return "done"

    ids = [s.submit(slow) for _ in range(5)]
    _wait_all_done(s, ids)
    for i in ids:
        assert s.get(i).status == "done", f"task {i} status={s.get(i).status}"
    assert peak[0] >= 1, "任务根本没跑起来，测试无效"
    assert peak[0] <= 2, f"峰值并发 {peak[0]} 超过 max_concurrent=2"


def test_scheduler_deps_wait():
    """B 依赖 A；A 没完成前 B 不应 done。

    ★ 924 修复：原实现 `submit` 后固定 `sleep(0.05)` 就断言 `"A" in order`，
    前提是"调度线程能在 50ms 内唤醒并执行到 append" —— 这在 Windows（线程启动延迟 +
    GIL 竞争）下是**赌运气**，单跑 6 次 3 过 3 败。
    现改为：A 的任务体在真正开始执行时 `set()` 一个 Event，测试**等这个信号**
    （有界超时），既确定又保留"A 已启动"的语义。
    """
    s = Scheduler(max_concurrent=4)
    order: list[str] = []
    lock = threading.Lock()
    a_started = threading.Event()

    def run_a():
        with lock:
            order.append("A")
        a_started.set()          # 明确告知"A 已开始"，与调度线程启动时机解耦
        time.sleep(0.1)

    def run_b():
        with lock:
            order.append("B")

    a = s.submit(run_a, name="A")
    b = s.submit(run_b, name="B", deps=[a])

    # A 必然启动（否则说明调度器坏了）—— 这是确定性等待，不是赌时长
    assert a_started.wait(timeout=3.0), "A 未在 3s 内启动"
    # 此刻 A 还在 sleep(0.1) 内 → 依赖 A 的 B 不得 done
    assert s.get(b).status != "done", f"B 在 A 完成前就 done 了: {s.get(b).status}"

    _wait_all_done(s, [a, b])
    assert s.get(a).status == "done"
    assert s.get(b).status == "done"
    with lock:
        assert order.index("A") < order.index("B"), f"A 应在 B 之前开始: {order}"


def test_scheduler_dep_unblocks_even_when_dependent_sorts_first():
    """回归钉子（924）：依赖未齐的任务**不得**阻塞就绪队列（队头活锁）。

    历史缺陷：原实现把"依赖未齐"的任务 `put` 回同一个 PriorityQueue。该队列按
    `(priority, tid)` 排序而 `tid` 是随机 uuid —— 当依赖方 B 的 id 恰好小于
    被依赖方 A 的 id 时，B 的键恒为最小，worker 反复 pop B→塞回→pop B……
    **A 永远不执行**（实测 2s 后 running=0、pending=2 彻底死锁）。

    `tid` 随机 → 单次运行的复现概率约 50%，故此处循环多次以稳定捕获回归。
    """
    rounds = 25
    for i in range(rounds):
        s = Scheduler(max_concurrent=4)
        done = threading.Event()

        def run_a():
            time.sleep(0.02)
            done.set()

        a = s.submit(run_a, name="A")
        b = s.submit(lambda: "b", name="B", deps=[a])   # 依赖方可能排在被依赖方之前
        assert done.wait(timeout=3.0), f"第 {i} 轮：被依赖任务 A 未执行（就绪队列被活锁）"
        _wait_all_done(s, [a, b], timeout=3.0)
        assert s.get(a).status == "done"
        assert s.get(b).status == "done"
        # 阻塞区最终应清空
        assert s.stats().get("blocked", 0) == 0


def test_scheduler_stats_exposes_blocked():
    """stats() 必须暴露 blocked —— 否则"依赖未齐"会被误读成"排队中"。"""
    s = Scheduler(max_concurrent=2)
    never = s.submit(lambda: time.sleep(0.5), name="never-soon")
    dep = s.submit(lambda: "x", name="dep", deps=[never])
    deadline = time.time() + 3
    while time.time() < deadline and s.stats().get("blocked", 0) == 0:
        time.sleep(0.01)
    assert "blocked" in s.stats()
    _wait_all_done(s, [never, dep], timeout=5.0)
    assert s.get(dep).status == "done"


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
    """OSEventBus pub/sub + stats 字段全有。

    ★ 924：断言前用**有界轮询**等 handler 收到事件，而不是固定 `sleep(0.1)` 赌派发线程已跑完。
    """
    bus = OSEventBus(dispatch_timeout=2.0)
    received: list[dict] = []
    bus.subscribe("scan.done", lambda p: received.append(p))
    bus.publish("scan.done", {"id": "F-1"})
    deadline = time.time() + 3
    while time.time() < deadline and not received:
        time.sleep(0.01)
    assert received == [{"id": "F-1"}], f"未收到事件或收到多次: {received}"
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
