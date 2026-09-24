"""core.os.scheduler — 任务调度器（长期 L1）。

按 XUANJIAN_ROADMAP_LONG_TERM §2.3 落地：
- Task: id/name/fn/priority/deps/status/result/error
- Scheduler: PriorityQueue + N worker thread + 依赖等待
- atexit 注册 graceful_shutdown（daemon 线程不随主进程退出）

零外部依赖。
"""
from __future__ import annotations

import atexit
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Task:
    """调度器任务。"""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    fn: Callable[[], Any] | None = None
    priority: int = 1  # 0=highest
    deps: list[str] = field(default_factory=list)
    status: str = "pending"  # pending|running|done|failed|cancelled
    result: Any = None
    error: str = ""


class Scheduler:
    """并发受限 + 依赖感知的任务调度器。"""

    _instance: "Scheduler | None" = None  # 用于 atexit 兜底

    def __init__(self, *, max_concurrent: int = 50, resource_pool=None):
        if max_concurrent < 1:
            raise ValueError("max_concurrent 必须 >= 1")
        self.tasks: dict[str, Task] = {}
        self.q: queue.PriorityQueue = queue.PriorityQueue()
        # ★ 924 修复：依赖未齐的任务**不再塞回就绪队列**，而是移入阻塞区。
        #
        # 原实现的活锁（已复现）：就绪队列按 `(priority, tid)` 排序，`tid` 是随机 uuid。
        # 若"被依赖的任务 A"的 id 恰好大于"依赖方 B"的 id，则 B 的键恒小于 A 的键 ——
        # worker 每次都 pop 到 B，发现依赖未齐又把 B 塞回去（此时仍是队首），
        # 于是 **A 永远轮不到执行**，所有 worker 在 B 上空转：
        #     实测 a_id=813f6a9d / b_id=5ef663ab → 2s 后 running=0、pending=2（彻底死锁）
        # 概率 ≈50%（uuid 字典序），这正是 test_scheduler_deps_wait 3/6 失败的成因。
        self._blocked: dict[str, tuple[int, str]] = {}   # tid → (priority, tid)
        self.lock = threading.Lock()
        self.cv = threading.Condition(self.lock)
        self.max_concurrent = max_concurrent
        self.running = 0
        self.pool = resource_pool
        self._stop = threading.Event()
        self.workers: list[threading.Thread] = []
        for _ in range(max_concurrent):
            t = threading.Thread(target=self._loop, daemon=True, name="os-sched")
            t.start()
            self.workers.append(t)
        Scheduler._instance = self
        atexit.register(self._graceful_shutdown)

    def submit(
        self,
        fn: Callable[[], Any],
        *,
        name: str = "",
        priority: int = 1,
        deps: list[str] | None = None,
    ) -> str:
        """提交一个任务，返回 task.id。"""
        if not callable(fn):
            raise TypeError("fn 必须可调用")
        t = Task(name=name, fn=fn, priority=priority, deps=list(deps or []))
        with self.cv:
            self.tasks[t.id] = t
            self.q.put((priority, t.id))
            self.cv.notify_all()
        return t.id

    def _deps_satisfied(self, tid: str) -> bool:
        t = self.tasks.get(tid)
        if t is None:
            return False
        for d in t.deps:
            _d = self.tasks.get(d)
            if not _d or _d.status != "done":
                return False
        return True

    def _promote_unblocked_locked(self) -> int:
        """把依赖已齐的阻塞任务移回就绪队列（**必须在持有 ``self.cv`` 时调用**）。

        ★ 924：这是"完成一个任务后主动解阻塞"的唯一入口。
        返回本次解阻塞的任务数（供 stats / 诊断）。
        """
        ready = [tid for tid in list(self._blocked) if self._deps_satisfied(tid)]
        for tid in ready:
            prio, _ = self._blocked.pop(tid)
            self.q.put((prio, tid))
        return len(ready)

    def _loop(self) -> None:
        """worker 主循环。"""
        while not self._stop.is_set():
            with self.cv:
                while self.running >= self.max_concurrent or self.q.empty():
                    if self._stop.is_set():
                        return
                    self.cv.wait(timeout=0.1)
                    if self._stop.is_set():
                        return
                try:
                    prio, tid = self.q.get_nowait()
                except queue.Empty:
                    continue
                if not self._deps_satisfied(tid):
                    # ★ 924：依赖未齐 → 移入**阻塞区**，等依赖任务完成时由
                    #   `_promote_unblocked_locked()` 唤醒。
                    #   ⛔ 绝不能 `self.q.put(...)` 塞回就绪队列 —— 会造成队头活锁
                    #   （键恒为最小 → 就绪任务永远轮不到），见 __init__ 注释。
                    self._blocked[tid] = (prio, tid)
                    continue
                self.tasks[tid].status = "running"
                self.running += 1
            try:
                t = self.tasks[tid]
                if self.pool is not None:
                    with self.pool.acquire():
                        t.result = t.fn()
                else:
                    t.result = t.fn()
                t.status = "done"
            except Exception as e:  # noqa: BLE001
                self.tasks[tid].status = "failed"
                self.tasks[tid].error = str(e)[:200]
            finally:
                with self.lock:
                    self.running -= 1
                    # ★ 924：任务收尾即解阻塞，让依赖它的任务立刻可跑
                    self._promote_unblocked_locked()
                    self.cv.notify_all()

    def _graceful_shutdown(self, timeout: float = 5.0) -> None:
        """atexit 触发：等所有 running 任务收尾，超时强制退出。"""
        self._stop.set()
        deadline = time.time() + timeout
        with self.cv:
            while self.running > 0 and time.time() < deadline:
                self.cv.wait(timeout=0.1)
        # 超时也返回，daemon 线程会被解释器回收

    def get(self, task_id: str) -> Task | None:
        return self.tasks.get(task_id)

    def stats(self) -> dict:
        with self.lock:
            return {
                "pending": self.q.qsize(),
                # ★ 924：依赖未齐而等待中的任务数（原实现无此概念，会把它们混在
                #   pending 里且永远不减少）
                "blocked": len(self._blocked),
                "running": self.running,
                "total": len(self.tasks),
            }


__all__ = ["Scheduler", "Task"]
