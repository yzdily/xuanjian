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
        for d in self.tasks[tid].deps:
            t = self.tasks.get(d)
            if not t or t.status != "done":
                return False
        return True

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
                    # 依赖未齐，重新入队
                    self.q.put((prio, tid))
                    self.cv.wait(timeout=0.05)
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
                "running": self.running,
                "total": len(self.tasks),
            }


__all__ = ["Scheduler", "Task"]
