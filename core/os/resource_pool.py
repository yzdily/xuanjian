"""core.os.resource_pool — 资源配额（长期 L1）。

按 XUANJIAN_ROADMAP_LONG_TERM §2.3 落地：
- CPU: Semaphore（max_cpu）
- 内存: 软上限（mem_used + mem_mb <= max_mem_mb）
- 网络: Semaphore（max_net_qps）

零外部依赖。
"""
from __future__ import annotations

import contextlib
import threading
import time


class ResourcePool:
    """CPU + 内存 + 网络配额池。"""

    def __init__(
        self,
        *,
        max_cpu: int = 8,
        max_mem_mb: int = 4096,
        max_net_qps: int = 50,
    ):
        if max_cpu < 1 or max_mem_mb < 1 or max_net_qps < 1:
            raise ValueError("max_cpu/max_mem_mb/max_net_qps 必须 >= 1")
        self.cpu_sem = threading.Semaphore(max_cpu)
        self.mem_lock = threading.Lock()
        self.mem_used = 0
        self.max_mem = max_mem_mb
        self.net_sem = threading.Semaphore(max_net_qps)
        self.max_cpu = max_cpu
        self.max_net_qps = max_net_qps

    @contextlib.contextmanager
    def acquire(self, *, cpu: int = 1, mem_mb: int = 256, net: int = 1, wait_mem: bool = True):
        """获取 CPU + 内存 + 网络配额。

        Args:
            cpu: 占用 CPU 槽位数
            mem_mb: 占用内存 MB
            net: 占用网络 QPS 槽位数
            wait_mem: 内存超限时是否等待（False 则立即抛 RuntimeError）
        """
        if cpu < 1 or mem_mb < 1 or net < 1:
            raise ValueError("cpu/mem_mb/net 必须 >= 1")
        # CPU + 网络先抢
        self.cpu_sem.acquire(cpu)
        self.net_sem.acquire(net)
        # 内存用软上限（带超时等待）
        deadline = time.time() + 5.0
        while True:
            with self.mem_lock:
                if self.mem_used + mem_mb <= self.max_mem:
                    self.mem_used += mem_mb
                    break
            if not wait_mem or time.time() > deadline:
                self.cpu_sem.release(cpu)
                self.net_sem.release(net)
                raise RuntimeError(
                    f"资源池内存不足：used={self.mem_used}MB + need={mem_mb}MB > max={self.max_mem}MB"
                )
            time.sleep(0.05)
        try:
            yield
        finally:
            with self.mem_lock:
                self.mem_used -= mem_mb
            self.net_sem.release(net)
            self.cpu_sem.release(cpu)

    def stats(self) -> dict:
        with self.mem_lock:
            return {
                "max_cpu": self.max_cpu,
                "max_mem_mb": self.max_mem,
                "max_net_qps": self.max_net_qps,
                "mem_used_mb": self.mem_used,
            }


__all__ = ["ResourcePool"]
