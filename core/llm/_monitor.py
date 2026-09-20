"""LLM 调用监控（线程安全单例，缓冲写入 + 日志轮转）。

从 core.llm 拆分而来；导入即创建 _monitor 全局。
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from core.log import get_logger
from core.llm._context import get_current_task

log = get_logger("llm")

# ============================================================
# LLM 使用监控
# ============================================================

class LLMMonitor:
    """LLM 调用监控：记录每次调用的模型、tokens、耗时，持久化到文件。"""

    _instance = None
    _init_lock = __import__("threading").Lock()

    def __new__(cls):
        # ★ 线程安全的单例：用锁保护 __new__ + __init__ 的竞态
        with cls._init_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        # ★ __init__ 也需要锁保护，防止 __new__ 返回对象后、__init__ 执行前被其他线程抢先。
        # 关键：所有属性初始化必须在锁内完成，且 _initialized 标志放在最后置位，
        # 否则其他线程会看到 _initialized=True 但属性尚未赋值，引发 AttributeError。
        with self._init_lock:
            if self._initialized:
                return
            self._log_file = Path("data/logs/llm_usage.jsonl")
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            # ★ 线程安全：record() 加锁防止多 worker 并发写入竞态
            self._record_lock = threading.Lock()
            # 内存统计（当前进程生命周期）
            self.total_calls = 0
            self.total_input_tokens = 0
            self.total_output_tokens = 0
            self.total_cost_seconds = 0.0
            self.by_model: dict[str, dict] = {}  # model → {calls, input, output, seconds}
            self.by_caller: dict[str, dict] = {}  # caller → {calls, input, output}
            self.by_task: dict[str, dict] = {}    # task_id → {calls, input, output, seconds, started_at}
            # ★ 缓冲写入：攒够 _BUFFER_FLUSH 条或 _BUFFER_TIMEOUT 秒后批量 flush，减少 IO 次数
            self._buffer: list[str] = []
            self._buffer_flush_count = int(os.getenv("XUANJIAN_LLM_LOG_BUFFER", "50"))
            self._buffer_flush_timeout = 5.0
            self._buffer_last_flush = time.time()
            # ★ 日志轮转：超过 _MAX_LOG_SIZE_MB 时自动截断保留最新记录
            self._max_log_size = int(os.getenv("XUANJIAN_LLM_LOG_MAX_MB", "50")) * 1024 * 1024
            # ★ 标志放最后：确保上面所有属性都已赋值后，才允许其他线程跳过初始化
            self._initialized = True

    def record(self, model: str, input_tokens: int, output_tokens: int,
               elapsed: float, caller: str = "", has_tools: bool = False,
               task_id: str = "", call_id: str = "",
               is_error: bool = False, error: str = "",
               req_summary: str = "", resp_summary: str = ""):
        """记录一次 LLM 调用。

        task_id 优先使用显式传入的；否则自动从 ContextVar 读取（推荐方式）。

        新增字段（用于详细监控页）：
        - call_id: 单次调用唯一 ID（建议 uuid4 hex 8 位）
        - is_error: 是否调用异常
        - error: 异常 message（截断后）
        - req_summary: 请求摘要（messages 最后一条 user/system 截断 200 字）
        - resp_summary: 响应摘要（resp.content 截断 200 字）
        """
        if not task_id:
            task_id = get_current_task()

        # ★ 线程安全：整个 record 加锁，防止多 worker 并发自增竞态
        with self._record_lock:
            self.total_calls += 1
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_seconds += elapsed

            # 按模型聚合
            if model not in self.by_model:
                self.by_model[model] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "seconds": 0.0}
            m = self.by_model[model]
            m["calls"] += 1
            m["input_tokens"] += input_tokens
            m["output_tokens"] += output_tokens
            m["seconds"] += elapsed

            # 按调用方聚合
            if caller:
                if caller not in self.by_caller:
                    self.by_caller[caller] = {"calls": 0, "input_tokens": 0, "output_tokens": 0}
                c = self.by_caller[caller]
                c["calls"] += 1
                c["input_tokens"] += input_tokens
                c["output_tokens"] += output_tokens

            # ★ 按 task_id 聚合（本次会话维度）
            if task_id:
                if task_id not in self.by_task:
                    self.by_task[task_id] = {
                        "calls": 0, "input_tokens": 0, "output_tokens": 0,
                        "seconds": 0.0, "started_at": time.time(),
                        "last_at": time.time(),
                    }
                t = self.by_task[task_id]
                t["calls"] += 1
                t["input_tokens"] += input_tokens
                t["output_tokens"] += output_tokens
                t["seconds"] += elapsed
                t["last_at"] = time.time()

            # 持久化（缓冲写入）
            record = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "timestamp": time.time(),
                "call_id": call_id or "",
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
                "elapsed_s": round(elapsed, 2),
                "caller": caller,
                "has_tools": has_tools,
                "task_id": task_id,
                "is_error": bool(is_error),
                "error": (error or "")[:500],
                "req_summary": (req_summary or "")[:300],
                "resp_summary": (resp_summary or "")[:300],
            }
            self._buffer.append(json.dumps(record, ensure_ascii=False))
            need_flush = (
                len(self._buffer) >= self._buffer_flush_count
                or (time.time() - self._buffer_last_flush) > self._buffer_flush_timeout
            )
            if need_flush:
                self._flush_buffer()

    def _flush_buffer(self):
        """将缓冲区写入文件并执行轮转检查。"""
        if not self._buffer:
            return
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write("\n".join(self._buffer) + "\n")
            self._buffer.clear()
            self._buffer_last_flush = time.time()
            # ★ 日志轮转：文件过大时保留最新一半
            try:
                if self._log_file.stat().st_size > self._max_log_size:
                    lines = self._log_file.read_text(encoding="utf-8").splitlines()
                    keep = lines[-(len(lines) // 2):]
                    self._log_file.write_text("\n".join(keep) + "\n", encoding="utf-8")
                    log.info("LLM 日志轮转: %s 从 %d 行截断为 %d 行",
                             self._log_file, len(lines), len(keep))
            except Exception:
                pass
        except Exception:
            pass

    def get_summary(self) -> dict:
        """获取当前统计摘要。"""
        return {
            "total_calls": self.total_calls,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "total_seconds": round(self.total_cost_seconds, 1),
            "by_model": self.by_model,
            "by_caller": self.by_caller,
            "by_task": self.by_task,
        }

    def get_task_summary(self, task_id: str) -> dict:
        """获取单个 task 的统计摘要。"""
        if not task_id or task_id not in self.by_task:
            return {
                "task_id": task_id,
                "calls": 0, "input_tokens": 0, "output_tokens": 0,
                "total_tokens": 0, "seconds": 0.0,
            }
        t = self.by_task[task_id]
        return {
            "task_id": task_id,
            "calls": t["calls"],
            "input_tokens": t["input_tokens"],
            "output_tokens": t["output_tokens"],
            "total_tokens": t["input_tokens"] + t["output_tokens"],
            "seconds": round(t["seconds"], 1),
            "started_at": t.get("started_at", 0),
            "last_at": t.get("last_at", 0),
        }


# 全局单例
_monitor = LLMMonitor()
