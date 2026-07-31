"""
Logging — 统一日志配置

所有模块通过 `from core.log import logger` 获取 logger。
日志同时输出到控制台（彩色）和文件（JSON 结构化）。
第三方库（httpx/openai/httpcore）日志被压制到 WARNING 级别。

结构化字段注入：
- 通过 `bind_context()` 注入 session_id / phase / feature_id 等上下文
- 文件日志自动输出 JSON Lines 格式，便于日志分析系统消费
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from datetime import datetime, timezone


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_DIR = Path(os.getenv("LOG_DIR", "./data/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ---- 线程局部上下文 ----
_context = threading.local()


def bind_context(**kwargs) -> None:
    """注入结构化日志上下文（session_id / phase / feature_id 等）。

    用法：
        bind_context(session_id="task_xxx", phase="test", feature_id="fp_1")
        # 之后所有日志自动携带这些字段
    """
    if not hasattr(_context, "fields"):
        _context.fields = {}
    _context.fields.update(kwargs)


def clear_context() -> None:
    """清空上下文（扫描结束或 session 切换时调用）。"""
    _context.fields = {}


def get_context() -> dict:
    """获取当前上下文字典。"""
    return getattr(_context, "fields", {})


class _ContextInjector(logging.Filter):
    """日志 Filter：将线程局部上下文字段注入 LogRecord。"""

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = get_context()
        record.context = ctx  # type: ignore[attr-defined]
        return True


class _JsonFormatter(logging.Formatter):
    """JSON Lines 格式化器，输出到文件。"""

    def format(self, record: logging.LogRecord) -> str:
        # 基础字段
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # 位置信息
        if record.funcName and record.funcName != "<module>":
            entry["loc"] = f"{record.module}.{record.funcName}:{record.lineno}"

        # 上下文字段
        ctx = getattr(record, "context", None)
        if ctx:
            entry.update(ctx)

        # 异常信息
        if record.exc_info and record.exc_info[0] is not None:
            entry["exc_type"] = record.exc_info[0].__name__
            entry["exc_msg"] = str(record.exc_info[1])

        return json.dumps(entry, ensure_ascii=False, default=str)


def _setup_logger() -> logging.Logger:
    log = logging.getLogger("pentest_agent")
    log.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    if log.handlers:
        return log  # 避免重复添加

    # 注入上下文 Filter
    log.addFilter(_ContextInjector())

    # 控制台 Handler（简洁格式，人类可读）
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        "%(asctime)s [%(levelname).1s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    console.setFormatter(console_fmt)
    log.addHandler(console)

    # 文件 Handler（JSON Lines 格式，机器可读）
    file_handler = logging.FileHandler(
        LOG_DIR / "agent.jsonl", encoding="utf-8", mode="a",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(_JsonFormatter())
    log.addHandler(file_handler)

    # 兼容：保留纯文本日志（调试时更方便 tail）
    text_handler = logging.FileHandler(
        LOG_DIR / "agent.log", encoding="utf-8", mode="a",
    )
    text_handler.setLevel(logging.DEBUG)
    text_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s.%(funcName)s:%(lineno)d — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    text_handler.setFormatter(text_fmt)
    log.addHandler(text_handler)

    # ---- 压制第三方库的冗余日志 ----
    for noisy_lib in ("httpx", "httpcore", "openai", "anthropic", "urllib3",
                       "playwright", "mitmproxy", "hpack"):
        logging.getLogger(noisy_lib).setLevel(logging.WARNING)

    return log


logger = _setup_logger()


def get_logger(name: str) -> logging.Logger:
    """获取子 logger（自动继承 pentest_agent 的配置）。"""
    return logger.getChild(name)


# ================================================================
# 关键 Metrics 计数器
# ================================================================

import threading
from collections import defaultdict


class Metrics:
    """轻量级扫描指标计数器，线程安全。

    用法：
        metrics.inc("pages_crawled")
        metrics.inc("api_discovered", 5)
        metrics.set("active_workers", 3)
        print(metrics.snapshot())
    """

    def __init__(self):
        self._counters: dict[str, float] = defaultdict(float)
        self._gauges: dict[str, float] = {}
        self._lock = threading.Lock()
        self._started_at: float | None = None

    def inc(self, name: str, value: float = 1) -> None:
        """递增计数器。"""
        with self._lock:
            self._counters[name] += value

    def set(self, name: str, value: float) -> None:
        """设置仪表盘值。"""
        with self._lock:
            self._gauges[name] = value

    def mark_start(self) -> None:
        """标记扫描开始时间。"""
        self._started_at = time.time()

    @property
    def elapsed_sec(self) -> float:
        """扫描已用时间（秒）。"""
        if self._started_at is None:
            return 0.0
        return time.time() - self._started_at

    def snapshot(self) -> dict:
        """获取当前所有指标的快照。"""
        import time as _time
        with self._lock:
            result = dict(self._counters)
            result.update({f"gauge.{k}": v for k, v in self._gauges.items()})
            if self._started_at:
                result["elapsed_sec"] = round(_time.time() - self._started_at, 1)
            return result

    def reset(self) -> None:
        """重置所有指标（新扫描任务开始时调用）。"""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._started_at = None


# 全局单例
metrics = Metrics()

