"""
日志与指标模块测试

覆盖：logger、get_logger、bind_context、clear_context、get_context、
      Metrics（inc/set/mark_start/snapshot/reset）
"""

import pytest
import time

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.log import (
    logger, get_logger, bind_context, clear_context, get_context,
    metrics, Metrics, LOG_DIR,
)


class TestLogger:
    def test_logger_exists(self):
        assert logger is not None
        assert logger.name == "pentest_agent"

    def test_get_logger_child(self):
        child = get_logger("test_module")
        assert child.name == "pentest_agent.test_module"

    def test_log_dir_exists(self):
        assert LOG_DIR.exists()


class TestContext:
    def setup_method(self):
        clear_context()

    def teardown_method(self):
        clear_context()

    def test_bind_and_get(self):
        bind_context(session_id="sess_001", phase="test")
        ctx = get_context()
        assert ctx["session_id"] == "sess_001"
        assert ctx["phase"] == "test"

    def test_bind_multiple(self):
        bind_context(session_id="s1")
        bind_context(phase="explore")
        ctx = get_context()
        assert ctx["session_id"] == "s1"
        assert ctx["phase"] == "explore"

    def test_clear(self):
        bind_context(session_id="s1")
        clear_context()
        ctx = get_context()
        assert ctx == {}

    def test_get_empty(self):
        assert get_context() == {}


class TestMetrics:
    def setup_method(self):
        self.m = Metrics()

    def test_inc(self):
        self.m.inc("pages_crawled")
        self.m.inc("pages_crawled")
        self.m.inc("pages_crawled", 3)
        snap = self.m.snapshot()
        assert snap["pages_crawled"] == 5

    def test_set(self):
        self.m.set("active_workers", 3)
        snap = self.m.snapshot()
        assert snap["gauge.active_workers"] == 3

    def test_mark_start_and_elapsed(self):
        self.m.mark_start()
        time.sleep(0.05)
        assert self.m.elapsed_sec >= 0.04

    def test_elapsed_before_start(self):
        assert self.m.elapsed_sec == 0.0

    def test_snapshot(self):
        self.m.inc("api_discovered", 10)
        self.m.set("queue_size", 5)
        snap = self.m.snapshot()
        assert snap["api_discovered"] == 10
        assert snap["gauge.queue_size"] == 5

    def test_reset(self):
        self.m.inc("x", 100)
        self.m.set("y", 50)
        self.m.mark_start()
        self.m.reset()
        snap = self.m.snapshot()
        assert "x" not in snap
        assert "gauge.y" not in snap
        assert self.m.elapsed_sec == 0.0


class TestGlobalMetrics:
    """测试全局 metrics 单例。"""

    def setup_method(self):
        metrics.reset()

    def test_global_inc(self):
        metrics.inc("test_counter")
        assert metrics.snapshot()["test_counter"] == 1

    def test_global_set(self):
        metrics.set("test_gauge", 42)
        assert metrics.snapshot()["gauge.test_gauge"] == 42
