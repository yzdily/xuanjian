"""F12 上下文虚拟化单元测试。"""
from __future__ import annotations

import os
from pathlib import Path

from core.session.output_store import bound_result, truncate_tool_result


class TestBoundResult:
    def test_small_result_raw(self):
        result = bound_result("test_tool", "hello world")
        assert result["type"] == "raw"
        assert result["content"] == "hello world"

    def test_large_result_truncated(self):
        # Create a large result that exceeds MAX_LINES
        large = "\n".join(f"line {i}" for i in range(3000))
        result = bound_result("test_tool", large)
        assert result["type"] == "truncated"
        assert "TRUNCATED" in result["content"]
        assert "FULL OUTPUT saved to" in result["content"]
        assert "path" in result

    def test_large_bytes_truncated(self):
        large = "x" * (60 * 1024)  # 60KB
        result = bound_result("test_tool", large)
        assert result["type"] == "truncated"

    def test_empty_result_raw(self):
        result = bound_result("test_tool", "")
        assert result["type"] == "raw"

    def test_head_tail_preserved(self):
        lines = [f"line_{i}" for i in range(3000)]
        large = "\n".join(lines)
        result = bound_result("test_tool", large)
        content = result["content"]
        assert "line_0" in content  # head preserved
        assert "line_2999" in content  # tail preserved
        assert "line_1500" not in content  # middle truncated


class TestTruncateToolResult:
    def test_small_result_unchanged(self):
        result = truncate_tool_result("tool", "hello", max_chars=6000)
        assert result == "hello"

    def test_large_result_truncated(self):
        large = "x" * 10000
        result = truncate_tool_result("tool", large, max_chars=6000)
        assert len(result) < 10000
        assert "TRUNCATED" in result

    def test_fallback_to_raw(self):
        result = truncate_tool_result("tool", "hello", max_chars=6000)
        assert result == "hello"
