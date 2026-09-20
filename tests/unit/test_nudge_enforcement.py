"""F11 nudge 强制出工具单元测试。"""
from __future__ import annotations

from core.session.utils_mixin import UtilsMixin


class TestLoopNudgeTemplates:
    def test_actuator_exposure_nudge(self):
        mixin = UtilsMixin()
        nudge = mixin.get_loop_nudge("actuator_exposure")
        assert "Actuator" in nudge
        assert "heapdump" in nudge

    def test_shiro_nudge(self):
        mixin = UtilsMixin()
        nudge = mixin.get_loop_nudge("shiro_remmeberme_active")
        assert "Shiro" in nudge
        assert "deleteMe" in nudge

    def test_heapdump_nudge(self):
        mixin = UtilsMixin()
        nudge = mixin.get_loop_nudge("heapdump_leak")
        assert "heapdump" in nudge

    def test_unknown_trigger_empty(self):
        mixin = UtilsMixin()
        assert mixin.get_loop_nudge("nonexistent") == ""


class TestEnforceLifecycleTool:
    def test_no_tool_calls_returns_nudge(self):
        mixin = UtilsMixin()
        class MockResp:
            tool_calls = []
        result = mixin._enforce_lifecycle_tool(MockResp())
        assert result is not None
        assert "lifecycle" in result.lower()

    def test_lifecycle_tool_no_nudge(self):
        mixin = UtilsMixin()
        class MockResp:
            tool_calls = [{"name": "finish_scan"}]
        result = mixin._enforce_lifecycle_tool(MockResp())
        assert result is None

    def test_non_lifecycle_tool_returns_nudge(self):
        mixin = UtilsMixin()
        class MockResp:
            tool_calls = [{"name": "browser_goto"}]
        result = mixin._enforce_lifecycle_tool(MockResp())
        assert result is not None

    def test_spawn_agent_no_nudge(self):
        mixin = UtilsMixin()
        class MockResp:
            tool_calls = [{"name": "spawn_agent"}]
        result = mixin._enforce_lifecycle_tool(MockResp())
        assert result is None

    def test_record_coverage_no_nudge(self):
        mixin = UtilsMixin()
        class MockResp:
            tool_calls = [{"name": "record_coverage"}]
        result = mixin._enforce_lifecycle_tool(MockResp())
        assert result is None
