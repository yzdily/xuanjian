"""
工具路由模块测试

覆盖：ToolRouter 的路由表完整性、execute 方法、参数校验、错误处理
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.tool_router import ToolRouter


class TestToolRouterRouteTable:
    def test_route_table_not_empty(self):
        assert len(ToolRouter.ROUTE_TABLE) >= 20

    def test_all_routes_have_valid_format(self):
        for tool_name, (mod_attr, func_name) in ToolRouter.ROUTE_TABLE.items():
            assert mod_attr.startswith("_"), f"{tool_name}: mod_attr 应以 _ 开头"
            assert func_name, f"{tool_name}: func_name 不能为空"

    def test_browser_tools_present(self):
        browser_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("browser_")]
        assert len(browser_tools) >= 8

    def test_proxy_tools_present(self):
        proxy_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("proxy_")]
        assert len(proxy_tools) >= 5

    def test_knowledge_tools_present(self):
        knowledge_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("knowledge_")]
        assert len(knowledge_tools) >= 2

    def test_note_tools_present(self):
        note_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("note_")]
        assert len(note_tools) >= 2


class TestToolRouterExecute:
    def test_unknown_tool(self):
        router = ToolRouter()
        # 手动设置模块为 Mock，避免触发真实 lazy_import（可能因环境问题失败）
        router._browser_mod = MagicMock()
        router._proxy_mod = MagicMock()
        router._knowledge_mod = MagicMock()
        router._note_mod = MagicMock()
        router._report_mod = MagicMock()
        router._target_mod = MagicMock()
        result = router.execute("nonexistent_tool", {})
        assert "未知工具" in result

    def test_missing_params_detected(self):
        """缺少必填参数时应给出清晰提示。"""
        router = ToolRouter()
        # Mock 一个模块和函数
        mock_mod = MagicMock()

        async def fake_func(url: str, method: str = "GET"):
            return f"ok: {url}"

        mock_mod.browser_goto = MagicMock()
        mock_mod.browser_goto.fn = fake_func
        router._browser_mod = mock_mod
        router._proxy_mod = MagicMock()
        router._knowledge_mod = MagicMock()
        router._note_mod = MagicMock()
        router._report_mod = MagicMock()
        router._target_mod = MagicMock()

        result = router.execute("browser_goto", {})  # 缺少 url 参数
        assert "缺少必填参数" in result or "参数错误" in result

    def test_successful_execution(self):
        """成功执行工具调用。"""
        router = ToolRouter()
        mock_mod = MagicMock()

        async def fake_goto(url: str):
            return f"已导航到 {url}"

        mock_mod.browser_goto = MagicMock()
        mock_mod.browser_goto.fn = fake_goto
        router._browser_mod = mock_mod
        router._proxy_mod = MagicMock()
        router._knowledge_mod = MagicMock()
        router._note_mod = MagicMock()
        router._report_mod = MagicMock()
        router._target_mod = MagicMock()

        result = router.execute("browser_goto", {"url": "http://example.com"})
        assert "已导航到" in result

    def test_execution_error_handling(self):
        """工具执行异常时应返回错误信息而非崩溃。"""
        router = ToolRouter()
        mock_mod = MagicMock()

        async def failing_func(url: str):
            raise ConnectionError("连接被拒绝")

        mock_mod.browser_goto = MagicMock()
        mock_mod.browser_goto.fn = failing_func
        router._browser_mod = mock_mod
        router._proxy_mod = MagicMock()
        router._knowledge_mod = MagicMock()
        router._note_mod = MagicMock()
        router._report_mod = MagicMock()
        router._target_mod = MagicMock()

        result = router.execute("browser_goto", {"url": "http://x.com"})
        assert "失败" in result or "连接" in result


class TestToolRouterLazyImport:
    def test_initial_state(self):
        router = ToolRouter()
        assert router._browser_mod is None
        assert router._proxy_mod is None
