"""
ToolRouter 扩展测试 — 覆盖 execute 方法、参数校验、错误处理、异步桥接。

与 tests/test_tool_router.py 互补（后者仅覆盖路由表结构）。
"""

from __future__ import annotations

import asyncio
import inspect
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.tool_router import ToolRouter


# ============================================================
# 辅助：构造带 .fn 属性的 mock 函数（模拟 @mcp.tool() 装饰器）
# ============================================================

def _make_mock_tool(fn):
    """模拟 FastMCP 的 @mcp.tool() 装饰结果：函数挂 .fn 属性。"""
    wrapper = MagicMock()
    wrapper.fn = fn
    return wrapper


def _setup_router_with_mock_modules(router: ToolRouter, tool_map: dict[str, dict[str, any]]):
    """把 router 的 7 个 _xxx_mod 设置为 mock 模块。

    tool_map 格式: {"browser_goto": {"fn": async_func, "module": "_browser_mod"}, ...}
    """
    modules_cache: dict[str, MagicMock] = {}

    for tool_name, config in tool_map.items():
        mod_attr = config.get("module", "_browser_mod")
        func_name = config.get("func_name", tool_name)
        fn = config["fn"]

        if mod_attr not in modules_cache:
            mod = MagicMock()
            modules_cache[mod_attr] = mod
        setattr(router, mod_attr, modules_cache[mod_attr])
        mock_tool = _make_mock_tool(fn)
        setattr(modules_cache[mod_attr], func_name, mock_tool)


@pytest.fixture
def no_lazy_import():
    """阻止 _lazy_import 真正导入 MCP 模块（mcp 包未安装时会失败）。"""
    with patch.object(ToolRouter, "_lazy_import"):
        yield


# ============================================================
# 测试类
# ============================================================


class TestRouteTableCompleteness:
    """路由表完整性测试（不需要 _lazy_import）。"""

    def test_route_table_has_30_plus_tools(self):
        assert len(ToolRouter.ROUTE_TABLE) >= 30

    def test_all_routes_reference_valid_mod_attrs(self):
        valid_mods = {"_browser_mod", "_proxy_mod", "_knowledge_mod",
                      "_note_mod", "_report_mod", "_custom_report_mod", "_target_mod"}
        for tool_name, (mod_attr, func_name) in ToolRouter.ROUTE_TABLE.items():
            assert mod_attr in valid_mods, f"{tool_name}: mod_attr={mod_attr} 不在有效集合中"

    def test_report_tools_present(self):
        report_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("report_")]
        assert len(report_tools) >= 4

    def test_target_tools_present(self):
        target_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("target_")]
        assert len(target_tools) >= 3

    def test_custom_report_tools_present(self):
        custom_tools = [k for k in ToolRouter.ROUTE_TABLE
                        if k in ("report_check_template", "report_format_with_template", "report_save_formatted")]
        assert len(custom_tools) == 3

    def test_js_tools_present(self):
        assert "js_extract_apis" in ToolRouter.ROUTE_TABLE
        assert "js_analyze_selected" in ToolRouter.ROUTE_TABLE

    def test_no_duplicate_func_names_per_module(self):
        """同一模块下的函数名不重复。"""
        from collections import defaultdict
        mod_funcs: dict[str, set[str]] = defaultdict(set)
        for _, (mod_attr, func_name) in ToolRouter.ROUTE_TABLE.items():
            assert func_name not in mod_funcs[mod_attr], f"重复函数: {mod_attr}.{func_name}"
            mod_funcs[mod_attr].add(func_name)

    def test_browser_tools_count(self):
        browser_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("browser_") or k.startswith("js_")]
        assert len(browser_tools) >= 10

    def test_proxy_tools_count(self):
        proxy_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("proxy_")]
        assert len(proxy_tools) >= 5

    def test_knowledge_tools_count(self):
        knowledge_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("knowledge_")]
        assert len(knowledge_tools) >= 2

    def test_note_tools_count(self):
        note_tools = [k for k in ToolRouter.ROUTE_TABLE if k.startswith("note_")]
        assert len(note_tools) >= 2


class TestExecuteUnknownTool:
    """未知工具名处理。"""

    def test_unknown_tool_returns_error_message(self, no_lazy_import):
        router = ToolRouter()
        result = router.execute("nonexistent_tool_xyz", {})
        assert "未知工具" in result
        assert "nonexistent_tool_xyz" in result

    def test_empty_tool_name(self, no_lazy_import):
        router = ToolRouter()
        result = router.execute("", {})
        assert "未知工具" in result

    def test_none_tool_name(self, no_lazy_import):
        router = ToolRouter()
        result = router.execute(None, {})  # type: ignore
        assert "未知工具" in result or "None" in result


class TestExecuteWithMockModules:
    """使用 mock 模块测试 execute 路由执行。"""

    def test_execute_calls_correct_function(self, no_lazy_import):
        """execute 正确路由到对应模块的函数。"""
        router = ToolRouter()

        called = {"flag": False}

        async def fake_goto(url: str = ""):
            called["flag"] = True
            return f"navigated to {url}"

        _setup_router_with_mock_modules(router, {
            "browser_goto": {"fn": fake_goto, "module": "_browser_mod", "func_name": "browser_goto"}
        })

        result = router.execute("browser_goto", {"url": "http://example.com"})
        assert "navigated to" in result
        assert called["flag"] is True

    def test_execute_with_no_args(self, no_lazy_import):
        """函数无必填参数时正常调用。"""
        router = ToolRouter()

        async def fake_list():
            return "[]"

        _setup_router_with_mock_modules(router, {
            "target_list_scope": {"fn": fake_list, "module": "_target_mod", "func_name": "target_list_scope"}
        })

        result = router.execute("target_list_scope", {})
        assert "[]" in result

    def test_execute_missing_required_param(self, no_lazy_import):
        """缺少必填参数时返回清晰提示。"""
        router = ToolRouter()

        async def fake_click(selector: str):  # selector 无默认值 → 必填
            return f"clicked {selector}"

        _setup_router_with_mock_modules(router, {
            "browser_click": {"fn": fake_click, "module": "_browser_mod", "func_name": "browser_click"}
        })

        result = router.execute("browser_click", {})
        assert "缺少必填参数" in result
        assert "selector" in result

    def test_execute_missing_one_of_multiple_required(self, no_lazy_import):
        """多个必填参数只缺一个时提示正确。"""
        router = ToolRouter()

        async def fake_send(method: str, url: str):
            return f"{method} {url}"

        _setup_router_with_mock_modules(router, {
            "proxy_send_request": {"fn": fake_send, "module": "_proxy_mod", "func_name": "proxy_send_request"}
        })

        result = router.execute("proxy_send_request", {"method": "GET"})
        assert "缺少必填参数" in result
        assert "url" in result

    def test_execute_with_optional_params(self, no_lazy_import):
        """有默认值的参数不视为必填。"""
        router = ToolRouter()

        async def fake_search(query: str, limit: int = 10):
            return f"results for {query} limit={limit}"

        _setup_router_with_mock_modules(router, {
            "knowledge_search": {"fn": fake_search, "module": "_knowledge_mod", "func_name": "knowledge_search"}
        })

        result = router.execute("knowledge_search", {"query": "sqli"})
        assert "results for sqli" in result
        assert "limit=10" in result

    def test_execute_returns_string(self, no_lazy_import):
        """execute 始终返回字符串。"""
        router = ToolRouter()

        async def fake_return_int():
            return 42

        _setup_router_with_mock_modules(router, {
            "note_summary": {"fn": fake_return_int, "module": "_note_mod", "func_name": "note_summary"}
        })

        result = router.execute("note_summary", {})
        assert isinstance(result, str)
        assert "42" in result

    def test_execute_function_returns_none(self, no_lazy_import):
        """函数返回 None 时 str(None) = 'None'。"""
        router = ToolRouter()

        async def fake_returns_none():
            return None

        _setup_router_with_mock_modules(router, {
            "browser_get_cookies": {"fn": fake_returns_none, "module": "_browser_mod", "func_name": "browser_get_cookies"}
        })

        result = router.execute("browser_get_cookies", {})
        assert isinstance(result, str)

    def test_execute_with_extra_optional_args(self, no_lazy_import):
        """传了额外参数不影响调用。"""
        router = ToolRouter()

        async def fake_goto(url: str = ""):
            return f"goto {url}"

        _setup_router_with_mock_modules(router, {
            "browser_goto": {"fn": fake_goto, "module": "_browser_mod", "func_name": "browser_goto"}
        })

        result = router.execute("browser_goto", {"url": "http://example.com", "extra": "ignored"})
        assert "goto" in result


class TestExecuteErrorHandling:
    """错误处理测试。"""

    def test_network_error_caught(self, no_lazy_import):
        """网络异常被降级为 warning。"""
        router = ToolRouter()

        async def fake_network_error(url: str = ""):
            raise ConnectionRefusedError("Connection refused")

        _setup_router_with_mock_modules(router, {
            "browser_goto": {"fn": fake_network_error, "module": "_browser_mod", "func_name": "browser_goto"}
        })

        result = router.execute("browser_goto", {"url": "http://10.255.255.1"})
        assert "工具执行失败" in result or "Connection refused" in result

    def test_timeout_error_caught(self, no_lazy_import):
        """超时异常被捕获。"""
        router = ToolRouter()

        async def fake_timeout(url: str = ""):
            raise TimeoutError("Request timed out")

        _setup_router_with_mock_modules(router, {
            "browser_goto": {"fn": fake_timeout, "module": "_browser_mod", "func_name": "browser_goto"}
        })

        result = router.execute("browser_goto", {"url": "http://slow.example.com"})
        assert "工具执行失败" in result or "timed out" in result.lower()

    def test_generic_exception_caught(self, no_lazy_import):
        """普通异常被捕获并返回错误信息。"""
        router = ToolRouter()

        async def fake_crash(url: str = ""):
            raise RuntimeError("Unexpected crash")

        _setup_router_with_mock_modules(router, {
            "browser_goto": {"fn": fake_crash, "module": "_browser_mod", "func_name": "browser_goto"}
        })

        result = router.execute("browser_goto", {"url": "http://example.com"})
        assert "工具执行失败" in result
        assert "Unexpected crash" in result

    def test_dns_error_treated_as_network(self, no_lazy_import):
        """DNS 解析失败被识别为网络错误。"""
        router = ToolRouter()

        class FakeGaiError(Exception):
            pass

        async def fake_dns_error(url: str = ""):
            raise FakeGaiError("gaierror: Name or service not known")

        _setup_router_with_mock_modules(router, {
            "browser_goto": {"fn": fake_dns_error, "module": "_browser_mod", "func_name": "browser_goto"}
        })

        result = router.execute("browser_goto", {"url": "http://nonexistent.invalid"})
        assert "工具执行失败" in result

    def test_module_not_loaded_returns_error(self, no_lazy_import):
        """模块属性为 None 时返回模块未加载提示。"""
        router = ToolRouter()
        router._browser_mod = None
        result = router.execute("browser_goto", {"url": "http://example.com"})
        assert "模块未加载" in result

    def test_function_not_found_in_module(self, no_lazy_import):
        """模块已加载但函数不存在。"""
        router = ToolRouter()
        # 设置一个 MagicMock 模块但不设置对应函数
        router._browser_mod = MagicMock()
        # 让 getattr 返回 None
        router._browser_mod.nonexistent_func = None
        # 临时添加路由
        ToolRouter.ROUTE_TABLE["test_missing_func"] = ("_browser_mod", "nonexistent_func")
        try:
            result = router.execute("test_missing_func", {})
            assert "函数未找到" in result
        finally:
            ToolRouter.ROUTE_TABLE.pop("test_missing_func", None)


class TestRunAsync:
    """_run_async 静态方法测试。"""

    def test_run_async_no_running_loop(self):
        """无事件循环时 asyncio.run 直接执行。"""
        async def fake_func(x: int = 0):
            return x * 2

        result = ToolRouter._run_async(fake_func, {"x": 21})
        assert result == 42

    def test_run_async_with_no_args(self):
        async def fake_func():
            return "ok"

        result = ToolRouter._run_async(fake_func, {})
        assert result == "ok"

    def test_run_async_with_exception(self):
        async def fake_func():
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            ToolRouter._run_async(fake_func, {})

    def test_run_async_returns_dict(self):
        async def fake_func():
            return {"key": "value"}

        result = ToolRouter._run_async(fake_func, {})
        assert result == {"key": "value"}

    def test_run_async_returns_list(self):
        async def fake_func():
            return [1, 2, 3]

        result = ToolRouter._run_async(fake_func, {})
        assert result == [1, 2, 3]


class TestLazyImport:
    """_lazy_import 方法测试。

    由于 mcp 包未安装，通过 mock sys.modules 模拟 MCP 模块。
    """

    @pytest.fixture
    def mock_mcp_modules(self):
        """在 sys.modules 中注入 mock MCP 模块。"""
        original = {}
        mod_names = [
            "mcp_servers.browser_mcp", "mcp_servers.proxy_mcp",
            "mcp_servers.knowledge_mcp", "mcp_servers.note_mcp",
            "mcp_servers.report_mcp", "mcp_servers.target_mcp",
            "mcp_servers.custom_report_mcp",
        ]
        for name in mod_names:
            original[name] = sys.modules.get(name)
            sys.modules[name] = MagicMock()

        yield

        for name, orig in original.items():
            if orig is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = orig

    def test_lazy_import_sets_all_modules(self, mock_mcp_modules):
        """_lazy_import 后所有 7 个模块属性被设置。"""
        router = ToolRouter()
        router._lazy_import()

        assert router._browser_mod is not None
        assert router._proxy_mod is not None
        assert router._knowledge_mod is not None
        assert router._note_mod is not None
        assert router._report_mod is not None
        assert router._custom_report_mod is not None
        assert router._target_mod is not None

    def test_lazy_import_idempotent(self, mock_mcp_modules):
        """多次调用 _lazy_import 不会重复导入。"""
        router = ToolRouter()
        router._lazy_import()
        mod1 = router._browser_mod
        router._lazy_import()
        mod2 = router._browser_mod
        assert mod1 is mod2  # 同一引用

    def test_lazy_import_only_imports_once(self, mock_mcp_modules):
        """_browser_mod 已设置时不会重新导入。"""
        router = ToolRouter()
        sentinel = MagicMock()
        router._browser_mod = sentinel
        router._lazy_import()
        assert router._browser_mod is sentinel  # 未被覆盖
