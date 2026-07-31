"""
ToolRouter — 将工具调用路由到真实 MCP Server 函数

每个 MCP Server 暴露的是 async 函数，ToolRouter 在同步上下文中
通过 asyncio.run 桥接调用。
"""

from __future__ import annotations

import asyncio
from typing import Any

from core.log import get_logger

log = get_logger("tool_router")


class ToolRouter:
    """将工具名路由到对应的 MCP Server 异步函数。"""

    def __init__(self):
        self._browser_mod = None
        self._proxy_mod = None
        self._knowledge_mod = None
        self._note_mod = None
        self._report_mod = None
        self._custom_report_mod = None
        self._target_mod = None

    def _lazy_import(self):
        """懒加载 MCP 模块，避免启动时全部初始化。"""
        if self._browser_mod is None:
            from mcp_servers import browser_mcp, proxy_mcp, knowledge_mcp, note_mcp, report_mcp, target_mcp, custom_report_mcp
            self._browser_mod = browser_mcp
            self._proxy_mod = proxy_mcp
            self._knowledge_mod = knowledge_mcp
            self._note_mod = note_mcp
            self._report_mod = report_mcp
            self._custom_report_mod = custom_report_mcp
            self._target_mod = target_mcp

    # 工具名 → (模块, 函数名) 的路由表
    ROUTE_TABLE: dict[str, tuple[str, str]] = {
        # Browser
        "browser_goto": ("_browser_mod", "browser_goto"),
        "browser_click": ("_browser_mod", "browser_click"),
        "browser_hover": ("_browser_mod", "browser_hover"),
        "browser_fill": ("_browser_mod", "browser_fill"),
        "browser_get_content": ("_browser_mod", "browser_get_content"),
        "browser_get_accessibility_tree": ("_browser_mod", "browser_get_accessibility_tree"),
        "browser_screenshot": ("_browser_mod", "browser_screenshot"),
        "browser_get_cookies": ("_browser_mod", "browser_get_cookies"),
        "browser_set_cookie": ("_browser_mod", "browser_set_cookie"),
        "browser_evaluate": ("_browser_mod", "browser_evaluate"),
        "js_extract_apis": ("_browser_mod", "js_extract_apis"),
        "js_analyze_selected": ("_browser_mod", "js_analyze_selected"),
        # Proxy
        "proxy_get_traffic": ("_proxy_mod", "proxy_get_traffic"),
        "proxy_get_flow_detail": ("_proxy_mod", "proxy_get_flow_detail"),
        "proxy_replay": ("_proxy_mod", "proxy_replay"),
        "proxy_send_request": ("_proxy_mod", "proxy_send_request"),
        "proxy_batch_send": ("_proxy_mod", "proxy_batch_send"),
        "proxy_diff_responses": ("_proxy_mod", "proxy_diff_responses"),
        # Knowledge
        "knowledge_search": ("_knowledge_mod", "knowledge_search"),
        "knowledge_load_skill": ("_knowledge_mod", "knowledge_load_skill"),
        "knowledge_list_categories": ("_knowledge_mod", "knowledge_list_categories"),
        # Note
        "note_add": ("_note_mod", "note_add"),
        "note_read": ("_note_mod", "note_read"),
        "note_summary": ("_note_mod", "note_summary"),
        # Report
        "report_generate": ("_report_mod", "report_generate"),
        # Custom Report Template
        "report_check_template": ("_custom_report_mod", "report_check_template"),
        "report_format_with_template": ("_custom_report_mod", "report_format_with_template"),
        "report_save_formatted": ("_custom_report_mod", "report_save_formatted"),
        # Target
        "target_add_scope": ("_target_mod", "target_add_scope"),
        "target_remove_scope": ("_target_mod", "target_remove_scope"),
        "target_check_scope": ("_target_mod", "target_check_scope"),
        "target_list_scope": ("_target_mod", "target_list_scope"),
    }

    def execute(self, tool_name: str, args: dict[str, Any]) -> str:
        """同步执行一个工具调用，返回字符串结果。"""
        self._lazy_import()

        route = self.ROUTE_TABLE.get(tool_name)
        if not route:
            log.warning("未知工具: %s", tool_name)
            return f"未知工具: {tool_name}"

        mod_attr, func_name = route
        module = getattr(self, mod_attr)
        if module is None:
            return f"模块未加载: {mod_attr}"

        func = getattr(module, func_name, None)
        if func is None:
            return f"函数未找到: {func_name}"

        try:
            actual_func = getattr(func, "fn", func)

            # ★ 参数校验：检查必填参数是否缺失，给出清晰提示而非 TypeError traceback
            import inspect
            sig = inspect.signature(actual_func)
            missing = []
            for pname, param in sig.parameters.items():
                if param.default is inspect.Parameter.empty and param.kind in (
                    inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY,
                ) and pname not in args:
                    missing.append(pname)
            if missing:
                hint = f"缺少必填参数: {', '.join(missing)}。你提供的参数: {list(args.keys()) or '(空)'}"
                log.warning("工具参数缺失 %s: %s", tool_name, hint)
                return f"❌ {tool_name} 调用失败 — {hint}\n请重新调用并补全所有必填参数。"

            result = self._run_async(actual_func, args)
            return str(result)
        except TypeError as e:
            # 函数签名不匹配（LLM 传了错误参数名等）
            log.warning("工具参数错误 %s: %s (args=%s)", tool_name, e, list(args.keys()))
            return f"❌ {tool_name} 参数错误: {e}\n你提供的参数: {list(args.keys())}\n请检查参数名和类型后重试。"
        except Exception as e:
            # 网络层异常（DNS/超时/连接拒绝等）是预期内的，降级为 warning，不打 traceback
            err_str = str(e).lower()
            err_type = type(e).__name__.lower()
            is_network_err = (
                "dns" in err_type or "timeout" in err_type or "connection" in err_type
                or "could not resolve" in err_str or "timed out" in err_str
                or "connection refused" in err_str or "connection reset" in err_str
                or "network is unreachable" in err_str
            )
            if is_network_err:
                log.warning("工具网络异常 %s: %s", tool_name, e)
            else:
                log.error("工具执行错误 %s: %s", tool_name, e, exc_info=True)
            return f"工具执行失败: {tool_name} — {e}"

    @staticmethod
    def _run_async(func, args: dict) -> Any:
        """在同步上下文中运行异步函数。"""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, func(**args))
                return future.result(timeout=60)
        else:
            return asyncio.run(func(**args))
