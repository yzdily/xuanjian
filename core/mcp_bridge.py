"""Core → MCP 服务器状态访问桥接层（A2 耦合治理）。

背景
----
``core`` 中曾有 19 处直接 ``from mcp_servers.proxy_mcp / browser_mcp import <私有符号>``，
形成 core → mcp_servers 私有内部的紧耦合。本模块是**唯一契约点**：

- core 业务代码统一 ``from core.mcp_bridge import _store, _load_new_flows, ...``
- 若 MCP 内部重构（重命名 / 迁移状态所有权到 core），只需改本文件，不必改 19 处调用方。

为什么没有 import-time 循环依赖
------------------------------
所有调用方都是**惰性导入**（``from core.mcp_bridge import ...`` 写在函数体内），
本文件的 ``import mcp_servers.*`` 在运行时才触发，不会在 core 包加载时造成循环。

后续方向（需架构师拍板）
------------------------
将 proxy / browser 的状态所有权从 ``mcp_servers`` 迁到 ``core``，
``mcp_servers`` 退化为薄壳；届时本桥接层可整体删除，core 彻底不依赖 mcp_servers 私有内部。
"""
from __future__ import annotations

from mcp_servers.browser_mcp import _ensure_browser, browser_goto, _page
from mcp_servers.proxy_mcp import _current_task_id, _load_new_flows, _store

__all__ = [
    "_ensure_browser",
    "browser_goto",
    "_page",
    "_current_task_id",
    "_load_new_flows",
    "_store",
]
