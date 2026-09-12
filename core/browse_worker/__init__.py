"""BrowseWorker — Phase 1 浏览器操作子 Agent

每个 BrowseWorker 负责一组菜单页面的深度操作和流量抓取。
独立 LLM 上下文，串行执行，共享同一个浏览器实例。

设计原则：
- 每组控制在 15-25 个 Tab 总量（约 5-8 个菜单页面）
- 独立上下文避免长对话幻觉
- 操作完毕后上报抓到的 API 列表，由主 Agent 汇总

★ 本包由原 core/browse_worker.py 拆分而来，所有公开/私有名保持兼容。
  子模块：
    _menu_parser  — 常量 + 菜单树解析函数
    _menu_grouper — 菜单分组 + checklist 生成
    _ledger       — BrowseTaskLedger 任务账本
    _worker       — BrowseWorker 子 Agent
"""

from __future__ import annotations

# ============================================================
# 常量（菜单树分组逻辑）
# ============================================================
from ._menu_parser import (
    TARGET_TABS_PER_GROUP,
    MAX_TABS_PER_GROUP,
    MIN_TABS_PER_GROUP,
    MENU_API_KEYWORDS,
    MENU_NODE_KEYS,
    MENU_CHILD_KEYS,
    MENU_PATH_KEYS,
    MENU_NAME_KEYS,
    MENU_META_NAME_KEYS,
    NEGATIVE_MENU_HINTS,
)

# ============================================================
# 菜单树解析函数（含 _page_name_from_url，外部 crawler 直接 import）
# ============================================================
from ._menu_parser import (
    _contains_menu_keyword,
    _unwrap_menu_payload,
    _node_children,
    _node_name,
    _node_path,
    _combine_route_path,
    _route_to_page_url,
    _route_entry_url_candidates,
    _flatten_menu_nodes,
    _normalize_menu_node,
    normalize_menu_tree_to_ruoyi_like,
    _score_menu_candidate,
    _add_menu_candidate,
    parse_menu_tree,
    build_menu_tree_from_crawl,
    _page_name_from_url,
)

# ============================================================
# 菜单分组函数
# ============================================================
from ._menu_grouper import (
    _get_auth_token,
    _count_tabs,
    _count_pages,
    _collect_menu_page_keys,
    _build_js_route_groups,
    group_menus_by_tab_weight,
    build_group_checklist,
)

# ============================================================
# 任务账本
# ============================================================
from ._ledger import BrowseTaskLedger

# ============================================================
# 子 Agent 执行
# ============================================================
from ._worker import (
    BROWSE_WORKER_MAX_ROUNDS,
    BrowseWorker,
)

# ============================================================
# 模块级日志（保持兼容）
# ============================================================
from ._menu_parser import log

# ============================================================
# 外部依赖再导出（保持原模块 import 兼容）
# ============================================================
from ._menu_parser import json, get_logger
from ._worker import (
    asyncio,
    Path,
    AsyncGenerator,
    TYPE_CHECKING,
    LLMClient,
    Message,
    parse_tool_call_arguments,
    ContextManager,
    build_browse_worker_tools,
    ToolExecutor,
    MAX_TOOL_RESULT,
    REPEAT_TOOL_THRESHOLD,
    classify_realtime_flow,
    dedupe_realtime_channels,
)

# ============================================================
# __all__ — 公开 API
# ============================================================
__all__ = [
    # 主入口
    "parse_menu_tree",
    "group_menus_by_tab_weight",
    "build_menu_tree_from_crawl",
    "build_group_checklist",
    "normalize_menu_tree_to_ruoyi_like",
    # 子 Agent
    "BrowseWorker",
    "BrowseTaskLedger",
]
