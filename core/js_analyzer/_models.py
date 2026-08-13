"""JS Analyzer 数据模型 — 从 js_analyzer.py 抽取，行为不变。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class JSApiCall:
    """从 JS 中提取的一个 API 调用。"""
    method: str          # GET/POST/PUT/DELETE/PATCH/UNKNOWN
    path: str            # /api/user/list
    source_file: str     # 来源 JS 文件 URL
    context: str = ""    # 周围代码片段（帮助理解业务语义）
    params: list[str] = field(default_factory=list)  # 请求参数名


@dataclass
class JSRoute:
    """从 JS 中提取的一个前端路由。"""
    path: str            # /admin/dashboard
    component: str = ""  # AdminDash
    meta: str = ""       # 路由元信息（权限标记等）
    source_file: str = ""


@dataclass
class JSAuthPattern:
    """识别到的鉴权模式。"""
    pattern_type: str    # "interceptor" / "global_header" / "route_guard" / "token_storage"
    description: str     # 描述
    code_snippet: str    # 相关代码片段
    source_file: str = ""
    storage_keys: list[str] = field(default_factory=list)


@dataclass
class JSSensitiveInfo:
    """敏感信息泄露。"""
    info_type: str       # "api_key" / "secret" / "password" / "internal_url" / "debug_flag"
    value: str           # 具体值
    context: str = ""    # 周围代码
    source_file: str = ""


@dataclass
class JSAnalysisResult:
    """JS 分析完整结果。"""
    api_calls: list[JSApiCall] = field(default_factory=list)
    routes: list[JSRoute] = field(default_factory=list)
    auth_patterns: list[JSAuthPattern] = field(default_factory=list)
    sensitive_info: list[JSSensitiveInfo] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)  # 可访问的 .map URL
    js_files_analyzed: int = 0
    total_js_size: int = 0  # 总 JS 大小（字节）
    router_mode: str = ""   # "hash" / "history" / ""（未探测到，默认 hash 处理）
    # ★ 所有外链 JS 文件 URL（含 hash 文件名，如 chunk-2cd2c088.a68ccc9c.js）
    # 用于 Source Map 动态推导探测：对每个 JS URL 追加 .map 检测
    js_file_urls: list[str] = field(default_factory=list)
    # ★ WebSocket / SSE 端点（new WebSocket() / new EventSource()）
    websocket_endpoints: list[str] = field(default_factory=list)
    sse_endpoints: list[str] = field(default_factory=list)
    # ★ 提取到的 baseURL（用于拼接相对路径 API）
    base_urls: list[str] = field(default_factory=list)
