"""JS Analyzer — JS 深度静态分析

从 SPA 应用的 JS 文件中提取：
1. API 端点（fetch/axios/$.ajax/XMLHttpRequest 调用）
2. 前端路由表（Vue Router / React Router / Angular）
3. 鉴权模式（interceptor / 全局 token 注入）
4. 敏感信息（硬编码 key/secret/token）
5. Source Map 探测

不依赖 AST 解析器，用精心设计的正则实现高召回率提取。

★ 本包由原 core/js_analyzer.py（1937 行）拆分而来，所有公开/私有名保持兼容。
  子模块：
    _models       — 数据模型
    _patterns     — 正则模式集
    _extractors   — 提取器函数
    _analyzer     — 主入口 analyze_js
    _page         — 爬虫集成高层函数 analyze_page_js
    _llm          — LLM 增强 JS 分析
    _crawl_data   — CDN 判定 + 爬虫数据转换
    _cache        — JS 源码缓存 & API 定位
"""

from __future__ import annotations

# ============================================================
# 数据模型
# ============================================================
from ._models import (
    JSApiCall,
    JSRoute,
    JSAuthPattern,
    JSSensitiveInfo,
    JSAnalysisResult,
)

# ============================================================
# 正则模式（保持兼容，外部测试 / 文档可能引用）
# ============================================================
from ._patterns import (
    _API_PATTERNS,
    _CONCAT_URL_PATTERN,
    _TEMPLATE_API_PATTERN,
    _PATH_PATTERNS,
    _AXIOS_BASEURL_PATTERN,
    _BASEURL_ASSIGN_PATTERN,
    _WEBSOCKET_PATTERN,
    _SSE_PATTERN,
    _ROUTE_PATTERNS,
    _TOKEN_KEY_HINTS,
    _AUTH_STATE_HINTS,
    _STORAGE_KEY_DIRECT_PATTERN,
    _STORAGE_KEY_VAR_PATTERN,
    _STORAGE_VAR_USE_PATTERN,
    _AUTH_PATTERNS,
    _SENSITIVE_PATTERNS,
    _SOURCEMAP_PATTERN,
    _ROUTE_TABLE_HEAD,
    _PATH_FIELD_LOOSE,
    _ROUTE_NEIGHBOR_HINT,
    _REACT_ROUTE_PATTERN,
    _ANGULAR_PATH_PATTERN,
    _STATIC_SUFFIXES,
    _API_PREFIXES,
    _NON_ROUTE_HINTS,
    _HASH_MODE_PATTERN,
    _HISTORY_MODE_PATTERN,
)

# ============================================================
# 提取器（含 auth key 判定，外部 crawler_core 直接 import）
# ============================================================
from ._extractors import (
    _looks_like_auth_storage_key,
    _looks_like_auth_state_key,
    _extract_api_calls,
    _extract_routes,
    _is_valid_spa_route,
    _find_matching_bracket,
    _detect_router_mode,
    _extract_storage_keys,
    _extract_auth_patterns,
    _extract_sensitive_info,
    _extract_source_maps,
    _extract_realtime_endpoints,
    _extract_base_urls,
    _apply_base_urls,
    _is_valid_api_path,
    _extract_params_from_context,
)

# ============================================================
# 主入口
# ============================================================
from ._analyzer import analyze_js

# ============================================================
# 爬虫集成高层函数
# ============================================================
from ._page import analyze_page_js

# ============================================================
# LLM 增强 JS 分析
# ============================================================
from ._llm import (
    llm_analyze_key_js,
    _is_key_business_js,
    _extract_api_chunks,
    _KEY_JS_PATTERNS,
    _API_CONTEXT_KEYWORDS,
)

# ============================================================
# CDN 判定 + 爬虫数据转换
# ============================================================
from ._crawl_data import (
    _is_static_cdn_host,
    _route_base_url_from_source,
    _STATIC_CDN_HOSTS,
    _STATIC_CDN_KEYWORDS,
    js_result_to_crawl_data,
)

# ============================================================
# JS 源码缓存 & API 定位
# ============================================================
from ._cache import (
    _js_source_cache,
    _MAX_CACHE_BYTES_PER_TARGET,
    _MAX_TARGETS_IN_CACHE,
    _normalize_target_key,
    cache_js_sources,
    clear_js_cache,
    get_js_cache_stats,
    locate_api_in_js,
)

# ============================================================
# __all__ — 公开 API
# ============================================================
__all__ = [
    # 数据模型
    "JSApiCall",
    "JSRoute",
    "JSAuthPattern",
    "JSSensitiveInfo",
    "JSAnalysisResult",
    # 主入口
    "analyze_js",
    # 爬虫集成
    "analyze_page_js",
    # LLM 增强
    "llm_analyze_key_js",
    # 爬虫数据转换
    "js_result_to_crawl_data",
    # 缓存
    "cache_js_sources",
    "clear_js_cache",
    "get_js_cache_stats",
    "locate_api_in_js",
]
