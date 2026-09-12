"""JS Analyzer 主入口 — analyze_js，从 js_analyzer.py 抽取，行为不变。"""

from __future__ import annotations

from core.log import get_logger

from ._models import JSAnalysisResult
from ._extractors import (
    _extract_api_calls,
    _extract_routes,
    _detect_router_mode,
    _extract_auth_patterns,
    _extract_sensitive_info,
    _extract_source_maps,
    _extract_realtime_endpoints,
    _extract_base_urls,
    _apply_base_urls,
)

log = get_logger("js_analyzer")


def analyze_js(
    js_contents: list[tuple[str, str]],
    base_url: str = "",
) -> JSAnalysisResult:
    """分析多个 JS 文件内容。

    Args:
        js_contents: [(js_url, js_text), ...]
        base_url: 站点基础 URL（用于拼接相对路径）

    Returns:
        JSAnalysisResult
    """
    import time as _time
    result = JSAnalysisResult()
    result.js_files_analyzed = len(js_contents)

    seen_apis: set[str] = set()
    seen_routes: set[str] = set()

    # ★ 单文件正则匹配的硬超时（秒）
    #   超过此时长则跳过该文件剩余的正则提取，避免拖慢 Phase 0
    PER_FILE_BUDGET = 8.0
    # ★ 大文件阈值：超过则只跑"安全"的轻量正则（敏感信息 + source map），
    #   跳过含 DOTALL 的复杂正则（API 配置对象、Vue Router 元数据等）
    LARGE_FILE_THRESHOLD = 500 * 1024  # 500 KB

    for js_url, js_text in js_contents:
        result.total_js_size += len(js_text)
        is_large = len(js_text) >= LARGE_FILE_THRESHOLD
        t0 = _time.monotonic()

        try:
            # ---- 1. API 调用提取 ----
            _extract_api_calls(js_text, js_url, base_url, seen_apis, result,
                              skip_dotall=is_large)
            if _time.monotonic() - t0 > PER_FILE_BUDGET:
                log.warning("JS 分析超时跳过 (%s, %dKB): API 提取后已超 %.1fs",
                            js_url[-80:], len(js_text) // 1024, PER_FILE_BUDGET)
                continue

            # ---- 2. 路由表提取 ----
            _extract_routes(js_text, js_url, seen_routes, result,
                           skip_dotall=is_large)
            # 顺手探测 router 模式（hash / history），整个任务里只要任一文件命中即可
            if not result.router_mode:
                rm = _detect_router_mode(js_text)
                if rm:
                    result.router_mode = rm
            if _time.monotonic() - t0 > PER_FILE_BUDGET:
                log.warning("JS 分析超时跳过 (%s, %dKB): 路由提取后已超 %.1fs",
                            js_url[-80:], len(js_text) // 1024, PER_FILE_BUDGET)
                continue

            # ---- 3. 鉴权模式识别（含 DOTALL，但量词都是有界的） ----
            if not is_large:
                _extract_auth_patterns(js_text, js_url, result)

            # ---- 4. 敏感信息（量词都是有界的，安全） ----
            _extract_sensitive_info(js_text, js_url, result)

            # ---- 5. Source Map（简单匹配，安全） ----
            _extract_source_maps(js_text, js_url, base_url, result)

            # ---- 6. WebSocket / SSE 端点 ----
            _extract_realtime_endpoints(js_text, js_url, result)

            # ---- 7. baseURL 提取（axios.create / 变量赋值） ----
            _extract_base_urls(js_text, js_url, result)
        except Exception as e:
            log.warning("JS 分析单文件出错 (%s): %s", js_url[-80:], e)
            continue

        elapsed = _time.monotonic() - t0
        if elapsed > 2.0:
            log.info("JS 分析单文件耗时 %.1fs (%dKB, %s%s)",
                     elapsed, len(js_text) // 1024,
                     js_url[-60:], " [大文件简化]" if is_large else "")

    # ★ baseURL 后处理：将相对路径 API 拼接完整 URL
    _apply_base_urls(result, base_url)

    log.info("JS 分析完成: %d 文件, %d 个 API, %d 个路由, %d 个鉴权模式, %d 个敏感信息, "
             "%d 个 source map, %d 个 WebSocket, %d 个 SSE, %d 个 baseURL",
             result.js_files_analyzed, len(result.api_calls), len(result.routes),
             len(result.auth_patterns), len(result.sensitive_info), len(result.source_maps),
             len(result.websocket_endpoints), len(result.sse_endpoints), len(result.base_urls))

    return result
