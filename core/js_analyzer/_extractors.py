"""JS Analyzer 提取器 — 所有 _extract_* 函数与辅助，从 js_analyzer.py 抽取，行为不变。"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urljoin

from core.log import get_logger

from ._models import (
    JSApiCall,
    JSRoute,
    JSAuthPattern,
    JSSensitiveInfo,
    JSAnalysisResult,
)
from ._patterns import (
    _API_PATTERNS,
    _CONCAT_URL_PATTERN,
    _TEMPLATE_API_PATTERN,
    _PATH_PATTERNS,
    _AXIOS_BASEURL_PATTERN,
    _BASEURL_ASSIGN_PATTERN,
    _WEBSOCKET_PATTERN,
    _SSE_PATTERN,
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

log = get_logger("js_analyzer")


# ============================================================
# Auth key 判定
# ============================================================

def _looks_like_auth_storage_key(key: str) -> bool:
    """判断是否像 token/auth 类 storage key（值为 JWT）。"""
    key_lower = key.lower()
    return any(hint in key_lower for hint in _TOKEN_KEY_HINTS)


def _looks_like_auth_state_key(key: str) -> bool:
    """判断是否像登录状态类 storage key（值为固定字符串，如 tenant_user_pass）。"""
    key_lower = key.lower()
    return any(hint in key_lower for hint in _AUTH_STATE_HINTS)


# ============================================================
# API 调用提取
# ============================================================

def _extract_api_calls(
    js_text: str, js_url: str, base_url: str,
    seen: set[str], result: JSAnalysisResult,
    skip_dotall: bool = False,
):
    """提取 API 调用。

    Args:
        skip_dotall: True 时跳过含 DOTALL 标志的复杂正则（用于超大 minified 文件防回溯）
    """
    # 精确匹配：fetch/axios/$.ajax 等
    for pattern in _API_PATTERNS:
        # ★ 大文件保护：跳过 DOTALL 模式（即 axios({...})/$.ajax({...})/request({...}) 这三个）
        if skip_dotall and (pattern.flags & re.DOTALL):
            continue
        for m in pattern.finditer(js_text):
            groups = m.groups()
            if len(groups) >= 2:
                # 有些模式是 (method, path)，有些是 (path, method)
                g0, g1 = groups[0], groups[1]
                if g0 and g0.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    method, path = g0.upper(), g1
                elif g1 and g1.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    method, path = g1.upper(), g0
                elif g0 and g0.startswith("/"):
                    path, method = g0, "GET"
                elif g1 and g1.startswith("/"):
                    path, method = g1, "GET"
                else:
                    path = g0 or g1 or ""
                    method = "UNKNOWN"
            else:
                path = groups[0] if groups else ""
                method = "GET"

            if not path or not _is_valid_api_path(path):
                continue

            dedup_key = f"{method} {path}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # 提取上下文（前后各 80 字符）
            start = max(0, m.start() - 80)
            end = min(len(js_text), m.end() + 80)
            context = js_text[start:end].replace("\n", " ").strip()

            # 尝试提取参数名
            params = _extract_params_from_context(js_text, m.start(), m.end())

            result.api_calls.append(JSApiCall(
                method=method, path=path, source_file=js_url,
                context=context[:200], params=params,
            ))

    # 宽松匹配：API 前缀路径（补全精确匹配漏掉的）
    for m in _TEMPLATE_API_PATTERN.finditer(js_text):
        path = m.group(1)
        # 清理模板变量
        path = re.sub(r'\$\{[^}]+\}', '{id}', path)
        if not _is_valid_api_path(path):
            continue
        dedup_key = f"UNKNOWN {path}"
        if dedup_key in seen:
            continue
        # 检查是否已被精确匹配覆盖（路径前缀匹配）
        if any(path in k for k in seen):
            continue
        seen.add(dedup_key)
        result.api_calls.append(JSApiCall(
            method="UNKNOWN", path=path, source_file=js_url,
        ))

    # ★ 2026-08-12: 字符串拼接 URL 提取 — minified JS 中 e+"/api/user" 形式
    _CONCAT_MAX = 50
    _concat_count = 0
    for m in _CONCAT_URL_PATTERN.finditer(js_text):
        if _concat_count >= _CONCAT_MAX:
            break
        # 两个捕获组：group(1) 是 +后面的路径，group(2) 是 +前面的路径
        path = m.group(1) or m.group(2)
        if not path:
            continue
        path = re.sub(r'\$\{[^}]+\}', '{id}', path)
        if not _is_valid_api_path(path):
            continue
        dedup_key = f"UNKNOWN {path}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        result.api_calls.append(JSApiCall(
            method="UNKNOWN", path=path, source_file=js_url,
        ))
        _concat_count += 1

    # ★ 2026-08-12: 兜底通用路径提取 — 之前 _PATH_PATTERNS 定义了但从未调用
    # 始终运行（不再仅限0结果时），但严格过滤+去重避免噪音
    # 覆盖场景：自定义前缀(如/custom/user)、非标准命名等精确和模板匹配漏掉的路径
    _GENERIC_MAX = 100
    _generic_count = 0
    for m in _PATH_PATTERNS.finditer(js_text):
        if _generic_count >= _GENERIC_MAX:
            break
        path = m.group(1)
        # 清理模板变量
        path = re.sub(r'\$\{[^}]+\}', '{id}', path)
        if not _is_valid_api_path(path):
            continue
        # 兜底模式额外过滤：路径至少 2 段（如 /api/user），排除单段路径(如 /test)
        parts = [p for p in path.strip("/").split("/") if p]
        if len(parts) < 2:
            continue
        dedup_key = f"UNKNOWN {path}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        result.api_calls.append(JSApiCall(
            method="UNKNOWN", path=path, source_file=js_url,
        ))
        _generic_count += 1


# ============================================================
# 路由提取
# ============================================================

def _extract_routes(
    js_text: str, js_url: str,
    seen: set[str], result: JSAnalysisResult,
    skip_dotall: bool = False,
):
    """提取前端路由定义。

    2026-05-22 重写：原来的正则在 Webpack/minify 后的 prod bundle 上召回率几乎为 0，
    因为它要求 `component:` 紧跟 `path:` 200 字符内 + component 必须是标识符。
    新策略：双轨提取 + 严格白名单过滤。

    轨 1（高置信）：先定位"路由表数组上下文"（routes:[...] / routes=[...]），
                    在数组花括号范围内贪婪扫所有 path:"/..."
    轨 2（中置信）：宽松扫 path:"/xxx"，但要求邻近 ±300 字符内有路由表特征字段
                    （component / redirect / meta / name / import / loadView / lazy）

    最后所有候选过一遍白名单过滤：
    - 必须 / 开头
    - 排除静态资源后缀 + 已知 API 前缀
    - 排除带 ? & 的 URL
    - 字符集限于 [a-zA-Z0-9_\\-/:]

    Args:
        skip_dotall: 大文件保护开关（保留参数兼容旧调用）
    """
    candidates: list[tuple[str, str]] = []  # [(path, hint)]

    # === 轨 1：路由表数组上下文 ===
    # 匹配 routes:[...] / routes=[...] / Routes:[...] 等数组定义
    # 用栈式括号匹配找到对应的 ]，避免简单 .*? 漏掉嵌套
    for m in _ROUTE_TABLE_HEAD.finditer(js_text):
        start = m.end() - 1  # m.end()-1 指向 [
        end = _find_matching_bracket(js_text, start, "[", "]", max_span=200_000)
        if end < 0:
            continue
        block = js_text[start:end + 1]
        # 在数组块内贪婪扫 path / p
        for pm in _PATH_FIELD_LOOSE.finditer(block):
            path = pm.group(1)
            candidates.append((path, "table"))

    # === 轨 2：宽松 path 扫描 + 邻近上下文校验 ===
    # 限制最多扫的次数，防止超大文件极端情况
    MAX_LOOSE_HITS = 2000
    hits = 0
    for pm in _PATH_FIELD_LOOSE.finditer(js_text):
        if hits >= MAX_LOOSE_HITS:
            break
        hits += 1
        path = pm.group(1)
        # ★ 强约束：path 字段前 30 字符内必须出现 { 或 , （路由对象的起始或分隔符），
        #   这能精确干掉 `console.log({ path:'/x' })` 这种伪装为对象字段的误报。
        #   实测在真实 prod JS 上保留 97% 真实路由，几乎无损召回。
        prev_win = js_text[max(0, pm.start() - 30):pm.start()]
        if "{" not in prev_win and "," not in prev_win:
            continue
        # 邻近窗口检查：±300 字符内必须出现路由表特征字段
        win_start = max(0, pm.start() - 300)
        win_end = min(len(js_text), pm.end() + 300)
        window = js_text[win_start:win_end]
        if _ROUTE_NEIGHBOR_HINT.search(window):
            candidates.append((path, "neighbor"))

    # === React Router JSX：<Route path="/xxx" /> ===
    for m in _REACT_ROUTE_PATTERN.finditer(js_text):
        candidates.append((m.group(1), "react"))

    # === Angular path() 调用 ===
    for m in _ANGULAR_PATH_PATTERN.finditer(js_text):
        candidates.append((m.group(1), "angular"))

    # === 白名单过滤 + 去重 ===
    for path, hint in candidates:
        if path in seen:
            continue
        if not _is_valid_spa_route(path):
            continue
        seen.add(path)
        result.routes.append(JSRoute(
            path=path, component="", meta=hint, source_file=js_url,
        ))


def _is_valid_spa_route(path: str) -> bool:
    """白名单过滤：判断 path 是否像合法的 SPA 前端路由。"""
    if not path or not isinstance(path, str):
        return False
    if not path.startswith("/"):
        return False
    if len(path) < 2 or len(path) > 80:
        return False
    # 排除带 query string
    if "?" in path or "&" in path or "#" in path:
        return False
    # 静态资源
    low = path.lower()
    for suf in _STATIC_SUFFIXES:
        if low.endswith(suf):
            return False
    # 后端 API
    for pref in _API_PREFIXES:
        if low.startswith(pref) or low == pref.rstrip("/"):
            return False
    # 假阳性片段
    for bad in _NON_ROUTE_HINTS:
        if bad in path:
            return False
    # 字符集校验：只允许字母/数字/下划线/连字符/斜杠/冒号(动态参数)/点(很少见但允许)
    if not re.fullmatch(r"/[a-zA-Z0-9_\-/:.]+", path):
        return False
    # i18n key 模式：含 . 但不像合理路径（如 /app.title）
    # 合理路径里 . 通常出现在末尾扩展（已被过滤）或不出现
    if "." in path:
        # 允许末段是单个 . 形式（少见），但 /a.b/c 这种全部禁掉
        return False
    # 路径段必须是合理的标识符样式（避免随机字符串混入）
    # 至少要有一段字母 — 排除像 /123/456 这种纯数字（通常是 ID 模板而非路由）
    segments = [s for s in path.split("/") if s]
    if not any(re.search(r"[a-zA-Z]", s) for s in segments):
        return False
    return True


def _find_matching_bracket(text: str, start: int, open_ch: str, close_ch: str,
                           max_span: int = 100_000) -> int:
    """从 start 位置（必须是 open_ch）开始，找配对的 close_ch 索引。

    支持嵌套括号，会跳过字符串字面量中的括号。
    超过 max_span 字符还没找到则返回 -1（防止扫到文件末尾耗时）。
    """
    if start >= len(text) or text[start] != open_ch:
        return -1
    depth = 0
    i = start
    end_limit = min(len(text), start + max_span)
    in_str: str = ""  # 当前字符串引号字符（"/'/`），空表示不在字符串中
    while i < end_limit:
        ch = text[i]
        if in_str:
            # 跳过转义
            if ch == "\\" and i + 1 < end_limit:
                i += 2
                continue
            if ch == in_str:
                in_str = ""
            i += 1
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
            i += 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _detect_router_mode(js_text: str) -> str:
    """探测 SPA 路由模式。返回 "hash" / "history" / ""（未识别）。

    优先级：明确字面量 > 默认。
    若同一文件里同时出现两种（例如 polyfill 写法），保守返回 "hash"（更通用）。
    """
    has_hash = bool(_HASH_MODE_PATTERN.search(js_text))
    has_history = bool(_HISTORY_MODE_PATTERN.search(js_text))
    if has_hash and not has_history:
        return "hash"
    if has_history and not has_hash:
        return "history"
    if has_hash and has_history:
        return "hash"  # 保守
    return ""


def _extract_storage_keys(js_text: str) -> list[str]:
    """提取前端实际读写的 token/auth 类 + login-type 类 storage key。"""
    keys: list[str] = []

    def _add(key: str):
        if not key:
            return
        if (_looks_like_auth_storage_key(key) or _looks_like_auth_state_key(key)) and key not in keys:
            keys.append(key)

    for m in _STORAGE_KEY_DIRECT_PATTERN.finditer(js_text):
        _add(m.group(1))

    var_values: dict[str, str] = {}
    for m in _STORAGE_KEY_VAR_PATTERN.finditer(js_text):
        name, value = m.group(1), m.group(2)
        if _looks_like_auth_storage_key(value) or _looks_like_auth_state_key(value):
            var_values[name] = value
    for m in _STORAGE_VAR_USE_PATTERN.finditer(js_text):
        value = var_values.get(m.group(1))
        if value:
            _add(value)

    return keys[:30]


def _extract_auth_patterns(js_text: str, js_url: str, result: JSAnalysisResult):
    """识别鉴权模式。"""
    storage_keys = _extract_storage_keys(js_text)
    if storage_keys and not any(a.pattern_type == "token_storage" and a.storage_keys == storage_keys for a in result.auth_patterns):
        result.auth_patterns.append(JSAuthPattern(
            pattern_type="token_storage",
            description="前端 Storage Token key（localStorage/sessionStorage）",
            code_snippet=", ".join(storage_keys[:10]),
            source_file=js_url,
            storage_keys=storage_keys,
        ))

    for pattern, ptype, desc in _AUTH_PATTERNS:
        for m in pattern.finditer(js_text):
            snippet = m.group(1)[:300]
            # 去重
            if any(a.code_snippet[:100] == snippet[:100] for a in result.auth_patterns):
                continue
            pattern_storage_keys = storage_keys if ptype == "token_storage" else []
            result.auth_patterns.append(JSAuthPattern(
                pattern_type=ptype, description=desc,
                code_snippet=snippet, source_file=js_url,
                storage_keys=pattern_storage_keys,
            ))


def _extract_sensitive_info(js_text: str, js_url: str, result: JSAnalysisResult):
    """提取敏感信息。"""
    for pattern, info_type in _SENSITIVE_PATTERNS:
        for m in pattern.finditer(js_text):
            value = m.group(1) if m.lastindex >= 1 else m.group(0)
            # 过滤明显的占位符
            if value.lower() in ("your_api_key", "xxx", "changeme", "placeholder", "example"):
                continue
            if len(value) < 6:
                continue
            # 去重
            if any(s.value == value for s in result.sensitive_info):
                continue

            start = max(0, m.start() - 40)
            end = min(len(js_text), m.end() + 40)
            context = js_text[start:end].replace("\n", " ").strip()

            result.sensitive_info.append(JSSensitiveInfo(
                info_type=info_type, value=value[:200],
                context=context[:200], source_file=js_url,
            ))


def _extract_source_maps(
    js_text: str, js_url: str, base_url: str,
    result: JSAnalysisResult,
):
    """提取 Source Map 引用。"""
    for m in _SOURCEMAP_PATTERN.finditer(js_text):
        map_ref = m.group(1).strip()
        if map_ref.startswith("http"):
            map_url = map_ref
        elif map_ref.startswith("data:"):
            continue  # 内联 source map，跳过
        else:
            # 相对路径：相对于 JS 文件本身
            map_url = urljoin(js_url or base_url, map_ref)
        if map_url and map_url not in result.source_maps:
            result.source_maps.append(map_url)


def _extract_realtime_endpoints(
    js_text: str, js_url: str,
    result: JSAnalysisResult,
):
    """提取 WebSocket / SSE 端点。

    检测模式：
    - new WebSocket("ws://xxx") / new WebSocket("wss://xxx")
    - new EventSource("/api/sse") / new EventSource("https://xxx/sse")
    - 也检测 minified 变量形式：new WebSocket(t) 跳过（无法解析变量值）
    """
    # WebSocket
    for m in _WEBSOCKET_PATTERN.finditer(js_text):
        ws_url = m.group(1).strip()
        if not ws_url or len(ws_url) < 5:
            continue
        # 过滤变量引用（minified JS 中可能是变量名）
        if ws_url.startswith("ws://") or ws_url.startswith("wss://"):
            full_url = ws_url
        elif ws_url.startswith("/"):
            # 相对路径 → 需要后续 baseURL 拼接
            full_url = ws_url
        elif ws_url.startswith("http"):
            # http(s):// → 转换为 ws(s)://
            full_url = ws_url.replace("https://", "wss://").replace("http://", "ws://")
        else:
            continue
        if full_url not in result.websocket_endpoints:
            result.websocket_endpoints.append(full_url)
            log.debug("WebSocket 端点: %s (from %s)", full_url, js_url[-60:])

    # SSE (EventSource)
    for m in _SSE_PATTERN.finditer(js_text):
        sse_url = m.group(1).strip()
        if not sse_url or len(sse_url) < 3:
            continue
        if sse_url.startswith("http") or sse_url.startswith("/"):
            if sse_url not in result.sse_endpoints:
                result.sse_endpoints.append(sse_url)
                log.debug("SSE 端点: %s (from %s)", sse_url, js_url[-60:])


def _extract_base_urls(
    js_text: str, js_url: str,
    result: JSAnalysisResult,
):
    """提取 axios.create({baseURL}) 和通用 baseURL 赋值。

    提取到的 baseURL 会存储在 result.base_urls 中，
    在 _apply_base_urls() 中用于拼接相对路径 API。
    """
    # axios.create({baseURL: "..."})
    for m in _AXIOS_BASEURL_PATTERN.finditer(js_text):
        bu = m.group(1).strip()
        if bu and len(bu) >= 2 and bu not in result.base_urls:
            result.base_urls.append(bu)
            log.debug("axios baseURL: %s (from %s)", bu, js_url[-60:])

    # 通用 baseURL 赋值
    for m in _BASEURL_ASSIGN_PATTERN.finditer(js_text):
        bu = m.group(1).strip()
        if bu and len(bu) >= 2 and bu not in result.base_urls:
            # 过滤明显的非 URL 值（如 "production"、"development" 等）
            if bu.startswith("/") or bu.startswith("http"):
                result.base_urls.append(bu)
                log.debug("baseURL 赋值: %s (from %s)", bu, js_url[-60:])


def _apply_base_urls(result: JSAnalysisResult, base_url: str):
    """将 baseURL 应用到相对路径 API 调用，生成完整 URL 的衍生 API。

    例如：
      baseURL = "/api/v1"
      API call: GET /user/list
      → 衍生: GET /api/v1/user/list

    这解决了 axios.create({baseURL}) 后 instance.get("/user") 的路径拼接问题，
    这是纯正则无法处理的场景。
    """
    if not result.base_urls:
        return

    seen_paths = {call.path for call in result.api_calls}
    new_calls: list[JSApiCall] = []

    for bu in result.base_urls:
        # 规范化 baseURL
        bu = bu.rstrip("/")
        if not bu:
            continue

        for call in result.api_calls:
            path = call.path
            # 只处理相对路径（以 / 开头但不是完整 URL）
            if not path or not path.startswith("/"):
                continue
            # 如果 path 已经以 baseURL 开头，跳过
            if path.startswith(bu + "/") or path == bu:
                continue
            # 如果 path 是完整 URL，跳过
            if path.startswith("http"):
                continue

            # 拼接
            new_path = f"{bu}{path}"
            if new_path in seen_paths:
                continue
            seen_paths.add(new_path)

            new_call = JSApiCall(
                method=call.method,
                path=new_path,
                source_file=call.source_file,
                context=f"[baseURL拼接] {call.context}",
                params=call.params,
            )
            new_calls.append(new_call)

    if new_calls:
        result.api_calls.extend(new_calls)
        log.info("baseURL 拼接: 从 %d 个 baseURL 衍生出 %d 个新 API 路径",
                 len(result.base_urls), len(new_calls))


def _is_valid_api_path(path: str) -> bool:
    """判断路径是否像有效的 API 路径（过滤静态资源、CSS 类名等）。"""
    if not path or len(path) < 3:
        return False
    # 必须以 / 开头
    if not path.startswith("/"):
        # 可能是完整 URL
        if path.startswith("http"):
            parsed = urlparse(path)
            path = parsed.path
            if not path or path == "/":
                return False
        else:
            return False

    # 排除静态资源
    static_exts = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4",
        ".mp3", ".pdf", ".zip", ".html", ".htm",
    )
    path_lower = path.lower()
    if any(path_lower.endswith(ext) for ext in static_exts):
        return False

    # 排除明显不是 API 的路径
    exclude_prefixes = (
        "/node_modules/", "/static/", "/assets/", "/public/",
        "/images/", "/img/", "/fonts/", "/css/", "/js/",
    )
    if any(path_lower.startswith(p) for p in exclude_prefixes):
        return False

    # 排除太长或包含明显非路径字符的
    if len(path) > 200 or any(c in path for c in (" ", "<", ">", "\n", "\t")):
        return False

    return True


def _extract_params_from_context(js_text: str, start: int, end: int) -> list[str]:
    """从 API 调用附近的代码提取请求参数名。"""
    # 向后看 300 字符，找 {key: value} 模式
    context = js_text[end:end + 300]
    params = re.findall(r'(?:^|[,{\s])(\w+)\s*:', context)
    # 过滤常见的非参数 key
    exclude = {"method", "headers", "body", "url", "type", "data", "dataType",
               "success", "error", "timeout", "contentType", "cache", "async",
               "crossDomain", "processData", "beforeSend", "complete", "mode",
               "credentials", "signal", "redirect", "referrer", "referrerPolicy"}
    return [p for p in params[:10] if p not in exclude and len(p) > 1]
