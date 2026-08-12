"""
JS Analyzer — JS 深度静态分析

从 SPA 应用的 JS 文件中提取：
1. API 端点（fetch/axios/$.ajax/XMLHttpRequest 调用）
2. 前端路由表（Vue Router / React Router / Angular）
3. 鉴权模式（interceptor / 全局 token 注入）
4. 敏感信息（硬编码 key/secret/token）
5. Source Map 探测

不依赖 AST 解析器，用精心设计的正则实现高召回率提取。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

from core.log import get_logger

log = get_logger("js_analyzer")


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


# ============================================================
# 正则模式集
# ============================================================

# API 调用模式：匹配 fetch/axios/$.ajax/http 调用
#
# ★ 关键安全约束：所有"两段式"配置对象的中间隔离量词必须用【有界 + 非贪婪】
#   形式 `[^}]{0,200}?`，禁止使用 `[^}]*?`。
#   原因：在 minified 单行 JS（4MB+）上，`[^}]*?` 配合 DOTALL 会触发
#   灾难性回溯（catastrophic backtracking），单次匹配可耗尽 CPU 数分钟。
_API_PATTERNS = [
    # fetch("url") / fetch(`url`) / fetch(url, {method: "POST"})
    re.compile(
        r'''fetch\s*\(\s*[`"']([^`"']+)[`"'](?:\s*,\s*\{[^}]{0,200}?method\s*:\s*[`"'](\w+)[`"'])?''',
        re.IGNORECASE
    ),
    # axios.get/post/put/delete/patch("url")
    re.compile(
        r'''axios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*[`"']([^`"']+)[`"']''',
        re.IGNORECASE
    ),
    # axios({url: "...", method: "..."})
    # ★ 用有界量词 {0,300} 防止灾难性回溯（minified JS 上 *? 会爆炸）
    re.compile(
        r'''axios\s*\(\s*\{[^}]{0,300}?url\s*:\s*[`"']([^`"']+)[`"'][^}]{0,300}?method\s*:\s*[`"'](\w+)[`"']''',
        re.IGNORECASE | re.DOTALL
    ),
    # this.$http.get/post("url") — Vue resource
    re.compile(
        r'''(?:this\s*\.\s*)?(?:\$http|\$axios|http|request|api)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*[`"']([^`"']+)[`"']''',
        re.IGNORECASE
    ),
    # $.ajax({url: "...", type/method: "..."})
    re.compile(
        r'''\$\s*\.\s*ajax\s*\(\s*\{[^}]{0,300}?url\s*:\s*[`"']([^`"']+)[`"'][^}]{0,300}?(?:type|method)\s*:\s*[`"'](\w+)[`"']''',
        re.IGNORECASE | re.DOTALL
    ),
    # $.get/$.post("url")
    re.compile(
        r'''\$\s*\.\s*(get|post|getJSON|ajax)\s*\(\s*[`"']([^`"']+)[`"']''',
        re.IGNORECASE
    ),
    # XMLHttpRequest.open("METHOD", "url")
    re.compile(
        r'''\.open\s*\(\s*[`"'](\w+)[`"']\s*,\s*[`"']([^`"']+)[`"']''',
        re.IGNORECASE
    ),
    # request({url: "...", method: "..."}) — 通用封装
    re.compile(
        r'''request\s*\(\s*\{[^}]{0,300}?url\s*:\s*[`"']([^`"']+)[`"'][^}]{0,300}?method\s*:\s*[`"'](\w+)[`"']''',
        re.IGNORECASE | re.DOTALL
    ),
]

# ★ 2026-08-12: minified JS 字符串拼接 URL 模式
# 在 minified/bundled JS 中，URL 常被拆分为字符串拼接：
#   e+"/api/user/list"  →  变量 + 字符串
#   "/api/user/"+t      →  字符串 + 变量
#   `${baseURL}/api/user/${id}`  →  模板字符串拼接（已由 _TEMPLATE_API_PATTERN 覆盖）
# 此模式只提取字符串字面量中的路径部分
_CONCAT_URL_PATTERN = re.compile(
    r'''[+]\s*[`"'](/[a-zA-Z][a-zA-Z0-9_/\-{}:]{2,80})[`"']'''
    r'''|'''
    r'''[`"'](/[a-zA-Z][a-zA-Z0-9_/\-{}:]{2,80})[`"']\s*[+]''',
    re.IGNORECASE
)

# 模板字符串中的 API 路径（如 `/api/user/${id}`）
# ★ 2026-08-12: 扩展前缀覆盖面 + 支持反引号模板字符串
# 原来只覆盖 api/v1-3/backend/admin/user/auth/data/service/graphql/rest 10个前缀
# 实际项目中 sys/system/operation/biz/manage/portal/common/app 等前缀极常见
# 原来不支持反引号(`)，导致 ES6 模板字符串中的路径全部漏掉
_TEMPLATE_API_PATTERN = re.compile(
    r'''[`"'](/(?:api|apis|v[1-3]|backend|admin|user|auth|data|service|services|
    graphql|rest|sys|system|operation|operations|biz|business|manage|manager|
    portal|common|app|inner|open|servlet|gateway|proxy|invoke|call|
    resource|file|upload|download|export|import|query|search|list|detail|
    create|update|delete|save|submit|login|logout|register|captcha|
    token|session|profile|account|password|menu|role|permission|dept|
    org|organization|config|setting|log|audit|monitor|task|job|schedule|
    message|notice|notification|dict|dictionary)[^`"']*?)[`"']''',
    re.IGNORECASE | re.VERBOSE
)

# 通用路径提取（宽松匹配，用于兜底补全）
# ★ 2026-08-12: 支持反引号模板字符串
_PATH_PATTERNS = re.compile(
    r'''[`"'](/[a-zA-Z][a-zA-Z0-9_/\-{}:]+)[`"']''',
)

# 前端路由模式 — 已废弃（被 _extract_routes 内的双轨提取 + 白名单替代，2026-05-22）
# 保留空列表占位避免外部 import 出错；新代码请用 _ROUTE_TABLE_HEAD / _PATH_FIELD_LOOSE
_ROUTE_PATTERNS: list = []

# 鉴权模式
# 两类 key：TOKEN_KEY_HINTS = token 类（值为 JWT）；AUTH_STATE_HINTS = 登录状态类（值为固定字符串如 "tenant_user_pass"）
_TOKEN_KEY_HINTS = ("token", "auth", "jwt", "session")
_AUTH_STATE_HINTS = ("login_type", "logintype", "login_method", "loginmethod")
_STORAGE_KEY_DIRECT_PATTERN = re.compile(
    r'''(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem)\s*\(\s*[`"']([^`"']{1,100})[`"']''',
    re.IGNORECASE,
)
_STORAGE_KEY_VAR_PATTERN = re.compile(
    r'''(?:var\s+|let\s+|const\s+)?([A-Za-z_$][\w$]{0,40})\s*=\s*[`"']([^`"']{1,100})[`"']''',
    re.IGNORECASE,
)
_STORAGE_VAR_USE_PATTERN = re.compile(
    r'''(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem)\s*\(\s*([A-Za-z_$][\w$]{0,40})\b''',
    re.IGNORECASE,
)


def _looks_like_auth_storage_key(key: str) -> bool:
    """判断是否像 token/auth 类 storage key（值为 JWT）。"""
    key_lower = key.lower()
    return any(hint in key_lower for hint in _TOKEN_KEY_HINTS)


def _looks_like_auth_state_key(key: str) -> bool:
    """判断是否像登录状态类 storage key（值为固定字符串，如 tenant_user_pass）。"""
    key_lower = key.lower()
    return any(hint in key_lower for hint in _AUTH_STATE_HINTS)


# 鉴权模式
_AUTH_PATTERNS = [
    # axios interceptor
    (re.compile(r'''((?:axios|http|request|instance)\s*\.\s*interceptors?\s*\.\s*request\s*\.\s*use\s*\([^)]{10,300}\)?)''', re.DOTALL),
     "interceptor", "Axios/HTTP 请求拦截器（全局注入 Token/Cookie）"),
    # Authorization header 注入
    (re.compile(r'''((?:headers?|config)\s*(?:\[|\.)\s*[`"'](?:Authorization|X-Token|X-Access-Token|Bearer)[`"']\s*(?:\]|)\s*=\s*[^;\n]{5,100})''', re.IGNORECASE),
     "global_header", "全局 Authorization/Token Header 注入"),
    # 路由守卫 (Vue)
    (re.compile(r'''((?:router|beforeEach)\s*\.?\s*beforeEach\s*\([^)]{10,500}\)?)''', re.DOTALL),
     "route_guard", "Vue Router 路由守卫（前端鉴权）"),
    # 路由守卫 (React)
    (re.compile(r'''((?:PrivateRoute|AuthRoute|ProtectedRoute|RequireAuth)\s*[^;]{10,200})''', re.IGNORECASE),
     "route_guard", "React 路由守卫组件"),
    # Token 存储读取
    (re.compile(r'''((?:localStorage|sessionStorage|cookies?)\s*\.(?:getItem|get|setItem|set)\s*\(\s*[`"'](?:token|access_token|auth_token|jwt|session_id|JSESSIONID)[`"']\s*\))''', re.IGNORECASE),
     "token_storage", "Token 存储/读取（localStorage/sessionStorage/cookie）"),
]

# 敏感信息模式
_SENSITIVE_PATTERNS = [
    # API Key / Secret
    (re.compile(r'''(?:api[_-]?key|apikey|app[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[=:]\s*[`"']([a-zA-Z0-9_\-]{16,})[`"']''', re.IGNORECASE),
     "api_key"),
    # AWS 密钥
    (re.compile(r'''(AKIA[0-9A-Z]{16})'''), "aws_key"),
    # 内部 URL / IP
    (re.compile(r'''[`"']((?:https?://)?(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|127\.0\.0\.1)(?::\d+)?[/][^`"']*)[`"']'''),
     "internal_url"),
    # 硬编码密码
    (re.compile(r'''(?:password|passwd|pwd)\s*[=:]\s*[`"']([^`"']{6,})[`"']''', re.IGNORECASE),
     "password"),
    # Debug/开发标记
    (re.compile(r'''(?:debug|dev_mode|is_debug|DEBUG_MODE)\s*[=:]\s*(true|1|[`"'](?:true|yes|on)[`"'])''', re.IGNORECASE),
     "debug_flag"),
    # JWT Token
    (re.compile(r'''[`"'](eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})[`"']'''),
     "jwt_token"),
]

# Source Map 引用
_SOURCEMAP_PATTERN = re.compile(r'''//[#@]\s*sourceMappingURL\s*=\s*(\S+)''')


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
        except Exception as e:
            log.warning("JS 分析单文件出错 (%s): %s", js_url[-80:], e)
            continue

        elapsed = _time.monotonic() - t0
        if elapsed > 2.0:
            log.info("JS 分析单文件耗时 %.1fs (%dKB, %s%s)",
                     elapsed, len(js_text) // 1024,
                     js_url[-60:], " [大文件简化]" if is_large else "")

    log.info("JS 分析完成: %d 文件, %d 个 API, %d 个路由, %d 个鉴权模式, %d 个敏感信息, %d 个 source map",
             result.js_files_analyzed, len(result.api_calls), len(result.routes),
             len(result.auth_patterns), len(result.sensitive_info), len(result.source_maps))

    return result


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


# === 路由抽取辅助：正则与白名单 ===

# 路由表"头部"：routes:[ / routes=[ / Routes:[ / _routes=[ / children:[
# 注意：children:[ 是嵌套子路由，也是路由表
# ★ 2026-08-12: 扩展 React Router v6 / Angular / 通用菜单路由模式
_ROUTE_TABLE_HEAD = re.compile(
    r'\b(?:routes|Routes|_routes|routeList|routeConfig|routeTable|routerConfig|'
    r'children|subRoutes|subMenus|menuItems|menuList|menuConfig|'
    r'createBrowserRouter|createHashRouter|RouterConfig|routerConfig|'
    r'forRoot|forChild|RouterModule)'
    r'\s*[:=(\[]\s*\[',
)

# 宽松 path 字段：path:"/xxx" / "path":"/xxx" / p:"/xxx" / to:"/xxx"
# 路径限定字符集，且首字符必须是字母/数字（防止 "/" "//" 这种空路由进来）
_PATH_FIELD_LOOSE = re.compile(
    r'''(?:[\b\{,\s]|^)["']?(?:path|Path|p|to|url)["']?\s*:\s*["'`](/[a-zA-Z0-9][a-zA-Z0-9_\-/:.]{0,80})["'`]''',
)

# 路由表特征字段（用于轨 2 邻近校验）
# 任一出现就视为"这是路由配置"
_ROUTE_NEIGHBOR_HINT = re.compile(
    r'\b(?:component|redirect|meta|name|children|beforeEnter|loadView|lazy)\s*[:=]\s*'
    r'|\bimport\s*\('
    r'|\b__webpack_require__\s*\.\s*e\s*\(',
)

# React Router JSX
_REACT_ROUTE_PATTERN = re.compile(
    r'<Route[^>]{0,500}?path\s*=\s*[`"\']([/][a-zA-Z0-9_\-/:.]{0,80})[`"\']',
    re.IGNORECASE,
)

# Angular path() 调用
_ANGULAR_PATH_PATTERN = re.compile(
    r'\bpath\s*\(\s*[`"\']([/][a-zA-Z0-9_\-/:.]{0,80})[`"\']',
)

# 静态资源后缀（这些是资源不是路由）
_STATIC_SUFFIXES = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".json", ".xml", ".txt", ".md", ".pdf", ".map",
    ".mp3", ".mp4", ".webm", ".ogg",
)

# 已知后端 API 前缀（这些是后端路径，不是前端路由）
_API_PREFIXES = (
    "/api/", "/v1/", "/v2/", "/v3/", "/v4/",
    "/rest/", "/graphql", "/rpc/", "/gw/",
    "/admin-api/", "/web-api/",
)

# 明显假阳性路径片段
_NON_ROUTE_HINTS = (
    "://",        # 完整 URL
    "//",         # 协议相对
    "..",         # 相对路径
)


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


# === Router 模式探测（hash / history）===
# Vue Router 4: createWebHashHistory() / createWebHistory()
# Vue Router 3: mode: "hash" / mode: "history"
# React Router: createHashRouter / createBrowserRouter
_HASH_MODE_PATTERN = re.compile(
    r'\bcreateWebHashHistory\b'
    r'|\bcreateHashHistory\b'
    r'|\bcreateHashRouter\b'
    r'|\bmode\s*:\s*["\']hash["\']'
    r'|\bhashbang\b',
)
_HISTORY_MODE_PATTERN = re.compile(
    r'\bcreateWebHistory\b'
    r'|\bcreateBrowserHistory\b'
    r'|\bcreateBrowserRouter\b'
    r'|\bmode\s*:\s*["\']history["\']',
)


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


# ============================================================
# 给爬虫集成用的高层函数
# ============================================================

async def analyze_page_js(page, base_url: str = "", llm_chat_fn=None) -> JSAnalysisResult:
    """在 Playwright page 上提取并分析所有 JS。

    包括：
    1. 内联 <script> 标签
    2. 外链 <script src> 文件
    3. 动态加载的 chunk 文件（从已加载的 JS 中找引用）
    4. （可选）对关键业务 JS 文件进行 LLM 分析，补充正则遗漏的 API

    Args:
        page: Playwright page 对象
        base_url: 站点基础 URL
        llm_chat_fn: 可选的 LLM 回调函数，签名为
            async (messages, caller?) -> response (response.content 为文本)
            传入后，对 main.js/index.js/app.js 等关键文件会自动调用 LLM 分析
    """
    js_contents: list[tuple[str, str]] = []

    try:
        # 1. 提取内联 JS
        inline_scripts = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('script:not([src])'))
                .map(s => s.textContent)
                .filter(t => t && t.length > 50);
        }""")
        for i, text in enumerate(inline_scripts or []):
            js_contents.append((f"inline_script_{i}", text))

        # 2. 提取外链 JS URL
        external_urls = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('script[src]'))
                .map(s => s.src)
                .filter(s => s && s.startsWith('http'));
        }""")

        # 3. 从 performance API 获取已加载的所有 JS 资源（包括动态 chunk）
        perf_js_urls = await page.evaluate("""() => {
            return performance.getEntriesByType('resource')
                .filter(e => e.initiatorType === 'script' || e.name.endsWith('.js'))
                .map(e => e.name);
        }""")

        # 合并去重
        all_js_urls = list(dict.fromkeys((external_urls or []) + (perf_js_urls or [])))

        # 4. 逐个下载 JS 内容（限制总量避免太慢）
        MAX_JS_FILES = 30
        MAX_SINGLE_SIZE = 2 * 1024 * 1024  # 2MB/文件
        total_size = sum(len(t) for _, t in js_contents)

        for js_url in all_js_urls[:MAX_JS_FILES]:
            if total_size > 10 * 1024 * 1024:  # 总量 10MB 上限
                log.info("JS 总量超 10MB，停止下载")
                break
            # ★ 单文件下载重试 2 次（退避 200ms / 500ms），
            # 避免网络抖动导致关键业务 JS（如 main.js/app.js）永久丢失。
            text = None
            for _js_attempt in range(3):
                try:
                    text = await page.evaluate("""async (url) => {
                        try {
                            const resp = await fetch(url);
                            if (!resp.ok) return '';
                            const ct = resp.headers.get('content-type') || '';
                            if (ct.includes('html')) return '';  // 不是 JS
                            const text = await resp.text();
                            return text.length > 2*1024*1024 ? text.slice(0, 2*1024*1024) : text;
                        } catch { return ''; }
                    }""", js_url)
                    if text and len(text) > 50:
                        break  # 成功
                except Exception as _js_e:
                    if _js_attempt < 2:
                        import asyncio as _aio
                        await _aio.sleep(0.2 * (_js_attempt + 1))
                        log.debug("JS 下载重试 %d/2 %s: %s", _js_attempt + 1, js_url[-60:], _js_e)
                    else:
                        log.debug("JS 下载最终失败 %s: %s", js_url[-60:], _js_e)
                if not text:
                    # 短暂退避后重试（避免空响应也立即重试）
                    if _js_attempt < 2:
                        import asyncio as _aio
                        await _aio.sleep(0.2 * (_js_attempt + 1))
            if text and len(text) > 50:
                js_contents.append((js_url, text))
                total_size += len(text)

    except Exception as e:
        log.warning("JS 提取失败: %s", e)

    if not js_contents:
        return JSAnalysisResult()

    log.info("提取到 %d 个 JS 文件 (%d 内联, %d 外链/chunk), 总 %dKB",
             len(js_contents),
             sum(1 for u, _ in js_contents if u.startswith("inline_")),
             sum(1 for u, _ in js_contents if not u.startswith("inline_")),
             total_size // 1024)

    # ★ 缓存 JS 源码供推测 API 参数构造使用（按 base_url 隔离不同目标）
    cache_js_sources(js_contents, target=base_url)

    result = analyze_js(js_contents, base_url)
    # ★ 记录所有外链 JS URL，供 FastScanner 动态推导 .map 探测
    result.js_file_urls = [u for u, _ in js_contents if u.startswith("http")]

    # ★ LLM 增强分析：对关键业务 JS 文件（main.js / index.js / app.js 等）
    #   用 LLM 理解代码逻辑，提取正则遗漏的 API（minified 变量名、baseURL 拼接、相对路径等）
    if llm_chat_fn and result.api_calls is not None:
        pre_count = len(result.api_calls)
        try:
            result = await llm_analyze_key_js(js_contents, result, base_url, llm_chat_fn)
            new_count = len(result.api_calls) - pre_count
            if new_count > 0:
                log.info("LLM JS 增强完成: 新增 %d 个 API（正则共 %d 个 → 合计 %d 个）",
                         new_count, pre_count, len(result.api_calls))
        except Exception as e:
            log.warning("LLM JS 增强失败，回退纯正则结果: %s", e)

    return result


# ============================================================
# LLM 增强 JS 分析（针对关键业务 JS 文件）
# ============================================================

# 关键业务 JS 文件名模式（入口/主业务 bundle）
_KEY_JS_PATTERNS = re.compile(
    r'(?:^|/)'
    r'(?:'
    r'index|main|app|vendor|bundle|chunk-[^/]*'
    r')'
    r'(?:[-.][\w]+)?'  # hash 后缀，如 .e1dfb5981f / -abc123
    r'\.(?:js|mjs)$',
    re.IGNORECASE,
)

# API 相关代码关键词（用于从大文件中提取片段）
_API_CONTEXT_KEYWORDS = (
    "axios", "fetch(", ".get(", ".post(", ".put(", ".delete(", ".patch(",
    "baseURL", "BASE_URL", "apiBase", "apiPrefix", "apiUrl",
    "request(", "http(", "XMLHttpRequest",
    "interceptor", "Authorization", "Bearer",
    "router", "routes", "path:",
)


def _is_key_business_js(js_url: str, js_text: str) -> bool:
    """判断 JS 文件是否是关键业务 JS（需要 LLM 分析）。

    条件：
    1. 文件名匹配入口模式（main.js / index.js / app.js 等）
    2. 文件大小 > 50KB（排除 tracker/pixel 类小文件）
    3. 不是第三方库（排除 vue/react/echarts 等）
    """
    # 从 URL 提取文件名
    name = js_url.split("/")[-1].split("?")[0].lower()

    # 第三方库黑名单（文件名中包含这些关键词的不分析）
    _LIB_KEYWORDS = (
        "vue.", "vuex", "vue-router", "react.", "react-dom", "redux",
        "angular", "rxjs", "zone.js", "echarts", "chart", "d3.",
        "lodash", "underscore", "moment", "dayjs", "axios.js",
        "element-plus", "ant-design", "el-", "iview",
        "polyfill", "core-js", "regenerator", "babel",
        "sentry", "firebase", "amplitude", "mixpanel",
        "hotjar", "clarity", "google-analytics", "gtag",
        "recaptcha", "facebook", "beacon",
    )
    for kw in _LIB_KEYWORDS:
        if kw in name:
            return False

    # 必须匹配入口模式
    if not _KEY_JS_PATTERNS.search(js_url.split("?")[0]):
        return False

    # 大小下限
    if len(js_text) < 50_000:  # 50KB
        return False

    return True


def _extract_api_chunks(js_text: str, max_total_chars: int = 30_000) -> list[str]:
    """从大 JS 文件中提取与 API 调用相关的代码片段。

    策略：找到每个 API 关键词的位置，提取其前后 ±2KB 的代码。
    片段之间有重叠的会合并，总大小不超过 max_total_chars。
    """
    CHUNK_RADIUS = 2048  # 每个关键词前后各取 2KB

    # 找到所有关键词位置
    positions = []
    for kw in _API_CONTEXT_KEYWORDS:
        start = 0
        while True:
            idx = js_text.find(kw, start)
            if idx == -1:
                break
            positions.append(idx)
            start = idx + len(kw)
            # 每个关键词最多找 20 个位置（避免 axios 在 vendor bundle 里命中几百次）
            if len(positions) > 200:
                break
        if len(positions) > 200:
            break

    if not positions:
        # 没有找到 API 关键词 → 返回文件头 20KB（入口配置通常在文件头）
        return [js_text[:20_000]] if len(js_text) > 20_000 else [js_text]

    # 去重 + 排序
    positions = sorted(set(positions))

    # 将相邻/重叠的位置合并为区间
    intervals: list[tuple[int, int]] = []
    for pos in positions:
        start = max(0, pos - CHUNK_RADIUS)
        end = min(len(js_text), pos + CHUNK_RADIUS)
        if intervals and start <= intervals[-1][1]:
            # 合并
            intervals[-1] = (intervals[-1][0], end)
        else:
            intervals.append((start, end))

    # 提取片段，控制总大小
    chunks = []
    total = 0
    for start, end in intervals:
        chunk = js_text[start:end]
        if total + len(chunk) > max_total_chars:
            # 截断最后一个片段
            remaining = max_total_chars - total
            if remaining > 1000:
                chunks.append(chunk[:remaining] + "\n// ... (截断)")
            break
        chunks.append(chunk)
        total += len(chunk)

    return chunks if chunks else [js_text[:20_000]]


async def llm_analyze_key_js(
    js_contents: list[tuple[str, str]],
    result: JSAnalysisResult,
    base_url: str,
    llm_chat_fn,
) -> JSAnalysisResult:
    """用 LLM 分析关键业务 JS 文件，补充正则遗漏的 API。

    在 analyze_js()（纯正则）之后调用，对 main.js / index.js / app.js 等关键文件
    进行 LLM 分析。LLM 能理解 minified 代码中的 axios 实例、baseURL 拼接、
    相对路径等正则搞不定的场景。

    Args:
        js_contents: [(js_url, js_text), ...] — 与 analyze_js 相同的输入
        result: analyze_js() 的结果（会被原地增强）
        base_url: 站点基础 URL
        llm_chat_fn: async callable，签名为 async (messages, caller?) -> response
                     response 需要有 .content 属性

    Returns:
        增强后的 JSAnalysisResult（与输入是同一个对象，原地修改）
    """
    import json as _json

    # 1. 识别关键业务 JS 文件
    key_files = [(url, text) for url, text in js_contents if _is_key_business_js(url, text)]

    if not key_files:
        log.info("LLM JS 分析: 未发现关键业务 JS 文件，跳过")
        return result

    # 已有的 API 去重集合（正则结果）
    seen_keys: set[str] = set()
    for api in result.api_calls:
        seen_keys.add(f"{api.method} {api.path}")

    # ★ 2026-08-05：前置过滤——如果正则已提取到足够 API，跳过 LLM 分析节省 token
    # 此前 6 次 LLM 调用有 4 次返回 []（32892:1 的输入输出比），纯浪费
    if len(seen_keys) >= 10:
        log.info("LLM JS 分析: 正则已提取 %d 个 API，跳过 LLM 分析", len(seen_keys))
        return result

    seen_route_keys: set[str] = set()
    for route in result.routes:
        seen_route_keys.add(route.path)

    log.info("LLM JS 分析: 发现 %d 个关键业务 JS 文件，开始 LLM 分析", len(key_files))

    # 2. 逐个分析关键文件
    for js_url, js_text in key_files:
        file_name = js_url.split("/")[-1].split("?")[0]
        log.info("LLM JS 分析: 分析 %s (%dKB)", file_name, len(js_text) // 1024)

        # 提取 API 相关代码片段
        chunks = _extract_api_chunks(js_text)
        combined_code = "\n\n// --- 片段分隔 ---\n\n".join(chunks)

        if len(combined_code) > 30_000:
            combined_code = combined_code[:30_000] + "\n// ... (截断)"

        # 3. 构建 LLM prompt
        prompt = f"""分析以下 JS 代码片段，提取所有 API 端点调用。

这个 JS 文件来自 Web 应用的业务代码（可能是 minified/uglified 后的）。
你需要理解代码逻辑来找出正则表达式无法匹配的 API 调用，例如：

1. **minified 变量名**：`Kt.get("ticket/receipts/")` 实际上是 `axios.get()`
2. **baseURL 拼接**：如果代码中有 `axios.create({{baseURL: "weixin/api/"}})`，那么后续 `.get("ticket/receipts/")` 的完整路径是 `weixin/api/ticket/receipts/`
3. **相对路径 API**：不以 `/api` 开头的路径也可能是 API，如 `"ticket/receipts/"`、`"user/info"`
4. **间接调用**：通过封装函数调用的请求，如 `request({{url: "xxx"}})`、`http.post("xxx")`

**输出要求**：只输出一个 JSON 数组，每个元素格式：
```json
[
  {{
    "method": "GET",
    "path": "weixin/api/ticket/receipts/",
    "reason": "Kt=axios.create({{baseURL:'weixin/api/'}}), Kt.get('ticket/receipts/')"
  }}
]
```

- method: GET/POST/PUT/DELETE/PATCH/UNKNOWN
- path: 尽可能给出完整路径（含 baseURL 拼接）；如果无法确定 baseURL，给原始路径
- reason: 简短说明为什么这是 API 调用（含关键变量名/行号）
- 如果没找到任何 API，输出空数组 `[]`
- 不要输出 JSON 以外的任何文字

JS 代码片段（来自 {file_name}）：
```
{combined_code}
```"""

        try:
            from core.llm import Message
            messages = [
                Message(role="system", content="你是一个 JS 代码分析专家，擅长从 minified/obfuscated 的前端代码中提取 API 端点。只输出 JSON。"),
                Message(role="user", content=prompt),
            ]
            response = await llm_chat_fn(messages, caller="js_llm_analyze")
            text = (response.content or "").strip()

            # 4. 解析 LLM 返回
            # 剥离 <think>...</think> 推理块
            text = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()
            # 提取 JSON 数组
            json_match = re.search(r'\[[\s\S]*\]', text)
            if not json_match:
                log.warning("LLM JS 分析: %s 未返回有效 JSON，跳过", file_name)
                continue

            apis = _json.loads(json_match.group())

            new_count = 0
            for item in apis:
                method = (item.get("method") or "UNKNOWN").upper()
                path = item.get("path", "").strip()
                reason = item.get("reason", "")

                if not path or len(path) < 3:
                    continue

                # 标准化路径：确保以 / 开头（除非是完整 URL）
                if not path.startswith("/") and not path.startswith("http"):
                    path = "/" + path

                # 去重
                dedup_key = f"{method} {path}"
                if dedup_key in seen_keys:
                    continue

                # 更宽松的去重：path 相同就算（忽略 method 差异，因为 LLM 可能猜错 method）
                path_only_keys = {k.split(" ", 1)[1] for k in seen_keys}
                if path in path_only_keys:
                    continue

                seen_keys.add(dedup_key)

                result.api_calls.append(JSApiCall(
                    method=method,
                    path=path,
                    source_file=js_url,
                    context=reason[:200],
                    params=[],
                ))
                new_count += 1

            if new_count > 0:
                log.info("LLM JS 分析: %s 发现 %d 个新 API（正则遗漏）", file_name, new_count)
            else:
                log.info("LLM JS 分析: %s 未发现新 API", file_name)

        except Exception as e:
            log.warning("LLM JS 分析: %s 分析出错，跳过: %s", file_name, e)
            continue

    log.info("LLM JS 分析完成: 关键文件 %d 个, 新增 API %d 个",
             len(key_files),
             len(result.api_calls) - len(seen_keys) + len(seen_keys))

    return result


# ★ 已知"纯静态 CDN"域名列表（只放 JS/CSS/图片等静态资源，没有业务后端 API）
# 这类域名下的 JS 调用的 API 路径，绝对不是指向 CDN 自己，必须拼回目标 base_url
_STATIC_CDN_HOSTS = {
    # 京东系
    "storage.360buyimg.com",          # 京东静态资源 CDN
    "img11.360buyimg.com",
    "img12.360buyimg.com",
    "img13.360buyimg.com",
    "img14.360buyimg.com",
    "static.360buyimg.com",
    "misc.360buyimg.com",
    "static.jd.com",
    "img.jd.com",
    "static.jdcloud.com",
    # 阿里系
    "g.alicdn.com",
    "at.alicdn.com",
    "img.alicdn.com",
    "gw.alicdn.com",
    "assets.alicdn.com",
    # 腾讯系
    "vfiles.gtimg.cn",
    "static.qq.com",
    "imgcache.qq.com",
    "puui.qpic.cn",
    # 字节系
    "lf-cdn-tos.bytescm.com",
    "sf1-cdn-tos.douyinstatic.com",
    "sf3-cdn-tos.douyinstatic.com",
    # 通用公共 CDN
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "use.fontawesome.com",
}

# 静态 CDN 域名前缀/关键词（兜底匹配，覆盖未列举的 CDN 子域）
_STATIC_CDN_KEYWORDS = (
    "cdn.", "static.", "assets.", "img.", "image.", "images.",
    "media.", "fonts.", "icons.",
)


def _is_static_cdn_host(host: str) -> bool:
    """判断 host 是否是"只放静态资源"的 CDN 域名。

    匹配规则：
    1. 精确命中白名单 _STATIC_CDN_HOSTS
    2. host 以 "cdn." / "static." / "assets." 等关键词开头
    3. host 包含 "buyimg.com" / "alicdn.com" / "qpic.cn" 等已知 CDN 主域
    """
    if not host:
        return False
    host = host.lower()
    if host in _STATIC_CDN_HOSTS:
        return True
    for kw in _STATIC_CDN_KEYWORDS:
        if host.startswith(kw):
            return True
    for cdn_root in ("buyimg.com", "alicdn.com", "qpic.cn", "bytescm.com",
                     "douyinstatic.com", "jsdelivr.net"):
        if host.endswith("." + cdn_root) or host == cdn_root:
            return True
    return False


def _route_base_url_from_source(base_url: str, source_file: str) -> str:
    """根据 JS 文件位置推断 SPA 路由基路径，避免 /view/#/x 被拼成 /#/x。"""
    if not base_url:
        return ""

    parsed_base = urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}" if parsed_base.scheme and parsed_base.netloc else base_url.rstrip("/")
    base_path = (parsed_base.path or "").rstrip("/")

    try:
        parsed_source = urlparse(source_file or "")
        if parsed_source.scheme in ("http", "https") and parsed_source.netloc == parsed_base.netloc:
            source_path = parsed_source.path or ""
            source_base = ""
            for marker in ("/static/", "/assets/", "/dist/", "/js/", "/scripts/"):
                if marker in source_path:
                    source_base = source_path.split(marker, 1)[0]
                    break
            if not source_base and "/" in source_path:
                source_base = source_path.rsplit("/", 1)[0]
            if source_base and not source_base.lower().endswith((".js", ".mjs")):
                base_path = source_base.rstrip("/")
    except Exception:
        pass

    return (origin + base_path).rstrip("/")


def js_result_to_crawl_data(result: JSAnalysisResult, base_url: str = "") -> dict:
    """将 JS 分析结果转换为爬虫可消费的格式，用于生成原子功能点。"""
    data = {
        "js_api_calls": [],
        "js_routes": [],
        "js_auth_patterns": [],
        "js_sensitive_info": [],
        "js_source_maps": result.source_maps,
        "js_file_urls": list(result.js_file_urls),
        "js_stats": {
            "files_analyzed": result.js_files_analyzed,
            "total_size_kb": result.total_js_size // 1024,
            "api_calls": len(result.api_calls),
            "routes": len(result.routes),
            "auth_patterns": len(result.auth_patterns),
            "sensitive_info": len(result.sensitive_info),
            "router_mode": result.router_mode or "hash",
        },
    }

    for api in result.api_calls:
        # ★ 相对路径拼接策略（2026-05-22 修复 storage.360buyimg.com 问题）：
        # - 如果 JS 文件和目标同域 → 拼目标 base_url（业务 JS，API 路径指向自家后端）
        # - 如果 JS 文件来自"已知静态 CDN" → 也拼目标 base_url（CDN 只放 JS/静态资源，
        #   里面的 API 路径绝不是指向 CDN 自己的后端）
        # - 如果 JS 文件是第三方域名 → 拼 JS 文件所在的域名（第三方 SDK 的 API 指向它自己的后端）
        # 这样避免把 cookielaw.org/consent.js 里的 /api/v1/config 错误拼到目标域名上，
        # 也避免把 storage.360buyimg.com/xxx.js 里的 /api/file/upload 拼到 CDN 域名上
        if api.path.startswith("http"):
            api_url = api.path
        elif base_url:
            from urllib.parse import urlparse as _up
            js_host = _up(api.source_file).netloc.lower() if api.source_file.startswith("http") else ""
            target_host = _up(base_url).netloc.lower() if base_url else ""
            # 取主域比较（最后两段）
            def _main_domain(h):
                parts = h.split(".")
                return ".".join(parts[-2:]) if len(parts) >= 2 else h
            same_main_domain = (_main_domain(js_host) == _main_domain(target_host))
            is_static_cdn = _is_static_cdn_host(js_host)
            if not js_host or same_main_domain or is_static_cdn:
                # 同域 JS / 静态 CDN → 拼目标 base_url
                api_url = base_url.rstrip("/") + api.path
            else:
                # 第三方业务 JS → 拼 JS 文件所在域名
                js_origin = f"{_up(api.source_file).scheme}://{js_host}"
                api_url = js_origin.rstrip("/") + api.path
        else:
            api_url = api.path

        data["js_api_calls"].append({
            "method": api.method,
            "url": api_url,
            "path": api.path,
            "source": api.source_file,
            "context": api.context,
            "params": api.params,
        })

    for route in result.routes:
        # ★ 把 SPA 路由拼成可访问的完整 URL。
        # hash/history 模式都保留应用部署基路径，例如 /view/#/manage。
        full_url = ""
        if base_url:
            base = _route_base_url_from_source(base_url, route.source_file)
            mode = result.router_mode or "hash"
            if mode == "history":
                full_url = base + route.path
            else:
                full_url = base + "/#" + route.path
        data["js_routes"].append({
            "path": route.path,
            "component": route.component,
            "meta": route.meta,
            "source": route.source_file,
            "url": full_url,            # ★ 拼好的完整 URL，供功能点 page_url / 报告 渲染
            "router_mode": result.router_mode or "hash",
        })

    for auth in result.auth_patterns:
        data["js_auth_patterns"].append({
            "type": auth.pattern_type,
            "description": auth.description,
            "snippet": auth.code_snippet[:200],
            "storage_keys": auth.storage_keys,
        })

    for info in result.sensitive_info:
        data["js_sensitive_info"].append({
            "type": info.info_type,
            "value": info.value[:50] + "..." if len(info.value) > 50 else info.value,
            "context": info.context[:100],
        })

    return data


# ============================================================
# JS 源码缓存 & API 定位（供推测 API 参数构造使用）
# ============================================================

# ★ 按 target（站点 base_url）分桶的缓存：
#   {target_key: {js_url: js_text}}
# 不同目标的 JS 完全隔离，避免跨任务串扰。
# 任务结束应调用 clear_js_cache(target) 主动释放。
_js_source_cache: dict[str, dict[str, str]] = {}

# 单 target 缓存大小上限（防止单任务的 JS 也撑爆内存 / 拖慢搜索）
_MAX_CACHE_BYTES_PER_TARGET = 50 * 1024 * 1024  # 50MB
# 全局 target 数量上限（防止长跑进程目标列表无限增长）
_MAX_TARGETS_IN_CACHE = 5


def _normalize_target_key(target: str) -> str:
    """把 target 归一化为缓存桶 key（取 scheme+host，忽略 path/query）。"""
    if not target:
        return "__default__"
    try:
        p = urlparse(target)
        if p.netloc:
            return f"{p.scheme or 'http'}://{p.netloc}".lower()
    except Exception:
        pass
    return target.lower()


def cache_js_sources(js_contents: list[tuple[str, str]], target: str = "") -> None:
    """缓存 JS 文件内容（由 analyze_page_js 调用）。

    Args:
        js_contents: [(js_url, js_text), ...]
        target: 站点 base_url，用作缓存桶 key。同一 target 的 JS 共享缓存，
                不同 target 完全隔离，避免跨任务串扰。
    """
    target_key = _normalize_target_key(target)

    # ★ LRU：限制 target 数量，超出时淘汰最早访问的
    if target_key not in _js_source_cache and len(_js_source_cache) >= _MAX_TARGETS_IN_CACHE:
        # 简化策略：丢掉第一个（dict 保持插入顺序）
        oldest = next(iter(_js_source_cache))
        log.info("JS 缓存达上限（%d 个 target），淘汰最早的: %s",
                 _MAX_TARGETS_IN_CACHE, oldest)
        _js_source_cache.pop(oldest, None)

    bucket = _js_source_cache.setdefault(target_key, {})

    # 写入新内容（同 url 覆盖，等价于刷新）
    for url, text in js_contents:
        if text and len(text) > 50:
            bucket[url] = text

    # ★ 单 target 容量超限：按"最大文件优先丢弃"策略压回上限内
    #   理由：单个超大 JS（vendor/framework）通常匹配价值低，先丢它
    total_bytes = sum(len(t) for t in bucket.values())
    if total_bytes > _MAX_CACHE_BYTES_PER_TARGET:
        # 按文件大小降序，逐个丢弃直到达标
        items_by_size = sorted(bucket.items(), key=lambda kv: -len(kv[1]))
        for url, text in items_by_size:
            if total_bytes <= _MAX_CACHE_BYTES_PER_TARGET:
                break
            bucket.pop(url, None)
            total_bytes -= len(text)
        log.info("JS 缓存超过 %dMB 上限（target=%s），已驱逐大文件至 %dKB",
                 _MAX_CACHE_BYTES_PER_TARGET // (1024 * 1024),
                 target_key, total_bytes // 1024)

    log.info("JS 源码缓存 [%s]: %d 个文件, 总 %dKB（全局 %d 个 target）",
             target_key, len(bucket),
             sum(len(t) for t in bucket.values()) // 1024,
             len(_js_source_cache))


def clear_js_cache(target: str = "") -> int:
    """清理 JS 缓存。任务结束时应主动调用以释放内存。

    Args:
        target: 指定目标则只清该 target 的缓存；留空则全清。

    Returns:
        清理掉的文件数量。
    """
    if target:
        target_key = _normalize_target_key(target)
        bucket = _js_source_cache.pop(target_key, {})
        n = len(bucket)
        if n:
            log.info("已清理 JS 缓存 [%s]: %d 个文件", target_key, n)
        return n

    n = sum(len(b) for b in _js_source_cache.values())
    _js_source_cache.clear()
    if n:
        log.info("已清理全部 JS 缓存: %d 个文件", n)
    return n


def get_js_cache_stats() -> dict:
    """返回当前缓存统计（用于诊断 / 监控）。"""
    return {
        "targets": len(_js_source_cache),
        "files_total": sum(len(b) for b in _js_source_cache.values()),
        "bytes_total": sum(len(t) for b in _js_source_cache.values() for t in b.values()),
        "by_target": {
            tk: {
                "files": len(b),
                "bytes": sum(len(t) for t in b.values()),
            }
            for tk, b in _js_source_cache.items()
        },
    }


def locate_api_in_js(api_path: str, context_lines: int = 40, target: str = "") -> str:
    """在缓存的 JS 源码中定位 API path 的调用位置，返回上下文代码。

    Args:
        api_path: API 路径，如 "/api/user/update" 或 "user/update"，
                  也可以是完整 URL（会自动从中解析 path）
        context_lines: 提取匹配位置前后各多少行
        target: 限制只在指定目标的缓存桶中搜索（强烈建议传，避免跨任务串扰）。
                留空则按以下顺序兜底：
                1. 如果 api_path 是完整 URL，用它的 host 作为 target
                2. 否则在所有桶里搜（仅兼容旧调用，不推荐）

    Returns:
        匹配到的 JS 上下文代码（带文件来源标注），未找到返回空字符串
    """
    # ★ 选择搜索的缓存桶
    if target:
        target_key = _normalize_target_key(target)
        bucket = _js_source_cache.get(target_key, {})
    elif api_path.startswith("http"):
        # 从 api_path 自身的 host 推断 target
        try:
            p = urlparse(api_path)
            target_key = f"{p.scheme}://{p.netloc}".lower()
            bucket = _js_source_cache.get(target_key, {})
        except Exception:
            bucket = {}
    else:
        # 兜底：合并所有桶（仅向后兼容；新代码请显式传 target）
        bucket = {}
        for b in _js_source_cache.values():
            bucket.update(b)

    if not bucket:
        return ""

    # 标准化搜索路径：去掉域名前缀，保留 path 部分
    search_path = api_path
    if "://" in search_path:
        search_path = urlparse(search_path).path
    # 去掉开头的 /，方便模糊匹配
    search_variants = [
        search_path,                          # /api/user/update
        search_path.lstrip("/"),              # api/user/update
    ]
    # 提取 path 的最后两段用于精确匹配
    path_parts = [p for p in search_path.split("/") if p]
    if len(path_parts) >= 2:
        search_variants.insert(1, "/".join(path_parts[-2:]))  # user/update

    # ★ 按文件质量排序：业务 chunk 优先，入口/路由配置文件最后
    def _file_priority(js_url: str) -> int:
        """越小越优先。"""
        name = js_url.lower().split("/")[-1] if "/" in js_url else js_url.lower()
        # 明确的业务组件文件（Vue/React 组件）优先级最高
        if any(kw in name for kw in ("service", "api.", "request", "http", "manage", "view")):
            return 0
        # 普通 chunk 文件
        if name.startswith("chunk-") or name.startswith("async-"):
            return 1
        # 内联脚本
        if name.startswith("inline_"):
            return 2
        # 框架/库文件（搜索价值低）
        if any(kw in name for kw in ("vue-", "react-", "element-plus", "echarts", "ant-design")):
            return 8
        # Vite/Webpack 入口文件（最容易产生低质量匹配）
        if name.startswith("index-") or name.startswith("app-") or name.startswith("main-"):
            return 7
        # 其他
        return 3

    sorted_cache = sorted(bucket.items(), key=lambda kv: _file_priority(kv[0]))

    # ★ 低质量上下文检测关键词
    _LOW_QUALITY_MARKERS = (
        "__vite__mapDeps", "__vite__", "mapDeps", "chunkFileNames",
        "manualChunks", "rollupOptions", "assetFileNames",
    )

    def _extract_lines_around(js_text: str, match_idx: int, ctx: int) -> tuple[int, int, str]:
        """高效提取 match_idx 附近的 ±ctx 行，返回 (start_line, end_line, code_block)。

        关键优化：避免 `js_text[:idx].split("\\n")` 这种 O(idx) 内存复制，
        用 `str.count("\\n", 0, idx)` 直接计数；用 rfind/find 定位行边界，
        只对真正需要的窗口做切片。
        """
        # 当前行号（1-based）
        line_num = js_text.count("\n", 0, match_idx) + 1
        start_line = max(1, line_num - ctx)
        end_line = line_num + ctx

        # 找 start_line 在 js_text 中的字节起点：从 match_idx 往回数 (line_num - start_line) 个 \n
        steps_back = line_num - start_line
        pos = match_idx
        for _ in range(steps_back):
            pos = js_text.rfind("\n", 0, pos)
            if pos == -1:
                pos = 0
                break
            # 跳过 '\n' 本身
        start_byte = pos + 1 if pos > 0 else 0

        # 找 end_line 末尾：从 match_idx 往后数 (end_line - line_num) 个 \n
        steps_fwd = end_line - line_num
        pos = match_idx
        for _ in range(steps_fwd):
            nxt = js_text.find("\n", pos + 1)
            if nxt == -1:
                pos = len(js_text)
                break
            pos = nxt
        end_byte = pos

        code_block = js_text[start_byte:end_byte]
        # 修正 end_line（如果遇到 EOF 提前结束）
        if end_byte == len(js_text):
            actual_end_line = start_line + code_block.count("\n")
        else:
            actual_end_line = end_line
        return start_line, actual_end_line, code_block

    results = []

    for js_url, js_text in sorted_cache:
        # 按优先级尝试匹配
        for variant in search_variants:
            if variant not in js_text:
                continue

            # 找到所有匹配位置
            idx = js_text.find(variant)
            # ★ 性能优化：只取第一处匹配（原本 < 3 在 fuzz 场景下被调用 954 次，
            #   每次找 3 处 + while 循环 + 200 字符 nearby 检查 → 累计 CPU 耗尽）
            #   第一处匹配已足够给 LLM 提供 API 调用上下文，多处匹配价值不大
            while idx != -1 and len(results) < 1:
                # ★ 上下文质量检查：匹配位置附近是否是低质量代码
                nearby = js_text[max(0, idx - 200):idx + 200]
                is_low_quality = any(marker in nearby for marker in _LOW_QUALITY_MARKERS)

                if is_low_quality:
                    # 跳过低质量匹配，继续搜索下一个位置
                    idx = js_text.find(variant, idx + len(variant))
                    continue

                # ★ 高效提取行号 + 上下文（避免全文 split）
                start_line, end_line, code_block = _extract_lines_around(
                    js_text, idx, context_lines)

                # ★ 二次质量检查：整个代码块是否有效（含 API 调用模式或参数构造）
                has_api_pattern = any(kw in code_block for kw in
                    ("fetch", "axios", "request", "http", "$ajax", ".get(", ".post(",
                     ".put(", ".delete(", "headers", "params", "body:", "data:"))
                # 如果代码块里全是文件路径列表，判定为低质量
                if not has_api_pattern and code_block.count('"./')  > 5:
                    idx = js_text.find(variant, idx + len(variant))
                    continue

                # 限制单个代码块大小
                if len(code_block) > 4000:
                    code_block = code_block[:4000] + "\n// ... (截断)"

                source_name = js_url.split("/")[-1] if "/" in js_url else js_url
                match_type = "精确匹配" if variant == search_path else "模糊匹配"
                results.append(
                    f"// === 来源: {source_name} (行 {start_line}~{end_line}, {match_type}) ===\n"
                    f"{code_block}"
                )

                # 继续找下一处
                idx = js_text.find(variant, idx + len(variant))

            if results:
                break  # 当前优先级已找到，不再尝试更模糊的

        if results:
            break  # 已在某个文件中找到

    # ★ 已删除最后兜底分支（用 last_segment 做正则全文搜索）：
    #   - 性能：每次失败时要扫所有非框架文件（数百 KB ~ 数 MB），
    #     在 fuzz 场景下 954 次调用 × 多文件 = CPU 雪崩元凶之一
    #   - 收益低：能命中兜底的 path，业务相关性已经很弱（只匹配最后一段），
    #     生成的 JS 上下文经常误导 LLM
    #   - 真业务 API 在前两个 variant（精确/最后两段）就该命中
    return "\n\n".join(results)
