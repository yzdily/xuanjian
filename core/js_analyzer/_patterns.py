"""JS Analyzer 正则模式集 — 从 js_analyzer.py 抽取，行为不变。

★ 关键安全约束：所有"两段式"配置对象的中间隔离量词必须用【有界 + 非贪婪】
  形式 `[^}]{0,200}?`，禁止使用 `[^}]*?`。
  原因：在 minified 单行 JS（4MB+）上，`[^}]*?` 配合 DOTALL 会触发
  灾难性回溯（catastrophic backtracking），单次匹配可耗尽 CPU 数分钟。
"""

from __future__ import annotations

import re

# ============================================================
# API 调用模式：匹配 fetch/axios/$.ajax/http 调用
# ============================================================

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

# ★ axios.create({baseURL: "/api/v1"}) — 提取 baseURL 用于拼接相对路径 API
# 覆盖场景：
#   axios.create({baseURL: "/api/v1"})
#   axios.create({baseURL: "https://api.example.com/v2"})
#   const service = axios.create({baseURL: window.CONFIG.apiBase})
_AXIOS_BASEURL_PATTERN = re.compile(
    r'''(?:axios\s*\.\s*create|createAxios|axios\.create)\s*\(\s*\{[^}]{0,300}?baseURL\s*:\s*[`"']([^`"']{2,200})[`"']''',
    re.IGNORECASE | re.DOTALL,
)
# 通用 baseURL 赋值（非 axios.create 场景）
#   const BASE_URL = "/api/v1"
#   window.API_BASE = "/api"
#   config.apiBase = "/service"
_BASEURL_ASSIGN_PATTERN = re.compile(
    r'''(?:const|let|var|window\.|this\.|config\.|app\.)(?:\w+\.){0,3}(?:BASE_URL|baseURL|apiBase|API_BASE|apiUrl|API_URL|baseUrl)\s*=\s*[`"']([^`"']{2,200})[`"']''',
    re.IGNORECASE,
)

# ★ WebSocket / SSE 端点提取
# new WebSocket("ws://xxx") / new WebSocket("wss://xxx")
_WEBSOCKET_PATTERN = re.compile(
    r'''new\s+WebSocket\s*\(\s*[`"']([^`"']+)[`"']''',
    re.IGNORECASE,
)
# new EventSource("/api/sse") / new EventSource("https://xxx/sse")
_SSE_PATTERN = re.compile(
    r'''new\s+EventSource\s*\(\s*[`"']([^`"']+)[`"']''',
    re.IGNORECASE,
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

# 鉴权模式列表
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

# ============================================================
# 路由抽取辅助：正则与白名单
# ============================================================

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

# ============================================================
# Router 模式探测（hash / history）
# Vue Router 4: createWebHashHistory() / createWebHistory()
# Vue Router 3: mode: "hash" / mode: "history"
# React Router: createHashRouter / createBrowserRouter
# ============================================================

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
