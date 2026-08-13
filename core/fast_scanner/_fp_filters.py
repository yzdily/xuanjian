"""fast_scanner 假阳性过滤函数（从原 fast_scanner.py 机械拆分，内容逐字保留）。

11 个铁律函数原样保留，仅改为从 _constants 导入所需常量。
"""

from __future__ import annotations

import re

from ._constants import (
    BUSINESS_DENY_PATTERNS,
    EMPTY_DATA_PATTERNS,
    WAF_BLOCK_KEYWORDS,
    SENSITIVE_DATA_PATTERNS,
    PUBLIC_DATA_PATTERNS,
    _HEADER_VERSION_RE,
    SENSITIVE_PATH_FINGERPRINTS,
)


def _is_business_deny(text: str) -> bool:
    """检测响应体是否为业务层拒绝（HTTP 200 但业务码表示未登录/未授权）。

    这是检测层防误报的核心：很多 API 返回 HTTP 200，但在响应体 JSON 中用
    code/message 字段表示"用户未登录"或"无权限"。仅看状态码会大量误报。
    """
    if not text or len(text) < 5:
        return False
    for pat in BUSINESS_DENY_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def _is_empty_data(text: str) -> bool:
    """检测响应体是否为空 data（200 但 data:null/[] → 无实际数据泄露）。

    参考 api-pentest-extension 铁律5：空 data 的 200 不算漏洞。
    """
    if not text or not text.strip():
        return True
    stripped = text.strip()

    # ★ 优先 JSON 层面判定：如果响应是合法 JSON 且是一个纯 API 包装器
    # （仅含 data/result/records/rows/list 数据字段 + code/msg/status 等元数据字段），
    # 且所有数据字段均为空值，则不论响应体长度都判定为空 data
    # （修复原 500 字符阈值漏判长响应的问题）
    try:
        import json as _json
        obj = _json.loads(stripped)
        if isinstance(obj, dict):
            _data_keys = ("data", "result", "records", "rows", "list")
            _meta_keys = ("code", "msg", "message", "status", "success",
                          "error", "errcode", "errno", "total", "count",
                          "timestamp", "time", "request_id", "trace_id")
            _has_any_data_key = False
            _has_non_empty_data = False
            _has_unknown_content_key = False
            for key, val in obj.items():
                if key in _data_keys:
                    _has_any_data_key = True
                    if val is not None and val != [] and val != {} and val != "":
                        _has_non_empty_data = True
                elif key not in _meta_keys:
                    # 存在非数据、非元数据的字段（如 padding/描述/详情等）
                    if val is not None and val != [] and val != {} and val != "":
                        _has_unknown_content_key = True
            # 存在非空数据字段 → 绝对不是空响应，直接返回 False
            if _has_non_empty_data:
                return False
            # 存在数据字段、全部为空、且无其他内容字段 → 空响应
            if (_has_any_data_key and not _has_non_empty_data
                    and not _has_unknown_content_key):
                return True
    except (ValueError, TypeError):
        pass

    for pat in EMPTY_DATA_PATTERNS:
        if re.search(pat, stripped, re.IGNORECASE):
            # 仅当响应体较短时才认定为空 data（长响应可能只是某个字段为空）
            if len(stripped) < 500:
                return True
    return False


def _is_waf_block_page(resp) -> bool:
    """检测响应是否为 WAF 拦截页（403/418/429/503 + 拦截关键词）。"""
    if resp.status_code not in (403, 418, 429, 503):
        return False
    body = (resp.text or "").lower()
    if not body:
        return False
    return any(kw in body for kw in WAF_BLOCK_KEYWORDS)


def _normalize_body(body: str) -> str:
    """归一化响应体：剥离动态内容，防止布尔盲注/响应对比误判。

    参考 api-pentest-extension 的 _normalize_body()：
    剥离时间戳、CSRF token、JWT、hash 等每次请求都变化的动态内容。
    """
    if not body:
        return ""
    s = body
    s = re.sub(r'\b\d{10,13}\b', '', s)                    # Unix 时间戳
    s = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?', '', s)  # ISO 时间
    s = re.sub(r'(csrf|nonce|_token|token|xsrf)["\']?\s*[:=]\s*["\']?'
               r'[a-zA-Z0-9_\-]{16,}', '', s, flags=re.IGNORECASE)  # CSRF/token
    s = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '', s)  # JWT
    s = re.sub(r'\b[0-9a-f]{32,64}\b', '', s, flags=re.IGNORECASE)  # MD5/SHA hash
    s = re.sub(r'\s+', ' ', s).strip()                      # 空白归一化
    return s


def _bodies_similar(text1: str, text2: str, threshold: float = 0.85) -> bool:
    """归一化后比较两段文本相似度（长度比 + Jaccard token 相似度）。"""
    n1, n2 = _normalize_body(text1), _normalize_body(text2)
    if not n1 and not n2:
        return True
    if not n1 or not n2:
        return False
    # 长度比
    len_ratio = min(len(n1), len(n2)) / max(len(n1), len(n2))
    if len_ratio < 0.8:
        return False
    # Jaccard token 相似度（按空格切词）
    tokens1 = set(n1.split())
    tokens2 = set(n2.split())
    if not tokens1 and not tokens2:
        return True
    if not tokens1 or not tokens2:
        return False
    jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
    return jaccard >= threshold


def _is_xss_executable_context(text: str, probe: str) -> bool:
    """检查 XSS 探针是否出现在可执行上下文中（而非 HTML 注释/JSON 字符串/纯文本）。

    参考 api-pentest-extension XSS 铁律5：探针在 HTML 注释中、纯 JSON 错误响应中
    → 假阳性（不可执行）。只有出现在 HTML body/属性/JS 代码区才算可执行上下文。
    """
    if not text or not probe:
        return False
    idx = text.find(probe)
    if idx < 0:
        return False
    # 检查探针前后上下文
    before = text[max(0, idx - 100):idx]
    after = text[idx + len(probe):idx + len(probe) + 100]
    context = (before + after).lower()
    # HTML 注释中 → 不可执行
    if "<!--" in before and "-->" not in before:
        return False
    # 纯 JSON 响应（非 HTML）→ 不可执行
    ct_lower = context.strip()
    if (text.strip().startswith("{") and text.strip().endswith("}")
            and "<" not in text[:idx]):
        return False
    # <script> 标签内 → JS 上下文（可执行）
    if "<script" in before.lower() and "</script>" not in before.lower():
        return True
    # <textarea> / <title> 标签内 → 纯文本上下文（浏览器会转义，不可执行）
    if "<textarea" in before.lower() and "</textarea>" not in before.lower():
        return False
    if "<title" in before.lower() and "</title>" not in before.lower():
        return False
    # 默认：在 HTML body 中 → 可执行上下文
    return True


def _body_contains_sensitive_data(text: str) -> bool:
    """检测响应体是否包含真实敏感数据特征。

    用于未授权访问/CORS/信息泄露的多因素验证：只有响应体确实含敏感数据，
    才认为该漏洞有实际危害，避免只看响应头/状态码就判漏洞。
    """
    if not text or len(text) < 5:
        return False
    # 邮箱需要批量出现才算（单个邮箱可能是示例）
    email_count = len(re.findall(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", text))
    for pat in SENSITIVE_DATA_PATTERNS:
        if "email" in pat.lower():
            continue
        if re.search(pat, text, re.IGNORECASE):
            return True
    if email_count >= 3:
        return True
    return False


def _is_public_data(text: str, content_type: str = "") -> bool:
    """检测响应体是否属于公开/无害数据。

    用于未授权访问/CORS 判定：如果响应体是公开数据（公告、商品、SPA 壳等），
    即使无需认证也不应判为漏洞。
    """
    if not text:
        return True
    ct = (content_type or "").lower()
    # 纯静态资源一般不含敏感业务数据
    if any(ct.startswith(p) for p in ("image/", "font/", "text/css",
                                       "application/javascript", "text/plain")):
        if len(text) < 200:
            return True
    for pat in PUBLIC_DATA_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def _is_auth_wall_page(text: str) -> bool:
    """检测响应体是否为登录/认证墙页面（优化.md 建议1 缺口补齐）。

    未授权访问检测中，去认证后服务器常返回登录页（HTTP 200 + 登录表单），
    这种"认证墙"不是真正的未授权数据访问。登录页天然含 password 输入框，
    会被 _body_contains_sensitive_data 误判为含敏感数据 → 误报 HIGH。
    本函数识别此类认证墙页面，用于在未授权检测中提前剔除。
    """
    if not text or len(text) < 20:
        return False
    low = text.lower()
    # 必须同时含密码输入框 + 登录特征，才算认证墙
    has_pwd_input = bool(re.search(
        r'<input[^>]*type=["\']?password["\']?', low))
    has_login_marker = any(kw in low for kw in (
        "login", "signin", "logon", "登录", "账号登录", "用户登录",
        "请输入密码", "忘记密码", "password\"", "name=\"password\"",
        "<form", "action=\"/login", "action=\"/auth",
    ))
    return has_pwd_input and has_login_marker


def _header_value_leaks_version(val: str) -> bool:
    """判断响应头值是否泄露了具体版本号。

    纯产品名（如 "nginx"、"cloudflare"、"Express" 无版本）不算泄露，
    因为无法据版本号匹配已知 CVE。
    """
    if not val:
        return False
    return bool(_HEADER_VERSION_RE.search(val))


def _verify_sensitive_path_content(path: str, text: str) -> tuple[bool, str]:
    """验证敏感路径响应体是否匹配预期内容特征。

    Returns:
        (matched, evidence_quality):
        - (True, "content_match")  路径有指纹且内容命中 → 强证据
        - (True, "header_only")     路径无指纹但 200 + 内容较大 → 弱证据（可能误报）
        - (False, "")               路径有指纹但内容未命中 → 跳过（多为 SPA 兜底）
    """
    if not text:
        return False, ""
    path_lower = path.lower()

    # ★ 公开网站正常文件白名单：这些路径是网站标准文件，不应报为信息泄露
    # sitemap.xml / robots.txt / crossdomain.xml / clientaccesspolicy.xml
    # 是搜索引擎和爬虫协议文件，公开可访问是正常行为
    _PUBLIC_NORMAL_PATHS = {
        "/sitemap.xml", "/robots.txt", "/crossdomain.xml",
        "/clientaccesspolicy.xml", "/humans.txt", "/security.txt",
        "/.well-known/security.txt",
    }
    if path_lower in _PUBLIC_NORMAL_PATHS:
        return False, ""

    # 查找匹配的指纹（按 path 后缀/子串匹配）
    # ★ 按长度降序迭代：让更具体的 key（如 "actuator/env"）先于
    #   更宽泛的 key（如 "actuator"）匹配，避免误用错误指纹导致漏判。
    for key in sorted(SENSITIVE_PATH_FINGERPRINTS, key=len, reverse=True):
        patterns = SENSITIVE_PATH_FINGERPRINTS[key]
        if key in path_lower:
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    return True, "content_match"
            # 有指纹但都没命中 → 大概率是 SPA 兜底页/默认页，跳过
            return False, ""
    # 无指纹的路径（少数）：仅当内容足够大且非 HTML 壳时给弱证据
    if len(text) > 50 and not re.search(r"<(?:html|!doctype|div id=\"(?:root|app))",
                                         text, re.IGNORECASE):
        return True, "header_only"
    return False, ""
