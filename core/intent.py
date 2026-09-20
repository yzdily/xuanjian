"""
Intent — LLM 意图解析

从用户输入中提取结构化意图（目标 URL、凭证、测试模式、Cookie/Token 等）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import re

from core.llm import LLMClient, Message
from core.prompts import load_prompt


INTENT_PARSE_PROMPT = load_prompt("intent_parse")

DEFAULT_INTENT = {
    "has_target": False,
    "target_url": "",
    "credentials": [],
    "session_cookies": "",
    "auth_header": "",
    "extra_headers": {},
    "extra_scope": [],   # ★ 关联域名白名单（多域 SaaS 场景：业务域 + SSO 域）
    "test_mode": "",
    "special_notes": "",
    "intent_kind": "site",  # ★ 默认 site 保持现有行为
    "target_features": [],  # ★ focused 模式：用户指定要测试的功能列表
}


async def parse_user_intent(llm: LLMClient, user_message: str) -> dict:
    """用 LLM 解析用户输入的意图，返回结构化数据。LLM 失败时正则 fallback。

    核心思路：LLM 做意图判断（包括 intent_kind），正则只做 HTTP 包/cURL 结构化解析
    和 LLM 失败时的兜底。不再用硬编码关键词覆盖 LLM 的判断。
    """

    # ★ 优先尝试解析完整 HTTP 请求包（Burp/Chrome F12 复制格式）或 cURL 命令
    # 这是最强的凭证形态：包含所有自定义 header（sign/key/token 等）
    packet = None
    if has_http_request_packet(user_message):
        packet = parse_http_request_packet(user_message)
    elif _looks_like_curl(user_message):
        packet = parse_curl_command(user_message)

    msgs = [
        Message(role="system", content=INTENT_PARSE_PROMPT),
        Message(role="user", content=user_message),
    ]
    try:
        response = await asyncio.to_thread(llm.chat, msgs, caller="intent_parse", max_tokens=1024)
        text = response.content or ""
        # ★ 使用统一的安全 JSON 解析（支持思考块剥离、围栏剥离、平衡括号提取）
        from core.llm import parse_llm_json
        result = parse_llm_json(text, expect=dict)
        if result and result.get("has_target") and result.get("target_url"):
            # 补全 LLM 可能漏掉的字段
            for k, v in DEFAULT_INTENT.items():
                result.setdefault(k, v)
            # ★ 清洗 LLM 给出的 extra_headers：剔除标准头（避免误注入）
            if result.get("extra_headers"):
                result["extra_headers"] = _filter_extra_headers(result["extra_headers"])
            # ★ 合并 HTTP 请求包结果（覆盖 cookie/headers）
            if packet:
                _merge_packet_into_intent(result, packet)
            # ★ "PROVIDED" 标记处理：LLM 不再复制长 Cookie/Auth，
            # 如果 packet 已覆盖则无事；否则从用户原文正则提取
            _resolve_provided_markers(result, user_message, packet)
            # ★ intent_kind 合法性校验：只校验值是否合法，不覆盖 LLM 判断
            _validate_intent_kind(result, packet, user_message)
            return result
        elif result is None and text:
            # ★ 解析失败时记录日志，便于排查 LLM 输出格式问题
            logging.getLogger(__name__).warning(
                "intent_parse JSON 解析失败，回退正则; raw=%r", text[:200])
    except Exception as e:
        # ★ llm 未配置时降级为 debug（fast/无 LLM 模式下这是预期行为，走正则 fallback）
        _msg = str(e)
        if "NoneType" in _msg or "no attribute" in _msg:
            logging.getLogger(__name__).debug(
                "intent_parse 跳过 LLM（未配置），使用正则 fallback")
        elif "404" in _msg or "not found" in _msg.lower():
            # ★ 2026-08-05：404 通常是模型名配错，清晰告警并提示检查配置
            logging.getLogger(__name__).error(
                "intent_parse LLM 返回 404（模型名可能配错），使用正则 fallback: %s", _msg[:200])
        else:
            logging.getLogger(__name__).warning("intent_parse LLM 调用失败: %s", e)

    # ---- 正则 fallback：直接从用户输入提取 ----
    result = _regex_fallback(user_message)
    if packet:
        _merge_packet_into_intent(result, packet)
    _validate_intent_kind(result, packet, user_message)
    return result


def _resolve_provided_markers(result: dict, user_message: str, packet: dict | None) -> None:
    """处理 LLM 返回的 "PROVIDED" 标记。

    当 LLM 按指令返回 session_cookies="PROVIDED" 或 auth_header="PROVIDED" 时：
    - 如果有 packet 且已覆盖 → 无需处理（packet 的值已是真实值）
    - 如果没有 packet → 从用户原文中正则提取 Cookie/Auth
    """
    # session_cookies 处理
    if result.get("session_cookies", "").strip().upper() == "PROVIDED":
        if not packet or not packet.get("cookies"):
            # 没有 packet 覆盖，从用户原文正则提取
            cookie_str = _extract_cookie_from_text(user_message)
            result["session_cookies"] = cookie_str
        # 如果有 packet 且有 cookies，_merge_packet_into_intent 已经覆盖了

    # auth_header 处理
    if result.get("auth_header", "").strip().upper() == "PROVIDED":
        if not packet:
            auth_str = _extract_auth_from_text(user_message)
            result["auth_header"] = auth_str


def _extract_cookie_from_text(text: str) -> str:
    """从用户文本中正则提取 Cookie 字符串（非 HTTP 包场景）。"""
    # 匹配 "cookie:" 或 "Cookie:" 后面的内容
    m = re.search(r'(?:cookie|Cookie)\s*[:：]\s*(.+?)(?:\n|$)', text)
    if m:
        return m.group(1).strip()
    # 匹配 name=value; name=value 格式（至少两个 key=value 对）
    m = re.search(r'(\w+=\S+(?:;\s*\w+=\S+)+)', text)
    if m:
        return m.group(1).strip()
    return ""


def _extract_auth_from_text(text: str) -> str:
    """从用户文本中正则提取 Authorization 头。"""
    m = re.search(r'(?:Authorization|authorization)\s*[:：]\s*(.+?)(?:\n|$)', text)
    if m:
        return m.group(1).strip()
    # Bearer token 格式
    m = re.search(r'(Bearer\s+\S+)', text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return ""


def _validate_intent_kind(result: dict, packet: dict | None, user_message: str = "") -> None:
    """校验 intent_kind 合法性。不覆盖 LLM 判断，只做降级：
    1. 值非法（非 site/packet/ambiguous/focused/exploit）→ 兜底 site
    2. 没有 HTTP 包数据 → packet 不合法，强制 site
    3. focused 模式必须有 target_features → 否则降级 site
    4. exploit 模式需要有 packet 或 target_url（至少有一个目标信息）
    """
    kind = (result.get("intent_kind") or "").strip().lower()
    if kind not in ("site", "packet", "ambiguous", "focused", "exploit"):
        result["intent_kind"] = "site"
    elif kind == "packet" and not packet:
        # 没有 HTTP 包/cURL → 不可能是 packet 模式
        result["intent_kind"] = "site"
    elif kind == "exploit" and not packet and not result.get("target_url"):
        # exploit 模式需要有数据包或目标 URL（两者都没有则降级）
        result["intent_kind"] = "site"
    elif kind == "focused" and not result.get("target_features"):
        # focused 模式但没有 target_features → 降级 site
        result["intent_kind"] = "site"


_STANDARD_HEADERS_TO_DROP = {
    "content-type", "content-length", "accept", "accept-encoding",
    "accept-language", "connection", "host", "origin", "referer",
    "user-agent", "cookie", "authorization",
    "cache-control", "pragma", "upgrade-insecure-requests",
    "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
}


def _filter_extra_headers(headers: dict) -> dict:
    """剔除 extra_headers 里的标准头（避免覆盖浏览器自身行为）。

    仅保留真正的自定义头（签名、租户、API Key 等），key 保留原始大小写。
    """
    if not isinstance(headers, dict):
        return {}
    return {k: v for k, v in headers.items()
            if isinstance(k, str) and k.lower() not in _STANDARD_HEADERS_TO_DROP
            and isinstance(v, (str, int, float))}


def _extract_token_value(value: str) -> str:
    """从 Header 值中提取可注入前端存储的 token。"""
    if not isinstance(value, str):
        return ""
    token = value.strip()
    if not token:
        return ""
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _looks_like_auth_token(value: str) -> bool:
    """判断字符串是否像登录态 token，避免把普通业务字段误写入 localStorage。"""
    token = _extract_token_value(value)
    if len(token) < 16:
        return False
    if token.startswith("eyJ"):
        return True
    if re.fullmatch(r"[A-Za-z0-9_\-\.=]{24,}", token):
        return True
    return False


def jwt_headers_to_local_storage(extra_headers: dict, storage_keys: list[str] | set[str] | tuple[str, ...] | None = None) -> dict:
    """从 extra_headers 中提取 JWT token，生成适合注入 localStorage 的 dict。

    SPA 前端（Vue/React）通常从 localStorage 读取 token 做前端路由守卫，
    而不是从 HTTP 请求头读取。仅 set_extra_http_headers 不够——
    前端路由仍判定未登录，跳转到 error/login 页面。

    此函数检测 JWT 格式（eyJ 开头）的 header 值，返回 {key: value} dict，
    可直接写入 PENTEST_INJECT_LOCAL_STORAGE 环境变量。storage_keys 来自
    JS 静态分析时，会额外写入前端真实读取的自定义 key。
    """
    if not isinstance(extra_headers, dict):
        return {}
    ls_items = {}
    normalized_storage_keys: list[str] = []
    if storage_keys:
        for key in storage_keys:
            if not isinstance(key, str):
                continue
            key = key.strip()
            key_lower = key.lower()
            if not key or len(key) > 100:
                continue
            if any(bad in key_lower for bad in ("refresh", "csrf", "xsrf", "nonce")):
                continue
            if key not in normalized_storage_keys:
                normalized_storage_keys.append(key)

    common_token_keys = [
        "token", "access_token", "accessToken", "auth_token", "authToken",
        "jwt", "id_token", "idToken", "Authorization",
    ]
    auth_header_names = {
        "authorization", "x-auth-token", "x-access-token", "access-token",
        "id-token", "id_token", "token", "jwt", "c-token", "sc-id-token",
    }

    for hk, hv in extra_headers.items():
        hk_name = str(hk)
        hk_lower = hk_name.lower()
        token = _extract_token_value(hv) if isinstance(hv, str) else ""
        if token and (hk_lower in auth_header_names or _looks_like_auth_token(token)):
            ls_items[hk_name] = token
            # 同时写入常见别名，提高 SPA 读取匹配率
            if hk_lower not in ("token", "access_token", "authtoken", "auth_token"):
                ls_items["token"] = token
            for key in common_token_keys:
                ls_items.setdefault(key, token)
            for key in normalized_storage_keys:
                ls_items[key] = token
            # 兼容历史经验：秀合同/ShowCon 前端路由守卫读取固定 key。
            # 通用链路会通过 JS 分析发现此 key；这里保留首屏加载前的兜底注入。
            if hk_lower == "sc-id-token":
                ls_items.setdefault("showcon_token_mpv1.0", token)
                # ★ 2026-06-05 根因修复：ShowCon 路由守卫在读取 token 之前
                # 先检查 localStorage 中的 showcon_login_type，若无则直接跳 /error。
                # 值固定为 "tenant_user_pass"（企业/租户密码登录），对应 edgeLogin 流程。
                ls_items.setdefault("showcon_login_type", "tenant_user_pass")
    return ls_items


def _merge_packet_into_intent(intent: dict, packet: dict):
    """把 HTTP 请求包的解析结果合并到 intent 里。

    - 优先用 packet 推导的 URL（仅当 intent 还没有 target_url 时）
    - cookies 用 packet 的覆盖
    - 把所有自定义 header 存到 intent["extra_headers"] 字段
    - ★ 2026-05-20：保留 packet 完整信息到 intent["packet"]，供包测模式使用
    - ★ 2026-05-22：多域 SaaS 场景修复（如 Freshworks: freshservice.com 业务 + myfreshworks.com SSO）
        以前 packet host "永远优先"，会把"用户明说的业务地址"覆盖成"登录数据包的 SSO host"，
        导致爬错站。新策略：
        - intent 已有 target_url（用户显式写了目标）→ 信任用户，packet host 不同则进 extra_scope
        - intent 没有 target_url → 沿用旧行为，packet host 当 target
    """
    packet_host = packet.get("host")
    packet_scheme = packet.get("scheme")
    packet_url = packet.get("url", "")  # 完整 URL: https://host/path
    if packet_host and packet_scheme:
        existing_target = intent.get("target_url") or ""
        if not existing_target:
            # 用户没显式给目标 → packet URL 就是 target
            intent["target_url"] = packet_url or f"{packet_scheme}://{packet_host}"
            intent["has_target"] = True
            intent["target_from_packet"] = True
        else:
            # ★ 2026-05-28 修复：LLM 容易从 Cookie 中的 landing_url/redirect_uri/referer 等
            # 字段误提取 target_url（如飞书 Cookie 里的 landing_url=https://project.feishu.cn/...）。
            # 当用户只粘贴了一个 HTTP 数据包时，数据包的 Host+Path 才是真正的目标。
            # 判断策略：如果 LLM 给出的 target_url 的 host 和 packet host 不同，
            # 且 LLM 的 target_url 出现在 Cookie 字符串中 → 说明 LLM 误提取了 Cookie 中的 URL，
            # 应该用 packet 的 URL 覆盖。
            from urllib.parse import urlparse as _urlparse
            try:
                existing_host = (_urlparse(existing_target).netloc or "").lower()
            except Exception:
                existing_host = ""
            if existing_host and packet_host.lower() != existing_host:
                # 检查 LLM 的 target_url 是否来自 Cookie（误提取）
                cookie_str = packet.get("cookies", "")
                target_in_cookie = existing_target in cookie_str
                if target_in_cookie:
                    # ★ LLM 从 Cookie 中误提取了 URL → 用 packet 的 URL 覆盖
                    intent["target_url"] = packet_url or f"{packet_scheme}://{packet_host}"
                    intent["has_target"] = True
                    intent["target_from_packet"] = True
                    # 把 LLM 误提取的 host 加到 extra_scope（可能是关联域名）
                    extra = list(intent.get("extra_scope") or [])
                    if existing_host not in extra:
                        extra.append(existing_host)
                    intent["extra_scope"] = extra
                else:
                    # 用户确实给了不同的 target → 信任用户，packet host 加进 extra_scope
                    extra = list(intent.get("extra_scope") or [])
                    if packet_host not in extra:
                        extra.append(packet_host)
                    intent["extra_scope"] = extra

    if packet.get("cookies"):
        intent["session_cookies"] = packet["cookies"]

    # 提取 Authorization 单独存（保持向后兼容）
    headers = packet.get("headers", {}) or {}
    for k, v in headers.items():
        if k.lower() == "authorization":
            intent["auth_header"] = v
            break

    # ★ 关键：把所有非自动管理的 header 都存到 extra_headers（dict 形式）
    # 过滤掉标准头（避免覆盖浏览器自身行为）
    intent["extra_headers"] = _filter_extra_headers(headers)

    # ★ 2026-05-20：完整保留 packet 信息（供包测模式 packet_test 使用）
    # 现有 site 模式不读这个字段，所以零干扰
    intent["packet"] = {
        "method": packet.get("method", "GET"),
        "url": packet.get("url", ""),         # 完整 URL: https://x.com/api/order?id=1
        "path": packet.get("path", ""),       # 路径: /api/order
        "host": packet.get("host", ""),
        "scheme": packet.get("scheme", "https"),
        "headers": headers,                    # 全部原始 header（包含 cookie/auth）
        "cookies": packet.get("cookies", ""),
        "body": packet.get("body", ""),
        "dynamic_signing_fields": packet.get("dynamic_signing_fields", []),
    }

    # 动态签名警告
    if packet.get("dynamic_signing_fields"):
        intent["dynamic_signing_fields"] = packet["dynamic_signing_fields"]
    if packet.get("warnings"):
        existing = intent.get("special_notes", "")
        warn_text = "; ".join(packet["warnings"])
        intent["special_notes"] = (existing + "\n" + warn_text).strip() if existing else warn_text
        intent["dynamic_signing_warning"] = warn_text


def _regex_fallback(text: str) -> dict:
    """正则从用户输入中提取 URL 和账号密码。"""
    result = dict(DEFAULT_INTENT)

    # 提取 URL
    url_match = re.search(r'https?://[^\s,，、\u3000]+', text)
    if url_match:
        url = url_match.group(0).rstrip('.,;。，；')
        result["has_target"] = True
        result["target_url"] = url

    # 提取账号密码（常见格式：账号 xxx 密码 xxx / username: xxx password: xxx）
    cred_patterns = [
        # 中文：账号 xxx 密码 xxx
        re.compile(r'(?:账号|用户名|用户)\s*[:：]?\s*(\S+)\s+(?:密码|口令)\s*[:：]?\s*(\S+)', re.IGNORECASE),
        # 英文：username xxx password xxx
        re.compile(r'(?:username|user|account)\s*[:=]?\s*(\S+)\s+(?:password|passwd|pwd)\s*[:=]?\s*(\S+)', re.IGNORECASE),
        # 斜杠格式：admin/admin123
        re.compile(r'(?:账号|用户|account|user)\s*[:：]?\s*(\S+?)[/／](\S+)', re.IGNORECASE),
    ]
    for pat in cred_patterns:
        m = pat.search(text)
        if m:
            result["credentials"] = [{"role": "user", "username": m.group(1), "password": m.group(2)}]
            break

    # 提取测试模式
    if any(k in text.lower() for k in ("src", "漏洞挖掘", "挖洞")):
        result["test_mode"] = "src"
    elif any(k in text.lower() for k in ("上线前", "渗透测试", "安全测试")):
        result["test_mode"] = "pre_launch"

    return result


def parse_cookie_string(cookie_str: str, target_url: str) -> list[dict]:
    """把 'name1=val1; name2=val2' 字符串解析为 Playwright add_cookies 需要的格式。

    ★ domain 策略：对于多级子域（如 my.feishu.cn），使用父域（.feishu.cn）作为 cookie domain，
    确保浏览器在访问同域下的其他子域 API 时也能带上 Cookie（飞书、企业微信等 SaaS 平台
    的认证依赖跨子域 Cookie 传递）。
    对于 IP 地址或二级域名（如 example.com），直接使用原始 host。

    Returns:
        [{"name": "...", "value": "...", "domain": "...", "path": "/"}]
    """
    from urllib.parse import urlparse
    if not cookie_str or not target_url:
        return []
    try:
        host = urlparse(target_url).hostname or ""
    except Exception:
        host = ""
    if not host:
        return []

    # ★ 计算 cookie domain：多级子域用父域，确保跨子域 API 请求能带上 Cookie
    domain = _compute_cookie_domain(host)

    cookies = []
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        cookies.append({
            "name": name,
            "value": value,
            "domain": domain,
            "path": "/",
        })
    return cookies


def _compute_cookie_domain(host: str) -> str:
    """根据主机名计算 Cookie 应该设置的 domain。

    规则：
    - IP 地址 → 原样返回（如 192.168.1.1）
    - 二级域名（如 example.com）→ 原样返回
    - 三级及以上子域（如 my.feishu.cn、app.example.co.uk）→ 返回父域（.feishu.cn、.example.co.uk）
      以便 Cookie 能跨子域生效

    常见双后缀 TLD（如 .co.uk, .com.cn）会被正确处理。
    """
    import re

    # IP 地址：直接返回
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) or ':' in host:
        return host

    parts = host.split('.')
    if len(parts) <= 2:
        # 二级域名（example.com）或更短 → 直接用
        return host

    # 常见的双后缀 TLD 列表（这些算作一个整体后缀）
    DOUBLE_TLDS = {
        'co.uk', 'co.jp', 'co.kr', 'co.nz', 'co.za', 'co.in',
        'com.cn', 'com.tw', 'com.hk', 'com.sg', 'com.au', 'com.br',
        'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
        'ac.uk', 'org.uk', 'gov.uk',
        'ne.jp', 'or.jp', 'ac.jp',
    }

    # 检查是否是双后缀 TLD
    last_two = '.'.join(parts[-2:])
    if last_two in DOUBLE_TLDS:
        # 双后缀：需要至少 4 段才算子域（如 app.example.co.uk）
        if len(parts) <= 3:
            return host  # example.co.uk → 直接用
        # app.example.co.uk → .example.co.uk
        return '.' + '.'.join(parts[-3:])
    else:
        # 普通后缀：3 段及以上就取父域
        # my.feishu.cn → .feishu.cn
        # sub.app.example.com → .app.example.com（保守策略：只去掉最左边一级）
        return '.' + '.'.join(parts[-2:])


# ============================================================
# HTTP 请求包解析（应对自定义 sign/key 等多 header 凭证场景）
# ============================================================

# Playwright/浏览器/HTTP 库会自动管理的 header，不应注入（避免冲突）
_AUTO_MANAGED_HEADERS = {
    "host", "connection", "content-length", "transfer-encoding",
    "expect", "upgrade", "proxy-connection", "te", "trailer",
    # CORS/CSP 类响应头，不应作为请求头注入
    "access-control-allow-origin", "access-control-allow-credentials",
    # Sec-Fetch-* 浏览器自动管理
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    # 编码相关浏览器自动管理
    "accept-encoding",
}

# 动态签名字段关键字（这些字段值通常随时间/参数变化，静态注入会很快失效）
_DYNAMIC_SIGNING_KEYWORDS = [
    "sign", "signature", "hmac",
    "timestamp", "ts", "time",
    "nonce", "random",
    "x-date", "date",
    "x-ca-",   # 阿里云 API 网关
    "x-tc-",   # 腾讯云
    "x-amz-",  # AWS
    "x-mse-",  # 阿里云 MSE
]


def parse_http_request_packet(text: str) -> dict | None:
    """解析用户粘贴的完整 HTTP 请求包（Burp/Chrome F12 复制格式）。

    支持格式：
        GET /api/user/profile HTTP/1.1
        Host: example.com
        Cookie: sid=abc; csrf=xyz
        Authorization: Bearer eyJ...
        X-Sign: a1b2c3
        ...
        (空行)
        <可选的请求体>

    Returns:
        None 如果不像 HTTP 请求包
        {
            "method": "GET",
            "path": "/api/user/profile",
            "host": "example.com",
            "scheme": "https",
            "url": "https://example.com/api/user/profile",
            "headers": {"Authorization": "...", "X-Sign": "...", ...},  # 已过滤掉自动管理的
            "cookies": "sid=abc; csrf=xyz",  # Cookie 字符串
            "body": "...",
            "dynamic_signing_fields": ["X-Sign", "X-Timestamp"],  # 检测到的动态字段
            "warnings": ["检测到 X-Sign 字段疑似动态签名..."],
        }
    """
    if not text or "\n" not in text:
        return None

    # 标准化换行
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()

    # ★ 在多行文本中定位"请求行"（METHOD path HTTP/x.x），跳过前置介绍文字
    request_line_re = re.compile(
        r'^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)\s+HTTP/[\d.]+\s*$',
        re.IGNORECASE | re.MULTILINE
    )
    m = request_line_re.search(text)
    if not m:
        return None
    # 截取从请求行开始的子串
    text = text[m.start():]
    lines = text.split("\n")

    # 第一行现在是请求行
    request_line_match = re.match(
        r'^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)\s+HTTP/[\d.]+\s*$',
        lines[0].strip(), re.IGNORECASE
    )
    if not request_line_match:
        return None

    method = request_line_match.group(1).upper()
    path = request_line_match.group(2)

    # 解析 headers（直到空行或 EOF）
    headers: dict[str, str] = {}
    body_start = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        headers[k] = v

    if not headers:
        return None  # 没有 header 不算 HTTP 包

    # 提取 body
    body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else ""

    # 从 Host 推导完整 URL（绝对路径优先用 path 自身）
    host = ""
    for k, v in headers.items():
        if k.lower() == "host":
            host = v.strip()
            break
    if not host and not path.startswith("http"):
        return None  # 无法构造 URL

    # 推导 scheme：path 自带协议则用 path 的，否则猜 https
    if path.startswith("http"):
        full_url = path
        from urllib.parse import urlparse as _up
        parsed = _up(full_url)
        host = parsed.hostname or host
        scheme = parsed.scheme
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    else:
        # Burp 抓 https 时常带 Origin/Referer，从中推 scheme
        scheme = "https"
        for k, v in headers.items():
            if k.lower() in ("origin", "referer") and v.startswith("http://"):
                scheme = "http"
                break
        full_url = f"{scheme}://{host}{path}"

    # 提取 Cookie 字符串（单独存）
    cookies_str = ""
    for k in list(headers.keys()):
        if k.lower() == "cookie":
            cookies_str = headers.pop(k).strip()
            break

    # 过滤自动管理的 header
    clean_headers = {}
    for k, v in headers.items():
        if k.lower() in _AUTO_MANAGED_HEADERS:
            continue
        clean_headers[k] = v

    # 检测动态签名字段
    dynamic_fields = []
    for k in clean_headers.keys():
        kl = k.lower()
        if any(kw in kl for kw in _DYNAMIC_SIGNING_KEYWORDS):
            dynamic_fields.append(k)

    warnings = []
    if dynamic_fields:
        warnings.append(
            f"检测到 {len(dynamic_fields)} 个疑似动态签名字段: {', '.join(dynamic_fields)}。"
            "这些字段值通常每次请求会变（时间戳/HMAC/nonce），静态注入可能登录态保持几分钟后失效。"
            "如长时间测试失败，建议: ①刷新更近的请求包重新导入；②启用 CryptoHook 抓取 JS 签名函数；③只测静态 GET 接口。"
        )

    return {
        "method": method,
        "path": path,
        "host": host,
        "scheme": scheme,
        "url": full_url,
        "headers": clean_headers,
        "cookies": cookies_str,
        "body": body,
        "dynamic_signing_fields": dynamic_fields,
        "warnings": warnings,
    }


def has_http_request_packet(text: str) -> bool:
    """快速检测一段文本里是否包含 HTTP 请求包（用于在自由聊天里识别）。"""
    if not text:
        return False
    # 至少要看到 "METHOD /xxx HTTP/x.x" 这样一行
    return bool(re.search(
        r'^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\S+\s+HTTP/[\d.]+\s*$',
        text, re.MULTILINE | re.IGNORECASE
    ))


def _looks_like_curl(text: str) -> bool:
    """检测文本中是否包含 cURL 命令。"""
    if not text:
        return False
    return bool(re.search(r'\bcurl\s+(?:[\'"]?https?://|-[XHd\b])', text, re.IGNORECASE))


def parse_curl_command(text: str) -> dict | None:
    """解析 cURL 命令，返回与 parse_http_request_packet 同结构的 dict。

    支持：
    - curl 'https://...' -H 'K: V' -H "K: V" --data 'body'
    - 多行命令（行末有 \\）
    """
    if not text:
        return None
    # 标准化：去掉行末 \、合并多行为单行
    text = re.sub(r'\\\s*\n', ' ', text).strip()

    # 提取 URL：第一个 http(s) 开头的 token
    url = ""
    url_match = re.search(r"""(?:^|\s)['"]?(https?://[^\s'"]+)['"]?""", text)
    if url_match:
        url = url_match.group(1)
    if not url:
        return None

    # 提取所有 -H "K: V" 或 -H 'K: V' 或 -H K:V
    headers: dict[str, str] = {}
    # 引号包裹
    for m in re.finditer(r"""-H\s+['"]([^'":]+?):\s*([^'"]*?)['"]""", text):
        headers[m.group(1).strip()] = m.group(2).strip()
    # 无引号（简单情况）
    for m in re.finditer(r"""-H\s+([A-Za-z][\w-]+):\s*([^\s-][^\s]*)""", text):
        k = m.group(1).strip()
        if k not in headers:
            headers[k] = m.group(2).strip()

    # body
    body = ""
    method = "GET"
    body_match = re.search(r"""(?:--data(?:-raw|-binary)?|-d)\s+['"]([^'"]*)['"]""", text)
    if body_match:
        body = body_match.group(1)
        method = "POST"
    method_match = re.search(r"""-X\s+([A-Z]+)""", text)
    if method_match:
        method = method_match.group(1)

    # 从 URL 解析 host / scheme / path
    try:
        from urllib.parse import urlparse as _up
        parsed = _up(url)
        host = parsed.hostname or ""
        scheme = parsed.scheme or "https"
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        if parsed.port:
            host = f"{host}:{parsed.port}"
    except Exception:
        return None
    if not host:
        return None

    # 提取 Cookie 字符串（从 headers 中单独拿出）
    cookies_str = ""
    for k in list(headers.keys()):
        if k.lower() == "cookie":
            cookies_str = headers.pop(k).strip()
            break

    # 过滤自动管理的 header
    clean_headers = {}
    for k, v in headers.items():
        if k.lower() in _AUTO_MANAGED_HEADERS:
            continue
        clean_headers[k] = v

    # 检测动态签名字段
    dynamic_fields = []
    for k in clean_headers.keys():
        kl = k.lower()
        if any(kw in kl for kw in _DYNAMIC_SIGNING_KEYWORDS):
            dynamic_fields.append(k)

    warnings = []
    if dynamic_fields:
        warnings.append(
            f"检测到 {len(dynamic_fields)} 个疑似动态签名字段: {', '.join(dynamic_fields)}。"
            "这些字段值通常每次请求会变（时间戳/HMAC/nonce），静态注入可能登录态保持几分钟后失效。"
            "如长时间测试失败，建议: ①刷新更近的请求包重新导入；②启用 CryptoHook 抓取 JS 签名函数；③只测静态 GET 接口。"
        )

    return {
        "method": method,
        "path": path,
        "host": host,
        "scheme": scheme,
        "url": url,
        "headers": clean_headers,
        "cookies": cookies_str,
        "body": body,
        "dynamic_signing_fields": dynamic_fields,
        "warnings": warnings,
    }
