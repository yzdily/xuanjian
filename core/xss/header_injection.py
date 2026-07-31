"""
Header / Cookie / Referer / UA 注入目标生成器 — P0 关键差异化能力。

真实赏金 XSS 中相当一部分来自非 URL/Body 参数：
- Referer 反射（错误页/统计页/登录页常见）
- User-Agent 反射（管理后台日志页、debug 页）
- X-Forwarded-For 反射（管理员 IP 显示页）
- Origin / Host 反射（CORS 调试页）
- Cookie 反射（个性化页面常带 cookie 值）
- 自定义业务 header（X-Request-ID、X-Tenant、X-Locale）反射

策略：
1. 对每个已发现的 GET 端点，自动生成 Header 注入目标
2. 优先级排序：常见反射 header 优先
3. 不暴力 fuzz 太多（防扫描器请求量爆炸），每端点最多 N 个 header
"""

from __future__ import annotations

from urllib.parse import urlparse

from core.xss.models import InjectionPoint, InjectionTarget

# ============================================================
# 常见可注入 Header — 按反射可能性排序
# ============================================================
COMMON_REFLECTABLE_HEADERS = [
    # Tier 1: 最常见反射
    "Referer",
    "User-Agent",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    # Tier 2: 后台/管理常见
    "X-Requested-With",
    "Origin",
    "X-Forwarded-Proto",
    "X-Forwarded-For-Original",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Client-IP",
    # Tier 3: 多租户/i18n
    "Accept-Language",
    "X-Tenant",
    "X-Tenant-ID",
    "X-Locale",
    "X-Request-ID",
    "X-Trace-ID",
    "X-Correlation-ID",
    # Tier 4: 调试/内部
    "X-Debug",
    "X-Forwarded-Server",
    "Via",
    "From",
]


def generate_header_injection_targets(
    sitemap,
    max_endpoints: int = 80,
    headers_per_endpoint: int = 10,
) -> list[InjectionTarget]:
    """对 sitemap 中的所有 GET 端点生成 Header 注入目标。

    去重策略：每个 hostname+path 只测一次 Header（不需要每参数变体都测）。
    """
    targets: list[InjectionTarget] = []
    seen_paths: set[str] = set()

    # 1. 从 api_samples 提取（有完整 header 上下文）
    samples = getattr(sitemap, "api_samples", {}) or {}
    endpoint_pool: list[tuple[str, str, dict]] = []  # (url, method, headers)

    for sample in samples.values():
        if not isinstance(sample, dict):
            continue
        url = sample.get("url", "")
        method = (sample.get("method", "GET") or "GET").upper()
        if not url or method != "GET":  # Header 注入主要测 GET（POST 也有但优先级低）
            continue
        parsed = urlparse(url)
        key = f"{parsed.netloc}{parsed.path}"
        if key in seen_paths:
            continue
        seen_paths.add(key)
        endpoint_pool.append((url, method, sample.get("request_headers", {}) or {}))
        if len(endpoint_pool) >= max_endpoints:
            break

    # 2. 从 sitemap.apis 补充
    if len(endpoint_pool) < max_endpoints:
        apis = getattr(sitemap, "apis", {}) or {}
        for api_key, api_info in apis.items():
            if hasattr(api_info, "url"):
                url = getattr(api_info, "url", "")
                method = (getattr(api_info, "method", "GET") or "GET").upper()
            elif isinstance(api_info, dict):
                url = api_info.get("url", "")
                method = (api_info.get("method", "GET") or "GET").upper()
            else:
                continue
            if not url:
                parts = api_key.split(" ", 1)
                if len(parts) == 2:
                    method, url = parts
                    method = method.upper()
            if not url or method != "GET":
                continue
            parsed = urlparse(url)
            key = f"{parsed.netloc}{parsed.path}"
            if key in seen_paths:
                continue
            seen_paths.add(key)
            endpoint_pool.append((url, method, {}))
            if len(endpoint_pool) >= max_endpoints:
                break

    # 3. 同时也从 pages（HTML 页面 URL）提取
    if len(endpoint_pool) < max_endpoints:
        pages = getattr(sitemap, "pages", {}) or {}
        for purl in list(pages.keys())[:max_endpoints]:
            parsed = urlparse(purl)
            key = f"{parsed.netloc}{parsed.path}"
            if key in seen_paths:
                continue
            seen_paths.add(key)
            endpoint_pool.append((purl, "GET", {}))
            if len(endpoint_pool) >= max_endpoints:
                break

    # 4. 对每个端点生成 N 个 header 注入目标
    for url, method, base_headers in endpoint_pool:
        for hname in COMMON_REFLECTABLE_HEADERS[:headers_per_endpoint]:
            t = InjectionTarget(
                url=url,
                method=method,
                injection_point=InjectionPoint.HEADER,
                param_name=hname,
                original_value=base_headers.get(hname, "") or base_headers.get(hname.lower(), ""),
                headers=dict(base_headers),
            )
            targets.append(t)

    # 5. Cookie 注入目标（每个端点测 1 个 cookie 注入点）
    cookies_seen: set[str] = set()
    for url, method, base_headers in endpoint_pool[:30]:
        # 从已有 cookie 中找名字（不发新 cookie，避免破坏会话）
        cookie_header = base_headers.get("Cookie", "") or base_headers.get("cookie", "")
        if cookie_header:
            for pair in cookie_header.split(";"):
                if "=" in pair:
                    cname = pair.split("=", 1)[0].strip()
                    if cname and cname not in cookies_seen and len(cname) < 30:
                        cookies_seen.add(cname)
                        targets.append(InjectionTarget(
                            url=url,
                            method=method,
                            injection_point=InjectionPoint.COOKIE,
                            param_name=cname,
                            original_value=pair.split("=", 1)[1].strip(),
                            headers=dict(base_headers),
                        ))

    return targets
