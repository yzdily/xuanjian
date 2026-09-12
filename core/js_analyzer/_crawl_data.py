"""JS Analyzer CDN 判定 + 爬虫数据转换 — 从 js_analyzer.py 抽取，行为不变。"""

from __future__ import annotations

from urllib.parse import urlparse

from core.log import get_logger

from ._models import JSAnalysisResult

log = get_logger("js_analyzer")

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

    # ★ WebSocket / SSE 端点
    data["js_websocket_endpoints"] = list(result.websocket_endpoints)
    data["js_sse_endpoints"] = list(result.sse_endpoints)
    data["js_base_urls"] = list(result.base_urls)
    data["js_stats"]["websocket_endpoints"] = len(result.websocket_endpoints)
    data["js_stats"]["sse_endpoints"] = len(result.sse_endpoints)
    data["js_stats"]["base_urls"] = len(result.base_urls)

    return data

# --- hoisted from js_result_to_crawl_data (A-grade, no local capture) ---
def _main_domain(h):
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h
