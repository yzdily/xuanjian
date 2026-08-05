"""
mitmproxy addon — 记录所有经过代理的 HTTP 流量

由 start.py 启动：mitmdump -s mcp_servers/mitm_addon.py -p 18080
记录到 PROXY_FLOW_FILE 指定的 JSONL 文件，由 proxy_mcp.py 读取。

★ TLS 透传策略：
  - 只对目标域名做 HTTPS 中间人解密（抓取 API 流量）
  - 对 CDN / 第三方域名做 TLS 透传（不解密），避免 CDN 检测到
    mitmproxy 的 TLS 指纹后返回 403，导致 JS/CSS 无法加载。
"""

import json
import time
import uuid
import os
import re
import gzip
import zlib
import logging

from mitmproxy import tls
from core.config import MAX_RESPONSE_BODY_SIZE


FLOW_FILE = os.getenv("PROXY_FLOW_FILE", "/tmp/pentest_agent_flows.jsonl")

# ============================================================
# TLS 透传配置
# ============================================================

# 目标域名（只有这些域名会被 HTTPS 中间人解密）
# 通过环境变量 MITM_TARGET_HOSTS 设置，多个域名用逗号分隔
# 例如: "crm.na1.insightly.com,api.na1.insightly.com,login.insightly.com"
# 如果未设置，则默认对所有域名做中间人（保持原有行为）
_TARGET_HOSTS_RAW = os.getenv("MITM_TARGET_HOSTS", "")

# 需要透传（不解密）的第三方域名正则列表
# 这些域名的 TLS 流量会直接转发，不做中间人
_PASSTHROUGH_PATTERNS = [
    # CDN
    r".*\.cloudfront\.net$",
    r".*\.cloudflare\.com$",
    r".*\.akamaized\.net$",
    r".*\.fastly\.net$",
    r".*\.cdn\..+$",
    # Google 服务
    r".*\.google\.com$",
    r".*\.googleapis\.com$",
    r".*\.gstatic\.com$",
    r".*\.googletagmanager\.com$",
    r".*\.google-analytics\.com$",
    r"android\.clients\.google\.com$",
    # 第三方分析/监控
    r".*\.pendo\.io$",
    r".*\.raygun\.io$",
    r".*\.sentry\.io$",
    r".*\.newrelic\.com$",
    r".*\.segment\.com$",
    r".*\.mixpanel\.com$",
    r".*\.hotjar\.com$",
    r".*\.fullstory\.com$",
    r".*\.customer\.io$",
    r".*\.intercom\.io$",
    r".*\.hubspot\.com$",
    # 字体/静态资源
    r"fonts\.googleapis\.com$",
    r"fonts\.gstatic\.com$",
    r"use\.fontawesome\.com$",
    # 社交/登录
    r".*\.facebook\.com$",
    r".*\.twitter\.com$",
    r".*\.linkedin\.com$",
]

_PASSTHROUGH_COMPILED = [re.compile(p, re.IGNORECASE) for p in _PASSTHROUGH_PATTERNS]


def _should_passthrough(hostname: str) -> bool:
    """判断该域名是否应该 TLS 透传（不做中间人解密）。
    
    策略：
    1. 如果设置了 MITM_TARGET_HOSTS，只对目标域名做中间人，其余全部透传
    2. 如果未设置，则对 _PASSTHROUGH_PATTERNS 中的域名透传，其余做中间人
    """
    if _TARGET_HOSTS_RAW:
        # 白名单模式：只有目标域名做中间人
        target_hosts = [h.strip().lower() for h in _TARGET_HOSTS_RAW.split(",") if h.strip()]
        hostname_lower = hostname.lower()
        for target in target_hosts:
            # 支持通配符匹配：*.insightly.com 匹配 crm.na1.insightly.com
            if target.startswith("*."):
                suffix = target[1:]  # .insightly.com
                if hostname_lower.endswith(suffix) or hostname_lower == target[2:]:
                    return False  # 目标域名，不透传
            elif hostname_lower == target:
                return False  # 精确匹配目标域名，不透传
        return True  # 非目标域名，透传
    else:
        # 黑名单模式：只对已知第三方域名透传
        for pattern in _PASSTHROUGH_COMPILED:
            if pattern.match(hostname):
                return True
        return False


def _get_response_body(flow):
    """安全提取响应体：先解压 gzip/deflate，再解码文本。"""
    if not flow.response:
        return ""
    content = flow.response.content
    if not content:
        return ""

    # 1) 解压
    ce = flow.response.headers.get("content-encoding", "").lower()
    try:
        if "gzip" in ce:
            content = gzip.decompress(content)
        elif "deflate" in ce:
            content = zlib.decompress(content)
    except Exception as e:
        logging.debug("响应体解压失败: %s (url=%s)", e, flow.request.pretty_url[:100])

    # 2) 解码（优先用 charset，否则 utf-8 + replace）
    try:
        ct = flow.response.headers.get("content-type", "")
        charset = None
        if "charset=" in ct:
            charset = ct.split("charset=")[-1].split(";")[0].strip().strip('"').strip("'")
        if charset:
            return content.decode(charset, errors="replace")[:MAX_RESPONSE_BODY_SIZE]
        return content.decode("utf-8", errors="replace")[:MAX_RESPONSE_BODY_SIZE]
    except Exception as e:
        logging.debug("响应体解码失败: %s (url=%s)", e, flow.request.pretty_url[:100])
        return ""

# 忽略的静态资源后缀
IGNORE_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map",
}

# 忽略的 Content-Type
IGNORE_CONTENT_TYPES = {
    "image/", "font/", "text/css", "application/javascript",
}


class TlsPassthrough:
    """TLS 透传：对非目标域名不做 HTTPS 中间人解密。
    
    这样 CDN 上的 JS/CSS 资源能正常加载（避免 CDN 检测 TLS 指纹后 403），
    同时目标站点的 API 流量仍然能被完整抓取和分析。
    """

    def tls_clienthello(self, data: tls.ClientHelloData):
        """在 TLS 握手阶段决定是否透传。
        
        优先使用 ClientHello 中的 SNI 扩展获取目标域名，
        这比 server.address 更可靠（后者在此阶段可能为 None）。
        """
        # 优先从 SNI 获取域名
        hostname = data.client_hello.sni
        
        # 如果 SNI 为空，尝试从 server address 获取
        if not hostname:
            server_address = data.context.server.address
            if not server_address:
                return
            hostname = server_address[0] if isinstance(server_address, tuple) else str(server_address)
        
        if not hostname:
            return
        
        if _should_passthrough(hostname):
            # 设置 ignore_connection = True，让 mitmproxy 直接透传 TLS 流量
            data.ignore_connection = True
            logging.debug(f"[TLS透传] {hostname}")


class FlowRecorder:
    """记录 HTTP 请求/响应到 JSONL 文件。"""

    def response(self, flow):
        # 跳过静态资源
        url = flow.request.pretty_url
        path = flow.request.path.split("?")[0].lower()
        if any(path.endswith(ext) for ext in IGNORE_EXTENSIONS):
            return

        # 跳过特定 Content-Type
        ct = flow.response.headers.get("content-type", "") if flow.response else ""
        if any(ct.startswith(ignore) for ignore in IGNORE_CONTENT_TYPES):
            return

        # ★ 跳过 XSS 扫描探测流量（参数值含 xPmInE9 marker）
        if "xPmInE9" in flow.request.pretty_url:
            return
        request_body_raw = ""
        try:
            request_body_raw = flow.request.get_text() or ""
        except Exception:
            pass
        if "xPmInE9" in request_body_raw:
            return

        # 获取请求体
        request_body = request_body_raw

        # 获取响应体（限制大小）
        response_body = _get_response_body(flow)[:10000]

        record = {
            "id": f"flow_{uuid.uuid4().hex[:8]}",
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": url,
            "request_headers": dict(flow.request.headers),
            "request_body": request_body,
            "status_code": flow.response.status_code if flow.response else 0,
            "response_headers": dict(flow.response.headers) if flow.response else {},
            "response_body": response_body,
            "content_type": ct,
        }

        try:
            with open(FLOW_FILE, "a") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            logging.warning("流量记录写入失败: %s (url=%s)", e, url[:100])


addons = [TlsPassthrough(), FlowRecorder()]
