"""
Proxy MCP — mitmproxy 流量拦截/分析/改包/重放服务

这是整个系统的心脏：等同于自动化的 Burp Suite。
- 拦截并记录所有经过代理的 HTTP 请求/响应
- 支持按条件过滤流量
- 支持修改参数重放（Repeater）
- 支持对比两个响应差异（越权检测）
"""

from __future__ import annotations

import os
import json
import time
import uuid
import asyncio
import contextvars
import httpx
import ipaddress
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlparse
from mcp.server.fastmcp import FastMCP

from core.config import (
    MAX_RESPONSE_BODY_SIZE,
    DEFAULT_HTTP_TIMEOUT,
    MAX_ERROR_MESSAGE_SIZE,
)

# ★ 2026-05-29: 用 contextvars 传递当前 task_id，让流量持久化时能标记归属任务
_current_task_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_current_task_id", default=""
)

mcp = FastMCP("proxy")

# ============================================================
# 流量存储（内存 + 可选持久化）
# ============================================================

@dataclass
class FlowRecord:
    id: str
    timestamp: float
    method: str
    url: str
    request_headers: dict
    request_body: str
    status_code: int
    response_headers: dict
    response_body: str
    content_type: str = ""

    def summary(self) -> str:
        """精简摘要：只保留 LLM 需要的核心信息，不输出 body 预览。"""
        return f"[{self.id}] {self.method} {self.url} → {self.status_code} ({self.content_type.split(';')[0]})"


class FlowStore:
    """流量记录存储。"""

    def __init__(self, max_size: int = 1000):
        self.flows: dict[str, FlowRecord] = {}
        self._order: list[str] = []
        self.max_size = max_size

    def add(self, flow: FlowRecord) -> None:
        # ★ 2026-05-22: 防重入（避免 _load_new_flows 把文件里的旧 flow 再次走 add 时重复写文件）
        is_new = flow.id not in self.flows
        self.flows[flow.id] = flow
        if is_new:
            self._order.append(flow.id)
            # ★ 主动持久化到 flows.jsonl，让 PoC 流量也能被流量管理/报告/补测Agent 读取
            # 仅持久化「主动构造类」流量（custom_/replay_/batch_），不持久化「已经从文件读回」的 flow_
            if flow.id.startswith(("custom_", "replay_", "batch_")):
                _persist_flow_to_file(flow)
        # 溢出清理
        while len(self._order) > self.max_size:
            old_id = self._order.pop(0)
            self.flows.pop(old_id, None)

    def get(self, flow_id: str) -> FlowRecord | None:
        return self.flows.get(flow_id)

    def recent(self, limit: int = 20) -> list[FlowRecord]:
        ids = self._order[-limit:]
        return [self.flows[fid] for fid in ids if fid in self.flows]

    def search(self, keyword: str) -> list[FlowRecord]:
        kw = keyword.lower()
        return [f for f in self.flows.values() if kw in f.url.lower() or kw in f.request_body.lower() or kw in f.response_body.lower()]


_store = FlowStore()


# ============================================================
# 流量持久化（2026-05-22 新增）
# ------------------------------------------------------------
# 历史问题：proxy_send_request / proxy_replay / proxy_batch_send 产生的流量
# 仅写入内存 FlowStore，不写文件，导致：
#   1. 流量管理页面看不到 PoC 流量（页面读 flows.jsonl + sitemap）
#   2. 重启服务后所有 PoC 流量永久丢失
#   3. Phase 2.6 危害验证、报告生成读不到完整证据链
#
# 修复：所有进入 _store 的「主动构造类」flow 都顺便 append 一份到 flows.jsonl
# 与 mitm_addon.py 写入同一个文件、同一种 schema，packet_merger 可统一读取。
# ============================================================
def _persist_flow_to_file(flow: FlowRecord) -> None:
    """把 FlowRecord 追加到 flows.jsonl（与 mitm_addon 共用文件）。

    失败静默：流量持久化不应阻塞主请求逻辑。
    """
    import logging
    _log = logging.getLogger("proxy")
    
    flow_file = os.getenv(
        "PROXY_FLOW_FILE",
        str(Path(__file__).parent.parent / "data" / "pentest_agent_flows.jsonl"),
    )
    try:
        # ★ 从 contextvars 获取当前 task_id（由 ToolExecutor 在调用前设置）
        task_id = _current_task_id.get("")
        record = {
            "id": flow.id,
            "timestamp": flow.timestamp,
            "method": flow.method,
            "url": flow.url,
            "request_headers": flow.request_headers,
            "request_body": flow.request_body,
            "status_code": flow.status_code,
            "response_headers": flow.response_headers,
            "response_body": flow.response_body,
            "content_type": flow.content_type,
        }
        if task_id:
            record["task_id"] = task_id
        # 父目录不存在就建（首次启动可能没有 data/ 目录）
        Path(flow_file).parent.mkdir(parents=True, exist_ok=True)
        with open(flow_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        # 永远不要让持久化失败影响业务调用
        _log.warning("流量持久化失败: %s (flow_id=%s)", e, flow.id)

# ============================================================
# mitmproxy addon（在独立进程中运行）
# ============================================================

MITM_ADDON_CODE = '''
"""mitmproxy addon：记录流量到共享文件（由 proxy_mcp 读取）。"""
import json, time, uuid, os, gzip, zlib

FLOW_FILE = os.getenv("PROXY_FLOW_FILE", "/tmp/pentest_agent_flows.jsonl")

def _get_response_body(flow):
    """安全提取响应体：先解压 gzip/deflate，再解码文本。"""
    if not flow.response:
        return ""
    content = flow.response.content
    if not content:
        return ""
    ce = flow.response.headers.get("content-encoding", "").lower()
    try:
        if "gzip" in ce:
            content = gzip.decompress(content)
        elif "deflate" in ce:
            content = zlib.decompress(content)
    except Exception:
        pass
    try:
        ct = flow.response.headers.get("content-type", "")
        charset = None
        if "charset=" in ct:
            charset = ct.split("charset=")[-1].split(";")[0].strip().strip('"').strip("'")
        if charset:
            return content.decode(charset, errors="replace")[:MAX_RESPONSE_BODY_SIZE]
        return content.decode("utf-8", errors="replace")[:MAX_RESPONSE_BODY_SIZE]
    except Exception:
        return ""

class FlowRecorder:
    def response(self, flow):
        record = {
            "id": f"flow_{uuid.uuid4().hex[:8]}",
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": dict(flow.request.headers),
            "request_body": flow.request.get_text() or "",
            "status_code": flow.response.status_code,
            "response_headers": dict(flow.response.headers),
            "response_body": _get_response_body(flow)[:MAX_RESPONSE_BODY_SIZE],
            "content_type": flow.response.headers.get("content-type", "") if flow.response else "",
        }
        with open(FLOW_FILE, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\\n")

addons = [FlowRecorder()]
'''


_last_read_pos = 0  # 文件读取偏移量

def _load_new_flows():
    """从 mitmproxy 的共享文件加载新流量（增量读取，不清空文件）。"""
    global _last_read_pos
    flow_file = os.getenv("PROXY_FLOW_FILE", "/tmp/pentest_agent_flows.jsonl")
    if not os.path.exists(flow_file):
        return
    try:
        file_size = os.path.getsize(flow_file)
        # 文件被重写/清空时，重置偏移量
        if file_size < _last_read_pos:
            _last_read_pos = 0
        with open(flow_file, "r") as f:
            f.seek(_last_read_pos)
            new_lines = f.readlines()
            _last_read_pos = f.tell()
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                flow = FlowRecord(**data)
                _store.add(flow)
            except Exception as e:
                import logging
                logging.getLogger("proxy").warning("流量记录解析失败: %s (line=%.50s)", e, line)
    except Exception as e:
        import logging
        logging.getLogger("proxy").warning("加载新流量失败: %s", e)


# ============================================================
# MCP Tools
# ============================================================

@mcp.tool()
async def proxy_get_traffic(limit: int = 20, filter_keyword: str = "") -> str:
    """获取最近的 HTTP 流量记录（精简模式）。
    - limit: 返回最近 N 条
    - filter_keyword: 可选过滤关键词（匹配 URL 或 Body）
    用 proxy_get_flow_detail(flow_id) 查看具体某条的完整详情。
    """
    _load_new_flows()

    if filter_keyword:
        flows = _store.search(filter_keyword)[-limit:]
    else:
        flows = _store.recent(limit)

    if not flows:
        return "暂无流量记录。请先用浏览器访问目标网站。"

    # RTK Grouping: 按状态码分组，相同 URL+Method 去重折叠
    from collections import OrderedDict
    groups: dict[int, list] = {}
    seen: dict[str, int] = {}  # "METHOD url" → 出现次数

    for f in flows:
        key = f"{f.method} {f.url}"
        if key in seen:
            seen[key] += 1
            continue
        seen[key] = 1
        sc = f.status_code
        groups.setdefault(sc, []).append(f)

    output = [f"共 {len(flows)} 条记录（去重后 {sum(len(v) for v in groups.values())} 条）:\n"]

    # RTK Deduplication: 折叠重复请求
    dupes = {k: v for k, v in seen.items() if v > 1}
    if dupes:
        output.append(f"重复请求已折叠: {', '.join(f'{k}(×{v})' for k, v in dupes.items())}\n")

    for sc in sorted(groups.keys()):
        flist = groups[sc]
        output.append(f"--- {sc} ({len(flist)} 条) ---")
        for f in flist:
            output.append(f.summary())

    return "\n".join(output)


@mcp.tool()
async def proxy_get_flow_detail(flow_id: str) -> str:
    """获取某条流量的完整详情（安全相关 Header + Body）。"""
    _load_new_flows()
    flow = _store.get(flow_id)
    if not flow:
        return f"流量 {flow_id} 不存在"

    # RTK Smart Filtering: 只保留安全测试相关的 headers
    SECURITY_HEADERS = {
        'cookie', 'set-cookie', 'authorization', 'x-csrf-token', 'x-xsrf-token',
        'content-type', 'location', 'www-authenticate', 'access-control-allow-origin',
        'access-control-allow-credentials', 'access-control-allow-methods',
        'x-frame-options', 'content-security-policy', 'strict-transport-security',
        'x-content-type-options', 'x-powered-by', 'server', 'x-request-id',
        'x-forwarded-for', 'x-real-ip', 'x-api-key', 'token', 'session',
        # ★ 业务自定义认证头（常见于企业 SaaS：Sc-Id-Token、X-Auth-Token 等）
        'sc-id-token', 'sc-i18n', 'x-auth-token', 'x-access-token',
        'x-token', 'x-session-token', 'x-id-token',
    }

    def _filter_headers(headers: dict) -> dict:
        return {k: v for k, v in headers.items() if k.lower() in SECURITY_HEADERS}

    req_headers = _filter_headers(flow.request_headers)
    resp_headers = _filter_headers(flow.response_headers)

    # 截断超长 body
    resp_body = flow.response_body
    if len(resp_body) > 3000:
        resp_body = resp_body[:3000] + f"\n... (截断，共 {len(flow.response_body)} 字符)"
    req_body = flow.request_body
    if len(req_body) > 2000:
        req_body = req_body[:2000] + "\n... (截断)"

    lines = [
        f"{flow.method} {flow.url} → {flow.status_code}",
        f"\n请求 Headers (安全相关): {json.dumps(req_headers, ensure_ascii=False)}",
        f"请求 Body: {req_body or '(空)'}",
        f"\n响应 Headers (安全相关): {json.dumps(resp_headers, ensure_ascii=False)}",
        f"响应 Body ({len(flow.response_body)} chars):\n{resp_body}",
    ]
    return "\n".join(lines)


@mcp.tool()
async def proxy_replay(flow_id: str, modifications: dict | None = None,
                        drop_auth: bool = False) -> str:
    """重放一个请求，可选修改参数（= Burp Repeater）。

    modifications 格式：
    {
        "headers": {"Cookie": "new_value"},    # 修改/添加 header
        "body": {"user_id": "1002"},           # 修改 body 中的字段（自动 JSON merge）
        "body_raw": "raw body string",         # 直接替换整个 body
        "method": "PUT",                       # 修改方法
        "url": "http://..."                    # 修改 URL
    }

    ⚠️ **关于认证**：本工具会**完全继承**原始 flow 的 request_headers，包括
    其中携带的 Cookie / Authorization。也就是说，如果原始流量是登录态抓的，
    重放默认也是登录态。

    - `drop_auth=False`（默认）：保留原始所有 header
    - `drop_auth=True`：清掉原始 flow 的 Cookie / Authorization，做真正的无认证重放。
      做"未授权访问"测试时必须设为 True。
    """
    _load_new_flows()
    flow = _store.get(flow_id)
    if not flow:
        return f"流量 {flow_id} 不存在"

    method = flow.method
    url = flow.url
    headers = dict(flow.request_headers)
    body = flow.request_body

    # ★ drop_auth=True：清掉原始流量中的认证字段（在 modifications 之前，
    # 这样如果用户还想显式传 Cookie 也能在 modifications.headers 里补回）
    if drop_auth:
        for k in list(headers.keys()):
            if k.lower() in ("cookie", "authorization"):
                headers.pop(k, None)

    if modifications:
        if "method" in modifications:
            method = modifications["method"]
        if "url" in modifications:
            url = modifications["url"]
        if "headers" in modifications:
            headers.update(modifications["headers"])
        if "body" in modifications:
            # JSON merge
            try:
                original = json.loads(body) if body else {}
                body_patch = modifications["body"]
                if isinstance(body_patch, str):
                    body_patch = json.loads(body_patch)
                original.update(body_patch)
                body = json.dumps(original, ensure_ascii=False)
            except (json.JSONDecodeError, TypeError, ValueError):
                body = modifications["body"] if isinstance(modifications["body"], str) else json.dumps(modifications["body"], ensure_ascii=False)
        if "body_raw" in modifications:
            body = modifications["body_raw"]

    # SSRF 防护
    ssrf_check = _check_ssrf(url)
    if ssrf_check:
        return f"⛔ 请求被拒绝: {ssrf_check}"

    # 去掉可能冲突的 header
    headers.pop("content-length", None)
    headers.pop("Content-Length", None)

    # 发送请求
    async with httpx.AsyncClient(verify=False, timeout=DEFAULT_HTTP_TIMEOUT) as client:
        resp = await client.request(method=method, url=url, headers=headers, content=body)

    # 记录新流量
    new_flow = FlowRecord(
        id=f"replay_{uuid.uuid4().hex[:8]}",
        timestamp=time.time(),
        method=method,
        url=url,
        request_headers=headers,
        request_body=body,
        status_code=resp.status_code,
        response_headers=dict(resp.headers),
        response_body=resp.text[:MAX_RESPONSE_BODY_SIZE],
        content_type=resp.headers.get("content-type", ""),
    )
    _store.add(new_flow)

    return (
        f"重放结果 [{new_flow.id}]:\n"
        f"  {method} {url} → {resp.status_code}\n"
        f"  Response ({len(resp.text)} chars):\n{resp.text[:MAX_ERROR_MESSAGE_SIZE]}"
    )


def _build_auth_headers() -> dict:
    """从环境变量构建认证头（用户输入的数据包提取的 Cookie/Token/自定义头）。

    所有通过 proxy_send_request / proxy_batch_send / proxy_replay 发出的请求
    都会自动带上这些头，LLM 不需要每次手动拼——用户给了数据包就代表"所有请求都用这个身份"。
    """
    headers: dict = {}
    inject_cookies = os.getenv("PENTEST_INJECT_COOKIES", "")
    inject_auth = os.getenv("PENTEST_INJECT_AUTH", "")
    inject_headers_json = os.getenv("PENTEST_INJECT_HEADERS", "")

    # 自定义头（X-Csrf-Token / X-Sign / X-Tenant 等）
    if inject_headers_json:
        try:
            custom = json.loads(inject_headers_json)
            if isinstance(custom, dict):
                for k, v in custom.items():
                    if isinstance(k, str) and isinstance(v, (str, int, float)):
                        headers[k] = str(v)
        except Exception as e:
            import logging
            logging.getLogger("proxy").warning("PENTEST_INJECT_HEADERS JSON 解析失败: %s", e)

    # Cookie
    if inject_cookies:
        headers["Cookie"] = inject_cookies

    # Authorization
    if inject_auth:
        headers["Authorization"] = inject_auth

    return headers


def _check_ssrf(url: str) -> str | None:
    """检查 URL 是否指向内网/云元数据等危险地址。返回 None=安全，否则返回拒绝原因。"""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return "无效的 URL：缺少主机名"
        
        # 云元数据地址（AWS/GCP/Azure/阿里云）
        CLOUD_METADATA_HOSTS = [
            "169.254.169.254",  # AWS/GCP/Azure
            "metadata.google.internal",
            "metadata.azure.internal",
            "100.100.100.100",  # 阿里云
        ]
        if host in CLOUD_METADATA_HOSTS:
            return f"禁止访问云元数据地址: {host}"
        
        # 内网 IP 段
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                # 检查是否允许访问内网（从环境变量配置）
                ssrf_allow_private = os.getenv("SSRF_ALLOW_PRIVATE", "false").lower() == "true"
                if not ssrf_allow_private:
                    return f"禁止访问内网地址: {host}"
        except ValueError:
            # 不是 IP，可能是域名，尝试 DNS 解析后检查
            # 这里暂时跳过域名检查，实际生产环境应进行 DNS 解析后检查
            pass
        
        # file:// 协议
        if parsed.scheme == "file":
            return "禁止使用 file:// 协议"
        
        return None  # 安全
    except Exception as e:
        return f"URL 解析失败: {e}"


@mcp.tool()
async def proxy_send_request(method: str, url: str, headers: dict | None = None,
                              body: str = "", drop_auth: bool = False) -> str:
    """发送一个自定义 HTTP 请求（= Burp Repeater 手动构造）。

    ⚠️ **关于认证（重要）**：本工具默认会**自动注入**用户在任务开始时提供的全局 Cookie /
    Authorization / 自定义 Header（来自 PENTEST_INJECT_* 环境变量），这意味着即使你
    `headers` 参数留空，请求**仍然会带认证**。

    - `drop_auth=False`（默认）：自动带认证，适合大多数测试场景
    - `drop_auth=True`：**完全不注入**任何全局认证头，请求真正以匿名身份发出。
      做"未授权访问"测试时**必须**设置为 True，否则你看到的"200 响应"其实是认证态下的结果。

    你也可以在 `headers` 中显式传 `{"Cookie": "", "Authorization": ""}` 来覆盖全局注入，
    但 `drop_auth=True` 是更明确、更不容易出错的方式。
    """
    # SSRF 防护
    ssrf_check = _check_ssrf(url)
    if ssrf_check:
        return f"⛔ 请求被拒绝: {ssrf_check}"

    # ★ 认证头处理：
    #   - drop_auth=True → 完全不注入全局认证（真正的无认证请求）
    #   - drop_auth=False → 注入全局认证头，再被 headers 参数覆盖
    if drop_auth:
        final_headers = dict(headers) if headers else {}
        # 同时清掉用户可能在 headers 里手抖传进来的认证字段
        for k in list(final_headers.keys()):
            if k.lower() in ("cookie", "authorization"):
                final_headers.pop(k, None)
    else:
        final_headers = _build_auth_headers()
        if headers:
            final_headers.update(headers)

    # ★ 使用 curl_cffi 模拟真实 Chrome TLS 指纹（绕过 Akamai/Cloudflare 等 WAF）
    # fallback 到 httpx（curl_cffi 未安装时）
    try:
        try:
            from curl_cffi.requests import AsyncSession
            async with AsyncSession(impersonate="chrome131", verify=False, timeout=DEFAULT_HTTP_TIMEOUT) as client:
                resp = await client.request(method=method, url=url, headers=final_headers,
                                            data=body.encode() if body else None)
                resp_status = resp.status_code
                resp_headers = dict(resp.headers)
                resp_text = resp.text[:MAX_RESPONSE_BODY_SIZE] if resp.text else ""
        except ImportError:
            async with httpx.AsyncClient(verify=False, timeout=DEFAULT_HTTP_TIMEOUT) as client:
                resp = await client.request(method=method, url=url, headers=final_headers, content=body or None)
                resp_status = resp.status_code
                resp_headers = dict(resp.headers)
                resp_text = resp.text[:MAX_RESPONSE_BODY_SIZE]
    except Exception as net_err:
        # 网络层错误（DNS/连接/超时/TLS）一律转成结构化字符串返回，
        # 不要抛 traceback 把整个 tool 调用打死 —— Agent 需要拿到反馈才能换策略。
        err_str = str(net_err)
        err_type = type(net_err).__name__
        hint = ""
        low = err_str.lower()
        if "could not resolve host" in low or "name or service not known" in low or "dns" in err_type.lower():
            hint = (
                "\n💡 提示：DNS 解析失败。可能原因：\n"
                "  1) 该域名在国内被墙，需要配置上游代理（V2Ray/Clash 的 HTTP 端口）\n"
                "  2) 子域名拼写错误或不存在\n"
                "  3) 本机 DNS 异常，可尝试切换到 8.8.8.8 / 1.1.1.1"
            )
        elif "timed out" in low or "timeout" in low:
            hint = "\n💡 提示：连接超时。目标可能不可达或需要代理。"
        elif "connection refused" in low or "connection reset" in low:
            hint = "\n💡 提示：连接被拒/重置。目标端口可能关闭，或对方主动断开。"
        return f"⛔ 请求失败 [{err_type}]: {err_str}{hint}"

    new_flow = FlowRecord(
        id=f"custom_{uuid.uuid4().hex[:8]}",
        timestamp=time.time(),
        method=method,
        url=url,
        request_headers=final_headers,
        request_body=body,
        status_code=resp_status,
        response_headers=resp_headers,
        response_body=resp_text,
        content_type=resp_headers.get("content-type", ""),
    )
    _store.add(new_flow)

    return (
        f"[{new_flow.id}] {method} {url} → {resp_status}\n"
        f"Response Headers: {json.dumps(resp_headers, ensure_ascii=False)[:500]}\n"
        f"Response Body ({len(resp_text)} chars):\n{resp_text[:2000]}"
    )


@mcp.tool()
async def proxy_batch_send(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str = "",
    count: int = 10,
    variations: list[dict] | None = None,
    drop_auth: bool = False,
) -> str:
    """并发发送多个请求（用于竞态条件/并发测试）。

    类似 Turbo Intruder 的 gate 同步释放：所有请求尽量同时发出。

    参数：
    - count: 并发请求数量（默认 10，最大 50）
    - variations: 可选，每个请求的差异化参数列表。
      如 [{"body": {"coupon": "A"}}, {"body": {"coupon": "B"}}]
      未指定则所有请求完全相同（典型竞态场景）。
    - drop_auth: 同 proxy_send_request。设为 True 时本批所有请求都不带全局认证。

    ⚠️ **认证行为**与 proxy_send_request 一致：默认自动注入全局 Cookie/Authorization。
    做未授权测试时务必 `drop_auth=True`。

    返回每个请求的状态码和响应摘要，便于判断竞态是否成功。
    """
    count = min(count, 50)

    # ★ 认证头处理（drop_auth=True 时不注入全局认证）
    if drop_auth:
        base_headers = dict(headers) if headers else {}
        for k in list(base_headers.keys()):
            if k.lower() in ("cookie", "authorization"):
                base_headers.pop(k, None)
    else:
        base_headers = _build_auth_headers()
        if headers:
            base_headers.update(headers)

    async def _send_one(idx: int, client: httpx.AsyncClient) -> dict:
        req_headers = dict(base_headers)
        req_body = body

        if variations and idx < len(variations):
            v = variations[idx]
            if "headers" in v:
                req_headers.update(v["headers"])
            if "body" in v:
                try:
                    original = json.loads(req_body) if req_body else {}
                    body_patch = v["body"]
                    if isinstance(body_patch, str):
                        body_patch = json.loads(body_patch)
                    original.update(body_patch)
                    req_body = json.dumps(original, ensure_ascii=False)
                except (json.JSONDecodeError, TypeError, ValueError):
                    req_body = v["body"] if isinstance(v["body"], str) else json.dumps(v["body"], ensure_ascii=False)
            if "body_raw" in v:
                req_body = v["body_raw"]

        t0 = time.time()
        try:
            resp = await client.request(method=method, url=url, headers=req_headers,
                                        data=req_body.encode() if req_body else None)
            elapsed = time.time() - t0

            flow = FlowRecord(
                id=f"batch_{uuid.uuid4().hex[:8]}",
                timestamp=time.time(),
                method=method,
                url=url,
                request_headers=req_headers,
                request_body=req_body,
                status_code=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.text[:MAX_RESPONSE_BODY_SIZE],
                content_type=resp.headers.get("content-type", ""),
            )
            _store.add(flow)

            return {
                "idx": idx, "flow_id": flow.id, "status": resp.status_code,
                "length": len(resp.text), "time_ms": int(elapsed * 1000),
                "body_preview": resp.text[:MAX_ERROR_MESSAGE_SIZE],
            }
        except Exception as e:
            return {"idx": idx, "flow_id": None, "status": "error", "error": str(e)}

    # 使用同一个 client（连接池），尽量同时发出
    # ★ 优先 curl_cffi 模拟 Chrome TLS 指纹
    try:
        from curl_cffi.requests import AsyncSession
        async with AsyncSession(impersonate="chrome131", verify=False, timeout=DEFAULT_HTTP_TIMEOUT) as client:
            tasks = [_send_one(i, client) for i in range(count)]
            results = await asyncio.gather(*tasks)
    except ImportError:
        async with httpx.AsyncClient(verify=False, timeout=DEFAULT_HTTP_TIMEOUT) as client:
            tasks = [_send_one(i, client) for i in range(count)]
            results = await asyncio.gather(*tasks)

    # 汇总分析 — RTK Grouping + Deduplication
    status_counts: dict[int | str, int] = {}
    body_groups: dict[str, list[int]] = {}  # body_hash → [idx...]
    for r in results:
        s = r["status"]
        status_counts[s] = status_counts.get(s, 0) + 1
        # 按响应内容分组（去重检测）
        preview = r.get("body_preview", "")[:100]
        body_groups.setdefault(preview, []).append(r["idx"])

    output = [
        f"## 并发请求结果 ({count} 个请求)\n",
        f"目标: {method} {url}",
        f"状态码分布: {json.dumps(status_counts)}",
    ]

    # 竞态检测提示
    success_statuses = [s for s in status_counts if isinstance(s, int) and 200 <= s < 300]
    if success_statuses:
        total_success = sum(status_counts[s] for s in success_statuses)
        if total_success > 1:
            output.append(f"⚠️ {total_success}/{count} 个请求返回成功 — 可能存在竞态条件！")
        else:
            output.append(f"✅ 仅 1 个请求成功 — 服务端可能有正确的并发控制")

    # RTK Dedup: 相同响应折叠，只展示唯一响应
    unique_responses = len(body_groups)
    if unique_responses == 1:
        output.append(f"\n所有 {count} 个请求响应完全相同（无差异）")
        r = results[0]
        output.append(f"  代表: [{r.get('flow_id','N/A')}] {r['status']} ({r.get('length',0)} chars, {r.get('time_ms','?')}ms)")
    elif unique_responses <= 5:
        output.append(f"\n{unique_responses} 种不同响应:")
        for preview, idxs in body_groups.items():
            r = results[idxs[0]]
            output.append(f"  [{r.get('flow_id','N/A')}] {r['status']} ×{len(idxs)} — {preview[:80]}")
    else:
        # 响应差异大，只展示前 10 条
        output.append(f"\n{unique_responses} 种不同响应（展示前10条）:")
        for i, r in enumerate(results[:10]):
            output.append(f"  [{r.get('flow_id','N/A')}] #{r['idx']+1}: {r['status']} ({r.get('length',0)} chars, {r.get('time_ms','?')}ms)")

    return "\n".join(output)


@mcp.tool()
async def proxy_diff_responses(flow_id_a: str, flow_id_b: str) -> str:
    """对比两个响应的差异（核心功能：用于越权/未授权检测）。

    典型用法：
    - 用户 A 的请求 vs 用户 B 的凭据发同一请求 → 检测水平越权
    - 带 Token vs 不带 Token → 检测未授权访问
    """
    _load_new_flows()
    flow_a = _store.get(flow_id_a)
    flow_b = _store.get(flow_id_b)

    if not flow_a:
        return f"流量 {flow_id_a} 不存在"
    if not flow_b:
        return f"流量 {flow_id_b} 不存在"

    diff_lines = [
        f"## 响应对比\n",
        f"### A: [{flow_a.id}] {flow_a.method} {flow_a.url} → {flow_a.status_code}",
        f"### B: [{flow_b.id}] {flow_b.method} {flow_b.url} → {flow_b.status_code}",
        "",
    ]

    # 状态码对比
    if flow_a.status_code == flow_b.status_code:
        diff_lines.append(f"状态码相同: {flow_a.status_code}")
    else:
        diff_lines.append(f"⚠️ 状态码不同: A={flow_a.status_code} vs B={flow_b.status_code}")

    # 响应长度对比
    len_a, len_b = len(flow_a.response_body), len(flow_b.response_body)
    diff_lines.append(f"响应长度: A={len_a} vs B={len_b}")

    # 响应内容对比
    if flow_a.response_body == flow_b.response_body:
        diff_lines.append("⚠️ 响应完全相同 — 可能存在越权（同一数据用不同凭据都能访问）")
    else:
        # 找出差异行
        a_lines = flow_a.response_body[:3000].splitlines()
        b_lines = flow_b.response_body[:3000].splitlines()

        diff_lines.append("\n差异片段:")
        for i, (la, lb) in enumerate(zip(a_lines, b_lines)):
            if la != lb:
                diff_lines.append(f"  行 {i+1}:")
                diff_lines.append(f"    A: {la[:100]}")
                diff_lines.append(f"    B: {lb[:100]}")
                if len(diff_lines) > 30:
                    diff_lines.append("  ... (更多差异省略)")
                    break

    return "\n".join(diff_lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
