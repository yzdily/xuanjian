"""
存储型 XSS 跨页面追踪器 — P0 关键差异化能力。

真实赏金里 60% 以上 XSS 是存储型：
- 用户 A 提交评论/昵称/Bio → 攻击载荷被持久化
- 用户 B 访问列表页 / 详情页 / 后台审核页 → 触发执行

传统扫描器只测"提交点 + 立即响应"，错过了"提交后 → 别处回显"。

本模块工作流：
1. 收集所有"写入型"端点（POST/PUT/PATCH 含表单/JSON 字段）
2. 对每个写入点，先发"探测 marker"（不破坏数据，全字母 token）
3. 等 1-2 秒（让后端持久化）
4. 主动爬"读取型"页面（列表、详情、首页、导出、消息等）
5. 在所有响应中搜索 marker
6. 一旦发现 marker 在某读取页回显 → 该写入点有"跨页面回显路径"
7. 然后真正发"危险 payload"到该写入点 + 重新爬取读取页 + 浏览器层验证

设计：
- 仅在 sitemap 已有的端点中选择"读取页"，不主动爬新页面
- 写入点优先级：POST > PUT > PATCH（DELETE 通常不持久化）
- 探测阶段不并发太高（防止服务端限流/异常状态）
- 持久化检测：取所有 GET 页面，匹配 marker 出现
"""

from __future__ import annotations

import asyncio
import logging
import random
import string
import time
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

import httpx

from core.xss.models import (
    ContextType,
    EchoMatch,
    InjectionPoint,
    InjectionTarget,
    XssCandidate,
    XssType,
)
from core.xss.context import detect_context
from core.xss.payloads import HTML_TEXT_PAYLOADS, MARKER
from core.xss.http_engine import _gen_marker

if TYPE_CHECKING:
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)


class StoredXssTracker:
    """存储型 XSS 跨页面追踪。"""

    def __init__(
        self,
        sitemap: "Sitemap",
        proxy: str = "",
        auth_headers: dict = None,
        cookies: dict = None,
        timeout: float = 15.0,
        concurrency: int = 4,
        on_progress: Optional[callable] = None,
    ):
        self.sitemap = sitemap
        self.proxy = proxy or None
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.concurrency = concurrency
        self.on_progress = on_progress

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def discover_stored_paths(
        self, write_targets: list[InjectionTarget], max_writes: int = 30
    ) -> list[XssCandidate]:
        """主流程：发现"写入→读取"的回显路径，返回 XssCandidate 列表。"""
        if not write_targets:
            return []

        # 1. 收集读取页 URL
        read_urls = self._collect_read_urls()
        if not read_urls:
            self._report("  ⚠️ 未发现可用读取页，跳过存储型追踪")
            return []
        self._report(f"  📖 收集到 {len(read_urls)} 个读取型页面用于回显检测")

        # 2. 限制写入点数量（防过量请求）
        write_pool = write_targets[:max_writes]
        self._report(f"  📝 选定 {len(write_pool)} 个写入点进行存储型探测")

        candidates: list[XssCandidate] = []
        sem = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(
            proxy=self.proxy, timeout=self.timeout, verify=False,
            follow_redirects=False, headers=self.auth_headers, cookies=self.cookies,
            limits=httpx.Limits(max_connections=20),
        ) as client:

            async def _probe_one(wt: InjectionTarget):
                async with sem:
                    try:
                        result = await self._probe_write_to_read(client, wt, read_urls)
                        if result:
                            candidates.extend(result)
                    except Exception as e:
                        log.debug("stored probe error: %s", e)

            await asyncio.gather(*[_probe_one(t) for t in write_pool])

        self._report(f"  ✅ 存储型探测完成: 发现 {len(candidates)} 个跨页面回显候选")
        return candidates

    def _collect_read_urls(self, max_urls: int = 50) -> list[str]:
        """从 sitemap 收集"读取型"页面 URL（用于检测回显）。"""
        urls: list[str] = []
        seen: set[str] = set()

        # 1. 所有 pages（HTML 页面）
        pages = getattr(self.sitemap, "pages", {}) or {}
        for purl in pages.keys():
            if purl not in seen:
                seen.add(purl)
                urls.append(purl)
                if len(urls) >= max_urls:
                    return urls

        # 2. GET 类 API（列表/详情）
        apis = getattr(self.sitemap, "apis", {}) or {}
        for api_key, api_info in apis.items():
            if hasattr(api_info, "url"):
                url = getattr(api_info, "url", "")
                method = (getattr(api_info, "method", "GET") or "GET").upper()
            elif isinstance(api_info, dict):
                url = api_info.get("url", "")
                method = (api_info.get("method", "GET") or "GET").upper()
            else:
                continue
            if method != "GET":
                continue
            base_url = url.split("?")[0] if "?" in url else url
            if base_url not in seen:
                seen.add(base_url)
                urls.append(url)
                if len(urls) >= max_urls:
                    return urls

        return urls

    async def _probe_write_to_read(
        self,
        client: httpx.AsyncClient,
        wt: InjectionTarget,
        read_urls: list[str],
    ) -> list[XssCandidate]:
        """对一个写入点发探测 marker → 等持久化 → 在读取页查找回显。"""
        # 生成唯一 marker（带可识别前缀方便回溯）
        marker = "STORED" + _gen_marker("s")
        probe_payload = f"<x{marker}>"  # 测一下 < 是否被过滤

        # 1. 发写入请求
        try:
            success = await self._send_write(client, wt, probe_payload)
            if not success:
                return []
        except Exception:
            return []

        # 2. 等持久化
        await asyncio.sleep(1.2)

        # 3. 并发拉所有读取页，找 marker
        echo_pages: list[tuple[str, str, str]] = []  # (read_url, body_excerpt, context_around)

        async def _check_one(read_url: str):
            try:
                resp = await client.get(read_url, timeout=self.timeout)
                body = resp.text or ""
                if marker in body:
                    idx = body.find(marker)
                    excerpt = body[max(0, idx - 200): idx + len(marker) + 200]
                    echo_pages.append((read_url, body, excerpt))
            except Exception:
                pass

        # 限制读取页数量（防过量请求）
        check_pool = read_urls[:30]
        await asyncio.gather(*[_check_one(u) for u in check_pool])

        if not echo_pages:
            return []

        # 4. 发现了跨页面回显 — 现在升级到真实 XSS payload
        self._report(
            f"  🎯 跨页面回显: 写入 {wt.url[:60]} 在 {len(echo_pages)} 个读取页回显"
        )
        candidates: list[XssCandidate] = []

        # 用 2-3 个高威力 payload 重新发
        attack_payloads = HTML_TEXT_PAYLOADS[:3]
        for raw_payload in attack_payloads:
            attack_marker = "STORED" + _gen_marker("a")
            real_payload = raw_payload.replace(MARKER, attack_marker)
            try:
                await self._send_write(client, wt, real_payload)
                await asyncio.sleep(1.2)
                # 重新拉读取页
                for read_url, _, _ in echo_pages[:5]:  # 最多查前 5 个回显页
                    try:
                        resp = await client.get(read_url, timeout=self.timeout)
                        body = resp.text or ""
                        if attack_marker not in body:
                            continue
                        echo_matches = detect_context(body, attack_marker)
                        if not echo_matches:
                            continue

                        # 构造 XssCandidate（target 改成读取页 URL，标记 stored 类型）
                        # 重要：target.url 设为读取页（受害者会访问的那个），但保留写入点信息
                        cand_target = InjectionTarget(
                            url=read_url,  # 受害者访问的 URL
                            method="GET",
                            injection_point=wt.injection_point,
                            param_name=wt.param_name,
                            original_value=wt.original_value,
                            headers=dict(wt.headers or {}),
                            body_template=wt.body_template,
                            content_type=wt.content_type,
                            feature_id=wt.feature_id,
                            source_flow_id=f"stored_via:{wt.method} {wt.url}",
                        )
                        cand = XssCandidate(
                            target=cand_target,
                            payload=real_payload,
                            marker=attack_marker,
                            echo_matches=echo_matches,
                            confidence=0.85,  # 跨页面回显本身就是高置信度
                            xss_type=XssType.STORED,
                            request_packet=(
                                f"[写入] {wt.method} {wt.url}\n"
                                f"参数: {wt.param_name} (via {wt.injection_point.value})\n"
                                f"Payload: {real_payload}\n\n"
                                f"[读取] GET {read_url}\n"
                                f"Marker {attack_marker} 在响应中出现"
                            )[:8000],
                            response_packet=body[:30000],
                            response_status=resp.status_code,
                            response_content_type=resp.headers.get("content-type", ""),
                            scanner="xss_stored_tracker",
                        )
                        candidates.append(cand)
                        # 该 payload 已经成功，不需要继续测其他读取页
                        break
                    except Exception:
                        continue
                if candidates:
                    break  # 该写入点已找到，不需要继续测其他 payload
            except Exception:
                continue

        return candidates

    async def _send_write(
        self, client: httpx.AsyncClient, wt: InjectionTarget, payload: str
    ) -> bool:
        """向写入点发请求。返回是否成功（不要求 200，只要不报网络错误）。"""
        import json as _json
        from urllib.parse import urlparse, parse_qsl, urlencode

        method = wt.method.upper()
        headers = dict(wt.headers or {})
        headers.pop("Content-Length", None)
        headers.pop("content-length", None)

        try:
            if wt.injection_point == InjectionPoint.URL_PARAM:
                parsed = urlparse(wt.url)
                existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
                existing[wt.param_name] = payload
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(existing)}"
                await client.request(method, new_url, headers=headers)
                return True
            if wt.injection_point == InjectionPoint.BODY_FORM:
                await client.request(method, wt.url, headers=headers,
                                     data={wt.param_name: payload})
                return True
            if wt.injection_point == InjectionPoint.BODY_JSON:
                obj = {}
                if wt.body_template:
                    try:
                        obj = _json.loads(wt.body_template)
                    except Exception:
                        obj = {}
                if "." in wt.param_name:
                    parts = wt.param_name.split(".")
                    cur = obj
                    for p in parts[:-1]:
                        if not isinstance(cur, dict):
                            break
                        cur = cur.setdefault(p, {})
                    if isinstance(cur, dict):
                        cur[parts[-1]] = payload
                else:
                    if not isinstance(obj, dict):
                        obj = {}
                    obj[wt.param_name] = payload
                headers.setdefault("Content-Type", "application/json")
                await client.request(method, wt.url, headers=headers,
                                     content=_json.dumps(obj))
                return True
            if wt.injection_point == InjectionPoint.BODY_MULTIPART:
                files = {wt.param_name: (None, payload)}
                await client.request(method, wt.url, headers=headers, files=files)
                return True
        except Exception as e:
            log.debug("stored write failed: %s", e)
            return False
        return False
