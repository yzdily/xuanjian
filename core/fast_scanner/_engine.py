"""fast_scanner 规则引擎（从原 fast_scanner.py 机械拆分，方法体逐字保留）。

FastScanner 继承 4 个 check mixin，通过 MRO 在运行期解析 self._check_x() 调用，
跨 mixin 的 self. 引用无需任何改写。
"""

from __future__ import annotations

import asyncio
import random
import time

import httpx

from core.log import get_logger
from core.false_positive_manager import is_false_positive

from ._constants import DEFAULT_USER_AGENTS, MOBILE_USER_AGENTS
from ._models import VulnFinding, ScanTarget, ScanResult
from ._rules_loader import load_rules_from_yaml
from ._checks_injection import _ChecksInjection
from ._checks_server import _ChecksServer
from ._checks_auth import _ChecksAuth
from ._sitemap_integration import _SitemapIntegration

log = get_logger("fast_scanner")


# ============================================================
# 规则引擎
# ============================================================

class FastScanner(_ChecksInjection, _ChecksServer, _ChecksAuth, _SitemapIntegration):
    """本地快速规则引擎，并发检测多种漏洞类型。

    规则来源：
    1. YAML 规则文件（rules/*.yaml）- 优先使用，支持热更新
    2. 硬编码规则（本文件中的默认值）- 作为 YAML 规则的补充/兜底
    """

    def __init__(
        self,
        max_workers: int = 20,
        timeout: float = 10.0,
        proxy: str | None = None,
        request_rate_limit: float = 5.0,
        hard_timeout: float = 600.0,
    ):
        self.max_workers = max_workers
        self.timeout = timeout
        self.proxy = proxy
        self.request_rate_limit = max(0.0, request_rate_limit)
        # ★ P0-1: 硬超时感知——引擎主动在接近 deadline 时收尾，避免被 orchestrator 强制 cancel 丢失结果
        self._hard_timeout = hard_timeout
        self._deadline: float | None = None  # time.monotonic() 基准的截止时刻
        self._scan_start_time: float = 0.0
        self._per_rule_timeout: float = 45.0  # 单条规则 handler 最大执行时间
        self._heartbeat_interval: float = 60.0  # 进度心跳间隔（秒）
        self._last_heartbeat: float = 0.0
        self._targets_scanned: int = 0
        self._targets_total: int = 0
        self._min_request_interval = (
            1.0 / self.request_rate_limit if self.request_rate_limit > 0 else 0.0
        )
        self._client: httpx.AsyncClient | None = None
        self._total_requests = 0
        self._blocked_count = 0
        self._timeout_count = 0
        self._error_count = 0
        self._lock = asyncio.Lock()
        self._rate_lock = asyncio.Lock()
        self._last_request_at = 0.0
        # ★ WAF 封禁标志：连续被拦截超过阈值后置 True，所有规则检测提前退出
        # 避免对已被 WAF 全量拦截的目标继续打数千次无效请求（实测 zzidc.com 拦截 1737 次仍在打）
        self._waf_blocked = False
        self._waf_block_threshold = 20  # 连续 20 次 403/418/429/503 即判定 WAF 封禁
        # ★ WAF/超时 跳过日志去重：scan_targets 并发多个 scan_target，封禁后
        #   每个并发任务都会命中 break 并打印一条日志，导致 20 条重复。
        #   此标志确保每次 scan_targets 只打印一次"已封禁"日志。
        self._waf_skip_logged = False
        self._timeout_skip_logged = False
        # ★ 超时熔断：连续超时达到阈值后置 True，避免对不可达目标继续打无效请求
        self._consecutive_timeout_count = 0
        self._timeout_blocked = False
        self._timeout_block_threshold = 10  # 连续 10 次超时即熔断
        # ★ 2026-08-05：全局超时统计——跨目标累计超时次数，超过阈值后全局降速
        # 此前 11,808 次超时说明扫描了几千个超时目标，每个都打 10 次才熔断
        # scan_target 不重置这两个字段，使其跨目标累积
        self._global_timeout_count = 0
        self._global_timeout_slowdown = False  # 全局降速标志
        self._global_timeout_threshold = 100  # 累计 100 次超时即触发全局降速
        self._global_slowdown_delay = 0.5     # 降速后每个请求额外 sleep 0.5s
        # ★ 并发信号量：限制同时在途的 HTTP 请求数，避免 gather 一次性创建数百协程
        # 当 WAF/超时熔断后，等待中的协程进入 _request 时会看到标志位并直接返回 None
        self._semaphore: asyncio.Semaphore | None = None
        # ★ 响应日志采样：同规则/状态/长度桶的重复响应只在里程碑输出，减少 500 噪声刷屏
        self._response_log_counts: dict[str, int] = {}
        self._response_log_suppressed = 0
        # ★ YAML 规则缓存：从 rules/*.yaml 加载的规则列表
        self._yaml_rules: list[dict] = []
        # ★ 生产修复：_check_ssrf 末尾的 SSRF OOB 增强分支会读取 self.config，
        # 但 __init__ 原先未初始化该属性，导致 url 参数型 SSRF 触发 OOB 分支时
        # 抛出 AttributeError 崩溃。这里显式初始化，默认禁用 OOB，避免运行时崩溃。
        self.config: dict = {}
        self._load_yaml_rules()

    def _record_scan_response_log(
        self,
        rule_tag: str,
        method: str,
        url: str,
        payload_tag: str,
        resp: httpx.Response,
    ) -> None:
        """采样输出扫描响应日志，聚合同类 4xx/5xx 噪声。"""
        from urllib.parse import urlparse

        status = resp.status_code
        length_bucket = len(resp.content) // 100
        path = urlparse(url).path or "/"
        parent = path.rsplit("/", 1)[0] or "/"
        key = f"{rule_tag}|{method}|{parent}|{status}|{length_bucket}"
        count = self._response_log_counts.get(key, 0) + 1
        self._response_log_counts[key] = count

        noisy_status = status >= 500 or status in (403, 404, 418, 429)
        milestones = {1, 2, 3, 10, 30, 100, 300, 1000}
        if noisy_status and count not in milestones:
            self._response_log_suppressed += 1
            return

        suffix = f" | same={count}" if count > 1 else ""
        if noisy_status and count > 3:
            suffix += f" | suppressed={self._response_log_suppressed}"
        log.info("[SCAN] %s | %s %s | payload=%s | => %d %s | body=%d%s",
                 rule_tag, method, url, payload_tag,
                 resp.status_code, resp.reason_phrase, len(resp.content), suffix)

    async def _throttle_before_request(self) -> None:
        """请求前节流，避免 FastScanner 瞬时并发触发 WAF/限流。

        request_rate_limit 默认 5 req/s；当已经出现 403/418/429/503 后，
        按拦截次数轻微增加间隔，让后续规则有机会拿到真实响应而不是批量拦截页。
        """
        if self._min_request_interval <= 0:
            return
        async with self._rate_lock:
            now = time.monotonic()
            adaptive_extra = min(1.5, 0.1 * self._blocked_count)
            wait_for = (self._last_request_at + self._min_request_interval + adaptive_extra) - now
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last_request_at = time.monotonic()

    def _load_yaml_rules(self) -> None:
        """加载 YAML 规则文件到内存缓存。

        调用 load_rules_from_yaml() 函数，将结果存储在 self._yaml_rules 中。
        """
        try:
            # 调用文件末尾定义的 load_rules_from_yaml 函数
            self._yaml_rules = load_rules_from_yaml("rules")
            if self._yaml_rules:
                log.info("[FastScanner] 加载了 %d 条 YAML 规则", len(self._yaml_rules))
        except Exception as e:
            log.warning("[FastScanner] 加载 YAML 规则失败: %s", e)
            self._yaml_rules = []

    def _get_yaml_payloads(self, rule_type: str) -> list[str]:
        """从 YAML 规则中提取指定类型的 payload 列表。

        Args:
            rule_type: 规则类型，如 'sql_injection', 'xss', 'weak_password'

        Returns:
            payload 列表，如果无匹配则返回空列表
        """
        payloads = []
        for rule in self._yaml_rules:
            if rule.get("type") == rule_type:
                rule_payloads = rule.get("payloads", [])
                if isinstance(rule_payloads, list):
                    payloads.extend(rule_payloads)
                elif isinstance(rule_payloads, dict):
                    # 处理布尔盲注等 dict 格式的 payloads
                    payloads.extend(rule_payloads.values())
        return payloads

    def _get_yaml_paths(self, rule_type: str) -> list[str]:
        """从 YAML 规则中提取指定类型的敏感路径列表。

        Args:
            rule_type: 规则类型，如 'info_disclosure', 'unauthorized'

        Returns:
            路径列表，如果无匹配则返回空列表
        """
        paths = []
        for rule in self._yaml_rules:
            if rule.get("type") == rule_type:
                rule_paths = rule.get("paths", [])
                if isinstance(rule_paths, list):
                    paths.extend(rule_paths)
        return paths

    def _get_yaml_credentials(self) -> list[tuple[str, str]]:
        """从 YAML 规则中提取弱口令凭据列表。

        Returns:
            (username, password) 元组列表
        """
        credentials = []
        for rule in self._yaml_rules:
            if rule.get("type") == "weak_password":
                rule_creds = rule.get("credentials", [])
                if isinstance(rule_creds, list):
                    for cred in rule_creds:
                        if isinstance(cred, list) and len(cred) >= 2:
                            credentials.append((cred[0], cred[1]))
        return credentials

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            kwargs = {
                "timeout": httpx.Timeout(self.timeout),
                "follow_redirects": True,
                "verify": False,
                "limits": httpx.Limits(max_connections=self.max_workers * 2),
            }
            if self.proxy:
                kwargs["proxy"] = self.proxy
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        content: str | None = None,
        drop_auth: bool = False,
        rule_tag: str = "",
        payload_tag: str = "",
    ) -> httpx.Response | None:
        """发送 HTTP 请求，返回响应对象。失败返回 None。

        ★ WAF 自适应：被拦截时自动降速，避免触发 IP 封禁。
          深度绕过（编码/分块/注释变体）由 WAFBypassFuzzer 负责，
          本引擎仅做快速规则检测 + 限速保护。
        """
        # ★ WAF / 超时熔断早退：一旦全局封禁标志置位，后续所有请求直接返回 None
        if self._waf_blocked or self._timeout_blocked:
            return None

        # ★ P0-1: deadline 早退——接近硬超时时不再发起新请求
        if self._is_deadline_exceeded():
            return None

        # ★ 并发信号量：限制同时在途的 HTTP 请求数
        # gather 创建的协程在此排队，进入后才检查熔断标志，避免数百请求同时发出
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_workers)
        async with self._semaphore:
            # 二次检查：排队期间可能已被熔断
            if self._waf_blocked or self._timeout_blocked:
                return None

            # ★ 2026-08-05：全局超时降速——跨目标累计超时过多时，每个请求额外 sleep
            # 避免对大量不可达目标继续高速打无效请求（此前 11,808 次超时）
            if self._global_timeout_slowdown:
                await asyncio.sleep(self._global_slowdown_delay)

            client = await self._get_client()
            # 去认证：移除 Cookie / Authorization
            req_headers = dict(headers) if headers else {}
            header_names = {str(k).lower() for k in req_headers}
            if "user-agent" not in header_names:
                req_headers["User-Agent"] = random.choice(DEFAULT_USER_AGENTS)
            req_headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            req_headers.setdefault("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
            if drop_auth:
                req_headers.pop("Cookie", None)
                req_headers.pop("cookie", None)
                req_headers.pop("Authorization", None)
                req_headers.pop("authorization", None)

            try:
                await self._throttle_before_request()
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=req_headers,
                    content=content,
                )

                _need_sleep = 0.0
                _should_retry_with_browser_headers = False
                async with self._lock:
                    self._total_requests += 1
                    # 请求成功，重置连续超时计数
                    self._consecutive_timeout_count = 0
                    # WAF 拦截检测
                    if resp.status_code in (403, 418, 429, 503):
                        self._blocked_count += 1
                        # ★ 首次拦截时标记需要浏览器头重试：区分"反爬 vs WAF"
                        #   很多站点对非浏览器 UA 返回 418/403，加上 Referer + 真实浏览器
                        #   UA + Sec-Fetch 头后可能恢复正常（反爬而非 WAF）
                        if self._blocked_count == 1:
                            _should_retry_with_browser_headers = True
                        # ★ WAF 日志指数退避采样：仅在 3/10/30/100/300/1000 次时输出
                        # 原逻辑每 3 次输出一条，拦截 576 次产生 192 条几乎相同的 WARNING
                        _log_milestones = {3, 10, 30, 100, 300, 1000, 3000}
                        if self._blocked_count in _log_milestones:
                            delay = min(2.0, 0.5 * (self._blocked_count // 3))
                            log.warning("[SCAN] WAF 拦截 %d 次，降速 %0.1fs",
                                        self._blocked_count, delay)
                            _need_sleep = delay
                        # ★ WAF 全局封禁早退：拦截次数达到阈值，置全局标志中止所有后续请求
                        if self._blocked_count >= self._waf_block_threshold and not self._waf_blocked:
                            self._waf_blocked = True
                            log.warning(
                                "[SCAN] WAF 封禁：连续被拦截 %d 次（阈值 %d），中止该目标所有后续 payload",
                                self._blocked_count, self._waf_block_threshold
                            )

                # ★ sleep 移到锁外执行，避免持锁期间阻塞其他协程
                if _need_sleep > 0:
                    await asyncio.sleep(_need_sleep)

                # ★ 首次拦截后浏览器头重试：区分反爬 vs WAF
                #   若加上 Referer + Sec-Fetch 头后响应恢复正常（非 403/418/429/503），
                #   说明是反爬而非 WAF，重置拦截计数避免误判封禁
                if _should_retry_with_browser_headers and not self._waf_blocked:
                    retry_headers = dict(req_headers)
                    retry_headers["User-Agent"] = (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/126.0.0.0 Safari/537.36"
                    )
                    retry_headers["Referer"] = url
                    retry_headers["Sec-Fetch-Dest"] = "document"
                    retry_headers["Sec-Fetch-Mode"] = "navigate"
                    retry_headers["Sec-Fetch-Site"] = "none"
                    retry_headers["Sec-Fetch-User"] = "?1"
                    retry_headers["Upgrade-Insecure-Requests"] = "1"
                    try:
                        retry_resp = await client.request(
                            method=method, url=url,
                            headers=retry_headers, content=content,
                        )
                        if retry_resp.status_code not in (403, 418, 429, 503):
                            # 反爬绕过成功：重置拦截计数，使用浏览器头继续
                            log.info("[SCAN] 首次拦截后浏览器头重试成功: %d → %d，判定为反爬非 WAF",
                                     resp.status_code, retry_resp.status_code)
                            async with self._lock:
                                self._blocked_count = 0
                            self._record_scan_response_log(rule_tag, method, url, payload_tag, retry_resp)
                            return retry_resp
                    except Exception:
                        pass  # 重试失败则继续用原响应

                    # ★ 移动 UA 重试：浏览器头仍被拦截时，尝试移动 UA 绕过 WAF
                    # （infer.md 发现 Jiasule WAF 可用移动 UA 绕过）
                    if not self._waf_blocked:
                        import random as _rnd
                        _mobile_ua = _rnd.choice(MOBILE_USER_AGENTS)
                        mobile_headers = dict(req_headers)
                        mobile_headers["User-Agent"] = _mobile_ua
                        mobile_headers["Referer"] = url
                        try:
                            mobile_resp = await client.request(
                                method=method, url=url,
                                headers=mobile_headers, content=content,
                            )
                            if mobile_resp.status_code not in (403, 418, 429, 503):
                                log.info("[SCAN] 移动 UA 绕过 WAF 成功: %d → %d (UA=%s...)",
                                         resp.status_code, mobile_resp.status_code,
                                         _mobile_ua[:30])
                                async with self._lock:
                                    self._blocked_count = 0
                                self._record_scan_response_log(rule_tag, method, url, payload_tag, mobile_resp)
                                return mobile_resp
                        except Exception:
                            pass  # 移动 UA 重试失败则继续用原响应

                self._record_scan_response_log(rule_tag, method, url, payload_tag, resp)
                return resp
            except httpx.TimeoutException:
                async with self._lock:
                    self._timeout_count += 1
                    self._consecutive_timeout_count += 1
                    # ★ 超时熔断：连续超时达到阈值，中止该目标所有后续请求
                    if (self._consecutive_timeout_count >= self._timeout_block_threshold
                            and not self._timeout_blocked):
                        self._timeout_blocked = True
                        log.warning(
                            "[SCAN] 超时熔断：连续超时 %d 次（阈值 %d），中止该目标所有后续 payload",
                            self._consecutive_timeout_count, self._timeout_block_threshold
                        )
                    # ★ 2026-08-05：全局超时统计——跨目标累积，超过阈值触发全局降速
                    # 此前每个超时目标都打满 10 次才熔断，数千目标累计 11,808 次超时
                    self._global_timeout_count += 1
                    if (not self._global_timeout_slowdown
                            and self._global_timeout_count >= self._global_timeout_threshold):
                        self._global_timeout_slowdown = True
                        log.warning(
                            "[SCAN] 全局超时降速：累计超时 %d 次（阈值 %d），后续所有请求额外 sleep %.2fs",
                            self._global_timeout_count, self._global_timeout_threshold,
                            self._global_slowdown_delay
                        )
                log.warning("[SCAN] %s | %s %s | payload=%s | => TIMEOUT",
                            rule_tag, method, url, payload_tag)
                return None
            except httpx.HTTPStatusError as e:
                log.warning("[SCAN] %s | %s %s | payload=%s | => HTTP_ERR %s",
                            rule_tag, method, url, payload_tag, e.response.status_code)
                return e.response
            except Exception as e:
                async with self._lock:
                    self._error_count += 1
                log.debug("[SCAN] %s | %s %s | payload=%s | => FAIL %s",
                          rule_tag, method, url, payload_tag, e)
                return None

    def _is_deadline_exceeded(self) -> bool:
        """检查是否已超过硬超时 deadline。"""
        if self._deadline is None:
            return False
        return time.monotonic() >= self._deadline

    def _remaining_time(self) -> float:
        """返回距离 deadline 的剩余秒数；无 deadline 时返回无穷大。"""
        if self._deadline is None:
            return float("inf")
        return max(0.0, self._deadline - time.monotonic())

    def _emit_heartbeat(self, phase: str = "") -> None:
        """进度心跳日志：每隔 _heartbeat_interval 秒输出一次扫描进度。"""
        now = time.monotonic()
        if now - self._last_heartbeat < self._heartbeat_interval and self._last_heartbeat > 0:
            return
        self._last_heartbeat = now
        elapsed = now - self._scan_start_time if self._scan_start_time > 0 else 0
        remaining = self._remaining_time()
        log.info(
            "[SCAN] ❤️ 心跳 | 阶段=%s | 已扫 %d/%d 目标 | 已耗时 %.0fs | 剩余预算 %.0fs | "
            "请求 %d 拦截 %d 超时 %d",
            phase, self._targets_scanned, self._targets_total,
            elapsed, remaining,
            self._total_requests, self._blocked_count, self._timeout_count,
        )

    async def scan_target(
        self,
        target: ScanTarget,
        enabled_rules: list[str] | None = None,
    ) -> ScanResult:
        """对单个目标执行快速扫描。

        Args:
            target: 扫描目标
            enabled_rules: 启用的规则类型列表，None 表示全部
        """
        all_rules = enabled_rules or [
            "sql_injection", "xss", "info_disclosure",
            "unauthorized", "auth_matrix", "weak_password", "cors",
            "path_traversal", "command_injection", "ssrf",
            "csrf", "xxe", "ssti", "file_upload",
            "open_redirect", "jwt",
        ]

        t0 = time.time()
        suppressed_before = self._response_log_suppressed
        self._total_requests = 0
        self._blocked_count = 0
        # ★ 2026-08-08: 仅在未封禁时才重置，避免并发目标覆盖已触发的 WAF 状态。
        #   原逻辑每个目标无条件重置 _waf_blocked=False，导致：
        #   批次内目标 A 触发 WAF 置 True → 目标 B 又将其重置为 False → 目标 B 继续打无效请求。
        #   修复后：一旦有目标触发 WAF，后续所有目标（同批次/跨批次）都会看到封禁标志。
        if not self._waf_blocked:
            self._waf_blocked = False
        self._consecutive_timeout_count = 0
        if not self._timeout_blocked:
            self._timeout_blocked = False
        self._semaphore = asyncio.Semaphore(self.max_workers)  # ★ 每个目标重建信号量
        # ★ 每个目标重置响应日志计数：否则 same=N 会跨目标累积，看起来像同一目标
        # 被打了 N 次，实际是 N 个不同目标的响应落入同一桶。重置后 same= 反映单目标
        # 内的重复度，便于识别 catch-all/soft-404 误报模式。
        # _response_log_suppressed 不重置：scan_target 用 delta（suppressed_before）计算本目标抑制数。
        self._response_log_counts.clear()
        findings: list[VulnFinding] = []

        # ★ 分批执行规则：每批 max_workers 个规则，批次间检查熔断标志
        # 原逻辑一次性 gather 所有规则，每条规则内部又 gather 数十 payload，
        # 导致数百协程同时在途，WAF 封禁后仍有大量在途请求返回 403 并刷日志
        all_handlers = []
        # ★ WAF 智能降级：当拦截次数过半时，过滤高 WAF 影响规则
        # 高影响规则：sql_injection、xss、command_injection、ssrf、xxe、ssti
        # 这些规则的 payload 容易触发 WAF，应在降级时跳过
        _HIGH_WAF_IMPACT_RULES = {"sql_injection", "xss", "command_injection",
                                   "ssrf", "xxe", "ssti", "path_traversal"}
        _waf_degradation_threshold = self._waf_block_threshold // 2  # 半数拦截时降级

        for rule in all_rules:
            handler = getattr(self, f"_check_{rule}", None)
            if handler:
                # ★ WAF 降级：拦截次数过半时，跳过高 WAF 影响规则
                if (self._blocked_count >= _waf_degradation_threshold
                        and rule in _HIGH_WAF_IMPACT_RULES):
                    log.info("[SCAN] WAF 降级中：跳过高影响规则 %s（已拦截 %d 次）",
                             rule, self._blocked_count)
                    continue
                all_handlers.append(handler)

        batch_size = min(3, len(all_handlers)) if all_handlers else 1
        for i in range(0, len(all_handlers), batch_size):
            # ★ P0-1: deadline 检查——接近硬超时时主动收尾，避免被 cancel 丢失已扫结果
            if self._is_deadline_exceeded():
                log.info("[SCAN] 硬超时 deadline 到达，跳过剩余 %d 个规则（目标: %s）",
                         len(all_handlers) - i, target.url)
                break
            # 批次间检查熔断标志，跳过剩余规则
            if self._waf_blocked:
                if not self._waf_skip_logged:
                    self._waf_skip_logged = True
                    log.info("[SCAN] WAF 已封禁，跳过剩余 %d 个规则", len(all_handlers) - i)
                break
            if self._timeout_blocked:
                if not self._timeout_skip_logged:
                    self._timeout_skip_logged = True
                    log.info("[SCAN] 超时已熔断，跳过剩余 %d 个规则", len(all_handlers) - i)
                break

            # ★ 调用 handler(target) 获取协程对象
            # ★ P0-1: 每条规则加 asyncio.wait_for 兜底，防止单规则卡死拖垮整个扫描
            batch = [handler(target) for handler in all_handlers[i:i + batch_size]]
            # 剩余时间不足时跳过本批（避免 wait_for 刚启动就超时）
            _remaining = self._remaining_time()
            _rule_timeout = min(self._per_rule_timeout, _remaining) if _remaining != float("inf") else self._per_rule_timeout
            if _rule_timeout <= 1.0:
                log.info("[SCAN] 剩余时间 %.1fs 不足，跳过剩余规则", _remaining)
                break
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*batch, return_exceptions=True),
                    timeout=_rule_timeout,
                )
            except asyncio.TimeoutError:
                log.warning("[SCAN] 规则批次超时（%.1fs），跳过本批 %d 条规则",
                            _rule_timeout, len(batch))
                continue
            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    log.warning("规则执行异常: %s", result)

        # 过滤用户标记的误报
        findings = self._filter_false_positives(findings)

        # ★ 优化.md 建议6：为每条发现分配溯源 ID（日志→报告溯源强制化）
        self._assign_trace_ids(findings)

        elapsed = time.time() - t0
        await self._close()

        return ScanResult(
            target_url=target.url,
            findings=findings,
            elapsed=elapsed,
            total_requests=self._total_requests,
            rules_run=len(all_handlers),
            blocked_count=self._blocked_count,
            timeout_count=self._timeout_count,
            error_count=self._error_count,
            log_suppressed_count=max(0, self._response_log_suppressed - suppressed_before),
            waf_blocked=self._waf_blocked,
            timeout_blocked=self._timeout_blocked,
        )

    async def scan_targets(
        self,
        targets: list[ScanTarget],
        enabled_rules: list[str] | None = None,
    ) -> list[ScanResult]:
        """批量扫描多个目标。

        ★ Fix4（优先级感知调度）：
        1. 目标按优先级降序排序（critical→high→medium→low），高价值目标先扫，
           在 WAF 封禁触发前尽量覆盖关键端点；
        2. WAF/超时封禁后不再盲目跳过全部剩余目标，而是仅跳过 medium/low，
           继续尝试剩余 critical/high 目标（红队原则：高价值目标值得多打几次）。
        """
        _PRIORITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0, None: 0}

        def _rank(t: ScanTarget) -> int:
            return _PRIORITY_RANK.get((getattr(t, "priority", "medium") or "medium"), 2)

        # ★ Fix4-1：按优先级降序，critical/high 排在最前
        targets = sorted(targets, key=_rank, reverse=True)

        # ★ P0-1: 设置 deadline——引擎主动在接近硬超时时收尾
        self._scan_start_time = time.monotonic()
        self._deadline = self._scan_start_time + self._hard_timeout
        self._targets_total = len(targets)
        self._targets_scanned = 0
        self._last_heartbeat = 0.0
        log.info("[SCAN] 硬超时预算: %.0fs (%d 个目标)", self._hard_timeout, len(targets))

        results = []
        # 分批并发，避免连接爆炸
        batch_size = self.max_workers
        # ★ 重置跳过日志去重标志：每次 scan_targets 只打印一次"已封禁/已熔断"日志
        self._waf_skip_logged = False
        self._timeout_skip_logged = False

        i = 0
        n = len(targets)
        while i < n:
            # ★ P0-1: deadline 检查——接近硬超时时主动收尾
            if self._is_deadline_exceeded():
                log.warning("[SCAN] 硬超时 deadline 到达，已扫描 %d/%d 目标，剩余 %d 个目标跳过",
                            self._targets_scanned, n, n - i)
                break
            self._emit_heartbeat(phase="scan_targets")

            if self._waf_blocked or self._timeout_blocked:
                # ★ Fix4-2：封禁后仅继续 critical/high，跳过 medium/low
                reason = "WAF 全局封禁" if self._waf_blocked else "全局超时熔断"
                remaining = targets[i:]
                high_value = [
                    t for t in remaining
                    if (getattr(t, "priority", "medium") or "medium") in ("critical", "high")
                ]
                if not high_value:
                    log.info("[SCAN] %s，无剩余 critical/high 目标，跳过剩余 %d 个 medium/low 目标",
                             reason, len(remaining))
                    break
                log.info("[SCAN] %s：仅继续 %d 个 critical/high 目标，跳过 %d 个 medium/low 目标",
                         reason, len(high_value), len(remaining) - len(high_value))
                hv_results = await asyncio.gather(
                    *[self.scan_target(t, enabled_rules) for t in high_value],
                    return_exceptions=True,
                )
                for r in hv_results:
                    if isinstance(r, ScanResult):
                        results.append(r)
                    elif isinstance(r, Exception):
                        log.warning("目标扫描异常: %s", r)
                        results.append(ScanResult(
                            target_url="unknown", elapsed=0,
                            total_requests=0, rules_run=0,
                        ))
                break

            batch = targets[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[self.scan_target(t, enabled_rules) for t in batch],
                return_exceptions=True,
            )
            for r in batch_results:
                if isinstance(r, ScanResult):
                    results.append(r)
                elif isinstance(r, Exception):
                    log.warning("目标扫描异常: %s", r)
                    results.append(ScanResult(
                        target_url="unknown", elapsed=0,
                        total_requests=0, rules_run=0,
                    ))
            self._targets_scanned += len(batch)
            i += batch_size
        return results

    def get_accumulated_stats(self) -> dict:
        """获取累计的请求统计（供 orchestrator 收集写入报告）。"""
        return {
            "total_requests": self._total_requests,
            "blocked": self._blocked_count,
            "timeout": self._timeout_count,
            "error": self._error_count,
            "log_suppressed": self._response_log_suppressed,
            "waf_blocked": self._waf_blocked,
            "timeout_blocked": self._timeout_blocked,
            "global_timeout_count": self._global_timeout_count,
            "global_slowdown": self._global_timeout_slowdown,
        }

    async def _close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def _filter_false_positives(self, findings: list[VulnFinding]) -> list[VulnFinding]:
        """过滤误报并去重

        检查用户标记的误报规则，排除已知误报；
        同时按 (vuln_type, url, method) 去重，保留 severity 最高 / evidence_quality 最强的一条。

        Args:
            findings: 原始发现列表

        Returns:
            过滤并去重后的发现列表
        """
        # ---- Step 1: 过滤用户标记的误报 ----
        filtered = []
        for finding in findings:
            # 转换为 dict 格式供误报管理器检查
            finding_dict = {
                "url": finding.url,
                "type": finding.vuln_type,
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "detail": finding.detail,
            }

            # 检查是否为用户标记的误报
            if is_false_positive(finding_dict):
                log.debug(f"排除用户标记的误报: {finding.url} ({finding.vuln_type})")
                continue

            filtered.append(finding)

        # ---- Step 2: 按 (vuln_type, url, method) 去重 ----
        # ★ 修复：同一 URL + 同一漏洞类型 + 同一方法的发现只保留一条，
        # 保留 severity 最高 / evidence_quality 最强的，避免重复条目污染报告
        _severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        _evidence_rank = {"body_confirmed": 3, "header_only": 2, "weak": 1, "": 0}

        dedup_map: dict[str, VulnFinding] = {}
        for finding in filtered:
            # 归一化 URL：去除 query string 和 fragment，统一小写
            norm_url = finding.url.split("?")[0].split("#")[0].lower().rstrip("/")
            dedup_key = f"{finding.vuln_type}|{norm_url}|{finding.method}"

            existing = dedup_map.get(dedup_key)
            if existing is None:
                dedup_map[dedup_key] = finding
                continue

            # 比较 severity，保留更高的
            existing_sev = _severity_rank.get(existing.severity or "", 0)
            new_sev = _severity_rank.get(finding.severity or "", 0)
            if new_sev > existing_sev:
                dedup_map[dedup_key] = finding
            elif new_sev == existing_sev:
                # severity 相同时比较 evidence_quality
                existing_ev = _evidence_rank.get(getattr(existing, "evidence_quality", "") or "", 0)
                new_ev = _evidence_rank.get(getattr(finding, "evidence_quality", "") or "", 0)
                if new_ev > existing_ev:
                    dedup_map[dedup_key] = finding

        deduped = list(dedup_map.values())
        if len(deduped) < len(filtered):
            log.info("[SCAN] 去重: %d → %d (去除 %d 条重复发现)",
                     len(filtered), len(deduped), len(filtered) - len(deduped))

        return deduped

    def _assign_trace_ids(self, findings: list[VulnFinding]) -> None:
        """★ 优化.md 建议6：为每条发现分配溯源 ID（原地修改）。

        生成格式：XJ-{rule_tag}-{short_uuid}
        每条发现可在 agent.log 中通过 trace_id 检索到对应的请求/响应日志，
        实现报告→日志的端到端溯源。
        """
        import uuid as _uuid
        _VT_TO_TAG = {
            "SQL注入": "SQLi", "SQL Injection": "SQLi",
            "XSS": "XSS", "跨站脚本": "XSS",
            "未授权访问": "Unauth", "未授权": "Unauth",
            "信息泄露": "InfoLeak", "敏感信息泄露": "InfoLeak",
            "弱口令": "WeakPwd", "弱密码": "WeakPwd",
            "CORS": "CORS", "路径遍历": "PathTrav",
            "命令注入": "CmdInj", "SSRF": "SSRF",
            "CSRF": "CSRF", "XXE": "XXE", "SSTI": "SSTI",
            "文件上传": "FileUpload", "IDOR": "IDOR",
            "越权访问": "AuthMatrix", "水平越权": "AuthMatrix",
            "垂直越权": "AuthMatrix",
        }
        for f in findings:
            if not f.trace_id:
                tag = f.rule_tag or _VT_TO_TAG.get(f.vuln_type, f.vuln_type[:8] or "VULN")
                short_id = _uuid.uuid4().hex[:8].upper()
                f.trace_id = f"XJ-{tag}-{short_id}"
                if not f.rule_tag:
                    f.rule_tag = tag
