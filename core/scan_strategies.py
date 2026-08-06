"""
ScanStrategies — 扫描策略模块

三档扫描策略 + 智能选择：
- 快速扫描: 仅本地规则引擎，不走 LLM
- 标准扫描: 本地规则 + LLM 分析（减少 LLM 调用）
- 深度扫描: 本地规则 + 完整 LLM 流程（当前模式）
- 智能扫描: 根据目标大小和响应自动选择
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from core.log import get_logger

log = get_logger("scan_strategies")


class ScanMode(Enum):
    """扫描模式"""
    FAST = "fast"        # 快速：仅本地规则
    STANDARD = "standard"  # 标准：本地规则 + LLM 分析
    DEEP = "deep"        # 深度：本地规则 + 完整 LLM 流程
    SMART = "smart"      # 智能：自动选择


@dataclass
class ScanConfig:
    """扫描配置"""
    mode: ScanMode = ScanMode.SMART
    # 爬虫配置
    crawl_max_pages: int = 120
    crawl_fast_mode: bool = False  # API-only 爬虫
    # 本地规则引擎
    fast_scan_enabled: bool = True
    fast_scan_workers: int = 20
    fast_scan_rules: list[str] = field(default_factory=lambda: [
        "sql_injection", "xss", "info_disclosure",
        "unauthorized", "weak_password", "cors",
        "path_traversal", "command_injection", "ssrf",
    ])
    # LLM 配置
    llm_workers: int = 5
    skip_business_understanding: bool = False
    skip_meta_analysis: bool = False
    skip_supplemental_test: bool = False
    skip_harm_validation: bool = False
    # 超时配置（秒）
    crawl_timeout: int = 300
    fast_scan_timeout: int = 120
    llm_phase_timeout: int = 1800
    total_timeout: int = 7200
    # 并发配置
    max_concurrent_requests: int = 20

    @classmethod
    def from_mode(cls, mode: ScanMode | str) -> "ScanConfig":
        """根据模式生成默认配置"""
        if isinstance(mode, str):
            mode = ScanMode(mode)

        if mode == ScanMode.FAST:
            return cls(
                mode=mode,
                crawl_max_pages=30,
                crawl_fast_mode=True,
                fast_scan_enabled=True,
                fast_scan_workers=20,
                llm_workers=0,
                skip_business_understanding=True,
                skip_meta_analysis=True,
                skip_supplemental_test=True,
                skip_harm_validation=True,
                crawl_timeout=60,
                fast_scan_timeout=120,
                llm_phase_timeout=0,
                total_timeout=600,
                max_concurrent_requests=20,
            )
        elif mode == ScanMode.STANDARD:
            return cls(
                mode=mode,
                crawl_max_pages=60,
                crawl_fast_mode=False,
                fast_scan_enabled=True,
                fast_scan_workers=15,
                llm_workers=3,
                skip_business_understanding=True,
                skip_meta_analysis=True,
                skip_supplemental_test=False,
                skip_harm_validation=False,
                crawl_timeout=180,
                fast_scan_timeout=120,
                llm_phase_timeout=1200,
                total_timeout=3600,
                max_concurrent_requests=15,
            )
        elif mode == ScanMode.DEEP:
            return cls(
                mode=mode,
                crawl_max_pages=120,
                crawl_fast_mode=False,
                fast_scan_enabled=True,
                fast_scan_workers=10,
                llm_workers=5,
                skip_business_understanding=False,
                skip_meta_analysis=False,
                skip_supplemental_test=False,
                skip_harm_validation=False,
                crawl_timeout=300,
                fast_scan_timeout=120,
                llm_phase_timeout=1800,
                total_timeout=7200,
                max_concurrent_requests=10,
            )
        else:  # SMART
            return cls(mode=mode)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "crawl_max_pages": self.crawl_max_pages,
            "crawl_fast_mode": self.crawl_fast_mode,
            "fast_scan_enabled": self.fast_scan_enabled,
            "fast_scan_workers": self.fast_scan_workers,
            "llm_workers": self.llm_workers,
            "skip_business_understanding": self.skip_business_understanding,
            "skip_meta_analysis": self.skip_meta_analysis,
            "skip_supplemental_test": self.skip_supplemental_test,
            "skip_harm_validation": self.skip_harm_validation,
            "total_timeout": self.total_timeout,
        }


class SmartModeSelector:
    """智能模式选择器：根据目标特征自动选择扫描策略"""

    @staticmethod
    async def analyze_target(target_url: str, auth_headers: dict | None = None) -> dict:
        """分析目标特征，返回决策依据"""
        features = {
            "url": target_url,
            "page_size": 0,
            "is_api": False,
            "is_spa": False,
            "has_auth": bool(auth_headers),
            "response_time_ms": 0,
            "status_code": 0,
        }

        try:
            t0 = time.time()
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                headers = dict(auth_headers) if auth_headers else {}
                resp = await client.get(target_url, headers=headers)
                features["page_size"] = len(resp.text)
                features["status_code"] = resp.status_code
                features["response_time_ms"] = int((time.time() - t0) * 1000)

                content_type = resp.headers.get("content-type", "")
                # API 接口
                if "application/json" in content_type:
                    features["is_api"] = True
                # SPA 检测
                if "text/html" in content_type:
                    if "<div id=" in resp.text and ("<app-root" in resp.text or "<div id=\"root\"" in resp.text):
                        features["is_spa"] = True
                    # 检查是否有大量 JS
                    script_count = resp.text.count("<script")
                    if script_count > 5:
                        features["is_spa"] = True
        except Exception as e:
            log.warning("目标分析失败 %s: %s", target_url, e)

        return features

    @staticmethod
    def select_mode(features: dict) -> ScanMode:
        """根据目标特征选择扫描模式（多因子评分增强版）。

        评分维度：
        - 认证复杂度：有认证 → 至少 STANDARD（需要登录爬取+浏览器操作）
        - 业务价值：支付/转账/上传关键词 → 强制 DEEP
        - 页面大小 + 静态内容：小且纯静态 → FAST
        - SPA + JS 复杂度：需要 LLM 分析 API → STANDARD 起步

        与旧逻辑的区别：
        - 旧逻辑只看 page_size<5KB 或 is_api → FAST，忽略认证和价值
        - 新逻辑支持返回 DEEP（旧逻辑永不返回 DEEP）
        """
        page_size = features.get("page_size", 0)
        is_api = features.get("is_api", False)
        is_spa = features.get("is_spa", False)
        has_auth = features.get("has_auth", False)
        url = features.get("url", "").lower()

        # ★ 因子1：高危业务关键词 → 强制 DEEP
        high_value_keywords = [
            "pay", "payment", "transfer", "upload", "order",
            "account", "wallet", "trade", "withdraw",
        ]
        has_high_value = any(kw in url for kw in high_value_keywords)

        # ★ 因子2：认证复杂度
        if has_auth:
            # 有认证 → 至少 STANDARD（需要登录态爬取+浏览器操作）
            if has_high_value or is_spa:
                return ScanMode.DEEP
            return ScanMode.STANDARD

        # ★ 因子3：纯 API 接口或小静态页面 → FAST
        if is_api and page_size < 5000:
            return ScanMode.FAST

        # ★ 因子4：页面大但纯静态（无 SPA 特征，JS 少）→ 仍可 FAST
        if page_size < 5000 and not is_spa:
            return ScanMode.FAST

        # ★ 因子5：SPA + 大量 JS → 需要 LLM 分析 API → STANDARD 起步
        if is_spa:
            if has_high_value or page_size > 50000:
                return ScanMode.DEEP
            return ScanMode.STANDARD

        # ★ 因子6：大页面 + 有价值 → DEEP
        if has_high_value and page_size > 5000:
            return ScanMode.DEEP

        # 默认 → 标准
        return ScanMode.STANDARD


class ScanExecutor:
    """扫描执行器：按策略编排扫描流程"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: list[dict] = []
        self.elapsed: float = 0
        self._progress_callbacks: list = []

    def on_progress(self, callback):
        """注册进度回调"""
        self._progress_callbacks.append(callback)

    async def _emit_progress(self, phase: str, message: str, progress: float = 0):
        """发送进度事件"""
        for cb in self._progress_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb({"phase": phase, "message": message, "progress": progress})
                else:
                    cb({"phase": phase, "message": message, "progress": progress})
            except Exception:
                pass

    async def execute(
        self,
        target_url: str,
        auth_headers: dict | None = None,
        credentials: list[dict] | None = None,
    ) -> dict:
        """执行扫描"""
        t0 = time.time()
        result = {
            "target": target_url,
            "mode": self.config.mode.value,
            "findings": [],
            "fast_scan_result": None,
            "llm_scan_used": False,
            "elapsed": 0,
        }

        # ============ Phase 0: 爬虫 ============
        await self._emit_progress("crawl", "启动爬虫阶段...", 0.05)

        crawl_apis = []
        try:
            from core.auto_crawler import AutoCrawler
            crawler = AutoCrawler(
                target=target_url,
                credentials=credentials or [],
                max_pages_per_round=self.config.crawl_max_pages,
            )
            crawl_result = await crawler.crawl()
            crawl_apis = crawl_result.get("apis", []) if crawl_result else []
            await self._emit_progress("crawl", f"爬虫完成，发现 {len(crawl_apis)} 个 API", 0.2)
        except Exception as e:
            log.warning("爬虫阶段失败: %s", e)
            await self._emit_progress("crawl", f"爬虫失败: {e}", 0.2)

        # ============ Phase 1: 本地规则引擎 ============
        if self.config.fast_scan_enabled and crawl_apis:
            await self._emit_progress("fast_scan", f"启动本地规则引擎 ({self.config.fast_scan_workers} 线程)...", 0.3)

            try:
                from core.fast_scanner import FastScanner, ScanTarget

                scanner = FastScanner(max_workers=self.config.fast_scan_workers)
                targets = [
                    ScanTarget(url=api_url, auth_headers=auth_headers or {})
                    for api_url in crawl_apis[:50]  # 限制最多 50 个 API
                ]
                scan_results = await scanner.scan_targets(
                    targets,
                    enabled_rules=self.config.fast_scan_rules,
                )

                fast_findings = []
                for sr in scan_results:
                    fast_findings.extend(sr.to_dict().get("findings", []))
                result["fast_scan_result"] = {
                    "targets_scanned": len(targets),
                    "findings": fast_findings,
                    "elapsed": sum(sr.elapsed for sr in scan_results),
                }
                result["findings"].extend(fast_findings)

                await self._emit_progress(
                    "fast_scan",
                    f"本地规则完成: {len(targets)} 个目标, {len(fast_findings)} 个发现",
                    0.5,
                )
            except Exception as e:
                log.warning("本地规则引擎失败: %s", e)
                await self._emit_progress("fast_scan", f"本地规则失败: {e}", 0.5)

        # ============ Phase 2: LLM 分析（仅标准/深度模式）============
        if self.config.mode in (ScanMode.STANDARD, ScanMode.DEEP) and self.config.llm_workers > 0:
            await self._emit_progress("llm_scan", "启动 LLM 分析阶段...", 0.6)
            result["llm_scan_used"] = True
            # LLM 扫描由现有 orchestrator 处理，这里只标记
            await self._emit_progress("llm_scan", "LLM 分析阶段已交接给 orchestrator", 0.8)

        # ============ 完成 ============
        self.elapsed = time.time() - t0
        result["elapsed"] = round(self.elapsed, 2)
        result["findings_count"] = len(result["findings"])
        await self._emit_progress("done", f"扫描完成，耗时 {self.elapsed:.1f}s", 1.0)

        return result


# ============================================================
# 策略适配器（供 orchestrator.py 使用）
# ============================================================

@dataclass
class ScanStrategyConfig:
    """orchestrator 使用的策略配置适配器"""
    mode: ScanMode
    llm_max_workers: int
    enable_fast_scanner: bool
    skip_meta_analysis: bool
    skip_business_understanding: bool
    crawl_max_pages: int
    crawl_fast_mode: bool
    fast_scan_workers: int
    total_timeout: int
    # ★ 修复：chat_loop 在 fast 模式下读取 _crawl_cfg.crawl_timeout 缩短爬虫硬超时，
    #   此前该字段仅存在于 ScanConfig 而未透传到本适配器，导致
    #   'ScanStrategyConfig' object has no attribute 'crawl_timeout' 崩溃
    crawl_timeout: int = 300
    fast_scan_timeout: int = 120

    @classmethod
    def from_scan_config(cls, cfg: ScanConfig) -> "ScanStrategyConfig":
        return cls(
            mode=cfg.mode,
            llm_max_workers=cfg.llm_workers,
            enable_fast_scanner=cfg.fast_scan_enabled,
            skip_meta_analysis=cfg.skip_meta_analysis,
            skip_business_understanding=cfg.skip_business_understanding,
            crawl_max_pages=cfg.crawl_max_pages,
            crawl_fast_mode=cfg.crawl_fast_mode,
            fast_scan_workers=cfg.fast_scan_workers,
            total_timeout=cfg.total_timeout,
            crawl_timeout=cfg.crawl_timeout,
            fast_scan_timeout=cfg.fast_scan_timeout,
        )


def get_scan_strategy(user_mode: str) -> ScanStrategyConfig:
    """根据用户选择的模式返回策略配置（供 orchestrator 调用）"""
    mode_map = {
        "fast": ScanMode.FAST,
        "quick": ScanMode.FAST,   # ★ 兼容前端 quick 别名
        "standard": ScanMode.STANDARD,
        "deep": ScanMode.DEEP,
        "smart": ScanMode.SMART,
        "batch": ScanMode.STANDARD,  # 兼容旧模式名
    }
    scan_mode = mode_map.get(user_mode, ScanMode.STANDARD)
    cfg = ScanConfig.from_mode(scan_mode)
    return ScanStrategyConfig.from_scan_config(cfg)


# ============================================================
# 便捷入口
# ============================================================

async def scan(
    target_url: str,
    mode: str = "smart",
    auth_headers: dict | None = None,
    credentials: list[dict] | None = None,
    on_progress=None,
) -> dict:
    """一键扫描入口

    用法:
        # 快速扫描
        result = await scan("http://example.com", mode="fast")

        # 标准扫描
        result = await scan("http://example.com", mode="standard",
                           auth_headers={"Cookie": "session=xxx"})

        # 智能扫描（自动选择策略）
        result = await scan("http://example.com", mode="smart")
    """
    scan_mode = ScanMode(mode)

    # 智能模式：先分析目标再选择
    if scan_mode == ScanMode.SMART:
        features = await SmartModeSelector.analyze_target(target_url, auth_headers)
        scan_mode = SmartModeSelector.select_mode(features)
        log.info("智能模式选择: %s (依据: %s)", scan_mode.value, features)

    config = ScanConfig.from_mode(scan_mode)
    executor = ScanExecutor(config)

    if on_progress:
        executor.on_progress(on_progress)

    return await executor.execute(
        target_url=target_url,
        auth_headers=auth_headers,
        credentials=credentials,
    )
