"""
ScanStrategies 单元测试 — core.scan_strategies

覆盖：
- ScanMode 枚举
- ScanConfig.from_mode 四种模式（FAST/STANDARD/DEEP/SMART）的字段预设
- ScanConfig.fast() / standard() 快捷构造
- ScanConfig.to_dict() 序列化
- SmartModeSelector.select_mode 多因子评分（认证/业务价值/页面大小/SPA）
- SmartModeSelector.analyze_target （mock httpx，零网络）
- ScanExecutor.on_progress / _emit_progress / execute（mock 爬虫，零网络）
- ScanStrategyConfig.from_scan_config 字段透传
- get_scan_strategy 用户模式映射

设计原则：零网络、零 LLM、零文件副作用；async 用 asyncio.run 驱动，避免依赖 pytest-asyncio。
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# 确保项目根目录可导入（pythonpath 已配置，此处为防御性兜底）
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402

from core.scan_strategies import (  # noqa: E402
    ScanConfig,
    ScanExecutor,
    ScanMode,
    ScanStrategyConfig,
    SmartModeSelector,
    get_scan_strategy,
)


# ============================================================
# 1. ScanMode 枚举
# ============================================================
class TestScanMode:
    def test_enum_values(self):
        assert ScanMode.FAST.value == "fast"
        assert ScanMode.STANDARD.value == "standard"
        assert ScanMode.DEEP.value == "deep"
        assert ScanMode.SMART.value == "smart"

    def test_enum_count(self):
        assert len(list(ScanMode)) == 4

    def test_enum_from_str(self):
        assert ScanMode("fast") is ScanMode.FAST
        assert ScanMode("standard") is ScanMode.STANDARD
        assert ScanMode("deep") is ScanMode.DEEP
        assert ScanMode("smart") is ScanMode.SMART

    def test_invalid_str_raises(self):
        with pytest.raises(ValueError):
            ScanMode("nonexistent")

    # ----- StrEnum 语义（云序列化 bug 修复回归）-----
    def test_member_equals_str_value(self):
        """StrEnum 修复核心：成员与其字符串值可直接比较为 True。"""
        assert ScanMode.FAST == "fast"
        assert ScanMode.STANDARD == "standard"
        assert ScanMode.DEEP == "deep"
        assert ScanMode.SMART == "smart"

    def test_member_is_str_instance(self):
        assert isinstance(ScanMode.FAST, str)
        assert isinstance(ScanMode.STANDARD, str)

    def test_json_serializes_as_plain_string(self):
        """成员可被 json 原生序列化为字符串，无需显式 .value。"""
        assert json.dumps(ScanMode.FAST) == '"fast"'
        assert json.dumps(ScanMode.STANDARD) == '"standard"'
        # 在容器内同样按字符串序列化
        assert json.dumps({"mode": ScanMode.DEEP}) == '{"mode": "deep"}'

    def test_json_roundtrip_preserves_value(self):
        s = json.dumps(ScanMode.SMART)
        assert json.loads(s) == "smart"
        assert ScanMode(json.loads(s)) is ScanMode.SMART

    def test_str_lookup_returns_member(self):
        assert ScanMode("fast") is ScanMode.FAST

    def test_member_passes_through_member_lookup(self):
        """ScanMode(已存在的成员) 仍返回该成员（str 子类 hash/eq 与其值一致）。"""
        assert ScanMode(ScanMode.FAST) is ScanMode.FAST
        assert ScanMode(ScanMode.DEEP) is ScanMode.DEEP

    def test_member_hash_compatible_with_str(self):
        """成员 hash 与其字符串值一致，可作为 dict/set 键与字符串互通。"""
        assert hash(ScanMode.FAST) == hash("fast")
        d = {ScanMode.FAST: 1}
        assert d["fast"] == 1
        assert ScanMode.FAST in {"fast"}

    def test_mode_value_still_str(self):
        """.value 仍返回普通字符串（向后兼容 to_dict 等序列化路径）。"""
        assert ScanMode.FAST.value == "fast"
        assert type(ScanMode.FAST.value) is str


# ============================================================
# 2. ScanConfig.from_mode 每种模式
# ============================================================
class TestScanConfigFromMode:
    def test_fast_mode(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        assert cfg.mode is ScanMode.FAST
        # FAST 模式核心特征
        assert cfg.crawl_fast_mode is True
        assert cfg.llm_workers == 0
        # 全部 LLM 阶段被 skip
        assert cfg.skip_business_understanding is True
        assert cfg.skip_meta_analysis is True
        assert cfg.skip_supplemental_test is True
        assert cfg.skip_harm_validation is True
        assert cfg.llm_phase_timeout == 0
        # fast_minimal_checks 保底清单 5 项
        assert cfg.fast_minimal_checks is not None
        assert len(cfg.fast_minimal_checks) == 5
        assert cfg.fast_minimal_checks == [
            "sql_injection",
            "unauthorized_access",
            "info_disclosure",
            "weak_password",
            "cors",
        ]

    def test_fast_mode_accepts_str(self):
        cfg = ScanConfig.from_mode("fast")
        assert cfg.mode is ScanMode.FAST
        assert cfg.llm_workers == 0

    def test_standard_mode(self):
        cfg = ScanConfig.from_mode(ScanMode.STANDARD)
        assert cfg.mode is ScanMode.STANDARD
        assert cfg.llm_workers == 3
        assert cfg.crawl_fast_mode is False
        # 部分阶段 skip
        assert cfg.skip_business_understanding is True
        assert cfg.skip_meta_analysis is True
        # 这两个阶段保留
        assert cfg.skip_supplemental_test is False
        assert cfg.skip_harm_validation is False
        assert cfg.fast_minimal_checks is None

    def test_deep_mode(self):
        cfg = ScanConfig.from_mode(ScanMode.DEEP)
        assert cfg.mode is ScanMode.DEEP
        assert cfg.llm_workers == 5
        assert cfg.crawl_fast_mode is False
        # 不 skip 任何 LLM 阶段
        assert cfg.skip_business_understanding is False
        assert cfg.skip_meta_analysis is False
        assert cfg.skip_supplemental_test is False
        assert cfg.skip_harm_validation is False
        assert cfg.llm_phase_timeout == 1800
        assert cfg.total_timeout == 7200

    def test_smart_mode_uses_defaults(self):
        cfg = ScanConfig.from_mode(ScanMode.SMART)
        assert cfg.mode is ScanMode.SMART
        # 走 dataclass 默认值
        assert cfg.llm_workers == 5
        assert cfg.crawl_fast_mode is False
        assert cfg.crawl_max_pages == 120
        assert cfg.skip_business_understanding is False
        assert cfg.skip_meta_analysis is False
        assert cfg.skip_supplemental_test is False
        assert cfg.skip_harm_validation is False
        assert cfg.fast_minimal_checks is None

    def test_fast_distinct_from_deep(self):
        fast = ScanConfig.from_mode(ScanMode.FAST)
        deep = ScanConfig.from_mode(ScanMode.DEEP)
        assert fast.llm_workers < deep.llm_workers
        assert fast.crawl_fast_mode is True
        assert deep.crawl_fast_mode is False


# ============================================================
# 3. ScanConfig.fast() / standard() 快捷方法
# ============================================================
class TestScanConfigShortcuts:
    def test_fast_shortcut_equals_from_mode(self):
        cfg = ScanConfig.fast()
        assert cfg.mode is ScanMode.FAST
        assert cfg.llm_workers == 0
        ref = ScanConfig.from_mode(ScanMode.FAST)
        assert cfg.crawl_fast_mode == ref.crawl_fast_mode
        assert cfg.llm_workers == ref.llm_workers
        assert cfg.fast_minimal_checks == ref.fast_minimal_checks

    def test_standard_shortcut_equals_from_mode(self):
        cfg = ScanConfig.standard()
        assert cfg.mode is ScanMode.STANDARD
        assert cfg.llm_workers == 3
        ref = ScanConfig.from_mode(ScanMode.STANDARD)
        assert cfg.llm_workers == ref.llm_workers
        assert cfg.crawl_max_pages == ref.crawl_max_pages


# ============================================================
# 4. ScanConfig.to_dict()
# ============================================================
class TestScanConfigToDict:
    def test_to_dict_contains_all_key_fields(self):
        cfg = ScanConfig.from_mode(ScanMode.DEEP)
        d = cfg.to_dict()
        expected_keys = {
            "mode",
            "crawl_max_pages",
            "crawl_fast_mode",
            "fast_scan_enabled",
            "fast_scan_workers",
            "llm_workers",
            "skip_business_understanding",
            "skip_meta_analysis",
            "skip_supplemental_test",
            "skip_harm_validation",
            "total_timeout",
            "enable_skill_routing",
            "skill_routing_top_n",
        }
        assert expected_keys.issubset(d.keys())

    def test_to_dict_mode_serialized_as_string(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        d = cfg.to_dict()
        assert d["mode"] == "fast"
        assert isinstance(d["mode"], str)

    def test_to_dict_reflects_fast_values(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        d = cfg.to_dict()
        assert d["llm_workers"] == 0
        assert d["crawl_fast_mode"] is True
        assert d["skip_harm_validation"] is True
        assert d["skip_business_understanding"] is True

    def test_to_dict_reflects_standard_values(self):
        cfg = ScanConfig.from_mode(ScanMode.STANDARD)
        d = cfg.to_dict()
        assert d["llm_workers"] == 3
        assert d["crawl_fast_mode"] is False
        assert d["skip_supplemental_test"] is False


# ============================================================
# 5. SmartModeSelector.select_mode 多因子评分
# ============================================================
class TestSmartModeSelectMode:
    def test_auth_and_high_value_returns_deep(self):
        features = {
            "url": "http://x.com/pay/order",
            "has_auth": True,
            "page_size": 10000,
            "is_api": False,
            "is_spa": False,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.DEEP

    def test_auth_no_high_value_returns_standard(self):
        features = {
            "url": "http://x.com/home",
            "has_auth": True,
            "page_size": 10000,
            "is_api": False,
            "is_spa": False,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.STANDARD

    def test_auth_and_spa_returns_deep(self):
        features = {
            "url": "http://x.com/home",
            "has_auth": True,
            "page_size": 10000,
            "is_api": False,
            "is_spa": True,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.DEEP

    def test_api_small_page_returns_fast(self):
        features = {
            "url": "http://x.com/api/list",
            "has_auth": False,
            "page_size": 1000,
            "is_api": True,
            "is_spa": False,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.FAST

    def test_small_static_page_returns_fast(self):
        features = {
            "url": "http://x.com/about",
            "has_auth": False,
            "page_size": 2000,
            "is_api": False,
            "is_spa": False,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.FAST

    def test_spa_and_high_value_returns_deep(self):
        features = {
            "url": "http://x.com/pay/wallet",
            "has_auth": False,
            "page_size": 10000,
            "is_api": False,
            "is_spa": True,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.DEEP

    def test_spa_no_high_value_returns_standard(self):
        features = {
            "url": "http://x.com/dashboard",
            "has_auth": False,
            "page_size": 10000,
            "is_api": False,
            "is_spa": True,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.STANDARD

    def test_spa_large_page_returns_deep(self):
        features = {
            "url": "http://x.com/dashboard",
            "has_auth": False,
            "page_size": 60000,
            "is_api": False,
            "is_spa": True,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.DEEP

    def test_high_value_large_page_returns_deep(self):
        features = {
            "url": "http://x.com/upload/file",
            "has_auth": False,
            "page_size": 6000,
            "is_api": False,
            "is_spa": False,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.DEEP

    def test_default_returns_standard(self):
        features = {
            "url": "http://x.com/home",
            "has_auth": False,
            "page_size": 10000,
            "is_api": False,
            "is_spa": False,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.STANDARD

    def test_empty_features_returns_fast(self):
        # page_size=0, is_spa=False, has_auth=False → 因子4 命中 FAST
        assert SmartModeSelector.select_mode({}) is ScanMode.FAST

    def test_high_value_keyword_variants_all_trigger_deep_with_auth(self):
        for kw in ["payment", "transfer", "wallet", "trade", "withdraw", "account", "order"]:
            features = {
                "url": f"http://x.com/{kw}",
                "has_auth": True,
                "page_size": 10000,
                "is_api": False,
                "is_spa": False,
            }
            assert SmartModeSelector.select_mode(features) is ScanMode.DEEP, kw

    def test_api_large_page_no_high_value_returns_standard(self):
        # is_api=True 但 page_size>=5000 → 因子3 不命中，落到默认 STANDARD
        features = {
            "url": "http://x.com/api/big",
            "has_auth": False,
            "page_size": 6000,
            "is_api": True,
            "is_spa": False,
        }
        assert SmartModeSelector.select_mode(features) is ScanMode.STANDARD


# ============================================================
# 5b. SmartModeSelector.analyze_target（mock httpx，零网络）
# ============================================================
class TestSmartModeAnalyzeTarget:
    @staticmethod
    def _make_client(resp):
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        return client

    def test_detects_spa_via_script_count(self):
        resp = MagicMock()
        resp.text = "<html>" + "<script></script>" * 6 + "</html>"
        resp.status_code = 200
        resp.headers = {"content-type": "text/html"}

        with patch("core.scan_strategies.httpx.AsyncClient", return_value=self._make_client(resp)):
            features = asyncio.run(
                SmartModeSelector.analyze_target("http://x.com/app", {"Cookie": "s=1"})
            )

        assert features["url"] == "http://x.com/app"
        assert features["has_auth"] is True
        assert features["status_code"] == 200
        assert features["page_size"] > 0
        assert features["is_spa"] is True
        assert features["is_api"] is False

    def test_detects_api_via_content_type(self):
        resp = MagicMock()
        resp.text = '{"code": 0, "data": []}'
        resp.status_code = 200
        resp.headers = {"content-type": "application/json"}

        with patch("core.scan_strategies.httpx.AsyncClient", return_value=self._make_client(resp)):
            features = asyncio.run(
                SmartModeSelector.analyze_target("http://x.com/api/list", None)
            )

        assert features["is_api"] is True
        assert features["is_spa"] is False
        assert features["has_auth"] is False

    def test_handles_request_exception_gracefully(self):
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None

        with patch("core.scan_strategies.httpx.AsyncClient", return_value=client):
            features = asyncio.run(
                SmartModeSelector.analyze_target("http://x.com/dead", None)
            )

        assert features["url"] == "http://x.com/dead"
        assert features["has_auth"] is False
        assert features["page_size"] == 0
        assert features["status_code"] == 0
        assert features["response_time_ms"] == 0


# ============================================================
# 6. ScanStrategyConfig.from_scan_config 字段透传
# ============================================================
class TestScanStrategyConfig:
    def test_from_scan_config_passes_all_fields(self):
        cfg = ScanConfig.from_mode(ScanMode.DEEP)
        s = ScanStrategyConfig.from_scan_config(cfg)
        assert s.mode is ScanMode.DEEP
        assert s.llm_max_workers == cfg.llm_workers
        assert s.enable_fast_scanner == cfg.fast_scan_enabled
        assert s.skip_meta_analysis == cfg.skip_meta_analysis
        assert s.skip_business_understanding == cfg.skip_business_understanding
        assert s.crawl_max_pages == cfg.crawl_max_pages
        assert s.crawl_fast_mode == cfg.crawl_fast_mode
        assert s.fast_scan_workers == cfg.fast_scan_workers
        assert s.total_timeout == cfg.total_timeout
        assert s.crawl_timeout == cfg.crawl_timeout
        assert s.fast_scan_timeout == cfg.fast_scan_timeout
        assert s.enable_skill_routing == cfg.enable_skill_routing
        assert s.skill_routing_top_n == cfg.skill_routing_top_n
        assert s.fast_minimal_checks == cfg.fast_minimal_checks

    def test_from_scan_config_fast_mode_minimal_checks(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        s = ScanStrategyConfig.from_scan_config(cfg)
        assert s.mode is ScanMode.FAST
        assert s.llm_max_workers == 0
        assert s.crawl_fast_mode is True
        assert s.fast_minimal_checks is not None
        assert len(s.fast_minimal_checks) == 5

    def test_from_scan_config_standard_mode(self):
        cfg = ScanConfig.from_mode(ScanMode.STANDARD)
        s = ScanStrategyConfig.from_scan_config(cfg)
        assert s.llm_max_workers == 3
        assert s.fast_minimal_checks is None
        assert s.crawl_fast_mode is False

    def test_from_scan_config_has_crawl_timeout_attribute(self):
        # 回归：适配器必须带 crawl_timeout（曾因缺失导致崩溃）
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        s = ScanStrategyConfig.from_scan_config(cfg)
        assert hasattr(s, "crawl_timeout")
        assert s.crawl_timeout == cfg.crawl_timeout
        assert s.crawl_timeout == 180


# ============================================================
# 7. get_scan_strategy 用户模式映射
# ============================================================
class TestGetScanStrategy:
    def test_fast(self):
        s = get_scan_strategy("fast")
        assert s.mode is ScanMode.FAST
        assert s.llm_max_workers == 0

    def test_quick_alias_maps_to_fast(self):
        s = get_scan_strategy("quick")
        assert s.mode is ScanMode.FAST

    def test_standard(self):
        s = get_scan_strategy("standard")
        assert s.mode is ScanMode.STANDARD
        assert s.llm_max_workers == 3

    def test_deep(self):
        s = get_scan_strategy("deep")
        assert s.mode is ScanMode.DEEP
        assert s.llm_max_workers == 5

    def test_smart(self):
        s = get_scan_strategy("smart")
        assert s.mode is ScanMode.SMART

    def test_batch_alias_maps_to_standard(self):
        s = get_scan_strategy("batch")
        assert s.mode is ScanMode.STANDARD

    def test_unknown_returns_standard(self):
        s = get_scan_strategy("nonexistent_mode")
        assert s.mode is ScanMode.STANDARD

    def test_returns_scan_strategy_config_instance(self):
        s = get_scan_strategy("fast")
        assert isinstance(s, ScanStrategyConfig)

    def test_fast_strategy_carries_minimal_checks(self):
        s = get_scan_strategy("fast")
        assert s.fast_minimal_checks is not None
        assert len(s.fast_minimal_checks) == 5


# ============================================================
# 8. ScanExecutor 基础行为（零网络）
# ============================================================
class TestScanExecutor:
    def test_initial_state(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        ex = ScanExecutor(cfg)
        assert ex.config is cfg
        assert ex.findings == []
        assert ex.elapsed == 0
        assert ex._progress_callbacks == []

    def test_on_progress_registers_callback(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        ex = ScanExecutor(cfg)
        cb = lambda evt: None  # noqa: E731
        ex.on_progress(cb)
        assert cb in ex._progress_callbacks
        assert len(ex._progress_callbacks) == 1
        # 可注册多个
        ex.on_progress(lambda evt: None)
        assert len(ex._progress_callbacks) == 2

    def test_emit_progress_invokes_sync_callback(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        ex = ScanExecutor(cfg)
        events = []
        ex.on_progress(lambda e: events.append(e))
        asyncio.run(ex._emit_progress("crawl", "starting", 0.1))
        assert len(events) == 1
        assert events[0]["phase"] == "crawl"
        assert events[0]["message"] == "starting"
        assert events[0]["progress"] == 0.1

    def test_emit_progress_invokes_async_callback(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        ex = ScanExecutor(cfg)
        events = []

        async def cb(e):
            events.append(e)

        ex.on_progress(cb)
        asyncio.run(ex._emit_progress("done", "finished", 1.0))
        assert len(events) == 1
        assert events[0]["phase"] == "done"
        assert events[0]["progress"] == 1.0

    def test_emit_progress_swallows_callback_exception(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        ex = ScanExecutor(cfg)

        def bad_cb(e):
            raise RuntimeError("boom")

        ex.on_progress(bad_cb)
        # 不应抛出，异常被吞掉
        asyncio.run(ex._emit_progress("crawl", "x", 0.0))

    def test_execute_fast_mode_no_findings(self):
        """FAST 模式 + 爬虫返回空 API 列表 → 走完流程并返回结构化结果。

        关键：关闭 enable_skill_routing 以规避源码中 fast_findings 未定义的潜在 NameError
        （当 crawl_apis 为空时 fast_findings 不会在 Phase 1 被绑定）。
        """
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        cfg.enable_skill_routing = False
        ex = ScanExecutor(cfg)

        with patch("core.auto_crawler.AutoCrawler") as MockCrawler:
            MockCrawler.return_value.crawl = AsyncMock(return_value={"apis": []})
            result = asyncio.run(ex.execute("http://x.com", None, None))

        assert result["target"] == "http://x.com"
        assert result["mode"] == "fast"
        assert result["findings"] == []
        assert result["fast_scan_result"] is None
        assert result["llm_scan_used"] is False
        assert result["findings_count"] == 0
        assert result["elapsed"] >= 0
        assert ex.elapsed >= 0

    def test_execute_emits_progress_events(self):
        cfg = ScanConfig.from_mode(ScanMode.FAST)
        cfg.enable_skill_routing = False
        ex = ScanExecutor(cfg)
        events = []
        ex.on_progress(lambda e: events.append(e["phase"]))

        with patch("core.auto_crawler.AutoCrawler") as MockCrawler:
            MockCrawler.return_value.crawl = AsyncMock(return_value={"apis": []})
            asyncio.run(ex.execute("http://x.com", None, None))

        # 至少包含 crawl 与 done 阶段
        assert "crawl" in events
        assert "done" in events
