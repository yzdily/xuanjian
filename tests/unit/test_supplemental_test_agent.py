"""
SupplementalTestAgent 单元测试（Phase 2.55 补测 Agent）

验证点：
- 关键常量值正确性（PER_API_TIMEOUT_S / TOTAL_BUDGET_S / FEATURES_PER_WORKER）
- 第三方域名黑名单过滤逻辑（_is_third_party：精确 + 子域后缀匹配）
- 作用域判定（_host_in_scope：精确 + 后缀匹配）
- 新 API 发现与过滤（discover_new_apis_from_flows：scope/第三方/2xx/已知/时间戳/去重）
- _DiscoveredAPI 归一化 key
- _normalize_related_api_for_scan 多格式归一化
- _find_best_matching_feature 共同前缀匹配
- 补测总预算控制（run_supplemental_test：剩余预算 < 30s 时跳过剩余 feature）

设计说明：
- 纯本地规则，零网络、零真实 LLM。
- discover_new_apis_from_flows 用 tmp_path 写临时 flows.jsonl 驱动。
- run_supplemental_test 预算测试用 patch 替换发现/挂载函数 + 注入 fake time，
  让 budget_deadline 立即过期，验证剩余 feature 被标记 skipped。
- 异步测试用 @pytest.mark.asyncio 标记（pytest-asyncio strict 模式）。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import core.supplemental_test_agent as sta
from core.supplemental_test_agent import (
    FEATURES_PER_WORKER,
    PER_API_TIMEOUT_S,
    TOTAL_BUDGET_S,
    _DiscoveredAPI,
    _find_best_matching_feature,
    _host_in_scope,
    _is_non_business_path,
    _is_third_party,
    _normalize_related_api_for_scan,
    discover_new_apis_from_flows,
)
from core.sitemap.models import CheckItem, CheckResult, FeaturePoint, Priority


# ============================================================
# 通用辅助
# ============================================================

class FakeMap:
    """discover_new_apis_from_flows 使用的轻量 sitemap 桩。"""

    def __init__(self, apis=None, extra_scope=None):
        self.apis: dict = apis or {}
        self.extra_scope: list = extra_scope or []
        self.features: dict = {}
        self.api_samples: dict = {}


def _flow(
    url: str,
    method: str = "GET",
    status_code: int = 200,
    timestamp: float = 1000.0,
    flow_id: str = "f1",
    task_id: str = "",
    response_body: str = "",
    content_type: str = "application/json",
) -> dict:
    return {
        "method": method,
        "url": url,
        "status_code": status_code,
        "timestamp": timestamp,
        "id": flow_id,
        "task_id": task_id,
        "response_body": response_body,
        "content_type": content_type,
        "request_body": "",
    }


def _write_flows(tmp_path: Path, flows: list[dict]) -> Path:
    p = tmp_path / "flows.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        for fl in flows:
            f.write(json.dumps(fl) + "\n")
    return p


async def _collect(async_gen) -> list:
    out: list = []
    async for item in async_gen:
        out.append(item)
    return out


def _make_feature(fid="fp-1", name="用户管理", related_apis=None) -> FeaturePoint:
    fp = FeaturePoint(
        id=fid, name=name, description="功能描述", priority=Priority.MEDIUM,
        related_apis=list(related_apis or []),
    )
    fp.checklist.append(CheckItem(vuln_type="IDOR", result=CheckResult.PENDING))
    return fp


# ============================================================
# 常量
# ============================================================

class TestConstants:
    """补测 Agent 关键常量。"""

    def test_per_api_timeout_is_60s(self):
        assert PER_API_TIMEOUT_S == 60.0

    def test_total_budget_is_30_minutes(self):
        assert TOTAL_BUDGET_S == 30 * 60.0
        assert TOTAL_BUDGET_S == 1800.0

    def test_features_per_worker_is_5(self):
        assert FEATURES_PER_WORKER == 5


# ============================================================
# 第三方域名黑名单
# ============================================================

class TestThirdPartyBlacklist:
    """_is_third_party 过滤逻辑。"""

    def test_blacklisted_exact_domain_filtered(self):
        assert _is_third_party("google-analytics.com") is True
        assert _is_third_party("sentry.io") is True
        assert _is_third_party("hm.baidu.com") is True

    def test_blacklisted_subdomain_filtered(self):
        # 子域后缀匹配黑名单根域
        assert _is_third_party("api.google-analytics.com") is True
        assert _is_third_party("sub.sentry.io") is True
        assert _is_third_party("x.y.datadoghq.com") is True

    def test_business_domain_not_filtered(self):
        assert _is_third_party("example.com") is False
        assert _is_third_party("api.target.cn") is False
        assert _is_third_party("moa.jd.com") is False

    def test_empty_and_dot_prefixed_host(self):
        assert _is_third_party("") is False
        assert _is_third_party(None) is False
        # 前导点应被剥离后匹配
        assert _is_third_party(".google-analytics.com") is True

    def test_blacklist_is_set_and_nonempty(self):
        bl = sta._THIRD_PARTY_BLACKLIST
        assert isinstance(bl, set)
        assert len(bl) > 50, "黑名单应包含大量第三方域名"
        # 抽样若干代表
        for d in ("google-analytics.com", "sentry.io", "cloudflare.com", "hm.baidu.com"):
            assert d in bl


# ============================================================
# 作用域判定
# ============================================================

class TestHostInScope:
    """_host_in_scope 精确 + 后缀匹配。"""

    def test_exact_match(self):
        assert _host_in_scope("api.example.com", {"api.example.com"}) is True

    def test_suffix_match_subdomain(self):
        # in_scope = {jd.com} → qw.jd.com 命中
        assert _host_in_scope("qw.jd.com", {"jd.com"}) is True
        assert _host_in_scope("a.b.jd.com", {"jd.com"}) is True

    def test_not_match_different_root(self):
        assert _host_in_scope("evil.com", {"jd.com"}) is False
        # 注意：后缀匹配需以 "." 分隔，jd.com 不应匹配 notjd.com
        assert _host_in_scope("notjd.com", {"jd.com"}) is False

    def test_empty_host_returns_false(self):
        assert _host_in_scope("", {"jd.com"}) is False
        assert _host_in_scope("api.example.com", set()) is False

    def test_multiple_scope_entries(self):
        scopes = {"jd.com", "api.example.com"}
        assert _host_in_scope("moa.jd.com", scopes) is True
        assert _host_in_scope("api.example.com", scopes) is True
        assert _host_in_scope("v2.api.example.com", scopes) is True
        assert _host_in_scope("other.com", scopes) is False


# ============================================================
# _DiscoveredAPI 与路径过滤
# ============================================================

class TestDiscoveredAPI:
    """_DiscoveredAPI 数据结构与 key 归一化。"""

    def test_key_strips_query_and_lowercases_host(self):
        flow = _flow(url="https://API.Example.com/users/1?foo=bar", method="get")
        api = _DiscoveredAPI(flow)
        # method 大写、host 小写、path 不含 query
        assert api.method == "GET"
        assert api.host == "api.example.com"
        assert api.path == "/users/1"
        assert api.key == "GET api.example.com/users/1"

    def test_is_non_business_path_filters_static(self):
        assert _is_non_business_path("/static/app.js") is True
        assert _is_non_business_path("/logo.png") is True
        assert _is_non_business_path("/assets/style.css") is True

    def test_is_non_business_path_keeps_business(self):
        assert _is_non_business_path("/api/users/list") is False
        assert _is_non_business_path("/order/create") is False


# ============================================================
# discover_new_apis_from_flows 过滤链
# ============================================================

class TestDiscoverNewApisFromFlows:
    """新 API 发现 + 多维过滤。"""

    def test_keeps_in_scope_2xx_business_api(self, tmp_path):
        """scope 内、2xx、业务路径、未知 → 保留 1 条。"""
        sitemap = FakeMap()
        flows = [_flow(url="https://target.com/api/orders/1", status_code=200, timestamp=2000.0)]
        path = _write_flows(tmp_path, flows)

        apis, stats = discover_new_apis_from_flows(
            sitemap=sitemap, target_url="https://target.com",
            phase2_started_at=1000.0, flows_path=path,
        )
        assert len(apis) == 1
        assert apis[0].key == "GET target.com/api/orders/1"
        assert stats["total_scanned"] == 1
        assert stats["kept"] == 1
        assert stats["flow_file"] == str(path)

    def test_filters_third_party_and_out_of_scope(self, tmp_path):
        """第三方域名（在 scope 内）+ 超出 scope 的 host 被分别过滤，统计正确。

        注意：discover_new_apis_from_flows 先做 scope 过滤再做第三方黑名单过滤，
        所以"第三方域名"只有当其落在 scope 内（如 extra_scope 显式纳入）才会被
        计入 third_party；否则会被计入 out_of_scope。
        """
        # sentry.io 显式纳入 extra_scope → 在 scope 内但仍命中黑名单 → third_party
        sitemap = FakeMap(extra_scope=["sentry.io"])
        flows = [
            _flow(url="https://target.com/api/a", status_code=200, timestamp=2000.0, flow_id="1"),
            _flow(url="https://sentry.io/api/store", status_code=200, timestamp=2000.0, flow_id="2"),
            _flow(url="https://evil.com/api/x", status_code=200, timestamp=2000.0, flow_id="3"),
        ]
        path = _write_flows(tmp_path, flows)

        apis, stats = discover_new_apis_from_flows(
            sitemap=sitemap, target_url="https://target.com",
            phase2_started_at=1000.0, flows_path=path,
        )
        assert len(apis) == 1
        assert apis[0].host == "target.com"
        assert stats["third_party"] == 1, f"sentry.io 应被计入 third_party，实际 stats: {stats}"
        assert stats["out_of_scope"] == 1, f"evil.com 应被计入 out_of_scope，实际 stats: {stats}"
        assert stats["kept"] == 1

    def test_filters_non_2xx_responses(self, tmp_path):
        """非 2xx 响应不保留。"""
        sitemap = FakeMap()
        flows = [
            _flow(url="https://target.com/api/ok", status_code=200, timestamp=2000.0, flow_id="1"),
            _flow(url="https://target.com/api/err", status_code=500, timestamp=2000.0, flow_id="2"),
            _flow(url="https://target.com/api/redirect", status_code=302, timestamp=2000.0, flow_id="3"),
            _flow(url="https://target.com/api/notfound", status_code=404, timestamp=2000.0, flow_id="4"),
        ]
        path = _write_flows(tmp_path, flows)

        apis, stats = discover_new_apis_from_flows(
            sitemap=sitemap, target_url="https://target.com",
            phase2_started_at=1000.0, flows_path=path,
        )
        assert len(apis) == 1
        assert apis[0].path == "/api/ok"
        assert stats["not_2xx"] == 3
        assert stats["kept"] == 1

    def test_dedup_against_known_apis(self, tmp_path):
        """已在 sitemap.apis 中的 API 被过滤（already_known）。"""
        sitemap = FakeMap(apis={"GET https://target.com/api/users": object()})
        flows = [
            _flow(url="https://target.com/api/users", status_code=200, timestamp=2000.0, flow_id="1"),
            _flow(url="https://target.com/api/orders", status_code=200, timestamp=2000.0, flow_id="2"),
        ]
        path = _write_flows(tmp_path, flows)

        apis, stats = discover_new_apis_from_flows(
            sitemap=sitemap, target_url="https://target.com",
            phase2_started_at=1000.0, flows_path=path,
        )
        assert len(apis) == 1
        assert apis[0].path == "/api/orders"
        assert stats["already_known"] == 1

    def test_filters_flows_before_phase2_timestamp(self, tmp_path):
        """timestamp < phase2_started_at 的流量被过滤。"""
        sitemap = FakeMap()
        flows = [
            _flow(url="https://target.com/api/old", status_code=200, timestamp=500.0, flow_id="1"),
            _flow(url="https://target.com/api/new", status_code=200, timestamp=2000.0, flow_id="2"),
        ]
        path = _write_flows(tmp_path, flows)

        apis, stats = discover_new_apis_from_flows(
            sitemap=sitemap, target_url="https://target.com",
            phase2_started_at=1000.0, flows_path=path,
        )
        assert len(apis) == 1
        assert apis[0].path == "/api/new"
        assert stats["before_phase2"] == 1

    def test_dedup_duplicate_flows(self, tmp_path):
        """同一新 API 多次出现只保留第一条。"""
        sitemap = FakeMap()
        flows = [
            _flow(url="https://target.com/api/x", status_code=200, timestamp=2000.0, flow_id="1"),
            _flow(url="https://target.com/api/x", status_code=200, timestamp=2100.0, flow_id="2"),
        ]
        path = _write_flows(tmp_path, flows)

        apis, stats = discover_new_apis_from_flows(
            sitemap=sitemap, target_url="https://target.com",
            phase2_started_at=1000.0, flows_path=path,
        )
        assert len(apis) == 1
        assert stats["duplicate"] == 1
        assert stats["kept"] == 1

    def test_task_id_filter_excludes_other_tasks(self, tmp_path):
        """指定 task_id 时，归属其他任务的流量被过滤。"""
        sitemap = FakeMap()
        flows = [
            _flow(url="https://target.com/api/a", status_code=200, timestamp=2000.0, flow_id="1", task_id="t1"),
            _flow(url="https://target.com/api/b", status_code=200, timestamp=2000.0, flow_id="2", task_id="t2"),
        ]
        path = _write_flows(tmp_path, flows)

        apis, stats = discover_new_apis_from_flows(
            sitemap=sitemap, target_url="https://target.com",
            phase2_started_at=1000.0, flows_path=path, task_id="t1",
        )
        assert len(apis) == 1
        assert apis[0].path == "/api/a"
        assert stats["other_task"] == 1

    def test_missing_flows_file_returns_empty(self, tmp_path):
        """flows.jsonl 不存在时返回空列表并标记 flow_file_missing。"""
        sitemap = FakeMap()
        apis, stats = discover_new_apis_from_flows(
            sitemap=sitemap, target_url="https://target.com",
            phase2_started_at=1000.0, flows_path=tmp_path / "not_exist.jsonl",
        )
        assert apis == []
        assert stats.get("flow_file_missing") == 1


# ============================================================
# _normalize_related_api_for_scan
# ============================================================

class TestNormalizeRelatedApi:
    """related_apis 多格式归一化为 (method, url)。"""

    def test_full_url_with_method(self):
        assert _normalize_related_api_for_scan(
            "POST https://example.com/api/user", "https://example.com"
        ) == ("POST", "https://example.com/api/user")

    def test_path_only_prepended_with_target(self):
        assert _normalize_related_api_for_scan(
            "/api/user", "https://example.com"
        ) == ("GET", "https://example.com/api/user")

    def test_method_and_path_only(self):
        assert _normalize_related_api_for_scan(
            "DELETE /api/user/1", "https://example.com"
        ) == ("DELETE", "https://example.com/api/user/1")

    def test_protocol_relative_url(self):
        m, u = _normalize_related_api_for_scan("//cdn.example.com/x", "https://example.com")
        assert m == "GET"
        assert u == "https://cdn.example.com/x"

    def test_empty_input_returns_none(self):
        assert _normalize_related_api_for_scan("", "https://example.com") is None
        assert _normalize_related_api_for_scan("   ", "https://example.com") is None

    def test_path_only_without_target_returns_none(self):
        assert _normalize_related_api_for_scan("/api/user", "") is None


# ============================================================
# _find_best_matching_feature
# ============================================================

class TestFindBestMatchingFeature:
    """按 path 共同前缀段数匹配现有 feature。"""

    def test_matches_by_common_prefix(self):
        sitemap = FakeMap()
        fp = _make_feature(related_apis=["GET /api/users/list"])
        sitemap.features["fp-1"] = fp
        api = _DiscoveredAPI(_flow(url="https://target.com/api/users/1"))
        matched = _find_best_matching_feature(sitemap, api)
        assert matched is fp

    def test_no_match_returns_none(self):
        sitemap = FakeMap()
        fp = _make_feature(related_apis=["GET /api/orders/list"])
        sitemap.features["fp-1"] = fp
        # /api/users/1 与 /api/orders/list 仅共享 /api（1 段），不足 2 段
        api = _DiscoveredAPI(_flow(url="https://target.com/api/users/1"))
        assert _find_best_matching_feature(sitemap, api) is None

    def test_short_path_no_match(self):
        sitemap = FakeMap()
        fp = _make_feature(related_apis=["GET /api/users"])
        sitemap.features["fp-1"] = fp
        # api path 段数 < 2 → 直接返回 None
        api = _DiscoveredAPI(_flow(url="https://target.com/x"))
        assert _find_best_matching_feature(sitemap, api) is None


# ============================================================
# 补测总预算控制（run_supplemental_test）
# ============================================================

class TestBudgetControl:
    """run_supplemental_test 的总预算熔断。"""

    @pytest.mark.asyncio
    async def test_budget_exhausted_skips_remaining_features(self, tmp_path):
        """剩余预算 < 30s 时，所有 feature 被标记 skipped，不启动 worker。"""
        from core.sitemap.models import TestStatus

        # 准备 3 个带 checklist 的新 feature（超过 FEATURES_PER_WORKER 的一半，便于观察跳过）
        new_features = [
            _make_feature(fid=f"fp-{i}", name=f"补测功能{i}",
                          related_apis=[f"GET https://target.com/api/new{i}"])
            for i in range(3)
        ]

        # 假 session：持有 sitemap/target_url/task_id/_phase2_started_at
        sitemap = FakeMap()
        # start_test 被 run_supplemental_test 调用，需提供
        sitemap.start_test = MagicMock()
        sitemap.features = {fp.id: fp for fp in new_features}
        session = SimpleNamespace(
            sitemap=sitemap,
            target_url="https://target.com",
            task_id="t1",
            _phase2_started_at=1000.0,
            llm=None,
            _inject_cookies="",
            _inject_headers={},
        )

        # fake time：第一次返回 0（started），之后返回 2000（预算 1800 已耗尽）
        calls = {"n": 0}

        def fake_time():
            calls["n"] += 1
            return 0.0 if calls["n"] == 1 else 2000.0

        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([SimpleNamespace()], {
                              "total_scanned": 1, "before_phase2": 0, "other_task": 0,
                              "out_of_scope": 0, "third_party": 0, "not_2xx": 0,
                              "non_business": 0, "already_known": 0, "duplicate": 0,
                              "kept": 1, "flow_file": "x",
                          })), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], {
                              "dirscan_total": 0, "dirscan_discovered": 0,
                              "dirscan_sensitive": 0, "dirscan_already_known": 0,
                              "dirscan_duplicate": 0, "dirscan_error": "",
                          }))), \
             patch.object(sta, "attach_apis_to_sitemap",
                          return_value=(list(new_features), [])), \
             patch.object(sta.time, "time", side_effect=fake_time), \
             patch("core.parallel.get_session_info", new=AsyncMock(return_value={})):
            events = await _collect(sta.run_supplemental_test(session))

        # 找到 done 事件，校验 summary
        done_evt = next(e for e in events if e.get("type") == "done")
        summary = done_evt["summary"]
        # 预算耗尽 → 3 个 feature 全部 skipped，0 个 tested
        assert summary["skipped_features"] == 3, f"应跳过 3 个，实际: {summary}"
        assert summary["tested_features"] == 0
        # 应有预算耗尽警告事件
        warn_msgs = [str(e.get("msg", "")) for e in events if e.get("type") == "warn"]
        assert any("预算" in m and "跳过" in m for m in warn_msgs), \
            f"应包含预算耗尽警告，实际 warn 事件: {warn_msgs}"
        # 不应实际启动任何 worker（无 worker_event 透传，无 🚀 启动日志）
        assert not any(e.get("type") == "worker_event" for e in events), \
            "预算耗尽时不应启动 worker（不应有 worker_event）"
        info_msgs = [str(e.get("msg", "")) for e in events if e.get("type") == "info"]
        assert not any("🚀 启动补测 Agent" in m for m in info_msgs), \
            "预算耗尽时不应出现 worker 启动日志"

    @pytest.mark.asyncio
    async def test_no_new_apis_skips_phase_255(self):
        """未发现新 API 时直接结束，不挂载/不启动 worker。"""
        sitemap = FakeMap()
        session = SimpleNamespace(
            sitemap=sitemap, target_url="https://target.com", task_id="t1",
            _phase2_started_at=1000.0, llm=None,
            _inject_cookies="", _inject_headers={},
        )

        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([], {
                              "total_scanned": 0, "before_phase2": 0, "other_task": 0,
                              "out_of_scope": 0, "third_party": 0, "not_2xx": 0,
                              "non_business": 0, "already_known": 0, "duplicate": 0,
                              "kept": 0, "flow_file": "x",
                          })), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], {
                              "dirscan_total": 0, "dirscan_discovered": 0,
                              "dirscan_sensitive": 0, "dirscan_already_known": 0,
                              "dirscan_duplicate": 0, "dirscan_error": "",
                          }))), \
             patch.object(sta, "attach_apis_to_sitemap") as attach_mock:
            events = await _collect(sta.run_supplemental_test(session))

        done_evt = next(e for e in events if e.get("type") == "done")
        summary = done_evt["summary"]
        assert summary["discovered"] == 0
        assert summary["new_features"] == 0
        assert summary["tested_features"] == 0
        # 未发现新 API → 不应调用 attach_apis_to_sitemap
        attach_mock.assert_not_called()
        # 应有"未发现需要补测的新 API"提示
        info_msgs = [str(e.get("msg", "")) for e in events if e.get("type") == "info"]
        assert any("未发现需要补测" in m for m in info_msgs), \
            f"应包含未发现新 API 提示，实际: {info_msgs}"
