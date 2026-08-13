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

import asyncio
import json
import sys
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


# ============================================================
# discover_apis_from_dirscan 主动目录爆破
# ============================================================

def _make_dir_entry(path: str, url: str | None = None, status: int = 200,
                    content_type: str = "application/json") -> SimpleNamespace:
    """构造目录扫描 entry 桩对象。"""
    return SimpleNamespace(
        path=path,
        url=url or f"https://target.com{path}",
        status=status,
        content_type=content_type,
    )


def _make_dir_result(entries=None, findings=None, total_requests: int = 10,
                     waf_blocked: bool = False, timeout_blocked: bool = False,
                     sensitive_count: int | None = None) -> SimpleNamespace:
    """构造目录扫描结果桩对象。"""
    findings = findings or []
    return SimpleNamespace(
        entries=entries or [],
        findings=findings,
        total_requests=total_requests,
        waf_blocked=waf_blocked,
        timeout_blocked=timeout_blocked,
        sensitive_count=len(findings) if sensitive_count is None else sensitive_count,
    )


class TestDiscoverApisFromDirscan:
    """discover_apis_from_dirscan 主动目录爆破发现新 API。

    通过 patch core.dir_scanner.DirectoryScanner 隔离真实扫描，
    验证空目标/导入失败/异常/过滤/去重/敏感发现透传等场景。
    """

    @pytest.mark.asyncio
    async def test_empty_target_url_returns_empty(self):
        """target_url 为空 → 直接返回空列表，不启动扫描。"""
        sitemap = FakeMap()
        apis, stats = await sta.discover_apis_from_dirscan(
            sitemap=sitemap, target_url="", auth_headers=None, existing_apis=None,
        )
        assert apis == []
        assert stats["dirscan_error"] == ""
        assert stats["dirscan_discovered"] == 0

    @pytest.mark.asyncio
    async def test_import_failure_returns_empty(self):
        """DirectoryScanner 导入失败 → 返回空列表，dirscan_error 含"导入失败"。"""
        sitemap = FakeMap()
        with patch.dict("sys.modules", {"core.dir_scanner": None}):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers=None, existing_apis=None,
            )
        assert apis == []
        assert "导入失败" in stats["dirscan_error"]

    @pytest.mark.asyncio
    async def test_normal_scan_returns_discovered(self):
        """正常扫描：scanner.scan() 返回有 entries 的 dir_result → 返回 discovered 列表。"""
        sitemap = FakeMap()
        entries = [
            _make_dir_entry(path="/api/users/list"),
            _make_dir_entry(path="/api/orders/detail"),
        ]
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=_make_dir_result(
            entries=entries, total_requests=50,
        ))
        with patch("core.dir_scanner.DirectoryScanner", return_value=mock_scanner):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers=None, existing_apis=None,
            )
        assert len(apis) == 2
        assert stats["dirscan_total"] == 50
        assert stats["dirscan_discovered"] == 2
        assert stats["dirscan_error"] == ""

    @pytest.mark.asyncio
    async def test_scan_exception_returns_error(self):
        """scanner.scan() 抛异常 → 返回空列表，dirscan_error 含异常类型和信息。"""
        sitemap = FakeMap()
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(side_effect=RuntimeError("connection refused"))
        with patch("core.dir_scanner.DirectoryScanner", return_value=mock_scanner):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers=None, existing_apis=None,
            )
        assert apis == []
        assert "RuntimeError" in stats["dirscan_error"]
        assert "connection refused" in stats["dirscan_error"]

    @pytest.mark.asyncio
    async def test_non_business_path_filtered(self):
        """entries 含非业务路径（/static/x.js）→ 被过滤，不计入 discovered。"""
        sitemap = FakeMap()
        entries = [
            _make_dir_entry(path="/static/app.js", content_type="application/javascript"),
            _make_dir_entry(path="/api/users"),
        ]
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=_make_dir_result(entries=entries))
        with patch("core.dir_scanner.DirectoryScanner", return_value=mock_scanner):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers=None, existing_apis=None,
            )
        assert len(apis) == 1
        assert apis[0].path == "/api/users"
        assert stats["dirscan_discovered"] == 1

    @pytest.mark.asyncio
    async def test_out_of_scope_host_filtered(self):
        """entries 含 scope 外 host → 被过滤。"""
        sitemap = FakeMap()
        entries = [
            _make_dir_entry(path="/api/evil", url="https://evil.com/api/evil"),
            _make_dir_entry(path="/api/ok", url="https://target.com/api/ok"),
        ]
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=_make_dir_result(entries=entries))
        with patch("core.dir_scanner.DirectoryScanner", return_value=mock_scanner):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers=None, existing_apis=None,
            )
        assert len(apis) == 1
        assert apis[0].host == "target.com"

    @pytest.mark.asyncio
    async def test_known_api_counted(self):
        """entries 含已知 API（在 sitemap.apis 中）→ 统计 dirscan_already_known。"""
        sitemap = FakeMap(apis={"GET https://target.com/api/users": object()})
        entries = [
            _make_dir_entry(path="/api/users"),
            _make_dir_entry(path="/api/orders"),
        ]
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=_make_dir_result(entries=entries))
        with patch("core.dir_scanner.DirectoryScanner", return_value=mock_scanner):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers=None, existing_apis=None,
            )
        assert len(apis) == 1
        assert apis[0].path == "/api/orders"
        assert stats["dirscan_already_known"] == 1

    @pytest.mark.asyncio
    async def test_duplicate_entries_deduped(self):
        """entries 有重复 → 去重只保留 1 条。

        首条 discovery 后 key 被加入 known_keys，第二条命中 already_known 计数。
        """
        sitemap = FakeMap()
        entries = [
            _make_dir_entry(path="/api/users"),
            _make_dir_entry(path="/api/users"),
        ]
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=_make_dir_result(entries=entries))
        with patch("core.dir_scanner.DirectoryScanner", return_value=mock_scanner):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers=None, existing_apis=None,
            )
        assert len(apis) == 1
        # 首条 discovery 后 key 加入 known_keys，第二条命中 already_known
        assert stats["dirscan_already_known"] == 1
        assert stats["dirscan_discovered"] == 1

    @pytest.mark.asyncio
    async def test_sensitive_findings_passthrough(self):
        """dir_result 有 findings → 透传到 stats["dirscan_sensitive_findings"]。"""
        sitemap = FakeMap()
        findings = [
            SimpleNamespace(vuln_type="info_leak", severity="high",
                            url="https://target.com/.git/config"),
        ]
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=_make_dir_result(
            entries=[], findings=findings, total_requests=20,
        ))
        with patch("core.dir_scanner.DirectoryScanner", return_value=mock_scanner):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers=None, existing_apis=None,
            )
        assert apis == []
        assert "dirscan_sensitive_findings" in stats
        assert len(stats["dirscan_sensitive_findings"]) == 1
        assert stats["dirscan_sensitive_findings"][0]["vuln_type"] == "info_leak"
        assert stats["dirscan_sensitive_findings"][0]["severity"] == "high"
        assert stats["dirscan_sensitive_findings"][0]["url"] == "https://target.com/.git/config"

    @pytest.mark.asyncio
    async def test_waf_blocked_passthrough(self):
        """dir_result.waf_blocked 为 True → 透传到 stats["waf_blocked"]。"""
        sitemap = FakeMap()
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=_make_dir_result(
            entries=[], total_requests=5, waf_blocked=True,
        ))
        with patch("core.dir_scanner.DirectoryScanner", return_value=mock_scanner):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers=None, existing_apis=None,
            )
        assert stats["waf_blocked"] is True
        assert stats["timeout_blocked"] is False

    @pytest.mark.asyncio
    async def test_stats_dirscan_total_and_discovered(self):
        """stats 正确设置 dirscan_total 和 dirscan_discovered。"""
        sitemap = FakeMap()
        entries = [
            _make_dir_entry(path="/api/a"),
            _make_dir_entry(path="/api/b"),
            _make_dir_entry(path="/api/c"),
        ]
        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=_make_dir_result(
            entries=entries, total_requests=100,
        ))
        with patch("core.dir_scanner.DirectoryScanner", return_value=mock_scanner):
            apis, stats = await sta.discover_apis_from_dirscan(
                sitemap=sitemap, target_url="https://target.com",
                auth_headers={"Authorization": "Bearer x"}, existing_apis=None,
            )
        assert stats["dirscan_total"] == 100
        assert stats["dirscan_discovered"] == 3
        assert len(apis) == 3


# ============================================================
# _fallback_cdp_recapture CDP 流量重捕获
# ============================================================

class TestFallbackCdpRecapture:
    """_fallback_cdp_recapture mitmproxy 故障时通过 CDP 重捕获流量。

    通过 patch core.crawler.crawler_core.get_cdp_flows 隔离真实 CDP 调用，
    验证正常返回/ImportError/其他异常/空流量等场景。
    """

    @pytest.mark.asyncio
    async def test_returns_cdp_flows(self):
        """正常返回 cdp_flows → 返回 flow 列表。"""
        flows = [
            {"url": "https://target.com/api/x", "method": "GET"},
            {"url": "https://target.com/api/y", "method": "POST"},
        ]
        with patch("core.crawler.crawler_core.get_cdp_flows",
                   new=AsyncMock(return_value=flows)):
            result = await sta._fallback_cdp_recapture("https://target.com")
        assert result == flows
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_import_error_returns_empty(self):
        """ImportError（CDP 模块不可用）→ 返回空列表。"""
        with patch.dict("sys.modules", {"core.crawler.crawler_core": None}):
            result = await sta._fallback_cdp_recapture("https://target.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_other_exception_returns_empty(self):
        """其他异常（如超时）→ 返回空列表。"""
        with patch("core.crawler.crawler_core.get_cdp_flows",
                   new=AsyncMock(side_effect=RuntimeError("cdp timeout"))):
            result = await sta._fallback_cdp_recapture("https://target.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_cdp_flows_returns_empty(self):
        """cdp_flows 为空 → 返回空列表。"""
        with patch("core.crawler.crawler_core.get_cdp_flows",
                   new=AsyncMock(return_value=[])):
            result = await sta._fallback_cdp_recapture("https://target.com")
        assert result == []


# ============================================================
# _fallback_passive_js_analysis 被动 JS 分析
# ============================================================

class TestFallbackPassiveJsAnalysis:
    """_fallback_passive_js_analysis 从 JS 源码缓存正则提取 API 路径。

    通过 patch core.js_analyzer._js_source_cache 和 _normalize_target_key
    隔离真实缓存，验证正则匹配/多文件合并/去重/sitemap 回退/异常等场景。
    """

    @pytest.mark.asyncio
    async def test_js_cache_with_api_paths(self):
        """js_cache 有内容，JS 含 API 路径模式 → 返回 discovered 列表。"""
        js_cache = {"target_key": {"js1.js": "fetch('/api/users/list');"}}
        with patch("core.js_analyzer._js_source_cache", js_cache), \
             patch("core.js_analyzer._normalize_target_key", return_value="target_key"):
            result = await sta._fallback_passive_js_analysis("https://target.com", None)
        assert len(result) == 1
        assert result[0]["path"] == "/api/users/list"
        assert result[0]["method"] == "GET"
        assert result[0]["source"] == "passive_js"
        assert result[0]["url"] == "https://target.com/api/users/list"

    @pytest.mark.asyncio
    async def test_empty_js_cache_returns_empty(self):
        """js_cache 为空 → 返回空列表。"""
        with patch("core.js_analyzer._js_source_cache", {}), \
             patch("core.js_analyzer._normalize_target_key", return_value="target_key"):
            result = await sta._fallback_passive_js_analysis("https://target.com", None)
        assert result == []

    @pytest.mark.asyncio
    async def test_js_without_api_paths_returns_empty(self):
        """JS 内容不含 API 路径 → 返回空列表。"""
        js_cache = {"target_key": {"js1.js": "console.log('hello world');"}}
        with patch("core.js_analyzer._js_source_cache", js_cache), \
             patch("core.js_analyzer._normalize_target_key", return_value="target_key"):
            result = await sta._fallback_passive_js_analysis("https://target.com", None)
        assert result == []

    @pytest.mark.asyncio
    async def test_multiple_js_files_merged_and_deduped(self):
        """多个 JS 文件 → 合并去重。"""
        js_cache = {"target_key": {
            "js1.js": "fetch('/api/users/list');",
            "js2.js": "fetch('/api/users/list'); fetch('/api/orders');",
        }}
        with patch("core.js_analyzer._js_source_cache", js_cache), \
             patch("core.js_analyzer._normalize_target_key", return_value="target_key"):
            result = await sta._fallback_passive_js_analysis("https://target.com", None)
        paths = [r["path"] for r in result]
        assert len(result) == 2
        assert "/api/users/list" in paths
        assert "/api/orders" in paths

    @pytest.mark.asyncio
    async def test_sitemap_js_content_cache_used(self):
        """sitemap 有 _js_content_cache 属性 → 使用 sitemap 缓存。"""
        sitemap = FakeMap()
        sitemap._js_content_cache = {"js1.js": "fetch('/api/users/list');"}
        # _js_source_cache 为空 → 回退到 sitemap 缓存
        with patch("core.js_analyzer._js_source_cache", {}), \
             patch("core.js_analyzer._normalize_target_key", return_value="target_key"):
            result = await sta._fallback_passive_js_analysis("https://target.com", sitemap)
        assert len(result) == 1
        assert result[0]["path"] == "/api/users/list"

    @pytest.mark.asyncio
    async def test_sitemap_without_cache_returns_empty(self):
        """sitemap 无缓存属性 → 返回空列表。"""
        sitemap = FakeMap()
        with patch("core.js_analyzer._js_source_cache", {}), \
             patch("core.js_analyzer._normalize_target_key", return_value="target_key"):
            result = await sta._fallback_passive_js_analysis("https://target.com", sitemap)
        assert result == []

    @pytest.mark.asyncio
    async def test_regex_matches_multiple_patterns(self):
        """正则匹配 /api/, /rest/, /v1/, /service/, /v2/ 等模式。"""
        js_content = (
            "fetch('/api/users');"
            "fetch('/rest/data');"
            "fetch('/v1/info');"
            "fetch('/service/action');"
            "fetch('/v2/items');"
        )
        js_cache = {"target_key": {"js1.js": js_content}}
        with patch("core.js_analyzer._js_source_cache", js_cache), \
             patch("core.js_analyzer._normalize_target_key", return_value="target_key"):
            result = await sta._fallback_passive_js_analysis("https://target.com", None)
        paths = [r["path"] for r in result]
        assert "/api/users" in paths
        assert "/rest/data" in paths
        assert "/v1/info" in paths
        assert "/service/action" in paths
        assert "/v2/items" in paths

    @pytest.mark.asyncio
    async def test_exception_returns_empty(self):
        """异常 → 返回空列表。

        js_cache 值为字符串（无 .items() 方法）→ 触发 AttributeError，
        被外层 except 捕获，返回空列表。
        """
        js_cache = {"target_key": "not_a_dict"}
        with patch("core.js_analyzer._js_source_cache", js_cache), \
             patch("core.js_analyzer._normalize_target_key", return_value="target_key"):
            result = await sta._fallback_passive_js_analysis("https://target.com", None)
        assert result == []


# ============================================================
# _generate_coverage_warning 兜底告警文本
# ============================================================

class TestGenerateCoverageWarning:
    """兜底层3: _generate_coverage_warning 生成 Markdown 格式告警文本。"""

    def test_without_details(self):
        """无 details 参数时输出告警标题、原因、建议，不含"详细信息"段。"""
        result = sta._generate_coverage_warning("mitmproxy 未启动")
        assert "测试覆盖不足告警" in result
        assert "mitmproxy 未启动" in result
        assert "建议" in result
        # 无 details 时不应出现"详细信息"标题
        assert "详细信息" not in result

    def test_with_multiple_details(self):
        """有 details（多 key-value）时逐行输出每个键值。"""
        details = {
            "flows_file": "/tmp/flows.jsonl",
            "flow_count": 0,
            "cdp_attempted": True,
        }
        result = sta._generate_coverage_warning("流量捕获失败", details)
        assert "测试覆盖不足告警" in result
        assert "流量捕获失败" in result
        assert "详细信息" in result
        for k, v in details.items():
            assert f"{k}: {v}" in result, f"应包含 {k}: {v}"

    def test_contains_warning_header(self):
        """返回值包含"测试覆盖不足告警"标题。"""
        result = sta._generate_coverage_warning("x")
        assert "测试覆盖不足告警" in result

    def test_contains_reason(self):
        """返回值包含传入的 reason。"""
        result = sta._generate_coverage_warning("CDP 重捕获也失败")
        assert "CDP 重捕获也失败" in result

    def test_contains_suggestion(self):
        """返回值包含建议文字。"""
        result = sta._generate_coverage_warning("x")
        assert "建议" in result
        assert "人工测试" in result


# ============================================================
# _build_supplemental_quality_report 补测质量度量报告
# ============================================================

class TestBuildSupplementalQualityReport:
    """_build_supplemental_quality_report 从 summary 生成质量度量报告。"""

    def test_scan_stats_with_discovery(self):
        """scan_stats 有 total_scanned>0 且 discovered>0 → 报告含"转化率"。"""
        summary = {
            "scan_stats": {"total_scanned": 100},
            "discovered": 10,
        }
        report = sta._build_supplemental_quality_report(summary, None)
        assert "转化率" in report
        assert "100" in report
        assert "10" in report

    def test_total_scanned_zero(self):
        """total_scanned=0 → 报告含"未扫描到新流量"。"""
        summary = {
            "scan_stats": {"total_scanned": 0},
            "discovered": 0,
        }
        report = sta._build_supplemental_quality_report(summary, None)
        assert "未扫描到新流量" in report

    def test_discovered_with_features(self):
        """discovered>0 且有 new_features/attached → 报告含"功能点转化"。"""
        summary = {
            "scan_stats": {"total_scanned": 50},
            "discovered": 5,
            "new_features": 3,
            "attached_features": 1,
        }
        report = sta._build_supplemental_quality_report(summary, None)
        assert "功能点转化" in report

    def test_discovered_zero_but_new_features(self):
        """discovered=0 但有 new_features → 报告含"非流量来源"。"""
        summary = {
            "scan_stats": {"total_scanned": 0},
            "discovered": 0,
            "new_features": 2,
            "attached_features": 0,
        }
        report = sta._build_supplemental_quality_report(summary, None)
        assert "非流量来源" in report

    def test_tested_and_skipped(self):
        """有 tested+skipped → 报告含"测试覆盖"。"""
        summary = {
            "scan_stats": {"total_scanned": 10},
            "discovered": 3,
            "tested_features": 2,
            "skipped_features": 1,
        }
        report = sta._build_supplemental_quality_report(summary, None)
        assert "测试覆盖" in report
        assert "2/3" in report  # 2 tested / 3 testable
        assert "因超时/异常被跳过" in report

    def test_testable_but_zero_tested(self):
        """testable>0 但 tested=0 → 报告含"质量告警"和"全部失败/跳过"。"""
        summary = {
            "scan_stats": {"total_scanned": 10},
            "discovered": 2,
            "tested_features": 0,
            "skipped_features": 2,
        }
        report = sta._build_supplemental_quality_report(summary, None)
        assert "质量告警" in report
        assert "全部失败/跳过" in report

    def test_scanned_but_no_discovery(self):
        """total_scanned>0 但 discovered=0 → 报告含"未发现新 API"。"""
        summary = {
            "scan_stats": {"total_scanned": 100},
            "discovered": 0,
        }
        report = sta._build_supplemental_quality_report(summary, None)
        assert "未发现新 API" in report

    def test_error_in_summary(self):
        """summary 有 error → 报告含"补测过程中发生错误"。"""
        summary = {
            "scan_stats": {"total_scanned": 0},
            "discovered": 0,
            "error": "attach_failed: connection refused",
        }
        report = sta._build_supplemental_quality_report(summary, None)
        assert "补测过程中发生错误" in report
        assert "attach_failed" in report

    def test_elapsed_in_summary(self):
        """summary 有 elapsed → 报告含"补测耗时"。"""
        summary = {
            "scan_stats": {"total_scanned": 0},
            "discovered": 0,
            "elapsed": 123.4,
        }
        report = sta._build_supplemental_quality_report(summary, None)
        assert "补测耗时" in report
        assert "123.4" in report

    def test_minimal_summary_returns_nonempty(self):
        """summary 几乎为空时返回非空字符串。

        当前实现中 lines 至少有 3 行（header + 流量扫描 + 耗时），
        因此 len(lines) > 2 恒为 True，guard 条件不会返回空串。
        此测试验证空 summary 不会崩溃，且返回包含基本结构的非空文本。
        """
        report = sta._build_supplemental_quality_report({}, None)
        assert len(report) > 0
        assert "补测质量度量报告" in report
        assert "补测耗时" in report


# ============================================================
# attach_apis_to_sitemap 挂载新 API
# ============================================================

class FakeSitemap(FakeMap):
    """attach_apis_to_sitemap 使用的 sitemap 桩，记录 add_feature/add_api/save 调用。"""

    def __init__(self, apis=None, extra_scope=None, features=None,
                 add_feature_raises=False, save_raises=False):
        super().__init__(apis=apis, extra_scope=extra_scope)
        self.features: dict = features or {}
        self.add_feature_calls: list = []
        self.add_api_calls: list = []
        self.save_calls: int = 0
        self._add_feature_raises = add_feature_raises
        self._save_raises = save_raises

    def add_feature(self, name="", description="", page_url="",
                    priority=None, related_apis=None, requires_auth=False,
                    module=""):
        self.add_feature_calls.append({
            "name": name, "description": description, "page_url": page_url,
            "priority": priority, "related_apis": list(related_apis or []),
            "requires_auth": requires_auth, "module": module,
        })
        if self._add_feature_raises:
            raise RuntimeError("add_feature failed (mock)")
        fp = _make_feature(name=name, related_apis=related_apis)
        return fp

    def add_api(self, method, url, discovered_by=""):
        self.add_api_calls.append({
            "method": method, "url": url, "discovered_by": discovered_by,
        })

    def save(self):
        self.save_calls += 1
        if self._save_raises:
            raise RuntimeError("save failed (mock)")


class TestAttachApisToSitemap:
    """attach_apis_to_sitemap 挂载新 API 到 sitemap。"""

    def test_attach_to_existing_feature(self):
        """API 匹配现有 feature → 挂载到现有 feature，不新建。"""
        fp = _make_feature(related_apis=["GET /api/users/list"])
        sitemap = FakeSitemap(features={"fp-1": fp})
        api = _DiscoveredAPI(_flow(url="https://target.com/api/users/1", method="GET"))
        new_features, attached = sta.attach_apis_to_sitemap(sitemap, [api])
        assert len(new_features) == 0
        assert len(attached) == 1
        assert attached[0][0] is fp
        assert attached[0][1] is api
        # api_str 应被追加到 related_apis
        assert len(fp.related_apis) == 2
        assert any("api/users/1" in r for r in fp.related_apis)

    def test_create_new_feature(self):
        """API 无匹配现有 feature → 新建 feature。"""
        sitemap = FakeSitemap()
        api = _DiscoveredAPI(_flow(url="https://target.com/api/orders/create", method="POST"))
        new_features, attached = sta.attach_apis_to_sitemap(sitemap, [api])
        assert len(new_features) == 1
        assert len(attached) == 0
        # add_feature 被调用且参数正确
        assert len(sitemap.add_feature_calls) == 1
        assert sitemap.add_feature_calls[0]["name"] == "POST /api/orders/create"
        assert sitemap.add_feature_calls[0]["module"] == "补测发现"

    def test_add_feature_exception_swallowed(self):
        """sitemap.add_feature 抛异常 → 异常被吞，new_features 为空。"""
        sitemap = FakeSitemap(add_feature_raises=True)
        api = _DiscoveredAPI(_flow(url="https://target.com/api/orders/create"))
        # 不应抛异常
        new_features, attached = sta.attach_apis_to_sitemap(sitemap, [api])
        assert len(new_features) == 0
        assert len(attached) == 0

    def test_save_exception_swallowed(self):
        """sitemap.save() 抛异常 → 异常被吞。"""
        sitemap = FakeSitemap(save_raises=True)
        api = _DiscoveredAPI(_flow(url="https://target.com/api/new/endpoint"))
        # 不应抛异常
        new_features, attached = sta.attach_apis_to_sitemap(sitemap, [api])
        assert len(new_features) == 1
        assert sitemap.save_calls == 1

    def test_returns_tuple_of_two_lists(self):
        """返回 (new_features, attached_features) 元组。"""
        sitemap = FakeSitemap()
        apis = [
            _DiscoveredAPI(_flow(url="https://target.com/api/a/b", flow_id="1")),
            _DiscoveredAPI(_flow(url="https://target.com/api/c/d", flow_id="2")),
        ]
        result = sta.attach_apis_to_sitemap(sitemap, apis)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], list)

    def test_api_str_already_in_related_apis(self):
        """api_str 已在 related_apis 中 → 不重复添加，但 add_api 仍被调用。"""
        # related_apis 使用与 api_str 相同格式（完整 URL）
        api_str = "GET https://target.com/api/users/1"
        fp = _make_feature(related_apis=[api_str])
        sitemap = FakeSitemap(features={"fp-1": fp})
        api = _DiscoveredAPI(_flow(url="https://target.com/api/users/1", method="GET"))
        new_features, attached = sta.attach_apis_to_sitemap(sitemap, [api])
        # 不应被加入 attached（因为 api_str 已存在）
        assert len(attached) == 0
        assert len(new_features) == 0
        # related_apis 不应增加
        assert len(fp.related_apis) == 1
        # 但 sitemap.add_api 仍被调用
        assert len(sitemap.add_api_calls) == 1

    def test_mixed_apis_some_attached_some_new(self):
        """多个 API 混合：部分挂载到现有 feature，部分新建。"""
        # 现有 feature 匹配 /api/users/*
        fp = _make_feature(related_apis=["GET /api/users/list"])
        sitemap = FakeSitemap(features={"fp-1": fp})
        apis = [
            # 匹配现有 feature（/api/users/1 与 /api/users/list 共享 /api/users）
            _DiscoveredAPI(_flow(url="https://target.com/api/users/1", flow_id="1")),
            # 不匹配 → 新建 feature（/api/orders 与 /api/users 仅共享 /api）
            _DiscoveredAPI(_flow(url="https://target.com/api/orders/create", flow_id="2")),
        ]
        new_features, attached = sta.attach_apis_to_sitemap(sitemap, apis)
        assert len(new_features) == 1
        assert len(attached) == 1
        # 新建 feature 的 name 应包含 orders
        assert "orders" in new_features[0].name
        # 挂载的应是 fp-1
        assert attached[0][0] is fp


# ============================================================
# _filter_flow_dicts_for_new_apis 内存 flow 过滤
# ============================================================

class TestFilterFlowDictsForNewApis:
    """_filter_flow_dicts_for_new_apis 从 flow 字典列表过滤新 API。

    注：源码中函数名为 _filter_flow_dicts_for_new_apis（非 _filter_flows_internal）。
    """

    def test_empty_flows_returns_empty_list(self):
        """flows 为空列表 → 返回空列表。"""
        sitemap = FakeMap()
        result = sta._filter_flow_dicts_for_new_apis(
            [], sitemap, "https://target.com"
        )
        assert result == []

    def test_keeps_in_scope_2xx_business_api(self):
        """scope 内、2xx、业务路径、未知 → 保留。"""
        sitemap = FakeMap()
        flows = [_flow(url="https://target.com/api/orders/1", status_code=200)]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com"
        )
        assert len(result) == 1
        assert result[0].path == "/api/orders/1"

    def test_filters_out_of_scope_host(self):
        """非 scope 的 host → 过滤。"""
        sitemap = FakeMap()
        flows = [_flow(url="https://evil.com/api/data", status_code=200)]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com"
        )
        assert len(result) == 0

    def test_filters_third_party_domain(self):
        """第三方域名（在 scope 内但命中黑名单）→ 过滤。"""
        # sentry.io 纳入 extra_scope → 通过 scope 检查但命中第三方黑名单
        sitemap = FakeMap(extra_scope=["sentry.io"])
        flows = [_flow(url="https://sentry.io/api/store", status_code=200)]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com"
        )
        assert len(result) == 0

    def test_filters_non_2xx_with_require(self):
        """require_2xx=True 时非 2xx → 过滤。"""
        sitemap = FakeMap()
        flows = [
            _flow(url="https://target.com/api/ok", status_code=200),
            _flow(url="https://target.com/api/err", status_code=500),
            _flow(url="https://target.com/api/notfound", status_code=404),
        ]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com", require_2xx=True
        )
        assert len(result) == 1
        assert result[0].path == "/api/ok"

    def test_keeps_non_2xx_without_require(self):
        """require_2xx=False 时非 2xx 也保留。"""
        sitemap = FakeMap()
        flows = [
            _flow(url="https://target.com/api/ok", status_code=200),
            _flow(url="https://target.com/api/err", status_code=500),
        ]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com", require_2xx=False
        )
        assert len(result) == 2

    def test_filters_known_in_sitemap(self):
        """已在 sitemap.apis 中的 → 过滤。"""
        sitemap = FakeMap(apis={"GET https://target.com/api/users": object()})
        flows = [
            _flow(url="https://target.com/api/users", status_code=200),
            _flow(url="https://target.com/api/orders", status_code=200),
        ]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com"
        )
        assert len(result) == 1
        assert result[0].path == "/api/orders"

    def test_filters_extra_known_keys(self):
        """在 extra_known_keys 中的 → 过滤。"""
        sitemap = FakeMap()
        flows = [
            _flow(url="https://target.com/api/extra", status_code=200),
            _flow(url="https://target.com/api/new", status_code=200),
        ]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com",
            extra_known_keys={"GET target.com/api/extra"},
        )
        assert len(result) == 1
        assert result[0].path == "/api/new"

    def test_filters_static_resources(self):
        """静态资源路径 → 过滤。"""
        sitemap = FakeMap()
        flows = [
            _flow(url="https://target.com/static/app.js", status_code=200),
            _flow(url="https://target.com/assets/style.css", status_code=200),
            _flow(url="https://target.com/api/users", status_code=200),
        ]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com"
        )
        assert len(result) == 1
        assert result[0].path == "/api/users"

    def test_dedup_duplicate_flows(self):
        """同一新 API 多次出现只保留第一条。"""
        sitemap = FakeMap()
        flows = [
            _flow(url="https://target.com/api/x", status_code=200, flow_id="1"),
            _flow(url="https://target.com/api/x", status_code=200, flow_id="2"),
        ]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com"
        )
        assert len(result) == 1

    def test_mixed_flows(self):
        """多 flow 混合：scope内2xx + 非scope + 第三方 + 非业务 + 已知 + 重复。"""
        sitemap = FakeMap(
            apis={"GET https://target.com/api/known": object()},
            extra_scope=["sentry.io"],
        )
        flows = [
            # 保留：scope 内 2xx 业务
            _flow(url="https://target.com/api/new1", status_code=200, flow_id="1"),
            # 过滤：非 scope
            _flow(url="https://evil.com/api/x", status_code=200, flow_id="2"),
            # 过滤：第三方（在 scope 内但命中黑名单）
            _flow(url="https://sentry.io/api/store", status_code=200, flow_id="3"),
            # 过滤：非 2xx
            _flow(url="https://target.com/api/err", status_code=500, flow_id="4"),
            # 过滤：静态资源
            _flow(url="https://target.com/static/app.js", status_code=200, flow_id="5"),
            # 过滤：已知
            _flow(url="https://target.com/api/known", status_code=200, flow_id="6"),
            # 过滤：重复（与 flow_id=1 相同 URL）
            _flow(url="https://target.com/api/new1", status_code=200, flow_id="7"),
            # 保留：另一个新 API
            _flow(url="https://target.com/api/new2", status_code=200, flow_id="8"),
        ]
        result = sta._filter_flow_dicts_for_new_apis(
            flows, sitemap, "https://target.com"
        )
        assert len(result) == 2
        paths = {r.path for r in result}
        assert paths == {"/api/new1", "/api/new2"}


# ============================================================
# 辅助：构造 scan_stats / dirscan_stats / fake session
# ============================================================

def _scan_stats(**overrides) -> dict:
    """构造 discover_new_apis_from_flows 返回的 scan_stats（默认全零）。"""
    base = {
        "total_scanned": 0, "before_phase2": 0, "other_task": 0,
        "out_of_scope": 0, "third_party": 0, "not_2xx": 0,
        "non_business": 0, "already_known": 0, "duplicate": 0,
        "kept": 0, "flow_file": "x",
    }
    base.update(overrides)
    return base


def _dirscan_stats(**overrides) -> dict:
    """构造 discover_apis_from_dirscan 返回的 dirscan_stats（默认全零）。"""
    base = {
        "dirscan_total": 0, "dirscan_discovered": 0,
        "dirscan_sensitive": 0, "dirscan_already_known": 0,
        "dirscan_duplicate": 0, "dirscan_error": "",
    }
    base.update(overrides)
    return base


def _make_session(**overrides) -> SimpleNamespace:
    """构造 run_supplemental_test(_local) 使用的 fake session。"""
    base = dict(
        sitemap=FakeMap(),
        target_url="https://target.com",
        task_id="t1",
        _phase2_started_at=1000.0,
        llm=None,
        _inject_cookies="",
        _inject_headers={},
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# ============================================================
# run_supplemental_test 错误路径
# ============================================================

class TestRunSupplementalTestErrorPaths:
    """run_supplemental_test 的各种错误/边界路径。"""

    @pytest.mark.asyncio
    async def test_sitemap_not_initialized(self):
        """1a: sitemap 未初始化 → error + done，summary.error 含 sitemap 未初始化。"""
        session = SimpleNamespace(sitemap=None, target_url="https://target.com")
        events = await _collect(sta.run_supplemental_test(session))
        # 第一个事件应是 error
        assert events[0]["type"] == "error"
        assert "sitemap 未初始化" in events[0]["msg"]
        done_evt = next(e for e in events if e.get("type") == "done")
        assert "sitemap 未初始化" in str(done_evt["summary"]["error"])

    @pytest.mark.asyncio
    async def test_phase2_started_at_zero_warns(self):
        """1b: _phase2_started_at=0 → warn 未记录起点时间戳，传给 discover 的值为 0.0。"""
        session = _make_session(_phase2_started_at=0)
        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([], _scan_stats())) as disc_mock, \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], _dirscan_stats()))):
            events = await _collect(sta.run_supplemental_test(session))
        warn_msgs = [str(e.get("msg", "")) for e in events if e.get("type") == "warn"]
        assert any("未记录 Phase 2 起点时间戳" in m for m in warn_msgs), \
            f"应包含未记录起点时间戳警告，实际: {warn_msgs}"
        # 校验传给 discover_new_apis_from_flows 的 phase2_started_at 被重置为 0.0
        _, kwargs = disc_mock.call_args
        assert kwargs.get("phase2_started_at") == 0.0

    @pytest.mark.asyncio
    async def test_discover_flows_raises(self):
        """1c: discover_new_apis_from_flows 抛异常 → error 含扫描失败，summary.error 含 scan_failed。"""
        session = _make_session()
        with patch.object(sta, "discover_new_apis_from_flows",
                          side_effect=RuntimeError("disk read error")):
            events = await _collect(sta.run_supplemental_test(session))
        err_evts = [e for e in events if e.get("type") == "error"]
        assert any("扫描 flows.jsonl 失败" in str(e.get("msg", "")) for e in err_evts), \
            f"应包含扫描失败错误，实际: {err_evts}"
        done_evt = next(e for e in events if e.get("type") == "done")
        assert "scan_failed" in str(done_evt["summary"]["error"])

    @pytest.mark.asyncio
    async def test_scan_stats_io_error(self):
        """1d: scan_stats 含 io_error → warn 扫描过程异常，summary.warning 含 flows_scan_partial。"""
        session = _make_session()
        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([], _scan_stats(io_error="文件读取错误"))), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], _dirscan_stats()))):
            events = await _collect(sta.run_supplemental_test(session))
        warn_msgs = [str(e.get("msg", "")) for e in events if e.get("type") == "warn"]
        assert any("扫描 flows.jsonl 过程中发生异常" in m for m in warn_msgs), \
            f"应包含扫描异常警告，实际: {warn_msgs}"
        done_evt = next(e for e in events if e.get("type") == "done")
        assert "flows_scan_partial" in str(done_evt["summary"].get("warning", ""))

    @pytest.mark.asyncio
    async def test_attach_apis_raises(self):
        """1e: 有新 API 但 attach_apis_to_sitemap 抛异常 → error 含挂载失败，summary.error 含 attach_failed。"""
        session = _make_session()
        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([SimpleNamespace()], _scan_stats(total_scanned=1, kept=1))), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], _dirscan_stats()))), \
             patch.object(sta, "attach_apis_to_sitemap",
                          side_effect=RuntimeError("attach boom")):
            events = await _collect(sta.run_supplemental_test(session))
        err_evts = [e for e in events if e.get("type") == "error"]
        assert any("挂载新 API 到 sitemap 失败" in str(e.get("msg", "")) for e in err_evts), \
            f"应包含挂载失败错误，实际: {err_evts}"
        done_evt = next(e for e in events if e.get("type") == "done")
        assert "attach_failed" in str(done_evt["summary"]["error"])

    @pytest.mark.asyncio
    async def test_new_features_without_checklist(self):
        """1f: 新 feature 无 checklist → info 含无需启动补测 Agent/无 checklist。"""
        session = _make_session()
        fp_no_cl = FeaturePoint(
            id="fp-nc", name="无checklist功能", description="",
            related_apis=["GET https://target.com/api/x"],
        )
        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([SimpleNamespace()], _scan_stats(total_scanned=1, kept=1))), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], _dirscan_stats()))), \
             patch.object(sta, "attach_apis_to_sitemap",
                          return_value=([fp_no_cl], [])):
            events = await _collect(sta.run_supplemental_test(session))
        info_msgs = [str(e.get("msg", "")) for e in events if e.get("type") == "info"]
        assert any(("无需启动补测 Agent" in m) or ("无 checklist" in m) for m in info_msgs), \
            f"应包含无需启动补测提示，实际: {info_msgs}"

    @pytest.mark.asyncio
    async def test_worker_agent_import_fails(self):
        """1g: WorkerAgent 导入失败 → error 含导入失败，summary.error 含 import_failed。"""
        new_features = [
            _make_feature(fid="fp-1", name="补测功能1",
                          related_apis=["GET https://target.com/api/new1"])
        ]
        sitemap = FakeMap()
        sitemap.start_test = MagicMock()
        session = _make_session(sitemap=sitemap)
        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([SimpleNamespace()], _scan_stats(total_scanned=1, kept=1))), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], _dirscan_stats()))), \
             patch.object(sta, "attach_apis_to_sitemap",
                          return_value=(list(new_features), [])), \
             patch.dict(sys.modules, {"core.worker_agent": None}):
            events = await _collect(sta.run_supplemental_test(session))
        err_evts = [e for e in events if e.get("type") == "error"]
        assert any("导入 WorkerAgent 失败" in str(e.get("msg", "")) for e in err_evts), \
            f"应包含导入失败错误，实际: {err_evts}"
        done_evt = next(e for e in events if e.get("type") == "done")
        assert "import_failed" in str(done_evt["summary"]["error"])


# ============================================================
# _run_worker_with_timeout
# ============================================================

class FakeWorker:
    """_run_worker_with_timeout 测试用的假 worker。"""

    def __init__(self, events=None, error=None, delay=0):
        self.events = events or []
        self.error = error
        self.delay = delay

    async def run(self):
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        for e in self.events:
            yield e


class TestRunWorkerWithTimeout:
    """_run_worker_with_timeout：正常完成 / 超时 / worker 异常。"""

    @pytest.mark.asyncio
    async def test_normal_completion(self):
        """2a: worker 正常 yield 2 个事件 → 收到 2 个。"""
        worker = FakeWorker(events=[{"type": "a"}, {"type": "b"}])
        events = await _collect(sta._run_worker_with_timeout(worker, timeout_s=5.0))
        assert len(events) == 2
        assert events[0] == {"type": "a"}
        assert events[1] == {"type": "b"}

    @pytest.mark.asyncio
    async def test_timeout(self):
        """2b: worker 长时间不返回 → 超时抛 asyncio.TimeoutError。"""
        worker = FakeWorker(delay=2.0)
        with pytest.raises(asyncio.TimeoutError):
            await _collect(sta._run_worker_with_timeout(worker, timeout_s=0.1))

    @pytest.mark.asyncio
    async def test_worker_error(self):
        """2c: worker.run 抛异常 → yield 一个 worker_error 事件。"""
        worker = FakeWorker(error=RuntimeError("worker crashed"))
        events = await _collect(sta._run_worker_with_timeout(worker, timeout_s=5.0))
        assert len(events) == 1
        assert events[0]["type"] == "worker_error"
        assert events[0]["error"] == "worker crashed"


# ============================================================
# run_supplemental_test_local
# ============================================================

class TestRunSupplementalTestLocal:
    """run_supplemental_test_local（FAST 模式本地规则版）基础路径。"""

    @pytest.mark.asyncio
    async def test_sitemap_not_initialized(self):
        """3a: sitemap 未初始化 → error + done。"""
        session = SimpleNamespace(sitemap=None, target_url="https://target.com")
        events = await _collect(sta.run_supplemental_test_local(session))
        err_evts = [e for e in events if e.get("type") == "error"]
        assert any("sitemap 未初始化" in str(e.get("msg", "")) for e in err_evts), \
            f"应包含 sitemap 未初始化错误，实际: {err_evts}"
        done_evt = next(e for e in events if e.get("type") == "done")
        assert "sitemap 未初始化" in str(done_evt["summary"]["error"])

    @pytest.mark.asyncio
    async def test_no_new_apis(self):
        """3b: flows + dirscan 均空 → info 未发现新 API，discovered==0。"""
        session = _make_session()
        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([], _scan_stats())), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], _dirscan_stats()))):
            events = await _collect(sta.run_supplemental_test_local(session))
        info_msgs = [str(e.get("msg", "")) for e in events if e.get("type") == "info"]
        assert any("未发现新 API" in m for m in info_msgs), \
            f"应包含未发现新 API 提示，实际: {info_msgs}"
        done_evt = next(e for e in events if e.get("type") == "done")
        assert done_evt["summary"]["discovered"] == 0

    @pytest.mark.asyncio
    async def test_flow_file_missing(self):
        """3c: scan_stats 含 flow_file_missing → error 含 flows.jsonl 不存在。"""
        session = _make_session()
        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([], _scan_stats(
                              flow_file_missing=1, flow_file="/tmp/missing.jsonl"))), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], _dirscan_stats()))):
            events = await _collect(sta.run_supplemental_test_local(session))
        err_evts = [e for e in events if e.get("type") == "error"]
        assert any("flows.jsonl 不存在" in str(e.get("msg", "")) for e in err_evts), \
            f"应包含 flows.jsonl 不存在错误，实际: {err_evts}"

    @pytest.mark.asyncio
    async def test_flows_no_new_api_warning(self):
        """3d: total_scanned>0 但 apis=[] → warn 含代理抓到 + 未发现新 API。"""
        session = _make_session()
        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([], _scan_stats(total_scanned=5))), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], _dirscan_stats()))):
            events = await _collect(sta.run_supplemental_test_local(session))
        warn_msgs = [str(e.get("msg", "")) for e in events if e.get("type") == "warn"]
        assert any(("代理抓到" in m) and ("未发现新 API" in m) for m in warn_msgs), \
            f"应包含 flows_no_new_api 告警，实际: {warn_msgs}"

    @pytest.mark.asyncio
    async def test_normal_flow_with_fast_scanner(self):
        """3e: 有新 API → 挂载 → FastScanner 测试 → tested_features>0。"""
        new_features = [
            _make_feature(fid="fp-1", name="补测功能1",
                          related_apis=["GET https://target.com/api/new1"])
        ]
        sitemap = FakeMap()
        sitemap.save = MagicMock()
        session = _make_session(sitemap=sitemap)

        # FastScanner.scan_target 返回的 ScanResult 桩
        mock_result = MagicMock()
        mock_result.vuln_count = 0
        mock_result.findings = []

        with patch.object(sta, "discover_new_apis_from_flows",
                          return_value=([SimpleNamespace()], _scan_stats(total_scanned=1, kept=1))), \
             patch.object(sta, "discover_apis_from_dirscan",
                          new=AsyncMock(return_value=([], _dirscan_stats()))), \
             patch.object(sta, "attach_apis_to_sitemap",
                          return_value=(list(new_features), [])), \
             patch("core.fast_scanner.FastScanner") as MockScanner, \
             patch("core.fast_scanner.ScanTarget") as MockScanTarget, \
             patch("core.fast_scanner.convert_findings_to_checklist_results",
                   return_value=[]):
            mock_scanner_instance = MagicMock()
            mock_scanner_instance.scan_target = AsyncMock(return_value=mock_result)
            mock_scanner_instance.get_accumulated_stats = MagicMock(return_value={})
            mock_scanner_instance._close = AsyncMock()
            MockScanner.return_value = mock_scanner_instance
            events = await _collect(sta.run_supplemental_test_local(session))

        done_evt = next(e for e in events if e.get("type") == "done")
        assert done_evt["summary"]["tested_features"] > 0, \
            f"应至少测试 1 个 feature，实际 summary: {done_evt['summary']}"
        # FastScanner 实例被创建并调用 scan_target
        MockScanner.assert_called_once()
        mock_scanner_instance.scan_target.assert_awaited()
