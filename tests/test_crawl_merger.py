"""
爬虫合并模块测试

覆盖：merge_crawl_results 的各种合并策略（API去重、页面合并、表单去重、
      角色合并、JS端点去重、菜单覆盖合并、计数字段求和等）
"""

import pytest
from copy import deepcopy

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.crawl_merger import merge_crawl_results, _dedupe_json, _json_signature


class TestDedupeJson:
    def test_simple_list(self):
        items = [1, 2, 3, 2, 1]
        result = _dedupe_json(items)
        assert result == [1, 2, 3]

    def test_dict_list(self):
        items = [
            {"a": 1, "b": 2},
            {"a": 1, "b": 2},  # 重复
            {"a": 3, "b": 4},
        ]
        result = _dedupe_json(items)
        assert len(result) == 2

    def test_preserves_order(self):
        items = [{"x": 3}, {"x": 1}, {"x": 2}, {"x": 1}]
        result = _dedupe_json(items)
        assert result == [{"x": 3}, {"x": 1}, {"x": 2}]


class TestMergeCrawlResults:
    def _make_primary(self):
        return {
            "api_endpoints": [
                {"method": "GET", "url": "http://x.com/api/user"},
                {"method": "POST", "url": "http://x.com/api/login"},
            ],
            "pages": {"http://x.com/": {"title": "首页"}},
            "forms": [{"page": "/login", "action": "/api/login", "method": "POST"}],
            "roles_crawled": ["anonymous"],
            "login_status": {"anonymous": True},
            "crawled_elements": [{"tag": "a", "text": "首页"}],
            "js_endpoints": ["/api/user", "/api/login"],
            "menu_coverage": [{"name": "首页", "apis_triggered": 1}],
            "menu_tree_responses": [],
            "extra_scope": ["cdn.x.com"],
            "realtime_channels": [],
            "api_doc_hits": [{"url": "/swagger.json"}],
            "role_comparison": {},
            "apis_inferred_verified": 2,
            "forms_submitted": 1,
            "total_clickable_elements": 10,
        }

    def _make_secondary(self):
        return {
            "api_endpoints": [
                {"method": "GET", "url": "http://x.com/api/user"},  # 重复
                {"method": "GET", "url": "http://x.com/api/admin"},  # 新
            ],
            "pages": {
                "http://x.com/admin": {"title": "管理后台"},
            },
            "forms": [
                {"page": "/login", "action": "/api/login", "method": "POST"},  # 重复
                {"page": "/admin", "action": "/api/admin/update", "method": "POST"},  # 新
            ],
            "roles_crawled": ["admin"],
            "login_status": {"admin": True},
            "crawled_elements": [{"tag": "button", "text": "管理"}],
            "js_endpoints": ["/api/admin", "/api/user"],  # /api/user 重复
            "menu_coverage": [{"name": "管理", "apis_triggered": 2}],
            "menu_tree_responses": [],
            "extra_scope": ["api.x.com", "cdn.x.com"],  # cdn.x.com 重复
            "realtime_channels": [],
            "api_doc_hits": [{"url": "/swagger.json"}, {"url": "/openapi.yaml"}],
            "role_comparison": {"admin_vs_user": "差异数据"},
            "apis_inferred_verified": 3,
            "forms_submitted": 2,
            "total_clickable_elements": 15,
        }

    def test_api_dedup(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        # 3 个唯一 API（GET /user, POST /login, GET /admin）
        assert result["apis_total"] == 3
        urls = [a["url"] for a in result["api_endpoints"]]
        assert "http://x.com/api/admin" in urls

    def test_pages_merge(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        assert result["pages_total"] == 2
        assert "http://x.com/admin" in result["pages"]

    def test_forms_dedup(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        assert result["forms_total"] == 2

    def test_roles_merge(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        assert "anonymous" in result["roles_crawled"]
        assert "admin" in result["roles_crawled"]
        assert result["crawl_rounds"] == 2

    def test_login_status_merge(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        assert result["login_status"]["anonymous"] is True
        assert result["login_status"]["admin"] is True

    def test_js_endpoints_dedup(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        assert len(result["js_endpoints"]) == 3  # /api/user, /api/login, /api/admin

    def test_extra_scope_dedup(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        assert len(result["extra_scope"]) == 2  # cdn.x.com, api.x.com

    def test_counters_sum(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        assert result["apis_inferred_verified"] == 5
        assert result["forms_submitted"] == 3
        assert result["total_clickable_elements"] == 25

    def test_role_comparison_prefers_secondary(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        assert result["role_comparison"] == {"admin_vs_user": "差异数据"}

    def test_empty_secondary_noop(self):
        primary = self._make_primary()
        original = deepcopy(primary)
        result = merge_crawl_results(primary, {})
        # 空 secondary 不应改变 primary
        assert result["api_endpoints"] == original["api_endpoints"]

    def test_none_secondary_noop(self):
        primary = self._make_primary()
        result = merge_crawl_results(primary, None)
        assert result is primary

    def test_crawled_elements_concat(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        # 列表拼接，不去重
        assert len(result["crawled_elements"]) == 2

    def test_api_doc_hits_dedup(self):
        primary = self._make_primary()
        secondary = self._make_secondary()
        result = merge_crawl_results(primary, secondary)
        assert len(result["api_doc_hits"]) == 2  # /swagger.json + /openapi.yaml
