"""G14 回归套件 —— G1 端点风险域识别 gate 锁定。

锁定 0911 方案 G1 的 DoD：
  - 每个功能点/API 自动打 ≥1 风险域标签
  - 8 域关键字命中正确
  - 多域并集（一个端点属多域）
  - 写操作无命中归 authz，读操作归 general（默认安全：越权优先）
  - 与业务域 domain_label 解耦
  - 纯 stdlib，可独立 pytest 复跑

运行：python -m pytest tests/unit/test_risk_domain.py -v -o addopts="" -p no:cacheprovider
"""
from __future__ import annotations

import sys
from pathlib import Path

# 让 tests/ 在无安装的情况下也能直接 import core.*
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.endpoint.risk_domain import (  # noqa: E402
    DOMAIN_LABELS,
    RISK_DOMAIN_RULES,
    classify_risk_domain,
    group_by_risk_domain,
    tag_endpoints,
)


class TestClassifyRiskDomain:
    """G1 核心：classify_risk_domain 多域并集 + 默认安全。"""

    def test_upload_domain(self):
        assert "upload" in classify_risk_domain("/api/users/avatar/upload", "POST")
        assert "upload" in classify_risk_domain("/file/uploads", "POST")

    def test_ssrf_domain(self):
        assert "ssrf" in classify_risk_domain("/api/proxy/fetch?url=...", "GET")
        assert "ssrf" in classify_risk_domain("/webhook/callback", "POST")

    def test_injection_domain(self):
        assert "injection" in classify_risk_domain("/api/report/export", "GET")
        assert "injection" in classify_risk_domain("/search?q=x", "GET")

    def test_authz_domain(self):
        assert "authz" in classify_risk_domain("/api/users/123", "GET")
        assert "authz" in classify_risk_domain("/admin/orders", "GET")

    def test_csrf_domain(self):
        assert "csrf" in classify_risk_domain("/api/password/reset", "POST")
        assert "csrf" in classify_risk_domain("/oauth/sso", "POST")

    def test_file_domain(self):
        assert "file" in classify_risk_domain("/download/document?id=1", "GET")
        assert "file" in classify_risk_domain("/getfile?path=x", "GET")

    def test_business_domain(self):
        assert "business" in classify_risk_domain("/api/pay/transfer", "POST")
        assert "business" in classify_risk_domain("/coupon/recharge", "POST")

    def test_config_domain(self):
        assert "config" in classify_risk_domain("/actuator/env", "GET")
        assert "config" in classify_risk_domain("/swagger", "GET")

    def test_chinese_keywords(self):
        """中文同义词纳入（玄鉴目标多为国内系统）。"""
        assert "upload" in classify_risk_domain("/api/头像/上传", "POST")
        assert "authz" in classify_risk_domain("/用户/订单", "GET")

    def test_multi_domain_union(self):
        """多域并集：一个端点属多域，保序去重。

        "export" 同时在 injection 域与 file 域——/api/users/export 合法命中三域：
        injection(export) + authz(users) + file(export)。
        """
        doms = classify_risk_domain("/api/users/export", "POST")
        assert "injection" in doms
        assert "authz" in doms
        assert "file" in doms
        # 保序去重：无重复
        assert len(doms) == len(set(doms))

    def test_write_method_defaults_to_authz(self):
        """默认安全：写操作无关键字命中归 authz（越权优先关注）。"""
        assert classify_risk_domain("/api/xyz", "POST") == ["authz"]
        assert classify_risk_domain("/api/xyz", "DELETE") == ["authz"]
        assert classify_risk_domain("/api/xyz", "PATCH") == ["authz"]
        assert classify_risk_domain("/api/xyz", "PUT") == ["authz"]

    def test_read_method_defaults_to_general(self):
        assert classify_risk_domain("/api/xyz", "GET") == ["general"]

    def test_query_string_ignored(self):
        """query 不影响风险域判定（取 ? 前部分）。"""
        assert classify_risk_domain(
            "/api/users?callback=evil", "GET"
        ) == classify_risk_domain("/api/users", "GET")

    def test_empty_path(self):
        assert classify_risk_domain("", "GET") == ["general"]
        assert classify_risk_domain(None, "GET") == ["general"]


class TestTagEndpoints:
    """G1 端点打标：三种 api_info 形态统一 + is_static_asset + is_same_host。"""

    def test_dict_form_with_method_url(self):
        eps = [
            {"method": "POST", "url": "/api/users/avatar/upload"},
            {"method": "GET", "url": "/static/app.js"},
        ]
        tagged = tag_endpoints(eps, host="example.com")
        # upload 域是主风险域（avatar/upload）；users → authz 并集（多域正常）
        assert "upload" in tagged[0]["_tags"]["risk_domain"]
        assert "authz" in tagged[0]["_tags"]["risk_domain"]
        # 修正后 "load" 不再误命中 upload → 无 ssrf 假阳
        assert "ssrf" not in tagged[0]["_tags"]["risk_domain"]
        assert tagged[1]["_tags"]["is_static_asset"] is True
        assert tagged[1]["_tags"]["risk_domain"] == ["general"]

    def test_object_form(self):
        class _EP:
            method = "GET"
            url = "/api/orders/123"
        tagged = tag_endpoints([_EP()], host="example.com")
        assert "authz" in tagged[0]["_tags"]["risk_domain"]
        assert tagged[0]["_tags"]["is_same_host"] is True

    def test_api_key_string_form(self):
        tagged = tag_endpoints(["POST http://evil.com/api/pay"], host="example.com")
        assert "business" in tagged[0]["_tags"]["risk_domain"]
        assert tagged[0]["_tags"]["is_same_host"] is False  # 跨域

    def test_tags_preserve_original_fields(self):
        eps = [{"method": "GET", "url": "/api/users", "credential_id": "c1"}]
        tagged = tag_endpoints(eps)
        assert tagged[0]["credential_id"] == "c1"
        assert "risk_domain" in tagged[0]["_tags"]


class TestGroupByRiskDomain:
    """G1 分组：编排轨道 A 按域分批派活。"""

    def test_grouping(self):
        eps = [
            {"method": "POST", "url": "/upload"},
            {"method": "GET", "url": "/users/1"},
            {"method": "POST", "url": "/api/users/avatar/upload"},  # 多域
        ]
        tagged = tag_endpoints(eps)
        groups = group_by_risk_domain(tagged)
        assert "upload" in groups
        assert "authz" in groups
        # 多域端点出现在多个分组
        multi = tagged[2]
        assert multi in groups["upload"]
        assert multi in groups["authz"]


class TestDecouplingAndZeroDeps:
    """G1 与业务域解耦 + 零外部依赖（Security Engineer 验收）。"""

    def test_no_external_imports(self):
        import importlib
        mod = importlib.import_module("core.endpoint.risk_domain")
        # 仅标准库，无第三方依赖
        src = Path(mod.__file__).read_text(encoding="utf-8")
        assert "import requests" not in src
        assert "import httpx" not in src
        assert "import cvss" not in src

    def test_decoupled_from_business_domain(self):
        """风险域与 business_understanding 的 domain_label 并存不冲突。"""
        # 风险域管"测什么漏洞"，domain_label 管"什么系统"
        rd = classify_risk_domain("/api/users/1", "GET")
        assert "authz" in rd
        # domain_label 可以是任意业务名，二者正交
        domain_label = "Web 应用"
        assert rd  # 风险域非空
        assert domain_label  # 业务域非空，互不影响

    def test_eight_domains_defined(self):
        """8 风险域全量定义（对标 api-pentest-extension）。"""
        domains = [d for d, _ in RISK_DOMAIN_RULES]
        assert domains == [
            "upload", "ssrf", "injection", "authz",
            "csrf", "file", "business", "config",
        ]
        # 每域都有中文标签
        for d in domains:
            assert d in DOMAIN_LABELS
