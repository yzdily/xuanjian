"""§1.3 补测：Track A 按风险域派活（core/endpoint/risk_domain.py）。

group_by_risk_domain 是编排轨道 A 的按域分批派活入口：
一个端点命中多域时出现在多个分组（与多域并集语义一致）。
"""
from __future__ import annotations

from core.endpoint.risk_domain import group_by_risk_domain, tag_endpoints


def test_tag_endpoints_attaches_risk_domain():
    eps = [
        {"method": "POST", "url": "http://x/upload"},
        {"method": "GET", "url": "http://x/api/user/list"},
    ]
    tagged = tag_endpoints(eps, host="x")
    assert len(tagged) == 2
    for ep in tagged:
        assert "_tags" in ep
        assert ep["_tags"]["risk_domain"]


def test_group_by_risk_domain_single_domain_each():
    eps = [
        {"_tags": {"risk_domain": "upload"}},
        {"_tags": {"risk_domain": "ssrf"}},
    ]
    groups = group_by_risk_domain(eps)
    assert set(groups.keys()) == {"upload", "ssrf"}
    assert len(groups["upload"]) == 1
    assert len(groups["ssrf"]) == 1


def test_group_by_risk_domain_multi_domain_endpoint():
    """一个端点命中多域 → 出现在多个分组。"""
    eps = [{"_tags": {"risk_domain": ["upload", "injection"]}}]
    groups = group_by_risk_domain(eps)
    assert len(groups["upload"]) == 1
    assert len(groups["injection"]) == 1


def test_group_by_risk_domain_missing_tags_goes_general():
    """无 _tags 的端点落入 general 分组，不崩溃。"""
    eps = [{"method": "GET", "url": "http://x/"}]
    groups = group_by_risk_domain(eps)
    assert "general" in groups
    assert len(groups["general"]) == 1


def test_group_by_risk_domain_empty():
    assert group_by_risk_domain([]) == {}


def test_group_by_risk_domain_string_domain():
    """risk_domain 为字符串时按单域处理。"""
    eps = [{"_tags": {"risk_domain": "upload"}}]
    groups = group_by_risk_domain(eps)
    assert set(groups.keys()) == {"upload"}


def test_tag_then_group_pipeline():
    """tag_endpoints → group_by_risk_domain 全链路。"""
    eps = [
        {"method": "POST", "url": "http://x/upload"},
        {"method": "GET", "url": "http://x/static/app.js"},
        {"method": "GET", "url": "http://x/api/v1/users/1"},
    ]
    tagged = tag_endpoints(eps, host="x")
    groups = group_by_risk_domain(tagged)
    # 静态资源不应占满分组（其 risk_domain 独立）
    assert sum(len(v) for v in groups.values()) >= 3
