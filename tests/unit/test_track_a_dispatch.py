"""§1.3 补测：Track A 按风险域派活（core/endpoint/risk_domain.py）。

group_by_risk_domain 是编排轨道 A 的按域分批派活入口：
一个端点命中多域时出现在多个分组（与多域并集语义一致）。
"""
from __future__ import annotations

from core.endpoint.risk_domain import group_by_risk_domain, tag_endpoints
from core.endpoint.track_a import batch_groups_by_risk_domain, track_a_summary


class _FP:
    """最小 FeaturePoint 替身（_fp_to_endpoints 仅用 name/related_apis/page_url）。"""

    def __init__(self, name, related_apis=(), page_url=""):
        self.name = name
        self.related_apis = list(related_apis)
        self.page_url = page_url


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


# ========== track_a_summary 直测（2026-09-23 Bug#2 回归钉）==========
# 背景：track_a_summary 曾把 total_groups（已是 int）再套一层 len() → TypeError，
# 被 apply_track_a 的 except 兜住降级，导致 Track A 按域派活「每次都降级、从未生效」；
# 既有测试只断言源码字符串、从不执行本函数，故长期漏测。

def test_track_a_summary_with_domains():
    s = track_a_summary({"total_groups": 4, "dispatched_domains": ["authz", "inject"]})
    assert "4 组" in s
    assert "2 域" in s
    assert "authz" in s and "inject" in s


def test_track_a_summary_no_explicit_domain():
    s = track_a_summary({"total_groups": 0, "dispatched_domains": []})
    assert "未命中任何显式风险域" in s


def test_batch_groups_by_risk_domain_stats_and_summary():
    """端到端：分组 → stats → 摘要，全链路不抛（`total_groups` 必须是 int）。"""
    fg = [(
        "grp",
        [
            _FP("上传", related_apis=["POST http://x/upload"]),
            _FP("列表", related_apis=["GET http://x/api/user/list"]),
        ],
    )]
    new_groups, stats = batch_groups_by_risk_domain(fg, host="x")
    assert isinstance(stats["total_groups"], int)
    assert stats["total_groups"] == len(new_groups)
    # 关键回归：摘要生成不得因 total_groups 是 int 而崩
    assert "Track A" in track_a_summary(stats)
