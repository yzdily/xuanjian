import asyncio

from core.parallel.batch_test import _meta_analyze_checklist
from core.parallel.grouping import _smart_group_features
from core.sitemap import CheckItem, FeaturePoint, Priority


class BrokenLLM:
    chat = None


def _feature(idx: int) -> FeaturePoint:
    return FeaturePoint(
        id=f"fp_{idx}",
        name=f"测试功能 {idx}",
        related_apis=[f"GET https://example.com/api/v1/items/{idx}"],
        priority=Priority.HIGH,
        checklist=[CheckItem("未授权访问")],
    )


def test_meta_analyze_skips_when_llm_chat_not_callable():
    result = asyncio.run(_meta_analyze_checklist([_feature(1)], BrokenLLM()))

    assert result == {"script_batch": [], "llm_required": []}


def test_smart_group_falls_back_when_llm_chat_not_callable():
    features = [_feature(i) for i in range(6)]

    groups = asyncio.run(_smart_group_features(features, BrokenLLM()))

    assert groups
    assert sum(len(group_features) for _, group_features in groups) == len(features)
