"""A5 / D6 契约冻结测试：core.crawler.crawler_core 公开面。

依据 hollowing-optimization-plan/plan/D6_split_contract_draft.md §1.1 + §3.3：
拆分 crawler_core（AutoCrawler 方法按阶段抽到 core/crawler/_phases/）时，以下
公开名与签名必须保持原样，全仓调用点零改动。

冻结公开面：
- AutoCrawler（class，__init__ 签名冻结）
- get_cdp_flows（function，调用方从 core.crawler.crawler_core 导入）
- CrawledElement / CrawledForm / CrawledPage / CrawlRoundResult / FORM_FILL_RULES

零网络、零 LLM；本机即可跑（crawler_core 无重依赖）。
"""
from __future__ import annotations

import inspect

import pytest


def _params(callable_) -> list[str]:
    return list(inspect.signature(callable_).parameters)


def test_autocrawler_importable_from_frozen_paths():
    """AutoCrawler 必须可从包路径与模块路径导入，且为同一对象。"""
    from core.crawler import AutoCrawler as FromPkg
    from core.crawler.crawler_core import AutoCrawler as FromMod

    assert FromPkg is FromMod, "core.crawler 与 core.crawler.crawler_core 的 AutoCrawler 必须同一对象"
    assert inspect.isclass(FromPkg)


def test_autocrawler_init_signature_frozen():
    """__init__ 形参名/顺序冻结（R1：入参签名不可改）。"""
    from core.crawler import AutoCrawler

    params = _params(AutoCrawler.__init__)
    assert params == [
        "self",
        "target",
        "credentials",
        "max_pages_per_round",
        "on_progress",
        "extra_scope",
        "skip_anonymous_round",
        "llm_chat_fn",
        "fast_mode",
        "api_only_mode",
    ], f"AutoCrawler.__init__ 签名漂移：{params}"


def test_get_cdp_flows_frozen_path_and_signature():
    """get_cdp_flows 必须仍可从 core.crawler.crawler_core 导入（R3 兼容路径）。"""
    from core.crawler.crawler_core import get_cdp_flows

    assert callable(get_cdp_flows)
    assert _params(get_cdp_flows) == ["target_url", "timeout"], (
        f"get_cdp_flows 签名漂移：{_params(get_cdp_flows)}"
    )


def test_crawler_models_re_exported():
    """数据类/常量经 core.crawler 暴露（§1.1）。"""
    from core.crawler import (
        CrawlRoundResult,
        CrawledElement,
        CrawledForm,
        CrawledPage,
        FORM_FILL_RULES,
    )

    assert all(inspect.isclass(c) for c in (CrawledElement, CrawledForm, CrawledPage, CrawlRoundResult))
    assert FORM_FILL_RULES is not None
