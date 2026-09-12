"""怪物方法 golden 回放闸门 — D6 Stage 2–4 decompose 的解锁开关。

每个怪物方法一个参数化测试：
  1. ``list_samples(method)`` 返回样本 id 列表；为空 → 整体 skip（沙箱常态）
  2. 读取样本的 ``recipe``，经 ``replay_runtime`` 重建运行时；
     运行时不可用（无 playwright / 无 mock_spa）→ skip（不 fail）
  3. 跑当前实现产出 actual envelope，与 golden ``semantic_diff``
  4. diff 非空 → 断言失败，打印差异行，**挡住 decompose 合并**

样本落盘（完整 venv 跑 ``scripts/record_golden.py``）后，本测试自动激活；
行为等价（空 diff）即解锁对应怪物方法的拆分（D6 §6.4.3）。
"""
from __future__ import annotations

import pytest

from tests.golden.diff import semantic_diff
from tests.golden.recorder import (
    list_samples,
    load_sample,
    replay_chat,
    replay_crawl_page_inner,
    replay_crawl_round,
)
from tests.golden.replay_runtime import (
    RuntimeUnavailable,
    build_chat_session,
    build_crawler,
    build_page_for_inner,
    close_page,
)

pytestmark = pytest.mark.golden


def _sample_ids(method: str):
    """返回样本 id 列表；空时给一个带 skip mark 的占位参数，保证显式 skip。"""
    samples = list_samples(method)
    if not samples:
        return [pytest.param(
            "__none__",
            marks=pytest.mark.skip(reason=f"无 golden 样本: {method}（沙箱跳过；完整 venv 跑 scripts/record_golden.py 录制）"),
        )]
    return samples


# ------------------------------------------------------------------
# _crawl_round
# ------------------------------------------------------------------
@pytest.mark.parametrize("sample_id", _sample_ids("crawl_round"))
async def test_replay_crawl_round(sample_id: str):
    golden = load_sample("crawl_round", sample_id)
    recipe = golden.get("recipe") or {}
    inputs = golden.get("inputs") or {}
    role = inputs.get("role", "anonymous")
    login_info = inputs.get("login_info")
    try:
        crawler = build_crawler(recipe)
    except RuntimeUnavailable as e:
        pytest.skip(f"运行时不可用: {e}")
        return
    actual = await replay_crawl_round(crawler, role, login_info)
    diffs = semantic_diff(golden, actual)
    assert diffs == [], f"_crawl_round 行为漂移（与 golden {sample_id} 不等价）:\n" + "\n".join(diffs)


# ------------------------------------------------------------------
# _crawl_page_inner
# ------------------------------------------------------------------
@pytest.mark.parametrize("sample_id", _sample_ids("crawl_page_inner"))
async def test_replay_crawl_page_inner(sample_id: str):
    golden = load_sample("crawl_page_inner", sample_id)
    recipe = golden.get("recipe") or {}
    inputs = golden.get("inputs") or {}
    url = inputs.get("url") or recipe.get("target") or "http://127.0.0.1:9876/"
    captured: list = []
    try:
        crawler, page = await build_page_for_inner(recipe)
    except RuntimeUnavailable as e:
        pytest.skip(f"运行时不可用: {e}")
        return
    try:
        # _noise / _noise_listener 由 _crawl_page 正常装配；回放直接传最小可用品：
        #   _noise: 仅需 enabled 标志 + has_polling() 返回 False（不影响 inner 主逻辑）
        #   _noise_listener: 接收 (request,) 的可调用，空实现即可
        _noise = _MinimalNoise()
        _noise_listener = lambda *a, **kw: None  # noqa: E731
        actual = await replay_crawl_page_inner(crawler, page, url, captured, _noise, _noise_listener)
    finally:
        await close_page(page)
    diffs = semantic_diff(golden, actual)
    assert diffs == [], f"_crawl_page_inner 行为漂移（与 golden {sample_id} 不等价）:\n" + "\n".join(diffs)


class _MinimalNoise:
    """回放用最小噪音探测器：绕过 _NoiseDetector 的构造依赖。"""
    enabled = False

    def has_polling(self) -> bool:
        return False

    def feed(self, *_a, **_kw) -> None:
        pass

    def record(self, *_a, **_kw) -> None:
        pass

    def has_noise(self) -> bool:
        return False

    def blacklist_snapshot(self) -> list:
        return []


# ------------------------------------------------------------------
# chat()
# ------------------------------------------------------------------
@pytest.mark.parametrize("sample_id", _sample_ids("chat"))
async def test_replay_chat(sample_id: str):
    golden = load_sample("chat", sample_id)
    recipe = golden.get("recipe") or {}
    inputs = golden.get("inputs") or {}
    user_message = inputs.get("user_message", "")
    try:
        session = build_chat_session(recipe)
    except RuntimeUnavailable as e:
        pytest.skip(f"运行时不可用: {e}")
        return
    actual = await replay_chat(session, user_message)
    diffs = semantic_diff(golden, actual)
    assert diffs == [], f"chat() 行为漂移（与 golden {sample_id} 不等价）:\n" + "\n".join(diffs)
