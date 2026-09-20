"""录制怪物方法 golden 样本 — 在完整 venv（playwright + 项目依赖）下运行。

产出 ``tests/golden/<method>/<sample_id>.json``，落盘后
``tests/golden/test_golden_replay.py`` 自动激活回放比对。

样本设计（覆盖三个怪物方法 + 沙箱可回放路径）：
  - chat / chat_greeting_no_llm
      AgentSession(llm=None, skip_recover=True) + "你好"
      → 纯 fast 路径，无浏览器无 LLM；**沙箱可回放**（行为等价闸门的最低门槛）
  - crawl_round / crawl_round_anonymous_mockspa
      AutoCrawler(target=mock_spa, fast_mode=True) + role="anonymous"
      → 需 playwright；回放需完整 venv
  - crawl_page_inner / crawl_page_inner_root_mockspa
      page + mock_spa 根 URL
      → 需 playwright；回放需完整 venv

用法：
    python -m scripts.record_golden                  # 录制全部
    python -m scripts.record_golden --method chat    # 仅录制 chat
    python -m scripts.record_golden --method crawl_round
    python -m scripts.record_golden --method crawl_page_inner
    python -m scripts.record_golden --port 9876      # 指定 mock_spa 端口
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# 让脚本可直接运行
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tests.golden.recorder import (  # noqa: E402
    record_chat,
    record_crawl_page_inner,
    record_crawl_round,
)
from tests.golden.replay_runtime import (  # noqa: E402
    RUNTIME_FAST_NO_LLM,
    RUNTIME_MOCK_SPA,
    RuntimeUnavailable,
    build_chat_session,
    build_crawler,
    build_page_for_inner,
    close_page,
    ensure_mock_spa,
)


# ------------------------------------------------------------------
# chat：沙箱可回放路径（无浏览器无 LLM）
# ------------------------------------------------------------------
async def record_chat_sample(port: int) -> str:
    recipe = {
        "runtime": RUNTIME_FAST_NO_LLM,
        "scenario": "greeting_no_target",
        "user_message": "你好",
    }
    session = build_chat_session(recipe)
    env = await record_chat(
        session, "你好", "chat_greeting_no_llm",
        root=None, recipe=recipe,
    )
    return f"chat/chat_greeting_no_llm.json  ({len(env['events'])} events)"


# ------------------------------------------------------------------
# crawl_round：匿名轮，mock_spa
# ------------------------------------------------------------------
async def record_crawl_round_sample(port: int) -> str:
    base = ensure_mock_spa(port)
    recipe = {
        "runtime": RUNTIME_MOCK_SPA,
        "target": base,
        "port": port,
        "fast_mode": True,
        "role": "anonymous",
        "login_info": None,
    }
    crawler = build_crawler(recipe)
    env = await record_crawl_round(
        crawler, "anonymous", None, "crawl_round_anonymous_mockspa",
        root=None, recipe=recipe,
    )
    n_pages = len((env.get("output") or {}).get("pages") or {})
    return f"crawl_round/crawl_round_anonymous_mockspa.json  ({n_pages} pages, {len(env['events'])} events)"


# ------------------------------------------------------------------
# crawl_page_inner：mock_spa 根 URL
# ------------------------------------------------------------------
async def record_crawl_page_inner_sample(port: int) -> str:
    base = ensure_mock_spa(port)
    recipe = {
        "runtime": RUNTIME_MOCK_SPA,
        "target": base,
        "port": port,
        "fast_mode": True,
        "url": f"{base}/",
    }
    crawler, page = await build_page_for_inner(recipe)
    try:
        captured: list = []
        # _noise / _noise_listener 复用 _crawl_page 的装配方式的最小可用品
        # （录制与回放用同一套，保证 diff 公平）
        _noise = _MinimalNoise()
        _noise_listener = lambda *a, **kw: None  # noqa: E731
        env = await record_crawl_page_inner(
            crawler, page, f"{base}/", captured, _noise, _noise_listener,
            "crawl_page_inner_root_mockspa", root=None, recipe=recipe,
        )
    finally:
        await close_page(page)
    return f"crawl_page_inner/crawl_page_inner_root_mockspa.json  ({len(env['events'])} events)"


class _MinimalNoise:
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
# 入口
# ------------------------------------------------------------------
_RECORDERS = {
    "chat": record_chat_sample,
    "crawl_round": record_crawl_round_sample,
    "crawl_page_inner": record_crawl_page_inner_sample,
}


async def _run(methods: list[str], port: int) -> int:
    failures: list[str] = []
    for m in methods:
        try:
            line = await _RECORDERS[m](port)
            print(f"  [OK] {m}: {line}")
        except RuntimeUnavailable as e:
            failures.append(f"{m}: 运行时不可用 — {e}")
            print(f"  [SKIP] {m}: {e}")
        except Exception as e:
            failures.append(f"{m}: {type(e).__name__}: {e}")
            print(f"  [FAIL] {m}: {type(e).__name__}: {e}")
    if failures:
        print("\n失败/跳过汇总:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\n全部录制完成。回放测试将在下次 pytest 自动激活。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="录制怪物方法 golden 样本")
    parser.add_argument(
        "--method", choices=list(_RECORDERS) + ["all"], default="all",
        help="录制哪个方法（默认 all）",
    )
    parser.add_argument("--port", type=int, default=9876, help="mock_spa 端口")
    args = parser.parse_args()

    methods = list(_RECORDERS) if args.method == "all" else [args.method]
    print(f"录制 golden 样本: {methods}  (mock_spa port={args.port})")
    return asyncio.run(_run(methods, args.port))


if __name__ == "__main__":
    sys.exit(main())
