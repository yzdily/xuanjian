"""非侵入式录制器 — 零改动怪物方法，仅在外部「套」一层捕获。

捕获通道（不改 ``crawler_core`` / ``chat_loop`` 源码）：
  - crawl：``AutoCrawler.on_progress`` 回调 —— ``_report`` 走纯文本，
    ``_emit_event`` 以 ``__EVENT__:<json>`` 前缀走结构化事件；录制时临时替换
    ``on_progress`` 为捕获器，``finally`` 还原。
  - chat：``chat()`` 是 async generator，yield ``_event()`` 返回的 JSON 字符串；
    录制时直接 ``async for`` 消费，逐帧 ``parse_chat_event``。

样本落盘 ``tests/golden/<method>/<sample_id>.json``；回放测试按 sample_id 加载。
``meta.progress``（crawler 纯文本进度）落盘供人查阅，不参与 diff。
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .serializer import SCHEMA_VERSION, parse_chat_event, serialize

GOLDEN_ROOT = Path(__file__).resolve().parent
_EVENT_PREFIX = "__EVENT__:"


# ------------------------------------------------------------------
# 样本落盘 / 加载
# ------------------------------------------------------------------
def _method_dir(method: str, root: Path | None = None) -> Path:
    return (root or GOLDEN_ROOT) / method


def save_sample(env: dict, method: str, sample_id: str, root: Path | None = None) -> Path:
    d = _method_dir(method, root)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{sample_id}.json"
    p.write_text(json.dumps(env, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def load_sample(method: str, sample_id: str, root: Path | None = None) -> dict:
    p = _method_dir(method, root) / f"{sample_id}.json"
    return json.loads(p.read_text(encoding="utf-8"))


def list_samples(method: str, root: Path | None = None) -> list[str]:
    d = _method_dir(method, root)
    if not d.exists():
        return []
    return sorted(p.stem for p in d.glob("*.json"))


def has_samples(method: str, root: Path | None = None) -> bool:
    return bool(list_samples(method, root))


# ------------------------------------------------------------------
# envelope
# ------------------------------------------------------------------
def _envelope(
    method: str,
    sample_id: str,
    inputs: dict,
    output: Any,
    events: list,
    progress: list[str] | None = None,
    recipe: dict | None = None,
) -> dict:
    """组装 GoldenSample 信封。

    ``recipe`` 描述「如何重建运行时以回放本样本」——record_golden.py 录制时写入，
    test_golden_replay.py 回放时读取并据此重建 crawler/session。recipe 不参与 diff
    （它不是行为产物，而是回放指令）。
    """
    env = {
        "schema_version": SCHEMA_VERSION,
        "method": method,
        "sample_id": sample_id,
        "recorded_at": datetime.now(timezone.utc).isoformat(),  # 信息字段，不参与 diff
        "inputs": serialize(inputs),
        "output": serialize(output) if output is not None else None,
        "events": [serialize(e) for e in events],
        "meta": {"progress": [serialize(p) for p in (progress or [])]},
    }
    if recipe:
        env["recipe"] = serialize(recipe)
    return env


# ------------------------------------------------------------------
# crawl_round / crawl_page_inner —— on_progress 捕获器
# ------------------------------------------------------------------
def _make_progress_capturer(captured_events: list, progress: list[str]):
    """返回一个 on_progress 替换函数：结构化事件入 events，纯文本入 progress。"""

    def _cap(msg):
        if isinstance(msg, str) and msg.startswith(_EVENT_PREFIX):
            try:
                ev = json.loads(msg[len(_EVENT_PREFIX):])
                if isinstance(ev, dict):
                    captured_events.append(ev)
                    return
            except Exception:
                pass
            progress.append(msg)
        else:
            progress.append(msg)

    return _cap


def _attach_capturer(crawler):
    """临时替换 crawler.on_progress 为捕获器；返回 (restore_fn, events, progress)。"""
    events: list = []
    progress: list[str] = []
    orig = crawler.on_progress
    cap = _make_progress_capturer(events, progress)

    def _forward(msg):
        cap(msg)
        if orig:
            try:
                orig(msg)
            except Exception:
                pass

    crawler.on_progress = _forward

    def _restore():
        crawler.on_progress = orig

    return _restore, events, progress


async def record_crawl_round(
    crawler, role: str, login_info: dict | None, sample_id: str,
    root: Path | None = None, recipe: dict | None = None,
) -> dict:
    restore, events, progress = _attach_capturer(crawler)
    try:
        result = await crawler._crawl_round(role, login_info)
    finally:
        restore()
    env = _envelope(
        "crawl_round", sample_id,
        {"role": role, "login_info": login_info}, result, events, progress, recipe,
    )
    save_sample(env, "crawl_round", sample_id, root)
    return env


async def record_crawl_page_inner(
    crawler, page, url: str, captured: list, _noise, _noise_listener,
    sample_id: str, root: Path | None = None, recipe: dict | None = None,
) -> dict:
    restore, events, progress = _attach_capturer(crawler)
    try:
        result = await crawler._crawl_page_inner(page, url, captured, _noise, _noise_listener)
    finally:
        restore()
    env = _envelope(
        "crawl_page_inner", sample_id,
        {"url": url}, result, events, progress, recipe,
    )
    # captured 是 out-param（CDP 流量），快照到 meta 供人查阅（不参与 diff）
    env["meta"]["captured_count"] = len(captured)
    save_sample(env, "crawl_page_inner", sample_id, root)
    return env


# ------------------------------------------------------------------
# chat —— async generator 消费
# ------------------------------------------------------------------
async def record_chat(
    session, user_message: str, sample_id: str,
    root: Path | None = None, recipe: dict | None = None,
) -> dict:
    events: list = []
    async for chunk in session.chat(user_message):
        events.append(parse_chat_event(chunk))
    env = _envelope(
        "chat", sample_id, {"user_message": user_message}, None, events, [], recipe,
    )
    save_sample(env, "chat", sample_id, root)
    return env


# ------------------------------------------------------------------
# 回放（不落盘）—— 跑当前实现，返回规范化 envelope 供与 golden diff
# ------------------------------------------------------------------
async def replay_chat(session, user_message: str) -> dict:
    """回放：跑当前 chat() 实现并返回规范化 envelope（不落盘），供与 golden diff。"""
    events: list = []
    async for chunk in session.chat(user_message):
        events.append(parse_chat_event(chunk))
    return {
        "output": None,
        "events": [serialize(e) for e in events],
        "meta": {"progress": []},
    }


async def replay_crawl_round(
    crawler, role: str, login_info: dict | None,
) -> dict:
    """回放：跑当前 _crawl_round 实现并返回规范化 envelope（不落盘）。"""
    restore, events, progress = _attach_capturer(crawler)
    try:
        result = await crawler._crawl_round(role, login_info)
    finally:
        restore()
    return {
        "output": serialize(result) if result is not None else None,
        "events": [serialize(e) for e in events],
        "meta": {"progress": [serialize(p) for p in progress]},
    }


async def replay_crawl_page_inner(
    crawler, page, url: str, captured: list, _noise, _noise_listener,
) -> dict:
    """回放：跑当前 _crawl_page_inner 实现并返回规范化 envelope（不落盘）。"""
    restore, events, progress = _attach_capturer(crawler)
    try:
        result = await crawler._crawl_page_inner(page, url, captured, _noise, _noise_listener)
    finally:
        restore()
    env = {
        "output": serialize(result) if result is not None else None,
        "events": [serialize(e) for e in events],
        "meta": {
            "progress": [serialize(p) for p in progress],
            "captured_count": len(captured),
        },
    }
    return env
