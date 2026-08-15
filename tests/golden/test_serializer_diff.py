"""serializer / diff / recorder 的沙箱单测 —— 零浏览器/零 LLM。

证明「录制→回放→diff」机制本身正确（用 fake impl，不触怪物方法），
让闸门机制在样本落盘前就有 green 覆盖；真实样本回放见 ``test_golden_replay.py``。
"""
from __future__ import annotations

import json

import pytest

from core.crawler.models import (
    CrawledElement,
    CrawledForm,
    CrawledPage,
    CrawlRoundResult,
)
from core.js_analyzer._models import JSAnalysisResult, JSApiCall, JSRoute
from tests.golden.diff import semantic_diff
from tests.golden.recorder import (
    record_chat,
    record_crawl_round,
    replay_chat,
)
from tests.golden.serializer import canonicalize, parse_chat_event, serialize


# ------------------------------------------------------------------
# serializer
# ------------------------------------------------------------------
def test_serialize_crawl_round_result():
    r = CrawlRoundResult(role="anonymous")
    p = CrawledPage(url="http://x/api", title="API")
    p.elements.append(CrawledElement(page_url="http://x/api", tag="a", text="hi", selector="a"))
    p.forms.append(CrawledForm(page_url="http://x/api", action="/login", method="POST"))
    r.pages["http://x/api"] = p
    r.api_endpoints["GET /api"] = {"status": 200}
    r.js_endpoints.append("/hidden")
    r.login_success = True
    r.js_analysis = JSAnalysisResult(
        api_calls=[JSApiCall(method="GET", path="/api/x", source_file="a.js")],
        routes=[JSRoute(path="/dashboard")],
        js_files_analyzed=1,
        total_js_size=2048,
    )
    out = serialize(r)
    assert out["role"] == "anonymous"
    assert out["login_success"] is True
    assert out["pages"]["http://x/api"]["elements"][0]["text"] == "hi"
    # js_analysis 嵌套 dataclass 递归可序列化
    assert out["js_analysis"]["api_calls"][0]["method"] == "GET"
    assert out["js_analysis"]["routes"][0]["path"] == "/dashboard"
    # JSON 可往返
    json.dumps(out, ensure_ascii=False)


def test_canonicalize_normalizes_volatile_not_biz_ids():
    s = "at 2026-08-14T09:15:33.123Z run=550e8400-e29b-41d4-a716-446655440000 " \
        "token=eyJhbGci.eyJzdWI.s1234567890abcdef sha=abcdef0123456789abcdef0123456789ab user=123"
    out = canonicalize(s)
    assert "<TS>" in out and "<UUID>" in out and "<TOKEN>" in out
    # 业务数字 ID 保留（不误伤）
    assert "user=123" in out


def test_parse_chat_event_variants():
    assert parse_chat_event('{"type":"system","data":"hi"}') == {"type": "system", "data": "hi"}
    # SSE 帧：chat_loop._event 的实际产出形态（data: 前缀）
    assert parse_chat_event('data: {"type":"system","data":"hi"}') == {"type": "system", "data": "hi"}
    assert parse_chat_event("plain text") == {"type": "text", "data": "plain text"}
    assert parse_chat_event("{bad json")["type"] == "unparseable"
    assert parse_chat_event(None)["type"] == "nonstr"


# ------------------------------------------------------------------
# diff
# ------------------------------------------------------------------
def test_diff_identical_is_empty():
    g = {"output": {"a": 1, "b": [1, 2]}, "events": [{"type": "x", "data": "y"}], "meta": {}}
    assert semantic_diff(g, json.loads(json.dumps(g))) == []


def test_diff_output_field_drift():
    g = {"output": {"a": 1}, "events": [], "meta": {}}
    a = {"output": {"a": 2}, "events": [], "meta": {}}
    diffs = semantic_diff(g, a)
    assert any("output.a" in d and "值差异" in d for d in diffs)


def test_diff_event_sequence_order_and_type():
    g = {"output": None, "events": [{"type": "system", "data": "a"}, {"type": "data", "data": "b"}], "meta": {}}
    a = {"output": None, "events": [{"type": "system", "data": "a"}, {"type": "data", "data": "B"}], "meta": {}}
    diffs = semantic_diff(g, a)
    assert any("events[1]" in d for d in diffs)
    # 顺序差异
    a2 = {"output": None, "events": [{"type": "data", "data": "b"}, {"type": "system", "data": "a"}], "meta": {}}
    assert any("events[0].type" in d for d in semantic_diff(g, a2))


def test_diff_ignores_progress_meta():
    # meta.progress 不参与 diff
    g = {"output": {"a": 1}, "events": [], "meta": {"progress": ["x", "y"]}}
    a = {"output": {"a": 1}, "events": [], "meta": {"progress": ["z"]}}
    assert semantic_diff(g, a) == []


# ------------------------------------------------------------------
# recorder roundtrip —— 用 fake impl 证明 录制→回放→diff 闭环
# ------------------------------------------------------------------
class _FakeCrawler:
    """复刻 AutoCrawler 的 on_progress / _report / _emit_event 契约。"""

    def __init__(self):
        self.on_progress = None

    def _report(self, msg: str):
        if self.on_progress:
            self.on_progress(msg)

    def _emit_event(self, event_type: str, payload: dict):
        if not self.on_progress:
            return
        envelope = {"type": event_type, **payload}
        self.on_progress(f"__EVENT__:{json.dumps(envelope, ensure_ascii=False)}")

    async def _crawl_round(self, role: str, login_info):
        self._report(f"starting {role}")
        self._emit_event("phase", {"name": "crawl", "role": role})
        r = CrawlRoundResult(role=role)
        p = CrawledPage(url="http://x/api", title="API")
        p.elements.append(CrawledElement(page_url="http://x/api", tag="a", text="hi", selector="a"))
        r.pages["http://x/api"] = p
        r.login_success = role != "anonymous"
        self._report("done")
        return r


class _FakeCrawlerDrift(_FakeCrawler):
    async def _crawl_round(self, role, login_info):
        r = await super()._crawl_round(role, login_info)
        r.pages["http://x/api"].title = "CHANGED"  # 行为漂移
        return r


async def test_recorder_roundtrip_match(tmp_path):
    c = _FakeCrawler()
    golden = await record_crawl_round(c, "anonymous", None, "g1", root=tmp_path)
    actual = await record_crawl_round(c, "anonymous", None, "a1", root=tmp_path)
    # 结构化事件被正确捕获（phase 事件）
    assert any(e.get("type") == "phase" for e in golden["events"])
    assert golden["meta"]["progress"]  # 纯文本进度已落盘
    # 同实现 → 行为等价
    assert semantic_diff(golden, actual) == []


async def test_recorder_roundtrip_drift_detected(tmp_path):
    golden = await record_crawl_round(_FakeCrawler(), "anonymous", None, "g1", root=tmp_path)
    actual = await record_crawl_round(_FakeCrawlerDrift(), "anonymous", None, "a1", root=tmp_path)
    diffs = semantic_diff(golden, actual)
    assert any("title" in d for d in diffs), diffs


# ------------------------------------------------------------------
# chat roundtrip
# ------------------------------------------------------------------
class _FakeChatSession:
    def __init__(self, script: list[dict]):
        self._script = script

    async def chat(self, user_message: str):
        yield json.dumps({"type": "system", "data": f"echo:{user_message}"}, ensure_ascii=False)
        for ev in self._script:
            yield json.dumps(ev, ensure_ascii=False)


async def test_chat_roundtrip_match_and_drift(tmp_path):
    script = [{"type": "data", "data": "step1"}, {"type": "data", "data": "step2"}]
    golden = await record_chat(_FakeChatSession(script), "ping", "g1", root=tmp_path)
    # replay_chat 跑当前实现并返回规范化 envelope
    actual = await replay_chat(_FakeChatSession(script), "ping")
    assert semantic_diff(golden, actual) == []
    # 漂移：少一帧
    actual2 = await replay_chat(_FakeChatSession(script[:-1]), "ping")
    diffs = semantic_diff(golden, actual2)
    assert any("序列长度" in d for d in diffs)
