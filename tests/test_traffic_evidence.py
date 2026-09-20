"""
流量证据模块测试

覆盖：make_evidence_id、build_request_packet、build_response_packet、
      normalize_trigger_context、build_api_evidence、evidence_summary_lines
"""

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.traffic_evidence import (
    make_evidence_id,
    build_request_packet,
    build_response_packet,
    normalize_trigger_context,
    build_api_evidence,
    evidence_summary_lines,
    _clip_text,
)


class TestClipText:
    def test_short_text(self):
        assert _clip_text("hello", 100) == "hello"

    def test_long_text(self):
        text = "a" * 200
        result = _clip_text(text, 100)
        assert len(result) < 200
        assert "截断" in result

    def test_none_value(self):
        assert _clip_text(None) == ""


class TestMakeEvidenceId:
    def test_with_flow_id(self):
        eid = make_evidence_id("GET", "http://x.com/api", flow_id="flow_123")
        assert eid == "ev_flow_123"

    def test_without_flow_id(self):
        eid = make_evidence_id("POST", "http://x.com/api", body='{"id":1}')
        assert eid.startswith("ev_")
        assert len(eid) == 15  # "ev_" + 12 hex chars

    def test_deterministic(self):
        eid1 = make_evidence_id("GET", "http://x.com/api")
        eid2 = make_evidence_id("GET", "http://x.com/api")
        assert eid1 == eid2

    def test_different_inputs(self):
        eid1 = make_evidence_id("GET", "http://x.com/a")
        eid2 = make_evidence_id("GET", "http://x.com/b")
        assert eid1 != eid2


class TestBuildRequestPacket:
    def test_basic_get(self):
        pkt = build_request_packet("GET", "http://example.com/api/user?id=1")
        assert "GET /api/user?id=1 HTTP/1.1" in pkt
        assert "Host: example.com" in pkt

    def test_post_with_body(self):
        pkt = build_request_packet(
            "POST", "http://x.com/api/login",
            headers={"Content-Type": "application/json"},
            body='{"user":"admin","pass":"123"}'
        )
        assert "POST /api/login HTTP/1.1" in pkt
        assert "Content-Type: application/json" in pkt
        assert '"user":"admin"' in pkt

    def test_body_truncation(self):
        long_body = "x" * 5000
        pkt = build_request_packet("POST", "http://x.com/api", body=long_body, max_body=100)
        assert "截断" in pkt


class TestBuildResponsePacket:
    def test_basic(self):
        pkt = build_response_packet(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"status":"ok"}'
        )
        assert "HTTP/1.1 200" in pkt
        assert "Content-Type: application/json" in pkt
        assert '"status":"ok"' in pkt

    def test_empty(self):
        pkt = build_response_packet()
        assert "HTTP/1.1 0" in pkt


class TestNormalizeTriggerContext:
    def test_basic(self):
        ctx = normalize_trigger_context(
            role="admin",
            page_url="http://x.com/admin",
            element_text="删除按钮",
        )
        assert ctx["role"] == "admin"
        assert ctx["page_url"] == "http://x.com/admin"
        assert ctx["element_text"] == "删除按钮"

    def test_from_dict(self):
        ctx = normalize_trigger_context({"role": "user", "selector": "#btn"})
        assert ctx["role"] == "user"
        assert ctx["selector"] == "#btn"

    def test_empty_values_excluded(self):
        ctx = normalize_trigger_context(role="", page_url=None, element_text="")
        assert "role" not in ctx
        assert "page_url" not in ctx

    def test_merge_dict_and_kwargs(self):
        ctx = normalize_trigger_context({"role": "user"}, page_url="http://x.com")
        assert ctx["role"] == "user"
        assert ctx["page_url"] == "http://x.com"


class TestBuildApiEvidence:
    def test_full_evidence(self):
        ev = build_api_evidence(
            method="POST",
            url="http://x.com/api/order",
            headers={"Authorization": "Bearer token"},
            body='{"item_id": 1}',
            status_code=200,
            response_body='{"order_id": "abc"}',
            flow_id="flow_001",
            discovered_by="crawler",
            trigger_context={"role": "user", "page_url": "http://x.com/cart"},
        )
        assert ev["evidence_id"] == "ev_flow_001"
        assert ev["method"] == "POST"
        assert ev["url"] == "http://x.com/api/order"
        assert ev["path"] == "/api/order"
        assert ev["status_code"] == 200
        assert ev["discovered_by"] == "crawler"
        assert "Bearer token" in ev["request_packet"]
        assert "order_id" in ev["response_packet"]
        assert ev["trigger_context"]["role"] == "user"

    def test_minimal_evidence(self):
        ev = build_api_evidence(method="GET", url="http://x.com/")
        assert ev["evidence_id"].startswith("ev_")
        assert ev["method"] == "GET"


class TestEvidenceSummaryLines:
    def test_with_evidence(self):
        ev = {
            "evidence_id": "ev_abc123",
            "flow_id": "flow_001",
            "trigger_context": {
                "role": "admin",
                "page_url": "http://x.com/admin",
            }
        }
        lines = evidence_summary_lines(ev)
        assert len(lines) >= 1
        assert "ev_abc123" in lines[0]
        assert "flow_001" in lines[0]
        assert "admin" in lines[1]

    def test_empty_evidence(self):
        assert evidence_summary_lines(None) == []
        assert evidence_summary_lines({}) == []
