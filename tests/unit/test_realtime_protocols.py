"""realtime_protocols 单元测试（确定性，零网络 / 零文件副作用）

验证点：
- ``_header_get``：大小写不敏感、None / 空字典 / 缺失键 / None 值
- ``_json_loads_maybe``：有效 JSON / 无效 JSON / 空字符串 / 非字符串 / 非 JSON 文本
- ``_operation_from_query``：query / mutation / subscription / 空 / 匿名
- ``extract_graphql_operations``：URL 含 graphql / content-type 含 graphql /
  body 含 query 字段 / batch query / operationName 覆盖 / variables / query_hash /
  非 GraphQL 流量
- ``classify_realtime_flow``：WebSocket（ws:// / Upgrade / 101）/ SSE（content-type /
  accept / url）/ GraphQL / 多通道共存 / 纯静态流量
- ``websocket_event``：默认值 / page_url / discovered_by / path 解析
- ``dedupe_realtime_channels``：按 protocol+url+operation+query_hash 去重 /
  None / 非 dict 过滤 / 保序
"""

from __future__ import annotations

import hashlib
import json

import pytest

from core.realtime_protocols import (
    _header_get,
    _json_loads_maybe,
    _operation_from_query,
    classify_realtime_flow,
    dedupe_realtime_channels,
    extract_graphql_operations,
    websocket_event,
)


# ============================================================
# _header_get
# ============================================================
class TestHeaderGet:
    def test_case_insensitive_match(self):
        headers = {"Content-Type": "application/json"}
        assert _header_get(headers, "content-type") == "application/json"

    def test_uppercase_header_name(self):
        headers = {"CONTENT-TYPE": "text/event-stream"}
        assert _header_get(headers, "content-type") == "text/event-stream"

    def test_mixed_case_lookup_name(self):
        headers = {"content-type": "application/graphql"}
        assert _header_get(headers, "Content-Type") == "application/graphql"

    def test_none_headers(self):
        assert _header_get(None, "content-type") == ""

    def test_empty_dict(self):
        assert _header_get({}, "content-type") == ""

    def test_missing_key(self):
        headers = {"accept": "*/*"}
        assert _header_get(headers, "content-type") == ""

    def test_none_value(self):
        headers = {"content-type": None}
        assert _header_get(headers, "content-type") == ""

    def test_non_string_value_coerced(self):
        headers = {"content-length": 42}
        assert _header_get(headers, "content-length") == "42"


# ============================================================
# _json_loads_maybe
# ============================================================
class TestJsonLoadsMaybe:
    def test_valid_json_object(self):
        assert _json_loads_maybe('{"query": "{ user { id } }"}') == {
            "query": "{ user { id } }"
        }

    def test_valid_json_array(self):
        result = _json_loads_maybe('[{"query": "q1"}, {"query": "q2"}]')
        assert isinstance(result, list)
        assert len(result) == 2

    def test_invalid_json(self):
        assert _json_loads_maybe('{"query": broken') is None

    def test_empty_string(self):
        assert _json_loads_maybe("") is None

    def test_none_input(self):
        assert _json_loads_maybe(None) is None  # type: ignore[arg-type]

    def test_non_string_input(self):
        assert _json_loads_maybe(123) is None  # type: ignore[arg-type]

    def test_non_json_text(self):
        assert _json_loads_maybe("hello world") is None

    def test_json_with_leading_whitespace(self):
        assert _json_loads_maybe('  {"query": "q"}') == {"query": "q"}

    def test_string_not_starting_with_bracket(self):
        # 首字符不是 [ 或 { 的直接返回 None
        assert _json_loads_maybe('"just a string"') is None
        assert _json_loads_maybe('42') is None
        assert _json_loads_maybe('true') is None


# ============================================================
# _operation_from_query
# ============================================================
class TestOperationFromQuery:
    def test_named_query(self):
        assert _operation_from_query("query GetUser { user { id } }") == ("query", "GetUser")

    def test_named_mutation(self):
        assert _operation_from_query("mutation UpdateUser($id: ID!) { updateUser(id: $id) { ok } }") == ("mutation", "UpdateUser")

    def test_named_subscription(self):
        assert _operation_from_query("subscription OnMessage { newMessage { id text } }") == ("subscription", "OnMessage")

    def test_empty_string(self):
        assert _operation_from_query("") == ("query", "anonymous")

    def test_none(self):
        assert _operation_from_query(None) == ("query", "anonymous")  # type: ignore[arg-type]

    def test_anonymous_query_no_keyword(self):
        # 无 query/mutation/subscription 关键字的匿名查询
        assert _operation_from_query("{ user { id name } }") == ("query", "anonymous")

    def test_query_keyword_without_name(self):
        # query 关键字但无名字
        assert _operation_from_query("query { user { id } }") == ("query", "anonymous")

    def test_case_insensitive_keyword(self):
        assert _operation_from_query("QUERY GetUser { user { id } }") == ("query", "GetUser")
        assert _operation_from_query("Mutation UpdateUser { updateUser { ok } }") == ("mutation", "UpdateUser")


# ============================================================
# extract_graphql_operations
# ============================================================
class TestExtractGraphqlOperations:
    def test_url_contains_graphql(self):
        body = json.dumps({"query": "query GetUser { user { id } }"})
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/graphql",
            headers={"Content-Type": "application/json"}, body=body,
        )
        assert len(ops) == 1
        assert ops[0]["protocol"] == "graphql"
        assert ops[0]["operation_type"] == "query"
        assert ops[0]["operation_name"] == "GetUser"
        assert ops[0]["url"] == "https://example.com/graphql"
        assert ops[0]["path"] == "/graphql"

    def test_content_type_contains_graphql(self):
        body = json.dumps({"query": "mutation Up { updateUser { ok } }"})
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/api",
            headers={"Content-Type": "application/graphql+json"}, body=body,
        )
        assert len(ops) == 1
        assert ops[0]["operation_type"] == "mutation"

    def test_body_has_query_field(self):
        """body 是 JSON dict 且含 query 字段即判定为 GraphQL。"""
        body = json.dumps({"query": "{ user { id } }"})
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/api/data",
            headers={"Content-Type": "application/json"}, body=body,
        )
        assert len(ops) == 1
        assert ops[0]["operation_name"] == "anonymous"

    def test_body_has_operation_name_without_query(self):
        """body 含 operationName 也算 GraphQL。"""
        body = json.dumps({"operationName": "GetUser"})
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/api",
            headers={"Content-Type": "application/json"}, body=body,
        )
        assert len(ops) == 1
        # operationName 覆盖
        assert ops[0]["operation_name"] == "GetUser"

    def test_batch_query(self):
        """body 是 JSON 数组 → 多个 operation。"""
        body = json.dumps([
            {"query": "query GetA { a { id } }"},
            {"query": "query GetB { b { id } }"},
        ])
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/graphql",
            headers={"Content-Type": "application/json"}, body=body,
        )
        assert len(ops) == 2
        assert ops[0]["operation_name"] == "GetA"
        assert ops[1]["operation_name"] == "GetB"

    def test_non_graphql_request_returns_empty(self):
        ops = extract_graphql_operations(
            method="GET", url="https://example.com/api/users",
            headers={"Content-Type": "application/json"}, body='{"name": "test"}',
        )
        assert ops == []

    def test_operation_name_override(self):
        """payload 中的 operationName 覆盖 query 解析出的名字。"""
        body = json.dumps({
            "query": "query QFromQuery { user { id } }",
            "operationName": "ActualName",
        })
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/graphql",
            headers={"Content-Type": "application/json"}, body=body,
        )
        assert ops[0]["operation_name"] == "ActualName"

    def test_variables_keys_extracted(self):
        body = json.dumps({
            "query": "query GetUser($id: ID!, $name: String) { user { id } }",
            "variables": {"id": "1", "name": "alice"},
        })
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/graphql",
            headers={"Content-Type": "application/json"}, body=body,
        )
        assert ops[0]["variables_keys"] == ["id", "name"]

    def test_query_hash_computed(self):
        query = "query GetUser { user { id } }"
        body = json.dumps({"query": query})
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/graphql",
            headers={"Content-Type": "application/json"}, body=body,
        )
        expected = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
        assert ops[0]["query_hash"] == expected

    def test_empty_query_has_empty_hash(self):
        body = ""
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/graphql",
            headers={"Content-Type": "application/json"}, body=body,
        )
        assert len(ops) == 1
        assert ops[0]["query_hash"] == ""
        assert ops[0]["query_sample"] == ""

    def test_non_json_body_with_graphql_url(self):
        """body 是非 JSON 纯文本，但 URL 含 graphql → 作为 query 文本处理。"""
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/graphql",
            headers={"Content-Type": "text/plain"},
            body="query GetUser { user { id } }",
        )
        assert len(ops) == 1
        assert ops[0]["operation_name"] == "GetUser"
        assert ops[0]["query_sample"] == "query GetUser { user { id } }"

    def test_discovered_by_default(self):
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/graphql",
            body=json.dumps({"query": "{ user { id } }"}),
        )
        assert ops[0]["discovered_by"] == "traffic"

    def test_discovered_by_custom(self):
        ops = extract_graphql_operations(
            method="POST", url="https://example.com/graphql",
            body=json.dumps({"query": "{ user { id } }"}),
            discovered_by="crawler",
        )
        assert ops[0]["discovered_by"] == "crawler"

    def test_method_uppercased(self):
        ops = extract_graphql_operations(
            method="post", url="https://example.com/graphql",
            body=json.dumps({"query": "{ user { id } }"}),
        )
        assert ops[0]["method"] == "POST"

    def test_path_fallback_to_root(self):
        ops = extract_graphql_operations(
            method="POST", url="https://example.com",
            body=json.dumps({"query": "{ user { id } }"}),
        )
        assert ops[0]["path"] == "/"


# ============================================================
# classify_realtime_flow — WebSocket
# ============================================================
class TestClassifyWebSocket:
    def test_ws_url_scheme(self):
        channels = classify_realtime_flow(
            method="GET", url="wss://example.com/ws",
            request_headers={}, response_headers={},
        )
        ws = [c for c in channels if c["protocol"] == "websocket"]
        assert len(ws) == 1
        assert ws[0]["url"] == "wss://example.com/ws"
        assert ws[0]["path"] == "/ws"
        assert ws[0]["test_strategy"] == "websocket_replay_or_browser"

    def test_upgrade_header(self):
        channels = classify_realtime_flow(
            method="GET", url="https://example.com/socket",
            request_headers={"Upgrade": "websocket"},
            response_headers={},
        )
        ws = [c for c in channels if c["protocol"] == "websocket"]
        assert len(ws) == 1

    def test_status_101(self):
        channels = classify_realtime_flow(
            method="GET", url="https://example.com/socket",
            request_headers={}, response_headers={},
            status_code=101,
        )
        ws = [c for c in channels if c["protocol"] == "websocket"]
        assert len(ws) == 1

    def test_websocket_request_headers_of_interest(self):
        channels = classify_realtime_flow(
            method="GET", url="wss://example.com/ws",
            request_headers={
                "Sec-WebSocket-Protocol": "chat",
                "Origin": "https://example.com",
                "Authorization": "Bearer xxx",
                "Cookie": "session=abc",
                "X-Other": "ignored",
            },
            response_headers={},
        )
        ws = channels[0]
        hoi = ws["request_headers_of_interest"]
        assert "Sec-WebSocket-Protocol" in hoi
        assert "Origin" in hoi
        assert "Authorization" in hoi
        assert "Cookie" in hoi
        assert "X-Other" not in hoi


# ============================================================
# classify_realtime_flow — SSE
# ============================================================
class TestClassifySSE:
    def test_sse_via_response_content_type(self):
        channels = classify_realtime_flow(
            method="GET", url="https://example.com/events",
            request_headers={}, response_headers={"Content-Type": "text/event-stream"},
            response_body="data: hello\n\n",
        )
        sse = [c for c in channels if c["protocol"] == "sse"]
        assert len(sse) == 1
        assert sse[0]["test_strategy"] == "sse_auth_and_leakage"

    def test_sse_via_accept_header(self):
        channels = classify_realtime_flow(
            method="GET", url="https://example.com/events",
            request_headers={"Accept": "text/event-stream"},
            response_headers={},
        )
        sse = [c for c in channels if c["protocol"] == "sse"]
        assert len(sse) == 1

    def test_sse_via_url(self):
        channels = classify_realtime_flow(
            method="GET", url="https://example.com/api/event-stream",
            request_headers={}, response_headers={},
        )
        sse = [c for c in channels if c["protocol"] == "sse"]
        assert len(sse) == 1

    def test_sse_event_names_extracted(self):
        body = "event: update\ndata: {}\n\nevent: delete\ndata: {}\n\nevent: update\ndata: {}\n"
        channels = classify_realtime_flow(
            method="GET", url="https://example.com/events",
            request_headers={}, response_headers={"Content-Type": "text/event-stream"},
            response_body=body,
        )
        sse = channels[0]
        # update 出现两次但去重
        assert sse["event_names"] == ["update", "delete"]

    def test_sse_response_sample_truncated(self):
        long_body = "data: " + "x" * 2000 + "\n"
        channels = classify_realtime_flow(
            method="GET", url="https://example.com/events",
            request_headers={}, response_headers={"Content-Type": "text/event-stream"},
            response_body=long_body,
        )
        assert len(channels[0]["response_sample"]) == 1200


# ============================================================
# classify_realtime_flow — GraphQL & 多通道
# ============================================================
class TestClassifyGraphqlAndMulti:
    def test_graphql_channel_detected(self):
        body = json.dumps({"query": "query GetUser { user { id } }"})
        channels = classify_realtime_flow(
            method="POST", url="https://example.com/graphql",
            request_headers={"Content-Type": "application/json"},
            response_headers={}, request_body=body,
        )
        gql = [c for c in channels if c["protocol"] == "graphql"]
        assert len(gql) == 1
        assert gql[0]["operation_name"] == "GetUser"

    def test_multi_channel_graphql_and_websocket(self):
        """wss:// URL 含 graphql → 同时产生 graphql + websocket 通道。"""
        channels = classify_realtime_flow(
            method="GET", url="wss://example.com/graphql",
            request_headers={}, response_headers={},
            status_code=101,
        )
        protocols = {c["protocol"] for c in channels}
        assert "graphql" in protocols
        assert "websocket" in protocols

    def test_multi_channel_graphql_and_sse(self):
        """URL 含 graphql 且响应是 SSE → 同时产生 graphql + sse 通道。"""
        channels = classify_realtime_flow(
            method="GET", url="https://example.com/graphql",
            request_headers={}, response_headers={"Content-Type": "text/event-stream"},
            response_body="event: data\ndata: {}\n",
        )
        protocols = {c["protocol"] for c in channels}
        assert "graphql" in protocols
        assert "sse" in protocols

    def test_no_realtime_channel(self):
        """普通 HTTP 请求不产生任何通道。"""
        channels = classify_realtime_flow(
            method="GET", url="https://example.com/api/users",
            request_headers={"Accept": "application/json"},
            response_headers={"Content-Type": "application/json"},
            response_body='[{"id": 1}]',
        )
        assert channels == []


# ============================================================
# websocket_event
# ============================================================
class TestWebsocketEvent:
    def test_basic_construction(self):
        ev = websocket_event("wss://example.com/ws")
        assert ev["protocol"] == "websocket"
        assert ev["channel_type"] == "websocket"
        assert ev["method"] == "WEBSOCKET"
        assert ev["url"] == "wss://example.com/ws"
        assert ev["path"] == "/ws"
        assert ev["page_url"] == ""
        assert ev["status_code"] == 0
        assert ev["discovered_by"] == "crawler"
        assert ev["message_samples"] == []
        assert ev["test_strategy"] == "websocket_replay_or_browser"

    def test_with_page_url_and_discovered_by(self):
        ev = websocket_event(
            "wss://example.com/ws",
            page_url="https://example.com/dashboard",
            discovered_by="traffic",
        )
        assert ev["page_url"] == "https://example.com/dashboard"
        assert ev["discovered_by"] == "traffic"

    def test_path_fallback_to_root(self):
        ev = websocket_event("wss://example.com")
        assert ev["path"] == "/"

    def test_path_with_query_string(self):
        ev = websocket_event("wss://example.com/ws?token=abc")
        # urlparse path 不含 query
        assert ev["path"] == "/ws"
        assert ev["url"] == "wss://example.com/ws?token=abc"


# ============================================================
# dedupe_realtime_channels
# ============================================================
class TestDedupeRealtimeChannels:
    def test_none_returns_empty(self):
        assert dedupe_realtime_channels(None) == []

    def test_empty_list(self):
        assert dedupe_realtime_channels([]) == []

    def test_non_dict_items_filtered(self):
        items = ["not a dict", 42, None, {"protocol": "websocket", "url": "wss://x"}]
        result = dedupe_realtime_channels(items)  # type: ignore[arg-type]
        assert len(result) == 1
        assert result[0]["protocol"] == "websocket"

    def test_dedup_identical_graphql(self):
        op1 = {"protocol": "graphql", "url": "https://x/graphql",
               "operation_name": "GetUser", "query_hash": "abc123"}
        op2 = {"protocol": "graphql", "url": "https://x/graphql",
               "operation_name": "GetUser", "query_hash": "abc123"}
        result = dedupe_realtime_channels([op1, op2])
        assert len(result) == 1

    def test_different_operation_name_kept(self):
        op1 = {"protocol": "graphql", "url": "https://x/graphql",
               "operation_name": "GetUser", "query_hash": "aaa"}
        op2 = {"protocol": "graphql", "url": "https://x/graphql",
               "operation_name": "GetPost", "query_hash": "bbb"}
        result = dedupe_realtime_channels([op1, op2])
        assert len(result) == 2

    def test_different_query_hash_kept(self):
        op1 = {"protocol": "graphql", "url": "https://x/graphql",
               "operation_name": "GetUser", "query_hash": "aaa"}
        op2 = {"protocol": "graphql", "url": "https://x/graphql",
               "operation_name": "GetUser", "query_hash": "bbb"}
        result = dedupe_realtime_channels([op1, op2])
        assert len(result) == 2

    def test_different_protocol_kept(self):
        """同 URL 不同 protocol 不算重复。"""
        ws = {"protocol": "websocket", "url": "wss://x/ws"}
        sse = {"protocol": "sse", "url": "wss://x/ws"}
        result = dedupe_realtime_channels([ws, sse])
        assert len(result) == 2

    def test_order_preserved(self):
        items = [
            {"protocol": "graphql", "url": "https://x/g", "operation_name": "A", "query_hash": "1"},
            {"protocol": "websocket", "url": "wss://x/ws"},
            {"protocol": "sse", "url": "https://x/events"},
        ]
        result = dedupe_realtime_channels(items)
        assert [c["protocol"] for c in result] == ["graphql", "websocket", "sse"]

    def test_channel_type_used_as_protocol_fallback(self):
        """item 无 protocol 字段但有 channel_type 时，用 channel_type 做去重键。"""
        ws1 = {"channel_type": "websocket", "url": "wss://x/ws"}
        ws2 = {"channel_type": "websocket", "url": "wss://x/ws"}
        result = dedupe_realtime_channels([ws1, ws2])
        assert len(result) == 1

    def test_dedup_with_sse_events(self):
        """两个 SSE 通道同 URL 但不同 event 不去重（key 不含 event_names）。"""
        sse1 = {"protocol": "sse", "url": "https://x/events", "event_names": ["a"]}
        sse2 = {"protocol": "sse", "url": "https://x/events", "event_names": ["b"]}
        # key = (protocol, url, operation_name="", query_hash="") → 相同 → 去重
        result = dedupe_realtime_channels([sse1, sse2])
        assert len(result) == 1
