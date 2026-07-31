from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

_GRAPHQL_OPERATION_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)?", re.IGNORECASE)


def _header_get(headers: dict | None, name: str) -> str:
    if not headers:
        return ""
    name_l = name.lower()
    for k, v in headers.items():
        if str(k).lower() == name_l:
            return str(v or "")
    return ""


def _json_loads_maybe(text: str) -> Any:
    if not text or not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except Exception:
        return None


def _operation_from_query(query: str) -> tuple[str, str]:
    if not query:
        return "query", "anonymous"
    match = _GRAPHQL_OPERATION_RE.search(query)
    if not match:
        return "query", "anonymous"
    op_type = (match.group(1) or "query").lower()
    op_name = match.group(2) or "anonymous"
    return op_type, op_name


def extract_graphql_operations(
    *,
    method: str,
    url: str,
    headers: dict | None = None,
    body: str = "",
    response_body: str = "",
    status_code: int = 0,
    discovered_by: str = "",
) -> list[dict[str, Any]]:
    """从一次 HTTP 流量中拆出 GraphQL operation。"""
    method_u = (method or "GET").upper()
    content_type = _header_get(headers, "content-type").lower()
    url_l = (url or "").lower()
    parsed_body = _json_loads_maybe(body or "")

    looks_graphql = (
        "graphql" in url_l
        or "graphql" in content_type
        or (isinstance(parsed_body, dict) and ("query" in parsed_body or "operationName" in parsed_body))
        or (isinstance(parsed_body, list) and any(isinstance(x, dict) and "query" in x for x in parsed_body[:10]))
    )
    if not looks_graphql:
        return []

    payloads: list[dict[str, Any]] = []
    if isinstance(parsed_body, list):
        payloads = [x for x in parsed_body if isinstance(x, dict)]
    elif isinstance(parsed_body, dict):
        payloads = [parsed_body]
    elif body:
        payloads = [{"query": body}]
    else:
        payloads = [{"query": ""}]

    operations: list[dict[str, Any]] = []
    for payload in payloads[:20]:
        query = str(payload.get("query") or "")
        op_type, op_name = _operation_from_query(query)
        if payload.get("operationName"):
            op_name = str(payload.get("operationName"))
        variables = payload.get("variables") if isinstance(payload.get("variables"), dict) else {}
        query_hash = hashlib.sha256(query.encode("utf-8", errors="ignore")).hexdigest()[:16] if query else ""
        operations.append({
            "protocol": "graphql",
            "channel_type": "graphql",
            "method": method_u,
            "url": url,
            "path": urlparse(url).path or "/",
            "operation_type": op_type,
            "operation_name": op_name,
            "variables_keys": sorted(str(k) for k in variables.keys())[:50],
            "query_hash": query_hash,
            "query_sample": query[:1200],
            "status_code": status_code,
            "discovered_by": discovered_by or "traffic",
            "test_strategy": "graphql_operation",
        })
    return operations


def classify_realtime_flow(
    *,
    method: str,
    url: str,
    request_headers: dict | None = None,
    request_body: str = "",
    response_headers: dict | None = None,
    response_body: str = "",
    status_code: int = 0,
    discovered_by: str = "",
) -> list[dict[str, Any]]:
    """识别一次代理/浏览器流量中的 GraphQL、WebSocket、SSE 通道。"""
    channels: list[dict[str, Any]] = []
    method_u = (method or "GET").upper()
    url_s = url or ""
    url_l = url_s.lower()
    req_upgrade = _header_get(request_headers, "upgrade").lower()
    accept = _header_get(request_headers, "accept").lower()
    resp_ct = _header_get(response_headers, "content-type").lower()

    channels.extend(extract_graphql_operations(
        method=method_u,
        url=url_s,
        headers=request_headers,
        body=request_body or "",
        response_body=response_body or "",
        status_code=status_code,
        discovered_by=discovered_by,
    ))

    if url_l.startswith(("ws://", "wss://")) or req_upgrade == "websocket" or status_code == 101:
        channels.append({
            "protocol": "websocket",
            "channel_type": "websocket",
            "method": method_u,
            "url": url_s,
            "path": urlparse(url_s).path or "/",
            "status_code": status_code,
            "discovered_by": discovered_by or "traffic",
            "request_headers_of_interest": {
                k: v for k, v in (request_headers or {}).items()
                if str(k).lower() in {"sec-websocket-protocol", "origin", "authorization", "cookie"}
            },
            "message_samples": [],
            "test_strategy": "websocket_replay_or_browser",
        })

    if "text/event-stream" in resp_ct or "text/event-stream" in accept or "event-stream" in url_l:
        event_names: list[str] = []
        for line in (response_body or "").splitlines()[:200]:
            if line.startswith("event:"):
                name = line.split(":", 1)[1].strip()
                if name and name not in event_names:
                    event_names.append(name)
        channels.append({
            "protocol": "sse",
            "channel_type": "sse",
            "method": method_u,
            "url": url_s,
            "path": urlparse(url_s).path or "/",
            "status_code": status_code,
            "discovered_by": discovered_by or "traffic",
            "event_names": event_names[:30],
            "response_sample": (response_body or "")[:1200],
            "test_strategy": "sse_auth_and_leakage",
        })

    return dedupe_realtime_channels(channels)


def websocket_event(url: str, *, page_url: str = "", discovered_by: str = "crawler") -> dict[str, Any]:
    return {
        "protocol": "websocket",
        "channel_type": "websocket",
        "method": "WEBSOCKET",
        "url": url,
        "path": urlparse(url).path or "/",
        "page_url": page_url,
        "status_code": 0,
        "discovered_by": discovered_by,
        "message_samples": [],
        "test_strategy": "websocket_replay_or_browser",
    }


def dedupe_realtime_channels(items: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """按协议 + URL + operation/message 指纹保序去重。"""
    seen: set[tuple[str, str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        protocol = str(item.get("protocol") or item.get("channel_type") or "").lower()
        url = str(item.get("url") or "")
        op = str(item.get("operation_name") or "")
        qh = str(item.get("query_hash") or "")
        key = (protocol, url, op, qh)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
