from __future__ import annotations

import hashlib
import time
from typing import Any
from urllib.parse import urlparse


def _clip_text(value: Any, limit: int = 5000) -> str:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "...(截断)"


def _headers_to_lines(headers: dict | None, limit: int = 50) -> list[str]:
    if not headers:
        return []
    lines: list[str] = []
    for k, v in list(headers.items())[:limit]:
        lines.append(f"{k}: {v}")
    return lines


def make_evidence_id(method: str, url: str, body: str = "", flow_id: str = "") -> str:
    """生成稳定、短小、可在报告和样本文件中引用的证据 ID。"""
    if flow_id:
        return f"ev_{flow_id}"
    raw = f"{method.upper()}\n{url}\n{body or ''}"
    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"ev_{digest}"


def build_request_packet(method: str, url: str, headers: dict | None = None,
                         body: str = "", max_body: int = 3000) -> str:
    """构造适合报告/样本文件引用的 HTTP 请求包预览。"""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    host = parsed.netloc
    lines = [f"{method.upper()} {path} HTTP/1.1"]
    if host:
        lines.append(f"Host: {host}")
    lines.extend(_headers_to_lines(headers))
    if body:
        lines.append("")
        lines.append(_clip_text(body, max_body))
    return "\n".join(lines)


def build_response_packet(status_code: int = 0, headers: dict | None = None,
                          body: str = "", max_body: int = 3000) -> str:
    """构造适合报告/样本文件引用的 HTTP 响应包预览。"""
    lines = [f"HTTP/1.1 {status_code or 0}"]
    lines.extend(_headers_to_lines(headers))
    if body:
        lines.append("")
        lines.append(_clip_text(body, max_body))
    return "\n".join(lines)


def normalize_trigger_context(context: dict | None = None, **kwargs) -> dict[str, Any]:
    """规范化页面/按钮/角色等触发上下文。"""
    raw: dict[str, Any] = {}
    if isinstance(context, dict):
        raw.update(context)
    raw.update({k: v for k, v in kwargs.items() if v not in (None, "", [], {})})

    out: dict[str, Any] = {}
    for key in (
        "role", "account", "credential_id", "page_url", "page_title",
        "element_text", "selector", "action", "tool", "worker", "module",
    ):
        value = raw.get(key)
        if value not in (None, "", [], {}):
            out[key] = _clip_text(value, 500)
    return out


def build_api_evidence(*, method: str, url: str, headers: dict | None = None,
                       body: str = "", status_code: int = 0,
                       response_headers: dict | None = None,
                       response_body: str = "", flow_id: str = "",
                       discovered_by: str = "", trigger_context: dict | None = None,
                       timestamp: float | None = None) -> dict[str, Any]:
    """把一次 API 样本归一化为可持久化、可报告引用的证据结构。"""
    evidence_id = make_evidence_id(method, url, body, flow_id)
    return {
        "evidence_id": evidence_id,
        "flow_id": flow_id or "",
        "method": method.upper(),
        "url": url,
        "path": urlparse(url).path or "/",
        "status_code": status_code or 0,
        "discovered_by": discovered_by or "",
        "timestamp": timestamp or time.time(),
        "trigger_context": normalize_trigger_context(trigger_context),
        "request_packet": build_request_packet(method, url, headers, body),
        "response_packet": build_response_packet(status_code, response_headers, response_body),
    }


def evidence_summary_lines(evidence: dict | None) -> list[str]:
    """将 evidence 结构格式化为样本文件中的简洁说明。"""
    if not evidence:
        return []
    lines = []
    ev_id = evidence.get("evidence_id", "")
    flow_id = evidence.get("flow_id", "")
    if ev_id:
        if flow_id:
            lines.append(f"Evidence: {ev_id}; Flow: {flow_id}（可用 proxy_get_flow_detail 查看完整流量）")
        else:
            lines.append(f"Evidence: {ev_id}")
    ctx = evidence.get("trigger_context", {}) if isinstance(evidence.get("trigger_context"), dict) else {}
    ctx_parts = []
    if ctx.get("role"):
        ctx_parts.append(f"角色={ctx['role']}")
    if ctx.get("page_url"):
        ctx_parts.append(f"页面={ctx['page_url']}")
    if ctx.get("element_text"):
        ctx_parts.append(f"元素={ctx['element_text']}")
    if ctx.get("selector"):
        ctx_parts.append(f"selector={ctx['selector']}")
    if ctx_parts:
        lines.append("Trigger: " + "; ".join(ctx_parts))
    return lines
