"""Export merged packets to a minimal OpenAPI 3.0 document."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
UNSAFE_PATH_RE = re.compile(
    r"/(delete|remove|destroy|drop|transfer|pay|payment|withdraw|refund|order/confirm|logout)(/|$|[?_-])",
    re.IGNORECASE,
)


def _is_destructive(packet: dict) -> bool:
    method = str(packet.get("method", "GET")).upper()
    url = str(packet.get("url", ""))
    path = urlparse(url).path or str(packet.get("path", ""))
    if method not in SAFE_METHODS and UNSAFE_PATH_RE.search(path):
        return True
    return False


def _mask_headers(headers: dict) -> dict:
    masked = {}
    for key, value in (headers or {}).items():
        if key.lower() in {"authorization", "cookie", "set-cookie", "x-csrf-token", "x-xsrf-token"}:
            masked[key] = "***"
        else:
            masked[key] = value
    return masked


def _path_template(path: str) -> tuple[str, list[dict]]:
    params: list[dict] = []
    parts = []
    for segment in (path or "/").split("/"):
        if re.fullmatch(r"\d+|[0-9a-fA-F-]{16,}", segment or ""):
            name = f"id{len(params) + 1}"
            parts.append("{" + name + "}")
            params.append({"name": name, "in": "path", "required": True, "schema": {"type": "string"}})
        else:
            parts.append(segment)
    templated = "/".join(parts) or "/"
    if not templated.startswith("/"):
        templated = "/" + templated
    return templated, params


def export_openapi(packets: list[dict], output_path: str | Path, title: str = "xuanjian-export") -> Path:
    output = Path(output_path)
    servers: dict[str, None] = {}
    paths: dict[str, dict] = {}

    for packet in packets:
        if _is_destructive(packet):
            continue
        method = str(packet.get("method", "GET")).lower()
        if method == "connect":
            continue
        parsed = urlparse(str(packet.get("url", "")))
        if not parsed.scheme or not parsed.netloc:
            continue
        servers[f"{parsed.scheme}://{parsed.netloc}"] = None
        path, path_params = _path_template(parsed.path or "/")
        query_params = packet.get("query_params") or {
            key: values[0] if values else ""
            for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
        }
        parameters = list(path_params)
        for name in sorted(query_params):
            parameters.append({"name": name, "in": "query", "required": False, "schema": {"type": "string"}})
        paths.setdefault(path, {})[method] = {
            "parameters": parameters,
            "x-xj-sample": {
                "method": method.upper(),
                "url": packet.get("url", ""),
                "headers": _mask_headers(packet.get("request_headers") or {}),
                "query": query_params,
                "request_body": packet.get("request_body", ""),
                "status_code": packet.get("status_code", 0),
                "response_headers": packet.get("response_headers") or {},
                "response_body": packet.get("response_body", ""),
                "timestamp": packet.get("timestamp", 0),
            },
        }

    document = {
        "openapi": "3.0.0",
        "info": {"title": title, "version": "0.1"},
        "servers": [{"url": url} for url in servers] or [{"url": "https://example.invalid"}],
        "paths": paths,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    return output
