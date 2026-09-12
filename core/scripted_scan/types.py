"""Finding schema normalization for external scripted scanners."""

from __future__ import annotations

from urllib.parse import urlparse

VULN_TYPE_MAP = {
    "sqli": "SQL注入",
    "sql injection": "SQL注入",
    "sql_injection": "SQL注入",
    "xss": "XSS",
    "ssrf": "SSRF",
    "idor": "IDOR",
    "bola": "IDOR",
    "broken object level authorization": "IDOR",
    "unauth": "未授权访问",
    "unauthorized": "未授权访问",
    "auth bypass": "认证绕过",
    "auth_bypass": "认证绕过",
    "cors": "CORS配置错误",
    "csrf": "CSRF",
    "xxe": "XXE",
    "rce": "远程命令执行",
    "command injection": "命令注入",
    "cmd injection": "命令注入",
    "path traversal": "路径穿越",
    "directory traversal": "路径穿越",
    "file upload": "任意文件上传",
    "sensitive data exposure": "敏感信息泄露",
    "info leak": "信息泄露",
    "information disclosure": "信息泄露",
    "rate limit": "频率限制缺失",
    "mass assignment": "批量赋值",
    "graphql": "GraphQL安全问题",
}

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
}


def normalize_vuln_type(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return "未知"
    key = raw.lower().replace("-", " ").strip()
    return VULN_TYPE_MAP.get(key, raw)


def _first(*values) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _make_request_text(method: str, url: str, headers: dict | None, body: str) -> str:
    parsed = urlparse(url or "")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines = [f"{(method or 'GET').upper()} {path} HTTP/1.1"]
    if parsed.netloc:
        lines.append(f"Host: {parsed.netloc}")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if key and value is not None:
                lines.append(f"{key}: {value}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


def _make_response_text(status_code, headers: dict | None, body: str) -> str:
    status = int(status_code or 0) if str(status_code or "").isdigit() else 0
    lines = [f"HTTP/1.1 {status or 200}"]
    if isinstance(headers, dict):
        for key, value in headers.items():
            if key and value is not None:
                lines.append(f"{key}: {value}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


def normalize_finding(raw: dict, index: int = 0) -> dict | None:
    if not isinstance(raw, dict):
        return None

    method = _first(raw.get("method"), raw.get("http_method"), "GET").upper()
    url = _first(raw.get("url"), raw.get("endpoint"), raw.get("target"))
    vuln_type = normalize_vuln_type(_first(raw.get("vuln_type"), raw.get("type"), raw.get("name"), raw.get("category")))
    payload = _first(raw.get("payload"), raw.get("attack"), raw.get("test_payload"))
    evidence_request = _first(raw.get("evidence_request"), raw.get("request"), raw.get("raw_request"))
    evidence_response = _first(raw.get("evidence_response"), raw.get("response"), raw.get("raw_response"), raw.get("evidence"))

    if not url and evidence_request:
        for token in evidence_request.split():
            if token.startswith(("http://", "https://")):
                url = token
                break
    if not url:
        return None

    request_headers = raw.get("request_headers") if isinstance(raw.get("request_headers"), dict) else raw.get("headers")
    if not evidence_request:
        evidence_request = _make_request_text(method, url, request_headers, _first(raw.get("request_body"), raw.get("body")))
    if not evidence_response:
        evidence_response = _make_response_text(raw.get("status_code"), raw.get("response_headers"), _first(raw.get("response_body")))

    severity = SEVERITY_MAP.get(_first(raw.get("severity"), raw.get("severity_original")).lower(), "medium")
    title = _first(raw.get("title"), f"{vuln_type} - {url}")

    return {
        "vuln_id": _first(raw.get("vuln_id"), raw.get("id"), f"S-{index + 1:04d}"),
        "source": "scripted_scan",
        "phase": _first(raw.get("phase"), raw.get("stage")),
        "owasp_id": _first(raw.get("owasp_id"), raw.get("owasp")),
        "title": title[:160],
        "vuln_type": vuln_type,
        "method": method,
        "url": url,
        "severity_original": severity,
        "detail": _first(raw.get("detail"), raw.get("description"), raw.get("message"))[:1500],
        "evidence_request": evidence_request[:4000],
        "evidence_response": evidence_response[:4000],
        "payload": payload[:500],
        "fix_suggestion": _first(raw.get("fix_suggestion"), raw.get("remediation"), raw.get("recommendation"))[:800],
        "confidence": raw.get("confidence", raw.get("confidence_score", 0)),
        "candidate_level": "suspected",
    }


def dedup_findings(findings: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result: list[dict] = []
    for finding in findings:
        parsed = urlparse(finding.get("url", ""))
        path = (parsed.path or finding.get("url", "")).rstrip("/")
        key = "|".join([
            finding.get("method", "").upper(),
            path.lower(),
            finding.get("vuln_type", "").lower(),
            finding.get("payload", ""),
        ])
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result
