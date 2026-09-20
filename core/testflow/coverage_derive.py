"""per-endpoint 应测漏洞类型推导 — bug-legacy coverage_derive.py 复制件（v3 §2.1）。

来源：api-pentest-extension/skills/bug-legacy/scripts/coverage_derive.py
复制件纪律：判定规则照抄（已 9 单测验证），只适配 import 与 docstring。

derive_expected_vuln_types(ep) — 纯函数，无副作用，单测友好。
推导是"下界"——只增不减；risk_domain 命中的额外类型在调用方取并集。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set

__all__ = ["derive_expected_vuln_types", "derive_for_manifest", "VULN_TYPE_GROUPS"]

# 16-type coverage schema keys
VULN_TYPE_GROUPS: Dict[str, Set[str]] = {
    "injection": {
        "sqli", "cmdi", "ssti", "xxe", "nosqli",
        "ldap", "expression_injection", "header_injection",
    },
    "info": {"sensitive_response"},
    "business": {"logic"},
    "request_forgery": {"csrf"},
    "privilege": {"privilege_escalation"},
    "idor": {"idor"},
    "auth": {"auth_bypass"},
    "file": {"upload"},
    "xss": {"xss"},
    "ssrf": {"ssrf"},
    "lfi": {"lfi"},
}

# Injection types always added when any parameter exists
_INJECTION_TYPES = {
    "sqli", "cmdi", "ssti", "xxe", "nosqli",
    "ldap", "expression_injection", "header_injection",
}

_ID_PATTERN = re.compile(r"(^|[_-])(id|code|key)$")
_FILE_PATTERN = re.compile(r"(file|upload)")
_RENDER_PATH_KEYWORDS = ("download", "getfile", "export", "path", "temp")
_AUTH_PATH_KEYWORDS = ("login", "auth", "hasu", "hase")
_RENDERABLE_CONTENT_TYPES = {
    "text/html", "image/svg+xml", "application/xml", "application/pdf",
}


def derive_expected_vuln_types(ep: Dict[str, Any], response_signals: Dict[str, Any] = None) -> Set[str]:
    """Derive the set of expected vulnerability types for a single endpoint.

    Args:
        ep: endpoint dict（fp_to_endpoint_dict 产出 / 爬虫 APIEndpoint 转 dict）:
            endpoint: str (path/URL), method: str,
            params: list of {name, location} dicts,
            content_type: str (optional), reflects_html: bool (optional)

    Returns:
        set[str] of vuln type keys that this endpoint should be tested for.
    """
    types: Set[str] = set()

    params: List[Dict] = ep.get("params") or []
    names_lower = [p.get("name", "").lower() for p in params]
    path = (ep.get("endpoint") or ep.get("path") or "").lower()
    method = (ep.get("method") or "GET").upper()
    has_any_param = bool(params)

    # Rule 1: Any parameter -> 8 injection types + InfoDisclosure
    if has_any_param:
        types |= _INJECTION_TYPES
        types |= {"sensitive_response"}

    # Rule 2: Write methods -> BusinessLogic / CSRF / PrivilegeEscalation
    if method in {"POST", "PUT", "PATCH"}:
        types |= {"logic", "csrf", "privilege_escalation"}

    # Rule 3: Parameter names with _id/id/code/key -> IDOR
    if any(_ID_PATTERN.search(n) for n in names_lower):
        types |= {"idor"}

    # Rule 4: Path contains login/auth/hasu/hasE -> AuthBypass
    if any(k in path for k in _AUTH_PATH_KEYWORDS):
        types |= {"auth_bypass"}

    # Rule 5: Parameter names with file/upload -> FileUpload
    if any(_FILE_PATTERN.search(n) for n in names_lower):
        types |= {"upload"}

    # Rule 6: XSS — file content / download-render / renderable content-type
    ctype = (ep.get("content_type") or "").lower()
    renderable = ctype in _RENDERABLE_CONTENT_TYPES
    if (any(_FILE_PATTERN.search(n) for n in names_lower)
            or any(k in path for k in _RENDER_PATH_KEYWORDS)
            or renderable):
        types |= {"xss"}

    # Rule 7: Parameter values reflected in HTML -> XSS (reflected)
    if ep.get("reflects_html"):
        types |= {"xss"}

    # Rule 8: DELETE method -> also IDOR + PrivilegeEscalation
    if method == "DELETE":
        types |= {"idor", "privilege_escalation"}

    # Rule 9: SSRF — url/proxy/callback parameters
    if any(k in path for k in ("url", "proxy", "callback", "fetch", "redirect")):
        types |= {"ssrf"}

    # Rule 10: LFI/path traversal — download/path/file parameters
    if any(k in path for k in ("download", "getfile", "path", "read")):
        types |= {"lfi"}

    # bug-legacy §11 加固2: response_signals — response-aware derivation
    if response_signals:
        rs = response_signals
        ct = (rs.get("content_type") or "").lower()
        if ct in {"text/html", "application/xhtml+xml"}:
            types |= {"xss"}
        if rs.get("has_file_stream") or ct in {"application/octet-stream", "application/zip"}:
            types |= {"lfi"}
        if rs.get("error_signature"):
            err = rs["error_signature"].lower()
            if "file not found" in err or "no such file" in err:
                types |= {"lfi"}
            if "connection refused" in err or "timeout" in err:
                types |= {"ssrf"}
        if rs.get("contains_token") or rs.get("contains_html"):
            types |= {"sensitive_response"}

    return types


def derive_for_manifest(manifest: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    """Derive expected vuln types for all endpoints in a manifest."""
    result = {}
    for ep in manifest:
        surface = ep.get("endpoint") or ep.get("path") or ep.get("url") or ""
        if not surface:
            continue
        result[surface] = derive_expected_vuln_types(ep)
    return result
