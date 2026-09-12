"""G3 — 期望漏洞类型推导（端点 × 风险域 → 应测漏洞类型集合）。

对标参考：H:\\api-pentest-extension\\skills\\bug-legacy\\scripts\\coverage_derive.py:50
  derive_expected_vuln_types(ep, response_signals=None) -> Set[str]

职责：给定一个端点（已打 G1 风险域标签）+ 可选的响应信号，
推导该端点**应该测试**的漏洞类型集合，形成"期望覆盖矩阵"。

G4 覆盖账本以本模块输出为期望集，对照实际 coverage 行算"未覆盖"缺口。

设计原则（Security Engineer 视角）：
  - 默认安全：推导宁可多（过覆盖 = 多测，保守）不可少（漏测 = 真风险）。
  - 域 → 基线漏洞类型；method → 注入面（写操作默认带注入/越权）；
    response_signals → 启发式追加（如响应含 SQL 错误 → sqli；含重定向 → ssrf）。
  - 纯 stdlib，零依赖。
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

# 风险域 → 基线漏洞类型（CWE 对齐，供 G12 partialFingerprint 与 G7 STRIDE 复用）
_DOMAIN_VULN_TYPES: dict[str, list[str]] = {
    "upload": ["file_upload_unrestricted", "path_traversal", "xss"],
    "ssrf": ["ssrf", "rfi", "info_disclosure"],
    "injection": ["sqli", "cmdi", "ssti", "xxe", "xss"],
    "authz": ["idor", "bola", "bfla", "broken_object_level_authorization"],
    "csrf": ["csrf", "session_fixation", "weak_auth"],
    "file": ["path_traversal", "file_read", "lfi", "info_disclosure"],
    "business": ["business_logic", "race_condition", "idor"],
    "config": ["info_disclosure", "misconfig", "default_credentials"],
    "general": ["info_disclosure"],  # 通用兜底：至少查信息泄露
    "authz_default": ["idor", "bola", "bfla"],  # 写操作无关键字命中
}

# 写操作默认追加的漏洞类型（鉴权面是高频漏洞源）
_WRITE_METHOD_VULN_TYPES = ["idor", "bola", "bfla", "mass_assignment"]

# 响应信号 → 启发式漏洞类型（关键字 in 响应体/头 → 追加）
_RESPONSE_SIGNAL_RULES: list[tuple[tuple[str, ...], str]] = [
    (("sql syntax", "mysql_", "ora-", "syntax error at", "unterminated"), "sqli"),
    (("stack trace", "exception in", "at java.", "traceback"), "info_disclosure"),
    (("redirect", "location: http", "302 found"), "ssrf"),
    (("<script", "onerror=", "javascript:"), "xss"),
    (("internal", "debug", "server:"), "info_disclosure"),
    (("set-cookie", "httponly", "samesite"), "weak_cookie"),
]


def derive_expected_vuln_types(
    ep: Mapping[str, Any] | Any,
    response_signals: Mapping[str, Any] | None = None,
) -> list[str]:
    """推导端点应测的漏洞类型集合（去重保序）。

    Args:
        ep: 端点（dict 或对象）。优先读 ``_tags.risk_domain``（G1 打标结果）；
            未打标时用 method+url 现场推导（容错）。
        response_signals: 可选响应信号 dict，可含 ``body`` / ``headers`` / ``status``。
            用于启发式追加漏洞类型（如响应含 SQL 错误 → 追加 sqli）。

    Returns:
        list[str]：去重保序的漏洞类型集合。默认至少含 info_disclosure（兜底，不漏测）。
    """
    tags = {}
    if isinstance(ep, Mapping):
        tags = ep.get("_tags") or {}
        method = str(ep.get("method", "GET")).upper()
        url = str(ep.get("url", ""))
    elif hasattr(ep, "_tags"):
        tags = getattr(ep, "_tags", {}) or {}
        method = str(getattr(ep, "method", "GET")).upper()
        url = str(getattr(ep, "url", ""))
    else:
        # 未打标兜底：现场 classify
        from .risk_domain import classify_risk_domain
        tags = {"risk_domain": classify_risk_domain(str(ep), "GET")}
        method, url = "GET", str(ep)

    risk_domains = tags.get("risk_domain") or ["general"]
    if isinstance(risk_domains, str):
        risk_domains = [risk_domains]

    out: list[str] = []
    seen: set[str] = set()

    def _add(vt: str) -> None:
        if vt not in seen:
            seen.add(vt)
            out.append(vt)

    # 1) 域 → 基线漏洞类型
    for dom in risk_domains:
        for vt in _DOMAIN_VULN_TYPES.get(dom, []):
            _add(vt)
    # 兜底：至少 info_disclosure（不漏测）
    if not out:
        _add("info_disclosure")

    # 2) 写操作 → 追加鉴权面漏洞类型
    if method in ("POST", "PUT", "DELETE", "PATCH"):
        for vt in _WRITE_METHOD_VULN_TYPES:
            _add(vt)

    # 3) 响应信号 → 启发式追加
    if response_signals:
        blob = " ".join(str(v) for v in (
            response_signals.get("body", ""),
            response_signals.get("headers", ""),
        )).lower()
        if blob:
            for kws, vt in _RESPONSE_SIGNAL_RULES:
                if any(kw in blob for kw in kws):
                    _add(vt)

    return out


def expected_coverage_matrix(
    surfaces: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """对一批 surface 生成 (surface × 期望漏洞类型) 矩阵（G4 账本的期望集）。

    Args:
        surfaces: 已打标的端点清单（build_surface_inventory 的 surfaces 字段）。

    Returns:
        list[dict]：每项含 surface_key / risk_domain / expected_vuln_types。
    """
    matrix: list[dict[str, Any]] = []
    for s in surfaces:
        key = s.get("_surface_key") or (
            f"{str(s.get('method','GET')).upper()} {str(s.get('url','')).split('?',1)[0]}"
        )
        doms = (s.get("_tags") or {}).get("risk_domain") or ["general"]
        if isinstance(doms, str):
            doms = [doms]
        matrix.append({
            "surface_key": key,
            "risk_domain": doms,
            "expected_vuln_types": derive_expected_vuln_types(s),
        })
    return matrix


__all__ = [
    "derive_expected_vuln_types",
    "expected_coverage_matrix",
]
