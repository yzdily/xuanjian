"""域归属引擎桥接层（R1 · v3 §三）— 唯一真新代码之一。

职责：FeaturePoint ↔ endpoint dict 互转 + 8 域归属 + 矩阵格初始化。
纯分析 0 请求：只读 sitemap 已有特征（method/url/params/auth_required/
confidence/source_type），不发起任何 HTTP。

三层融合（v2 §7.2）：
  L1 特征提取   ← xj sitemap 模型（models.py APIEndpoint）
  L2 关键词归属 ← bug-legacy RISK_DOMAIN_RULES（attribution_rules.py）
  L3 应测推导   ← bug-legacy derive_expected_vuln_types（coverage_derive.py）
"""
from __future__ import annotations

from typing import Any, Iterable

from core.testflow.attribution_rules import (
    RISK_DOMAINS,
    classify_risk_domain,
    is_write_endpoint,
)
from core.testflow.coverage_derive import derive_expected_vuln_types

__all__ = [
    "fp_to_endpoint_dict",
    "attribute_domains",
    "apply_census_feedback",
    "attribution_summary",
]


def _related_api_of(fp) -> tuple[str, str]:
    """取 fp 首个 related_api，返回 (method, path)。"""
    for api_str in (fp.related_apis or []):
        parts = (api_str or "").split(" ", 1)
        if len(parts) == 2:
            return parts[0].upper(), parts[1].split("?")[0]
        if len(parts) == 1 and parts[0]:
            return "GET", parts[0].split("?")[0]
    return "GET", (fp.page_url or "").split("?")[0]


def _params_of(fp, apis: dict | None) -> list[dict[str, str]]:
    """从 sitemap.apis 取参数；无则从 query string 推导名字。"""
    if apis:
        for api_str in (fp.related_apis or []):
            ep = apis.get(api_str)
            if ep is not None and getattr(ep, "params", None):
                return [{"name": p, "location": "query"} for p in ep.params]
    from urllib.parse import urlparse, parse_qsl
    for api_str in (fp.related_apis or []) + ([fp.page_url] if fp.page_url else []):
        if not api_str:
            continue
        url = api_str.split(" ", 1)[-1]
        qsl = parse_qsl(urlparse(url).query)
        if qsl:
            return [{"name": k, "location": "query"} for k, _ in qsl]
    return []


def _content_type_of(fp, apis: dict | None) -> str:
    if apis:
        for api_str in (fp.related_apis or []):
            ep = apis.get(api_str)
            if ep is not None and getattr(ep, "content_type", ""):
                return ep.content_type
    return ""


def fp_to_endpoint_dict(fp, apis: dict | None = None) -> dict[str, Any]:
    """FeaturePoint → bug-legacy coverage_derive 兼容的 endpoint dict。"""
    method, path = _related_api_of(fp)
    return {
        "endpoint": path,
        "method": method,
        "params": _params_of(fp, apis),
        "content_type": _content_type_of(fp, apis),
        "reflects_html": bool(getattr(fp, "origin", "") == "validated" and _params_of(fp, apis)),
        "fp_id": getattr(fp, "id", ""),
    }


def attribute_domains(feature_points: Iterable, sitemap=None) -> dict[str, Any]:
    """主入口：对功能点列表做域归属，写回 fp.risk_domains + domain_status。

    Args:
        feature_points: list[FeaturePoint]
        sitemap: FeatureGen/Sitemap 实例（提供 self.apis）

    Returns:
        stats dict：attributed / avg_domains / domain_counts / no_domain
    """
    apis = getattr(sitemap, "apis", None) if sitemap is not None else None
    domain_counts: dict[str, int] = {d: 0 for d in RISK_DOMAINS}
    attributed = 0
    total_domains = 0
    no_domain = 0

    for fp in feature_points:
        endpoint = fp_to_endpoint_dict(fp, apis)
        method, path = endpoint["method"], endpoint["endpoint"]

        # L2 关键词归属（多域并集）
        domains = [d for d in classify_risk_domain(path, method) if d != "general"]
        # 写端点补 authz（0907 P0-2：GET 实则改库的写操作）
        if is_write_endpoint(method, path) and "authz" not in domains:
            domains.append("authz")
        # L3 应测推导反哺：推导出的类型映射回归属域（只增不减）
        expected = derive_expected_vuln_types(endpoint)
        for dom in _expected_to_domains(expected):
            if dom not in domains:
                domains.append(dom)

        domains = domains[:5]  # 上限保护（0~N 归属，防止极端路径刷满）
        fp.risk_domains = domains
        # 归属格初始化为待测试（MatrixOutcome 之外的哨兵值，engine/mark 后覆盖）
        fp.domain_status = {d: "needs_follow_up" for d in domains}

        if domains:
            attributed += 1
            total_domains += len(domains)
            for d in domains:
                if d in domain_counts:
                    domain_counts[d] += 1
        else:
            no_domain += 1
            # 无归属域的接口只进普查、直接出结论（v3.1 §3.2 R1）
            fp.domain_status = {"_census_only": "needs_follow_up"}

    return {
        "attributed": attributed,
        "no_domain": no_domain,
        "avg_domains": round(total_domains / attributed, 2) if attributed else 0.0,
        "domain_counts": domain_counts,
    }


# 应测类型 → 归属域 反哺映射（derive_expected_vuln_types 输出 key → 8 域）
_EXPECTED_DOMAIN_MAP: dict[str, str] = {
    "sqli": "injection", "cmdi": "injection", "ssti": "injection",
    "xxe": "injection", "nosqli": "injection", "ldap": "injection",
    "expression_injection": "injection", "header_injection": "injection",
    "sensitive_response": "injection",
    "logic": "business", "csrf": "csrf", "privilege_escalation": "authz",
    "idor": "authz", "auth_bypass": "csrf", "upload": "upload",
    "xss": "file", "lfi": "file", "ssrf": "ssrf",
}


def _expected_to_domains(expected: set[str]) -> list[str]:
    return [dom for t in expected if (dom := _EXPECTED_DOMAIN_MAP.get(t))]


def apply_census_feedback(fp, *, sensitivity: str = "", status: int = 0,
                          has_sensitive_fields: bool = False) -> list[str]:
    """普查反哺归属（v3 §五 Stage 2.4，census 循环内 3 行调用）。

    - sensitivity=="medium" 且 status∈(401,403) → 补 bypass 信号（csrf 域承接）
    - 响应含敏感字段 → 补 authz
    - 写方法+auth_required → 已由 attribute_domains 的 is_write_endpoint 覆盖
    """
    added: list[str] = []
    domains = list(fp.risk_domains or [])
    if sensitivity == "medium" and status in (401, 403):
        if "csrf" not in domains:
            domains.append("csrf")
            added.append("csrf")
    if has_sensitive_fields and "authz" not in domains:
        domains.append("authz")
        added.append("authz")
    if added:
        fp.risk_domains = domains
        for d in added:
            fp.domain_status.setdefault(d, "needs_follow_up")
    return added


def attribution_summary(stats: dict[str, Any]) -> str:
    """终端事件文案：🧩 域归属: N 端点 → avg X 域/端点。"""
    counts = stats.get("domain_counts") or {}
    deepest = max(counts, key=lambda k: counts[k]) if counts else "—"
    return (f"🧩 域归属: {stats.get('attributed', 0)} 功能点 → "
            f"avg {stats.get('avg_domains', 0)} 域/功能点，最深 {deepest}"
            f"({counts.get(deepest, 0)})")
