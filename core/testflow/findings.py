# -*- coding: utf-8 -*-
"""
文件名: findings.py
描述: collect_triage_findings —— 一次遍历 sitemap 抽取三态收敛集 finding dict。
      供 GATE-TRI 准入（_report_phase.py）、链引擎输入（chain_engine.match_all）复用，
      消除三处各自遍历 sitemap 的重复代码（方案 §3v3-4 / §2-漏4）。
"""
from __future__ import annotations

from typing import Any


def collect_triage_findings(sitemap: Any) -> list[dict[str, Any]]:
    """遍历 sitemap 功能点 × checklist，收集 VULNERABLE 结果为 finding dict。

    字段（漏V3-9）：vuln_type/severity/url/method/detail/evidence_*/response
    + feature_id（同 feature 幂等去重）+ risk_domains（多域 list，取
    FeaturePoint.risk_domains 已打好的标签，不重跑 classify_risk_domain）
    + evidence_flow_id（可回放 proxy flow 证据引用，§3v3-3）。
    附加 `_check` 原对象，供 GATE-TRI 门后回写 result/severity/detail。

    注意：只收 VULNERABLE（不模仿已清理的 "CONFIRMED" 幽灵死条件，§3v3-5）；
    ghost / 越界功能点不参与（§4 作用域隔离，防跨域/幽灵污染）。
    """
    findings: list[dict[str, Any]] = []
    if not sitemap:
        return findings
    is_ghost = getattr(sitemap, "_fp_is_ghost", None)
    out_of_scope = getattr(sitemap, "_fp_out_of_scope", None)
    for fp in sitemap.features.values():
        if is_ghost and is_ghost(fp):
            continue
        if out_of_scope and out_of_scope(fp):
            continue
        for c in fp.checklist:
            if not (c.result and c.result.name in ("VULNERABLE",)):
                continue
            findings.append({
                "vuln_type": c.vuln_type,
                "severity": (getattr(c, "severity", "medium") or "medium"),
                "url": (", ".join(fp.related_apis[:2]) if fp.related_apis else "") or fp.page_url,
                "method": "",
                "detail": c.detail or "",
                "evidence_request": getattr(c, "evidence_request", "") or getattr(c, "evidence_flow_id", "") or (c.detail or "")[:300],
                "evidence_response": getattr(c, "evidence_response", "") or (c.detail or "")[300:800],
                "evidence": getattr(c, "evidence_request", "") or (c.detail or "")[:300],
                "response": getattr(c, "evidence_response", "") or (c.detail or "")[300:800],
                "feature_id": fp.id,
                "risk_domains": list(getattr(fp, "risk_domains", None) or []),
                "evidence_flow_id": getattr(c, "evidence_flow_id", "") or "",
                # CheckResult 原值：链引擎 to_three_state 的 GATE-TRI 关闭兜底源（漏V3-3）
                "result": c.result,
                "_check": c,
            })
    return findings
