"""覆盖完整性闸门 — bug-legacy validate_workflow L6-L10 + L-NOVEL 复制件（v3 §2.1）。

来源：api-pentest-extension/skills/bug-legacy/scripts/validate_workflow.py
适配：数据源从 bug-legacy manifest 改为 xuanjian FeaturePoint
（risk_domains / domain_status / checklist / related_apis），判定规则照抄。

用法（Stage 5 报告门前置）：
    issues = validate_features(sitemap.features.values())
    errors = [i for i in issues if i["level"] == "ERROR"]
    if errors: 阻断交付，列出明细
"""
from __future__ import annotations

from typing import Any, Iterable

from core.sitemap.models import OUTCOMES_REQUIRING_EVIDENCE
from core.testflow.coverage_derive import derive_expected_vuln_types
from core.testflow.attribution import fp_to_endpoint_dict

__all__ = ["validate_features", "NA_RATIONALE_MIN_CHARS", "MIN_PAYLOADS"]

NA_RATIONALE_MIN_CHARS = 20   # L8: N/A 理由最少字符
MIN_PAYLOADS = 2              # L7: applicable_case 最少 payload 数

_INJECTION_POINT_KEYS = ("header", "path", "body")


def validate_features(feature_points: Iterable, apis: dict | None = None) -> list[dict[str, str]]:
    """对功能点列表跑 L6-L10 + L-NOVEL，返回 issue 列表。"""
    issues: list[dict[str, str]] = []

    for fp in feature_points:
        endpoint = fp_to_endpoint_dict(fp, apis)
        method = endpoint["method"]
        params = endpoint["params"]

        # ── L6: 应测集合 vs 矩阵格交叉（有参数 → 矩阵格必须有结论）──
        if params:
            expected = derive_expected_vuln_types(endpoint)
            if not expected:
                issues.append(_issue("L6", fp, "有参数但应测类型为空"))
        else:
            # 无参数 + 无归属域 → 普查即终，必须已在 domain_status 留痕
            if not getattr(fp, "risk_domains", None) and not getattr(fp, "domain_status", None):
                issues.append(_issue("L6", fp, "无归属且无普查留痕"))

        # ── L7: applicable_case ≥ 2 payload ──
        for c in getattr(fp, "checklist", []):
            if c.result is not None and c.vuln_type and _is_applicable(c):
                if _payload_count(c.evidence_request) < MIN_PAYLOADS and not c.needs_browser:
                    issues.append(_issue("L7", fp, f"{c.vuln_type} payload 数 < {MIN_PAYLOADS}"))

        # ── L8: N/A / ruled_out / needs_follow_up 必须带 ≥20 字符理由 ──
        for dom, status in (getattr(fp, "domain_status", None) or {}).items():
            if status in OUTCOMES_REQUIRING_EVIDENCE and dom != "_census_only":
                reason = _cell_reason(fp, dom)
                if len(reason or "") < NA_RATIONALE_MIN_CHARS:
                    issues.append(_issue("L8", fp, f"域 {dom} 状态 {status} 缺 ≥{NA_RATIONALE_MIN_CHARS} 字符理由"))

        # ── L9: POST/PUT/PATCH 必填 body 参数 ──
        if method in ("POST", "PUT", "PATCH"):
            has_body = bool(_body_params(fp, apis))
            if not has_body:
                issues.append(_issue("L9", fp, f"{method} 端点缺 body 参数（参数签名不齐）"))

        # ── L10: 注入域检查项必须覆盖 header+path+body 注入点 ──
        if "injection" in (getattr(fp, "risk_domains", None) or []):
            covered = _injection_points_covered(fp)
            missing = [k for k in _INJECTION_POINT_KEYS if k not in covered]
            if missing and _has_tested_injection(fp):
                issues.append(_issue("L10", fp, f"注入点缺 {missing}"))

        # ── L-NOVEL: 业务重端点强制人工复核桶 ──
        if "business" in (getattr(fp, "risk_domains", None) or []):
            has_review = any(
                c.result is not None and c.result.value == "needs_review"
                for c in getattr(fp, "checklist", [])
            )
            if not has_review and getattr(fp, "priority", None) and fp.priority.value == "critical":
                issues.append(_issue("L-NOVEL", fp, "业务 critical 端点缺人工复核桶"))

    return issues


# ── helpers ──

def _issue(level: str, fp, msg: str) -> dict[str, str]:
    return {"level": level, "fp": getattr(fp, "id", "?") or getattr(fp, "name", "?"), "msg": msg}


def _is_applicable(c) -> bool:
    """已测且非跳过 = applicable case。"""
    return c.result is not None and c.result.value not in ("pending", "skipped")


def _payload_count(evidence_request: str) -> int:
    """从证据请求粗算 payload 次数（分界符/多行变体）。"""
    if not evidence_request:
        return 0
    text = str(evidence_request)
    return max(text.count("\n### "), text.count("\n---"), text.count("\n\n")) + (0 if "\n" in text else 0)


def _cell_reason(fp, domain: str) -> str:
    """矩阵格理由来源：checklist detail（该域下首个带 detail 的项）。"""
    for err in getattr(fp, "_testflow_errors", []) or []:
        if domain in err:
            return err
    for c in getattr(fp, "checklist", []):
        if c.detail and len(c.detail) >= NA_RATIONALE_MIN_CHARS:
            return c.detail
    return ""


def _body_params(fp, apis: dict | None) -> list[str]:
    if apis:
        for api_str in fp.related_apis or []:
            ep = apis.get(api_str)
            if ep is not None:
                if getattr(ep, "request_body_sample", ""):
                    return ["__body_sample__"]
                if getattr(ep, "params", None):
                    return list(ep.params)
    return [p["name"] for p in (fp_to_endpoint_dict(fp, apis).get("params") or [])]


def _injection_points_covered(fp) -> set[str]:
    """checklist evidence 里的注入点覆盖粗判。"""
    covered: set[str] = set()
    for c in getattr(fp, "checklist", []):
        ev = (c.evidence_request or "") + (c.detail or "")
        ev = ev.lower()
        if "header" in ev or "x-" in ev or "cookie:" in ev:
            covered.add("header")
        if "path" in ev or "url" in ev:
            covered.add("path")
        if "body" in ev or "post" in ev or "param" in ev:
            covered.add("body")
    return covered


def _has_tested_injection(fp) -> bool:
    return any(c.vuln_type for c in getattr(fp, "checklist", [])
               if "injection" in (c.vuln_type or "").lower() or "sql" in (c.vuln_type or "").lower())
