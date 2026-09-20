"""严重程度定级规则表 — 四维模型（优化.md 建议2）。

按「数据敏感度 × 可利用性 × 认证要求 × 影响范围」综合定级，替代硬编码 severity。
设计为纯函数，可被 fast_scanner / compliance_report / render 复用。

参考：api-pentest-extension/skills/api-pentest-workflow/severity_rules.md
"""

from __future__ import annotations

from typing import Any

from core.cwe_mapping import lookup_cwe, normalize_vuln_type

# 四个维度各 0~3 分
#   数据敏感度 data_sensitivity: 0=无数据 1=非敏感 2=敏感(PII/内部) 3=密钥/口令/大量PII
#   可利用性   exploitability:   0=不可利用 1=需特殊条件 2=有公开PoC 3=无需条件即可利用
#   认证要求   auth_requirement: 0=需高权限 1=需普通账号 2=需认证但任意账号 3=无需认证
#   影响范围   impact_scope:     0=单条数据 1=单接口 2=多接口/模块 3=全系统/横向移动

# 漏洞类型 -> 默认四维基线（可被 finding 的证据字段覆盖）
_VULN_BASELINE: dict[str, dict[str, int]] = {
    "SQL注入":        {"data_sensitivity": 3, "exploitability": 2, "auth_requirement": 2, "impact_scope": 3},
    "命令注入":       {"data_sensitivity": 3, "exploitability": 2, "auth_requirement": 2, "impact_scope": 3},
    "SSTI":           {"data_sensitivity": 3, "exploitability": 2, "auth_requirement": 2, "impact_scope": 3},
    "XXE":            {"data_sensitivity": 2, "exploitability": 2, "auth_requirement": 2, "impact_scope": 2},
    "XSS":            {"data_sensitivity": 2, "exploitability": 2, "auth_requirement": 3, "impact_scope": 1},
    "CSRF":           {"data_sensitivity": 2, "exploitability": 1, "auth_requirement": 1, "impact_scope": 1},
    "CORS配置错误":   {"data_sensitivity": 2, "exploitability": 2, "auth_requirement": 3, "impact_scope": 1},
    "未授权访问":     {"data_sensitivity": 2, "exploitability": 3, "auth_requirement": 3, "impact_scope": 2},
    "IDOR":           {"data_sensitivity": 2, "exploitability": 2, "auth_requirement": 2, "impact_scope": 1},
    "越权":           {"data_sensitivity": 2, "exploitability": 2, "auth_requirement": 1, "impact_scope": 2},
    "认证绕过":       {"data_sensitivity": 3, "exploitability": 2, "auth_requirement": 3, "impact_scope": 3},
    "弱口令":         {"data_sensitivity": 3, "exploitability": 3, "auth_requirement": 3, "impact_scope": 2},
    "信息泄露":       {"data_sensitivity": 1, "exploitability": 1, "auth_requirement": 3, "impact_scope": 1},
    "敏感文件泄露":   {"data_sensitivity": 2, "exploitability": 2, "auth_requirement": 3, "impact_scope": 1},
    "目录穿越":       {"data_sensitivity": 2, "exploitability": 2, "auth_requirement": 2, "impact_scope": 2},
    "文件上传":       {"data_sensitivity": 3, "exploitability": 2, "auth_requirement": 2, "impact_scope": 3},
    "SSRF":           {"data_sensitivity": 2, "exploitability": 2, "auth_requirement": 2, "impact_scope": 2},
    "SSRF_OOB":       {"data_sensitivity": 2, "exploitability": 1, "auth_requirement": 2, "impact_scope": 2},
    "开放重定向":     {"data_sensitivity": 1, "exploitability": 2, "auth_requirement": 3, "impact_scope": 1},
    "业务逻辑":       {"data_sensitivity": 2, "exploitability": 1, "auth_requirement": 2, "impact_scope": 2},
    "竞态条件":       {"data_sensitivity": 2, "exploitability": 1, "auth_requirement": 2, "impact_scope": 1},
    "限流缺失":       {"data_sensitivity": 1, "exploitability": 2, "auth_requirement": 3, "impact_scope": 1},
}

# 证据强度 -> 对可利用性/数据敏感度的修正
_EVIDENCE_MOD: dict[str, dict[str, int]] = {
    # evidence_quality 值来自 fast_scanner / harm_validation
    "body_confirmed": {"exploitability": 1, "data_sensitivity": 1},   # 响应体实测含敏感数据
    "content_match":  {"exploitability": 1, "data_sensitivity": 0},   # 指纹匹配
    "header_only":    {"exploitability": -1, "data_sensitivity": -1}, # 仅响应头/状态码，弱证据
    "weak":           {"exploitability": -1, "data_sensitivity": 0},
}


def _clamp(v: int) -> int:
    return max(0, min(3, v))


def score_severity_explicit(
    data_sensitivity: int,
    exploitability: int,
    auth_requirement: int,
    impact_scope: int,
) -> tuple[str, int]:
    """四维显式打分，返回 (severity, score)。

    score = data_sensitivity*3 + exploitability*3 + auth_requirement*2 + impact_scope*2
    满分 30。
    """
    ds = _clamp(data_sensitivity)
    ex = _clamp(exploitability)
    ar = _clamp(auth_requirement)
    iscope = _clamp(impact_scope)
    score = ds * 3 + ex * 3 + ar * 2 + iscope * 2
    if score >= 22:
        return "critical", score
    if score >= 16:
        return "high", score
    if score >= 10:
        return "medium", score
    if score >= 5:
        return "low", score
    return "info", score


def _infer_baseline(vuln_type: str) -> dict[str, int]:
    key = normalize_vuln_type(vuln_type)
    return dict(_VULN_BASELINE.get(key, {
        "data_sensitivity": 1, "exploitability": 1,
        "auth_requirement": 2, "impact_scope": 1,
    }))


def score_severity(finding: dict) -> tuple[str, int, str]:
    """从 finding 自动推断四维并打分。

    依据：vuln_type 基线 + evidence_quality 修正 + detail 关键词修正。
    返回 (severity, score, rationale)。
    """
    vuln_type = finding.get("vuln_type", "") or finding.get("type", "")
    dims = _infer_baseline(vuln_type)

    # 证据强度修正
    eq = (finding.get("evidence_quality", "") or "").lower()
    mod = _EVIDENCE_MOD.get(eq, {})
    for k, delta in mod.items():
        dims[k] = _clamp(dims[k] + delta)

    detail = (finding.get("detail", "") or finding.get("evidence", "") or "").lower()
    # 实测到真实敏感数据（密钥/口令/大量PII）→ 数据敏感度拉满
    if any(kw in detail for kw in ("password", "secret", "api_key", "access_key",
                                    "private_key", "token=", "数据库", "手机号")):
        dims["data_sensitivity"] = 3
    # 已确认可执行/已复现 → 可利用性拉满
    if any(kw in detail for kw in ("已复现", "实测", "执行成功", "rce", "命令执行",
                                    "已确认", "verified")):
        dims["exploitability"] = max(dims["exploitability"], 2)
    # 无需认证
    if any(kw in detail for kw in ("无需认证", "未授权", "匿名", "no auth")):
        dims["auth_requirement"] = 3

    sev, score = score_severity_explicit(
        dims["data_sensitivity"], dims["exploitability"],
        dims["auth_requirement"], dims["impact_scope"],
    )
    rationale = (
        f"四维定级: 数据敏感度={dims['data_sensitivity']} "
        f"可利用性={dims['exploitability']} 认证要求={dims['auth_requirement']} "
        f"影响范围={dims['impact_scope']} → 得分 {score}/30 → {sev}"
    )
    return sev, score, rationale


def apply_severity(finding: dict) -> dict:
    """给 finding 就地打上 severity / severity_score / severity_rationale，返回该字典。

    幂等：已有 severity_score 时不覆盖（避免覆盖人工定级）。
    """
    if not isinstance(finding, dict):
        return finding
    if finding.get("severity_score") is not None:
        return finding
    sev, score, rationale = score_severity(finding)
    finding["severity"] = sev
    finding["severity_score"] = score
    finding["severity_rationale"] = rationale
    return finding
