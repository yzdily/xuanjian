"""G7 — STRIDE 威胁建模标签（T2，strix 核心②"漏洞可按威胁类别查询"）。

对标参考：H:\\api-pentest-extension 的 ``threat_model`` 工具族 + STRIDE 标签思想。

设计原则（Security Engineer 视角）：
  - 不改 ``scan_store.vulns`` 表结构（避免 DB 迁移风险）；STRIDE 标签在**渲染/报告期**
    由 ``vuln_type`` 实时推导，零持久化成本，且永远与漏洞类型自洽。
  - STRIDE = Spoofing / Tampering / Repudiation / Information disclosure /
    Denial of service / Elevation of privilege。
  - 每条 finding 可带多条腿（一个漏洞常跨多个威胁类别）。
  - 纯 stdlib，零依赖。

复用：``vuln_type_to_canonical`` 归一化复用 coverage_integration 的中文→英文映射，
避免两套别名表漂移。
"""
from __future__ import annotations

from typing import Any, Iterable

# canonical vuln_type → STRIDE 腿（S/T/R/I/D/E）
_STRIDE_LEGS: dict[str, list[str]] = {
    "sqli": ["T", "I"],
    "xss": ["S", "I"],
    "csrf": ["S", "E"],
    "idor": ["I", "E"],
    "bola": ["I", "E"],
    "bfla": ["E"],
    "broken_object_level_authorization": ["I", "E"],
    "ssrf": ["E", "I"],
    "rce": ["E", "T"],
    "cmdi": ["E", "T"],
    "ssti": ["T", "E"],
    "xxe": ["I", "D"],
    "file_upload_unrestricted": ["E", "T"],
    "path_traversal": ["I", "T"],
    "lfi": ["I", "T"],
    "rfi": ["E", "T"],
    "info_disclosure": ["I"],
    "business_logic": ["T", "E"],
    "race_condition": ["T", "E", "D"],
    "mass_assignment": ["T", "E"],
    "weak_auth": ["S", "E"],
    "default_credentials": ["S", "E"],
    "session_fixation": ["S"],
    "weak_cookie": ["S", "I"],
    "misconfig": ["S", "E"],
}

STRIDE_FULL = {
    "S": "Spoofing（伪装）",
    "T": "Tampering（篡改）",
    "R": "Repudiation（抵赖）",
    "I": "Information Disclosure（信息泄露）",
    "D": "Denial of Service（拒绝服务）",
    "E": "Elevation of Privilege（权限提升）",
}


def stride_legs_for(vuln_type: str) -> list[str]:
    """由漏洞类型推导 STRIDE 腿（去重保序）。

    未知类型默认归入 Information Disclosure（最保守、最通用）。
    """
    from core.loops.coverage_integration import vuln_type_to_canonical

    canonical = vuln_type_to_canonical(vuln_type)
    legs = _STRIDE_LEGS.get(canonical)
    if legs:
        return legs
    # 未知类型：保守归入 I（信息泄露）
    return ["I"]


def aggregate_by_stride(vulns: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """按 STRIDE 腿聚合漏洞，供报告"威胁建模"章节。

    Args:
        vulns: 漏洞列表，每项需含 ``vuln_type``（其余字段原样透传）。

    Returns:
        {腿字母: [漏洞项...]}，按 S/T/R/I/D/E 顺序。
    """
    buckets: dict[str, list[dict[str, Any]]] = {k: [] for k in "STRIDE"}
    for v in vulns:
        legs = stride_legs_for(str(v.get("vuln_type", "")))
        for leg in legs:
            buckets.setdefault(leg, []).append(dict(v))
    return buckets


def stride_summary(vulns: Iterable[Mapping[str, Any]]) -> str:
    """生成 STRIDE 聚合摘要（Markdown，报告章节用）。"""
    buckets = aggregate_by_stride(vulns)
    lines = ["**STRIDE 威胁建模聚合**："]
    for leg in "STRIDE":
        items = buckets.get(leg, [])
        label = STRIDE_FULL[leg]
        if not items:
            lines.append(f"- {leg} {label}：无")
        else:
            sample = "、".join(
                str(i.get("vuln_type", "?")) for i in items[:5]
            )
            more = f" 等 {len(items)} 项" if len(items) > 5 else ""
            lines.append(f"- {leg} {label}：{sample}{more}")
    return "\n".join(lines)


__all__ = [
    "STRIDE_FULL",
    "stride_legs_for",
    "aggregate_by_stride",
    "stride_summary",
]
