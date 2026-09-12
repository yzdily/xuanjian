"""G6 — SARIF 2.1.0 报告构建器（T1，strix 核心①"可接入 code-scanning"）。

对标参考：api-pentest-extension 的 sarif_builder 思路（纯 stdlib，零依赖优先）。

设计原则（Security Engineer 视角）：
  - 纯 stdlib 构建合规 SARIF 2.1.0 文档，可直接喂 GitHub code-scanning / DefectDojo。
  - ``ruleId = CWE-xxx``（漏洞类型归一为 CWE），``level`` 由 severity 映射。
  - 不改 ``scan_store.vulns`` schema；从内存 finding 列表构建。
  - 提供 ``write_sarif`` 落盘 + ``build_sarif`` 返回 dict（便于测试与 G8 CI 消费）。

SARIF 2.1.0 最小合规结构（节选）：
  {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
      "tool": {"driver": {"name": ..., "version": ..., "rules": [...]}},
      "results": [{"ruleId": "CWE-89", "level": "error",
                   "message": {"text": ...},
                   "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": ...}, "region": {"startLine": 1}}}]}]
    }]
  }
"""
from __future__ import annotations

import json
import os
from typing import Any, Iterable, Mapping

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "XuanJian"
TOOL_VERSION = "1.6"

# canonical vuln_type → CWE（CWE 编号对齐，供 ruleId 与下游 dedupe G12）
_VULN_TO_CWE: dict[str, str] = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "csrf": "CWE-352",
    "idor": "CWE-639",
    "bola": "CWE-639",
    "bfla": "CWE-285",
    "broken_object_level_authorization": "CWE-639",
    "ssrf": "CWE-918",
    "rce": "CWE-94",
    "cmdi": "CWE-77",
    "ssti": "CWE-1336",
    "xxe": "CWE-611",
    "file_upload_unrestricted": "CWE-434",
    "path_traversal": "CWE-22",
    "lfi": "CWE-22",
    "rfi": "CWE-98",
    "info_disclosure": "CWE-200",
    "business_logic": "CWE-840",
    "race_condition": "CWE-362",
    "mass_assignment": "CWE-915",
    "weak_auth": "CWE-307",
    "default_credentials": "CWE-798",
    "session_fixation": "CWE-384",
    "weak_cookie": "CWE-614",
    "misconfig": "CWE-16",
}

# severity → SARIF level
_SEVERITY_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
    "informational": "none",
}


def cwe_for(vuln_type: str) -> str:
    """漏洞类型 → CWE 编号（未知归 CWE-other / 用类型名兜底）。"""
    from core.loops.coverage_integration import vuln_type_to_canonical

    canonical = vuln_type_to_canonical(vuln_type)
    return _VULN_TO_CWE.get(canonical, "CWE-Other")


def _level_for(severity: str) -> str:
    return _SEVERITY_LEVEL.get((severity or "").lower(), "warning")


def build_sarif(
    vulns: Iterable[Mapping[str, Any]],
    *,
    tool_name: str = TOOL_NAME,
    tool_version: str = TOOL_VERSION,
) -> dict[str, Any]:
    """构建 SARIF 2.1.0 文档（dict）。

    Args:
        vulns: 漏洞列表，每项建议含 ``vuln_type`` / ``severity`` / ``url`` /
            ``detail`` / ``feature_name``。缺字段时给安全兜底。

    Returns:
        SARIF 2.1.0 合规 dict。
    """
    rules: dict[str, dict[str, str]] = {}
    results: list[dict[str, Any]] = []
    for v in vulns:
        vt = str(v.get("vuln_type", "unknown"))
        cwe = cwe_for(vt)
        sev = str(v.get("severity", "medium"))
        url = str(v.get("url") or v.get("target") or "")
        detail = str(v.get("detail") or v.get("description") or "")
        label = v.get("feature_name") or vt
        rules.setdefault(cwe, {
            "id": cwe,
            "name": vt,
            "shortDescription": {"text": f"{vt} ({cwe})"},
            "fullDescription": {"text": f"{label}: {detail[:200]}"},
        })
        msg = f"[{sev.upper()}] {label}: {detail[:300]}" if detail else f"[{sev.upper()}] {label}"
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": url or "unknown://target"},
                "region": {"startLine": 1},
            }
        }
        results.append({
            "ruleId": cwe,
            "ruleIndex": list(rules.keys()).index(cwe),
            "level": _level_for(sev),
            "message": {"text": msg},
            "locations": [loc],
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/xuanjian",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def write_sarif(
    path: str | os.PathLike[str],
    vulns: Iterable[Mapping[str, Any]],
    *,
    tool_name: str = TOOL_NAME,
    tool_version: str = TOOL_VERSION,
) -> str:
    """构建并写入 SARIF 文件，返回路径。"""
    doc = build_sarif(vulns, tool_name=tool_name, tool_version=tool_version)
    parent = os.path.dirname(str(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return str(path)


__all__ = ["SARIF_VERSION", "cwe_for", "build_sarif", "write_sarif"]
