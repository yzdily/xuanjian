"""G4/G5 运行时集成层 —— 把覆盖骨架（G1-G3）+ 账本（F14）+ SARIF(G6)+STRIDE(G7)
真正接入扫描闭环，并产出确定性产物供 G8 CI 门禁消费。

设计原则（Security Engineer 视角）：
  - **只读消费**扫描已产生的数据（sitemap.apis / features.checklist），不阻塞主扫描。
  - **确定性产物**落盘到 ``data/scan_artifacts/<task_id>/``：
      coverage_report.json / coverage_report.md  —— G4 域级结论表 + 未覆盖声明
      report.sarif                                    —— G6 SARIF 2.1.0
      stride_summary.md                               —— G7 STRIDE 聚合
      ci_gate_result.json                             —— G8 CI 门禁判定
    这样 CI / code-scanning / DefectDojo 拿到的不是 LLM 自由文本，而是结构化可机读结果。
  - **漏洞类型归一化** ``vuln_type_to_canonical`` 是 G6/G7 共用的中文→英文映射，单一来源。
  - G5 闭环：``enrich_sitemap_apis`` 对 sitemap.apis（含主动发现的新 API）补打 G1 风险域标签。

本模块只被 ``_report_phase`` 在 Phase 3 前调用一次（容错 try/except，失败不影响主报告）。
"""
from __future__ import annotations

import json
import os
from typing import Any, Iterable
from urllib.parse import urlparse

from .coverage_tracker import CoverageEntry
from .coverage_ledger import (
    build_coverage_ledger,
    domain_conclusion_table,
    gate_uncovered_high,
    uncovered_statement,
)
from .coverage_derive import expected_coverage_matrix
from ..endpoint.surface_inventory import build_surface_inventory
from ..endpoint.risk_domain import tag_endpoints


# ---------------------------------------------------------------------------
# 漏洞类型归一化（中文/英文 → canonical，G6/G7 共用单一来源）
# ---------------------------------------------------------------------------
_ENGLISH_CANON: dict[str, str] = {
    "sqli": "sqli", "sql injection": "sqli", "sql注入": "sqli",
    "xss": "xss", "cross-site scripting": "xss", "跨站脚本": "xss",
    "csrf": "csrf", "cross-site request forgery": "csrf", "跨站请求伪造": "csrf",
    "idor": "idor", "insecure direct object reference": "idor",
    "bola": "bola", "broken object level authorization": "bola",
    "bfla": "bfla", "broken function level authorization": "bfla",
    "ssrf": "ssrf", "server-side request forgery": "ssrf", "服务端请求伪造": "ssrf",
    "rce": "rce", "remote code execution": "rce", "远程代码执行": "rce",
    "cmdi": "cmdi", "command injection": "cmdi", "命令注入": "cmdi",
    "ssti": "ssti", "server-side template injection": "ssti", "模板注入": "ssti",
    "xxe": "xxe", "xml external entity": "xxe", "xml外部实体": "xxe",
    "path traversal": "path_traversal", "目录遍历": "path_traversal",
    "lfi": "lfi", "local file inclusion": "lfi",
    "rfi": "rfi", "remote file inclusion": "rfi",
    "file upload": "file_upload_unrestricted", "任意文件上传": "file_upload_unrestricted",
    "mass assignment": "mass_assignment", "批量赋值": "mass_assignment",
    "weak authentication": "weak_auth", "弱口令": "weak_auth", "弱密码": "weak_auth",
    "default credentials": "default_credentials", "默认口令": "default_credentials",
    "session fixation": "session_fixation", "会话固定": "session_fixation",
    "misconfiguration": "misconfig", "配置错误": "misconfig", "配置缺陷": "misconfig",
    "business logic": "business_logic", "业务逻辑": "business_logic",
    "race condition": "race_condition", "竞争条件": "race_condition",
    "information disclosure": "info_disclosure", "信息泄露": "info_disclosure",
    "info leak": "info_disclosure", "信息泄漏": "info_disclosure",
}

# 中文子串匹配（顺序敏感，更具体的放前面）
_CHINESE_SUBSTR: list[tuple[str, str]] = [
    ("IDOR越权", "idor"), ("越权查看", "idor"), ("水平越权", "idor"),
    ("IDOR", "idor"),
    ("垂直越权", "bfla"), ("功能级越权", "bfla"), ("未授权访问", "bola"),
    ("未授权", "bola"), ("越权导出", "bola"), ("越权访问", "bola"), ("越权", "idor"),
    ("文件上传绕过", "file_upload_unrestricted"), ("任意文件上传", "file_upload_unrestricted"),
    ("文件上传", "file_upload_unrestricted"),
    ("金额篡改", "business_logic"), ("篡改", "business_logic"),
    ("硬编码密钥", "info_disclosure"), ("客户端硬编码密钥泄露", "info_disclosure"),
    ("敏感信息", "info_disclosure"), ("信息泄露", "info_disclosure"),
    ("信息泄漏", "info_disclosure"),
    ("命令执行", "cmdi"), ("命令注入", "cmdi"),
    ("模板注入", "ssti"),
    ("xml外部实体", "xxe"), ("xxe", "xxe"),
    ("路径遍历", "path_traversal"), ("目录遍历", "path_traversal"),
    ("任意文件读取", "path_traversal"), ("文件读取", "path_traversal"),
    ("弱口令", "weak_auth"), ("弱密码", "weak_auth"),
    ("默认口令", "default_credentials"), ("默认密码", "default_credentials"),
    ("会话固定", "session_fixation"),
    ("配置错误", "misconfig"), ("配置缺陷", "misconfig"), ("暴露", "misconfig"),
    ("竞争条件", "race_condition"),
    ("sql注入", "sqli"), ("sql 注入", "sqli"),
    ("服务端请求", "ssrf"), ("ssrf", "ssrf"),
    ("跨站脚本", "xss"), ("xss", "xss"),
    ("跨站请求伪造", "csrf"), ("csrf", "csrf"),
    ("远程代码执行", "rce"), ("rce", "rce"),
]


def vuln_type_to_canonical(raw: str) -> str:
    """把任意（中文/英文）漏洞类型归一为 canonical 英文 token。

    未知类型返回小写原文（不会崩溃；下游映射为 CWE-Other / 归入 info_disclosure）。
    """
    if not raw:
        return "info_disclosure"
    s = str(raw).strip()
    low = s.lower()
    if low in _ENGLISH_CANON:
        return _ENGLISH_CANON[low]
    if low in ("sql注入", "sql 注入", "xss", "csrf", "ssrf", "idor", "xxe",
               "ssti", "rce", "cmdi", "越权", "信息泄露", "文件上传"):
        # 上面 _CHINESE_SUBSTR 会覆盖，这里仅兜底
        pass
    for sub, canon in _CHINESE_SUBSTR:
        if sub in s:
            return canon
    # 英文 token 直接复用
    if low in _ENGLISH_CANON.values():
        return low
    return low or "info_disclosure"


def normalize_path(url: str) -> str:
    """URL → 归一化路径（去 scheme/host/query，小写），用于跨源匹配。"""
    if not url:
        return ""
    try:
        pu = urlparse(url if "://" in url else f"//{url}")
        path = (pu.path or "").lower().split("?", 1)[0]
        return path or url.lower().split("?", 1)[0]
    except Exception:
        return url.lower().split("?", 1)[0]


# checklist 结果枚举名 → coverage outcome
_REPORTED = {"VULNERABLE", "CONFIRMED", "TRUE"}
_SAFE = {"SAFE", "NOT_VULNERABLE", "NO_ISSUE", "NO_ISSUE_FOUND", "FALSE"}


def _confirmed_vulns_from_features(features: Iterable[Any]) -> list[dict[str, Any]]:
    """从 features.checklist 提取已确认漏洞（供 SARIF/G7 聚合）。"""
    out: list[dict[str, Any]] = []
    for fp in features:
        checklist = getattr(fp, "checklist", None) or []
        for c in checklist:
            name = getattr(getattr(c, "result", None), "name", "") or ""
            if name not in _REPORTED:
                continue
            vt = getattr(c, "vuln_type", "") or "未知"
            sev = str(getattr(c, "severity", "medium") or "medium").lower()
            related = getattr(fp, "related_apis", None) or []
            url = related[0] if related else ""
            out.append({
                "vuln_type": vt,
                "severity": sev,
                "url": url,
                "detail": getattr(c, "detail", "") or "",
                "feature_name": getattr(fp, "name", "") or "",
            })
    return out


def derive_coverage_entries(
    features: Iterable[Any],
    surface_methods: dict[str, str] | None = None,
) -> list[CoverageEntry]:
    """从 features.checklist 推导真实 coverage 行（F14 期望的 CoverageEntry 列表）。

    每个 feature 的每个 related_api 路径，对其 checklist 中"已测"的漏洞类型记录 outcome：
      - VULNERABLE/CONFIRMED → reported
      - SAFE/...                → no_issue_found
      - 其余（PENDING/SKIPPED）→ 不记录（= 负空间，未覆盖）

    ``surface_methods``：归一化路径 → HTTP 方法（来自 G2 surfaces），用于把 coverage 行
    的 ``surface`` 键对齐到账本矩阵键（``METHOD path``），否则会因方法缺失而全部误判未覆盖。
    """
    surface_methods = surface_methods or {}
    # path → {canonical_vt: outcome}
    path_index: dict[str, dict[str, str]] = {}
    for fp in features:
        checklist = getattr(fp, "checklist", None) or []
        related = getattr(fp, "related_apis", None) or []
        for api_url in related:
            np = normalize_path(api_url)
            if not np:
                continue
            bucket = path_index.setdefault(np, {})
            for c in checklist:
                name = getattr(getattr(c, "result", None), "name", "") or ""
                if name not in _REPORTED and name not in _SAFE:
                    continue
                vt = vuln_type_to_canonical(getattr(c, "vuln_type", "") or "")
                outcome = "reported" if name in _REPORTED else "no_issue_found"
                # reported 优先于 no_issue_found
                if vt not in bucket or outcome == "reported":
                    bucket[vt] = outcome
    # 展开为 CoverageEntry（surface 键对齐账本矩阵：METHOD path）
    entries: list[CoverageEntry] = []
    for np, vts in path_index.items():
        method = (surface_methods.get(np) or "GET").upper()
        key = f"{method} {np}"
        for vt, outcome in vts.items():
            entries.append(CoverageEntry(
                surface=key, risk_area=vt, outcome=outcome,
            ))
    return entries


def _build_surfaces(sitemap: Any, host: str | None) -> dict[str, Any]:
    apis = getattr(sitemap, "apis", None) or {}
    if isinstance(apis, dict):
        endpoints = list(apis.values())
    elif isinstance(apis, (list, tuple)):
        endpoints = list(apis)
    else:
        endpoints = []
    return build_surface_inventory(endpoints, host=host)


def enrich_sitemap_apis(sitemap: Any) -> int:
    """G5 闭环：对 sitemap.apis（含主动发现的新 API）补打 G1 风险域标签。

    幂等：已含 ``_risk_domain`` 标签则跳过。返回本次新打标数量。
    """
    apis = getattr(sitemap, "apis", None) or {}
    if not isinstance(apis, dict) or not apis:
        return 0
    tagged = tag_endpoints(list(apis.values()))
    # 按 api_key 写回标签（保持原结构，仅追加标签字段）
    keys = list(apis.keys())
    n = 0
    for key, ep in zip(keys, tagged):
        info = apis[key]
        doms = (ep.get("_tags") or {}).get("risk_domain") or ["general"]
        if isinstance(info, dict):
            tags = info.setdefault("_risk_domain", doms)
            if tags != doms:
                info["_risk_domain"] = doms
            n += 1
        # 对象形态不强制写入（G4 运行时仍会从 values 重新打标）
    return n


def _artifacts_dir(task_id: str) -> str:
    d = os.path.join("data", "scan_artifacts", task_id)
    os.makedirs(d, exist_ok=True)
    return d


def export_scan_artifacts(session: Any) -> str:
    """G4/G5/G6/G7 统一导出：在 Phase 3 前调用一次。

    产出确定性产物并挂到 ``session.sitemap``。失败抛异常由调用方 try/except。

    Returns:
        供报告阶段 system event 展示的摘要字符串。
    """
    sitemap = getattr(session, "sitemap", None)
    if sitemap is None:
        return ""
    task_id = getattr(session, "task_id", "") or "unknown"
    host = None
    for attr in ("target_url", "target", "url"):
        v = getattr(session, attr, None) or getattr(sitemap, attr, None)
        if v:
            host = urlparse(v).netloc.lower() or host
            break

    # G5 闭环：补打风险域标签（含主动发现的新 API）
    enrich_sitemap_apis(sitemap)

    # G1/G2 surfaces
    inv = _build_surfaces(sitemap, host)
    surfaces = inv["surfaces"]

    # G4：从 features.checklist 推导真实 coverage 行
    features = getattr(sitemap, "features", None) or {}
    if isinstance(features, dict):
        features = list(features.values())
    # path → method 对齐表（让 coverage 行键与账本矩阵键一致）
    surface_methods: dict[str, str] = {}
    for s in surfaces:
        np = normalize_path(str(s.get("url", "")))
        if np:
            surface_methods[np] = str(s.get("method", "GET")).upper()
    entries = derive_coverage_entries(features, surface_methods=surface_methods)
    ledger = build_coverage_ledger(surfaces, entries)

    # 已确认漏洞（SARIF / STRIDE）
    confirmed = _confirmed_vulns_from_features(features)

    # G8 CI 门禁判定
    high_count = sum(1 for v in confirmed if v["severity"] in ("high", "critical"))
    gate_passed, gate_reason = gate_uncovered_high(ledger)
    ci_passed = gate_passed and high_count == 0
    ci_reasons = []
    if not gate_passed:
        ci_reasons.append(gate_reason)
    if high_count > 0:
        ci_reasons.append(f"发现 {high_count} 个 High/Critical 漏洞")
    if not ci_reasons:
        ci_reasons.append("覆盖门控通过且无非高危漏洞")

    # 落盘
    d = _artifacts_dir(task_id)
    with open(os.path.join(d, "coverage_report.json"), "w", encoding="utf-8") as f:
        json.dump(ledger, f, ensure_ascii=False, indent=2, default=str)
    with open(os.path.join(d, "coverage_report.md"), "w", encoding="utf-8") as f:
        f.write("## 域级结论表（覆盖骨架 G4）\n\n")
        f.write(domain_conclusion_table(ledger) + "\n\n")
        f.write("## 未覆盖声明（GATE-1.5 风格）\n\n")
        f.write(uncovered_statement(ledger) + "\n")

    # G6 SARIF
    from ..harm_validation.sarif_builder import write_sarif
    write_sarif(os.path.join(d, "report.sarif"), confirmed)

    # G7 STRIDE
    from ..harm_validation.stride import stride_summary
    with open(os.path.join(d, "stride_summary.md"), "w", encoding="utf-8") as f:
        f.write("## STRIDE 威胁建模聚合（G7）\n\n")
        f.write(stride_summary(confirmed) + "\n")

    # G8 CI 门禁结果
    ci_result = {
        "passed": ci_passed,
        "high_count": high_count,
        "coverage_failed": not gate_passed,
        "coverage_reason": gate_reason,
        "reasons": ci_reasons,
        "task_id": task_id,
    }
    with open(os.path.join(d, "ci_gate_result.json"), "w", encoding="utf-8") as f:
        json.dump(ci_result, f, ensure_ascii=False, indent=2)

    # 挂到 sitemap（容错）
    try:
        setattr(sitemap, "coverage_report", ledger)
        setattr(sitemap, "ci_gate_result", ci_result)
    except Exception:
        pass

    n_surfaces = inv["unique"]
    n_domains = len(ledger["by_risk_domain"])
    n_uncov = len(ledger["uncovered_high"])
    return (
        f"接口面 {n_surfaces} 端点 / {n_domains} 风险域；"
        f"高风险未覆盖 {n_uncov}；确认漏洞 {len(confirmed)}（High+ {high_count}）；"
        f"CI 门禁={'通过' if ci_passed else '阻断'}"
    )


__all__ = [
    "vuln_type_to_canonical",
    "normalize_path",
    "derive_coverage_entries",
    "enrich_sitemap_apis",
    "export_scan_artifacts",
    "expected_coverage_matrix",
]
