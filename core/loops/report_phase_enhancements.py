"""core/loops/report_phase_enhancements.py — report_phase 扩展（§4 Phase 2 item 6）。

两项增强：
1. root_cause 同因合并 —— 同一漏洞类型 + 同一根因（如同一参数同一注入点）
   的多条 finding 合并为一条，降低报告噪声。
2. PII 脱敏标记 —— 对 evidence/detail 中的 PII 做脱敏并标记 sanitized=True。

纯函数，零外部依赖。
"""
from __future__ import annotations

import re
from typing import Any


# ============================================================
# 1. root_cause 同因合并
# ============================================================

def _root_cause_key(finding: dict) -> str:
    """生成 finding 的根因键：漏洞类型 + URL 路径 + 参数名。

    同一键的 finding 视为同因，可合并。
    """
    vtype = finding.get("vuln_type", "")
    url = finding.get("url", "")
    # 取 URL 路径部分（去掉 query）
    path = url.split("?")[0] if url else ""
    # 从 detail 提取参数名
    detail = finding.get("detail", "")
    param_m = re.search(r"参数[ '\"]([^'\"]+)[ '\"]", detail)
    param = param_m.group(1) if param_m else ""
    return f"{vtype}|{path}|{param}"


def merge_findings_by_root_cause(findings: list[dict]) -> list[dict]:
    """按 root_cause 合并 finding。

    同因 finding 合并为一条，evidence 拼接，count 标记合并数。
    非同因保持原样。
    """
    groups: dict[str, list[dict]] = {}
    order: list[str] = []
    for f in findings:
        key = _root_cause_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    merged: list[dict] = []
    for key in order:
        group = groups[key]
        if len(group) == 1:
            merged.append(group[0])
            continue
        # 合并：保留第一条，evidence 拼接，加 merged_count
        base = dict(group[0])
        evidences = [g.get("evidence", "") for g in group if g.get("evidence")]
        base["evidence"] = "\n---\n".join(evidences)[:1000]
        base["merged_count"] = len(group)
        base["merged_from"] = [g.get("url", "") for g in group]
        merged.append(base)
    return merged


# ============================================================
# 2. PII 脱敏
# ============================================================

# PII 正则（与 deidentify_gate 对齐但更聚焦报告脱敏）
_PII_PATTERNS = [
    # 中国手机号
    (re.compile(r"(?<!\d)(1[3-9]\d{9})(?!\d)"), "PHONE"),
    # 中国身份证
    (re.compile(r"(?<!\d)([1-9]\d{16}[\dXx])(?!\d)"), "ID_CARD"),
    # 银行卡
    (re.compile(r"(?<!\d)(\d{16,19})(?!\d)"), "BANK_CARD"),
    # 邮箱
    (re.compile(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"), "EMAIL"),
]

# 占位域不脱敏
_SAFE_DOMAINS = ("example.com", "example.org", "example.net", "test.com")


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if domain.lower() in _SAFE_DOMAINS:
        return email
    if len(local) <= 2:
        return f"{local[0]}***@{domain}"
    return f"{local[0]}{local[1]}***{local[-1]}@{domain}"


def sanitize_pii(text: str) -> tuple[str, list[str]]:
    """脱敏文本中的 PII，返回 (脱敏后文本, 命中的 PII 类型列表)。"""
    if not text:
        return text, []
    hit_types: set[str] = set()
    masked = text
    for pattern, ptype in _PII_PATTERNS:
        def _repl(m, _pt=ptype):
            val = m.group(1)
            if _pt == "EMAIL":
                _, _, domain = val.partition("@")
                if domain.lower() in _SAFE_DOMAINS:
                    return val  # 安全域不脱敏、不计入类型
            hit_types.add(_pt)
            if _pt == "EMAIL":
                return _mask_email(val)
            if _pt == "PHONE":
                return val[:3] + "****" + val[-4:]
            if _pt == "ID_CARD":
                return val[:6] + "********" + val[-4:]
            if _pt == "BANK_CARD":
                return val[:4] + " **** **** " + val[-4:]
            return "***"
        masked = pattern.sub(_repl, masked)
    return masked, sorted(hit_types)


def mark_pii_sanitized(findings: list[dict]) -> list[dict]:
    """对 finding 列表的 evidence/detail 做 PII 脱敏并标记。

    在每条 finding 上加 pii_sanitized: bool 和 pii_types: list[str]。
    """
    out = []
    for f in findings:
        nf = dict(f)
        all_types: set[str] = set()
        for field in ("evidence", "detail"):
            if field in nf and isinstance(nf[field], str):
                sanitized, types = sanitize_pii(nf[field])
                nf[field] = sanitized
                all_types.update(types)
        nf["pii_sanitized"] = bool(all_types)
        nf["pii_types"] = sorted(all_types)
        out.append(nf)
    return out
