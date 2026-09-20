"""testflow 门体 — GATE-PRE / GATE-PAIR / GATE-TRI（G3/G4，v3 §八）。

GATE-TRI 语义对齐 ext gates.py:384 run_triage_gate 六项准入，
判定内核复用 xuanjian 已有 core/verdict.py 三道门（不重复实现）：
  高/危 finding 全准入 = verdict.vulnerable + evidence 齐全；
  缺任一 → _fp_downgraded → severity 降 Info（留人工复核，不静默剔除）。
"""
from __future__ import annotations

from typing import Any

from core.verdict import build_verdict, CONFIDENCES

__all__ = [
    "gate_pre",
    "FIELD_ALIASES",
    "normalize_field",
    "gate_pair",
    "run_triage_gate",
    "TRIAGE_ADMISSIBLE_SEVERITIES",
]

# GATE-PRE：playbook step 必填字段
_STEP_REQUIRED_FIELDS = ("id", "executor")


def gate_pre(step: dict[str, Any]) -> tuple[bool, str]:
    """G3 配对完整性门（前置）：step 结构完备才放行。

    Returns:
        (ok, reason)。reason 非空即拒绝原因（写入矩阵格 evidence）。
    """
    for fld in _STEP_REQUIRED_FIELDS:
        if not step.get(fld):
            return False, f"step 缺 {fld}"
    if step["executor"] not in ("local", "llm", "tool"):
        return False, f"未知 executor: {step['executor']}"
    if step["executor"] == "tool" and not step.get("tool"):
        return False, "tool 步骤缺 tool 引用"
    return True, ""


# ── GATE-PAIR：值池联动（G3 BOLA 链关键）──
# 41 个字段别名归一（A 接口响应的 ID 喂 B 接口输入时视为同类）
FIELD_ALIASES: dict[str, str] = {
    "id": "id", "uuid": "id", "uid": "id", "user_id": "id", "userid": "id",
    "order_id": "id", "orderid": "id",
    "accountid": "id", "account_id": "id",
    "memberid": "id", "member_id": "id",
    "customerid": "id", "customer_id": "id",
    "agentid": "id", "agent_id": "id",
    "deptid": "id", "dept_id": "id",
    "tenantid": "id", "tenant_id": "id",
    "orgid": "id", "org_id": "id",
    "roleid": "id", "role_id": "id",
    "productid": "id", "product_id": "id",
    "goodsid": "id", "goods_id": "id",
    "itemid": "id", "item_id": "id",
    "fileid": "id", "file_id": "id",
    "attachmentid": "id", "attachment_id": "id",
    "documentid": "id", "document_id": "id",
    "billid": "id", "bill_id": "id",
    "invoiceid": "id", "invoice_id": "id",
    "recordid": "id", "record_id": "id",
    "code": "code", "key": "code", "no": "code", "num": "code", "number": "code",
    "token": "token", "access_token": "token", "authtoken": "token",
}


def normalize_field(name: str) -> str:
    """字段名 → 别名类（值池配对的归一键）。"""
    return FIELD_ALIASES.get((name or "").strip().lower(), (name or "").strip().lower())


def gate_pair(source_response: dict[str, Any], target_params: list[str]) -> list[dict[str, Any]]:
    """G3 值池配对：A 接口响应字段 ↔ B 接口参数的归一化配对。

    Returns:
        list of {field, normalized, source_value} — 可直接喂 B 接口的值对。
    """
    pairs: list[dict[str, Any]] = []
    if not isinstance(source_response, dict):
        return pairs
    target_norm = {normalize_field(p) for p in target_params}

    def _walk(obj: dict, prefix: str = "") -> None:
        for k, v in obj.items():
            norm = normalize_field(k)
            if norm == k and prefix:
                # 无别名命中 → 退回带前缀的路径形式
                norm = normalize_field(f"{prefix}.{k}")
            if norm in target_norm and isinstance(v, (str, int, float)):
                pairs.append({"field": k, "normalized": norm, "source_value": v})
            if isinstance(v, dict):
                _walk(v, k)

    _walk(source_response)
    return pairs


# ── GATE-TRI：漏洞验证门（G4）──
TRIAGE_ADMISSIBLE_SEVERITIES = ("high", "critical")

_DEEP_VERIFY_TYPES = {"rce", "ssrf", "idor", "auth_bypass", "lfi", "upload", "sqli", "xss"}


def run_triage_gate(
    findings: list[dict[str, Any]],
    *,
    baseline: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """对 findings 跑 GATE-TRI 六项准入（G6 报告门前置调用）。

    六项：target / vuln_class / evidence dict / impact_demonstrated /
          non_public（非公开数据）/ public_data 降级。

    Returns:
        (admitted, blocked) — admitted 可入报告；
        blocked 带 "_triage_blocked" 键（原因写入 "_triage_reason"）。
        high/critical 才走全准入；medium/low 只要求溯源齐全。
    """
    admitted: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []

    for f in findings:
        sev = str(f.get("severity") or "").lower()
        v = build_verdict(f, baseline=baseline)
        f["verdict"] = v.to_dict()

        # 溯源门：无请求/响应证据 → 阻断（memblaze confidence 三态）
        has_evidence = bool(f.get("evidence_request") or f.get("evidence")) and (
            f.get("evidence_response") or f.get("response") or f.get("data")
        )
        if not has_evidence:
            f["_triage_blocked"] = True
            f["_triage_reason"] = "缺 evidence_request/response 溯源"
            blocked.append(f)
            continue

        if sev in TRIAGE_ADMISSIBLE_SEVERITIES:
            if v.verdict != "vulnerable":
                # verify 铁律未过 → 降 Info 留人工复核（不静默剔除）
                f["_fp_downgraded"] = True
                f["severity"] = "info"
                f["_triage_reason"] = f"verdict={v.verdict}（三道门未全过）"
            elif v.confidence not in CONFIDENCES:
                f["_fp_downgraded"] = True
                f["severity"] = "info"
                f["_triage_reason"] = f"confidence 非法: {v.confidence}"
        # medium/low：只要求溯源（已在上方统一拦截）
        admitted.append(f)

    return admitted, blocked
