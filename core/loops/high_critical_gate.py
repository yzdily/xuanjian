"""
core/loops/high_critical_gate.py — High/Critical 6 条验收门（strix §2.5，Downgrade-Don't-Delete）。

## 原则
未过门**降级为 `preliminary` 而不是删除**——保住线索，避免静默丢失；
同时阻止"证据不足却定 High/Critical"造成的误报。
"""
from __future__ import annotations

from typing import Any, Tuple

HIGH_CRITICAL_RULES = [
    "上传未读回不得判 High",
    "XSS 未证实执行只中危",
    "越权须三身份对照证据",
    "业务码失败态不得误判漏洞",
    "链式利用须末端证据",
    "置信度<observed 不得定 Critical",
]

_HIGH = {"high", "critical"}
_DENY_BUSINESS_CODES = {"401", "403", "500", "10001", "-1"}


def _cat(f: dict[str, Any]) -> str:
    return str(f.get("category") or f.get("rule") or f.get("type") or "").lower()


def evaluate_high_critical(f: dict[str, Any]) -> Tuple[bool, str]:
    """判定一条 finding 是否配得上 High/Critical。

    Returns:
        (ok, reason)：ok=False 时 reason 说明触发了哪条规则，
        调用方应把 severity 降级为 `preliminary`。
    """
    severity = str(f.get("severity") or "").lower()
    if severity not in _HIGH:
        return True, ""

    cat = _cat(f)

    # 1. 上传未读回
    if "upload" in cat and not f.get("readback"):
        return False, HIGH_CRITICAL_RULES[0]

    # 2. XSS 未证实执行
    if "xss" in cat and not f.get("exec_confirmed"):
        return False, HIGH_CRITICAL_RULES[1]

    # 3. 越权须三身份对照
    if any(k in cat for k in ("idor", "authz", "bola", "越权")):
        ids = f.get("identities") or []
        if len(set(ids)) < 3:
            return False, HIGH_CRITICAL_RULES[2]

    # 4. 业务码失败态（已被拦截）不得判漏洞
    if str(f.get("business_code")) in _DENY_BUSINESS_CODES or f.get("business_denied"):
        return False, HIGH_CRITICAL_RULES[3]

    # 5. 链式利用须末端证据
    if f.get("is_chain") and not f.get("terminal_evidence"):
        return False, HIGH_CRITICAL_RULES[4]

    # 6. Critical 的置信度门槛
    if severity == "critical" and str(f.get("confidence") or "inferred") == "inferred":
        return False, HIGH_CRITICAL_RULES[5]

    return True, ""


def apply_downgrade(findings: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """批量降级：把所有未过门的 High/Critical 改成 `preliminary`。

    原地修改并返回同一列表（便于链式调用）。
    """
    out: list[dict[str, Any]] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        ok, _reason = evaluate_high_critical(f)
        if not ok:
            f["severity"] = "preliminary"
            f["downgraded"] = True
        out.append(f)
    return out


__all__ = ["HIGH_CRITICAL_RULES", "evaluate_high_critical", "apply_downgrade"]
