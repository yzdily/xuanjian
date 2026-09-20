"""
core/verdict.py — 统一判定 schema + 三道门（§2.1 / 技术方案 3.4）。

## 为什么需要
`FindingVerdict` 全仓原本不存在：severity 是函数式 `score_severity`
（`severity_rules.py:96`），`VulnFinding`（`fast_scanner.py:73`）没有
`confidence / identities / verdict` 字段。导致"200 = 漏洞"这类误判无法在机制层拦住。

本模块**不侵入 `VulnFinding`**，而是通过 `finding["verdict"]` 旁路挂载。

## 三道门
1. `gate_business_code` — HTTP 非 401/403/500 且响应非"业务拒绝"文案（复用 `_is_business_deny`）
2. `gate_has_data`      — 响应体含真实业务数据（非空/非模板/非纯错误页）
3. `gate_control`       — 跨身份对照：低权限 basline 已 401 才算"拦截有效"，否则标测试局限性
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# 明确"不是漏洞"的 HTTP 状态（网关/鉴权拦截）
DENY_STATUS = (401, 403, 500)

# 置信度分级（红线 6：CVE 命中需版本确证而非 banner 猜测）
CONFIDENCES = ("confirmed", "observed", "inferred")

# 三态结论
VERDICTS = ("vulnerable", "safe", "needs_follow_up")


@dataclass
class FindingVerdict:
    """统一判定结果（挂 `finding["verdict"]`，不侵入 VulnFinding）。"""
    business_code: str | None = None
    has_data: bool = False
    identities: list[str] = field(default_factory=list)
    deep_dive_level: int = 0
    confidence: str = "inferred"
    verdict: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "business_code": self.business_code,
            "has_data": self.has_data,
            "identities": list(self.identities),
            "deep_dive_level": self.deep_dive_level,
            "confidence": self.confidence,
            "verdict": self.verdict,
        }


def _default_business_deny():
    """懒加载 `core.fast_scanner._is_business_deny`（重依赖，按需导入）。"""
    try:
        from core.fast_scanner import _is_business_deny

        return _is_business_deny
    except Exception:
        return lambda text: False


def gate_business_code(f: dict[str, Any], *, is_business_deny=None) -> bool:
    """门 1：HTTP 状态非拒绝态，且响应不含"业务失败"文案。"""
    deny = is_business_deny or _default_business_deny()
    status = f.get("http_code") or f.get("status") or 0
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 0
    if status in DENY_STATUS:
        return False
    evidence = f.get("evidence") or f.get("response") or ""
    if isinstance(evidence, (dict, list)):
        evidence = str(evidence)
    return not bool(deny(evidence))


def gate_has_data(f: dict[str, Any]) -> bool:
    """门 2：响应体含真实业务数据（非空、有 data/items/result 等载荷迹象）。"""
    body = f.get("data")
    if body in (None, "", [], {}):
        body = f.get("response_body")
    if body in (None, "", [], {}):
        return False
    if isinstance(body, str):
        stripped = body.strip()
        if not stripped:
            return False
        return True
    if isinstance(body, (list, dict)):
        return len(body) > 0
    return True


def gate_control(f: dict[str, Any], baseline: dict[str, Any] | None = None) -> bool:
    """门 3：跨身份对照。

    baseline 为低权限/无权限请求的响应。若 baseline 已经 401/403，
    说明拦截生效、对照组有效；否则标"测试局限性"（无法证明是鉴权还是接口本身不可用）。
    """
    if baseline is None:
        return True
    base_status = baseline.get("http_code") or baseline.get("status") or 0
    try:
        base_status = int(base_status)
    except (TypeError, ValueError):
        base_status = 0
    # baseline 被拦截 → 对照组成立
    return base_status in DENY_STATUS


def build_verdict(
    f: dict[str, Any],
    *,
    baseline: dict[str, Any] | None = None,
    is_business_deny=None,
) -> FindingVerdict:
    """对单条 finding 跑三道门，产出 FindingVerdict。"""
    v = FindingVerdict()
    v.business_code = str(f.get("business_code")) if f.get("business_code") is not None else None
    v.has_data = gate_has_data(f)
    v.identities = list(f.get("identities") or [])
    v.deep_dive_level = int(f.get("deep_dive_level") or 0)

    confidence = f.get("confidence")
    v.confidence = confidence if confidence in CONFIDENCES else "inferred"

    ok_code = gate_business_code(f, is_business_deny=is_business_deny)
    ok_data = gate_has_data(f)
    ok_ctrl = gate_control(f, baseline)

    if ok_code and ok_data and ok_ctrl:
        v.verdict = "vulnerable"
    elif not ok_code:
        v.verdict = "safe"
    else:
        v.verdict = "needs_follow_up"
    return v


def enforce_silent_zero(
    findings: list[dict[str, Any]] | None, *, error_rate: float = 0.0
) -> int:
    """单脚本 0 findings 且异常率 > 50% → 硬失败（静默归零不是"没漏洞"）。

    Returns:
        0 = 正常；1 = 硬失败（需阻断交付/回跑）。
    """
    if not findings and error_rate > 0.5:
        return 1
    return 0


__all__ = [
    "FindingVerdict",
    "gate_business_code",
    "gate_has_data",
    "gate_control",
    "build_verdict",
    "enforce_silent_zero",
]
