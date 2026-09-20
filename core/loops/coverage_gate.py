"""
core/loops/coverage_gate.py — 覆盖率闸门 L6–L10 + L-NOVEL（§1.5）。

## 定位
在 `export_scan_artifacts` 之前跑一遍，把"覆盖完整性"变成**可阻断的硬门**：
ERROR → `gate_exit_code()` 返回 1 → CI 流水线红 / 交付阻断。

## 闸门清单
- L6 期望矩阵 vs 实测矩阵交叉：缺行 → ERROR
- L7 单 finding 的 payloads 数 < 2 → ERROR
- L8 N/A rationale < 20 字或含 N/A/NA/不适用 → ERROR（缺证据说明）
- L9 POST/PUT/PATCH 无 body_params → WARNING
- L10 target_injection_points 未覆盖 header+path+body → WARNING
- L-NOVEL 数组/批量参数 + 业务流重点端点 → WARNING（强制人工复核桶，禁静默放过）
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ERROR = "ERROR"
WARNING = "WARNING"

_NA_TOKENS = ("n/a", "na", "不适用", "无", "-", "")


@dataclass
class GateResult:
    level: str          # L6 / L7 / ... / L-NOVEL
    severity: str       # ERROR | WARNING
    passed: bool
    message: str = ""


def _fields(entry: Any) -> dict[str, Any]:
    if isinstance(entry, dict):
        return entry
    return {k: getattr(entry, k, None) for k in (
        "payloads", "body_params", "target_injection_points",
        "rationale", "method", "is_business_flow", "has_array_param",
    )}


def run_coverage_gate(
    ledger: dict[str, Any] | None,
    findings: list[dict[str, Any]] | None,
    coverage_entries: list[Any] | None,
) -> list[GateResult]:
    """跑全部闸门，返回结果列表（按 level 升序）。"""
    results: list[GateResult] = []
    ledger = ledger or {}
    findings = findings or []
    entries = coverage_entries or []

    # L6 — 期望矩阵 vs 实测矩阵：期望里有、实测里没有 → ERROR
    expected = ledger.get("expected") or ledger.get("expected_coverage_matrix") or []
    actual = ledger.get("matrix") or ledger.get("coverage_matrix") or []
    if expected:
        exp_keys = {str(e.get("key") or e.get("surface_key") or e) for e in expected if isinstance(e, (dict, str))}
        act_keys = {str(a.get("key") or a.get("surface_key") or a) for a in actual if isinstance(a, (dict, str))}
        missing = sorted(exp_keys - act_keys)
        if missing:
            results.append(
                GateResult("L6", ERROR, False, f"期望矩阵缺覆盖: {missing[:5]}")
            )

    # L7 — 单 finding payloads >= 2
    for f in findings:
        if not isinstance(f, dict):
            continue
        payloads = f.get("payloads")
        n = len(payloads) if isinstance(payloads, (list, tuple)) else 0
        if n < 2:
            results.append(
                GateResult(
                    "L7", ERROR, False,
                    f"finding({f.get('rule') or f.get('id') or '?'}) payloads={n} < 2",
                )
            )

    # L8 / L9 / L10 / L-NOVEL — 逐条覆盖记录
    for entry in entries:
        fld = _fields(entry)
        if not fld:
            continue

        rationale = str(fld.get("rationale") or "")
        if rationale.strip().lower() in _NA_TOKENS or len(rationale.strip()) < 20:
            results.append(
                GateResult("L8", ERROR, False, "N/A rationale 缺失或过短（<20 字）")
            )

        method = str(fld.get("method") or "").upper()
        if method in ("POST", "PUT", "PATCH"):
            body = fld.get("body_params")
            if not body:
                results.append(
                    GateResult("L9", WARNING, False, f"{method} 缺 body_params")
                )

        points = fld.get("target_injection_points") or []
        points_l = [str(p).lower() for p in points]
        missing_points = [p for p in ("header", "path", "body") if p not in points_l]
        if missing_points:
            results.append(
                GateResult(
                    "L10", WARNING, False, f"注入点未覆盖: {missing_points}"
                )
            )

        if fld.get("has_array_param") and fld.get("is_business_flow"):
            results.append(
                GateResult(
                    "L-NOVEL", WARNING, False,
                    "数组/批量参数 + 业务流重点端点 → 强制人工复核",
                )
            )

    results.sort(key=lambda r: r.level)
    return results


def gate_exit_code(results: list[GateResult] | None) -> int:
    """任一 ERROR 未通过 → 1（阻断）；否则 0。"""
    for r in results or []:
        if r.severity == ERROR and not r.passed:
            return 1
    return 0


__all__ = ["GateResult", "run_coverage_gate", "gate_exit_code", "ERROR", "WARNING"]
