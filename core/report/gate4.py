"""
core/report/gate4.py — 报告硬校验 GATE-4（§2.6.4 / 技术方案 3.11.4）。

## 四条硬校验
1. **可溯源**：每条发现必须来自 `verified_findings`（禁止凭空生成）
2. **禁止手写绕过**：不得出现手写/绕过验证管道塞进来的 finding
3. **severity 一致**：报告的 severity 必须与门控降级后的结果一致
4. **未覆盖声明非空**：「未测端点/部分覆盖」声明必须存在且非空，否则不合格

## 玄鉴现状（grep 核验）
`coverage_ledger` 有 `unrecorded_risk_class`，但**没有**"禁止手写绕过硬门
+ 未覆盖声明" → 净新增。
"""
from __future__ import annotations

from typing import Any

from core.loops.coverage_gate import ERROR, WARNING, GateResult

_HANDWRITTEN_FLAGS = ("handwritten", "manual_entry", "手工", "手写")


def _findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    raw = report.get("findings") or []
    return [f for f in raw if isinstance(f, dict)]


def gate4_validate(report: dict[str, Any] | None) -> list[GateResult]:
    """跑 GATE-4 四条硬校验，返回结果列表。"""
    results: list[GateResult] = []
    report = report or {}

    # 1. 可溯源
    verified = report.get("verified_findings")
    findings = _findings(report)
    if not verified:
        results.append(
            GateResult("G4-1", ERROR, False, "缺少 verified_findings，发现不可溯源")
        )
    else:
        verified_ids = {str(v.get("id")) for v in verified if isinstance(v, dict)}
        for f in findings:
            fid = str(f.get("id"))
            if fid and fid not in verified_ids:
                results.append(
                    GateResult("G4-1", ERROR, False, f"finding {fid} 不在 verified_findings 中")
                )
                break

    # 2. 禁止手写绕过
    for f in findings:
        src = str(f.get("source") or f.get("origin") or "").lower()
        if any(flag in src for flag in _HANDWRITTEN_FLAGS):
            results.append(
                GateResult("G4-2", ERROR, False, f"发现手写绕过: {src}")
            )
            break

    # 3. severity 一致（与门控降级结果比对）
    expected = report.get("severity_by_id") or {}
    for f in findings:
        fid = str(f.get("id"))
        want = expected.get(fid)
        if want and str(f.get("severity")) != str(want):
            results.append(
                GateResult("G4-3", ERROR, False,
                           f"finding {fid} severity={f.get('severity')} 与门控 {want} 不一致")
            )
            break

    # 4. 未覆盖声明非空
    declaration = report.get("uncovered_declaration") or report.get("unrecorded_risk_class")
    if not declaration or (isinstance(declaration, (str, list, dict)) and len(declaration) == 0):
        results.append(
            GateResult("G4-4", ERROR, False, "未覆盖声明为空 → 报告不合格")
        )

    # 附：存在 WARNING 的提示项（不阻断）
    if findings and not report.get("summary"):
        results.append(GateResult("G4-5", WARNING, False, "报告缺 summary（建议补）"))

    results.sort(key=lambda r: r.level)
    return results


def gate4_exit_code(results: list[GateResult] | None) -> int:
    """任一 ERROR → 1（报告不合格）。"""
    for r in results or []:
        if r.severity == ERROR and not r.passed:
            return 1
    return 0


__all__ = ["gate4_validate", "gate4_exit_code"]
