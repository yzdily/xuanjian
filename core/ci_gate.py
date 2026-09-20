"""G8 — CI 门禁 + 退出码（借 api-pentest-extension 的 --ci-gate 打法）。

设计原则（Security Engineer 视角）：
  - 门禁判定**优先消费 G4 已落盘的确定性产物** ``data/scan_artifacts/<task_id>/ci_gate_result.json``；
    缺失时回退到 ``scan_store`` 实算（High+ 漏洞计数 + coverage_report.json 门控）。
  - 门禁语义（fail-on-finding 策略，与 0911.txt G8 DoD 一致）：
      * 存在 High/Critical 漏洞            → 阻断
      * 覆盖门控未过（高风险未覆盖）  → 阻断
    （仅当显式传 ``--ci-gate`` 时生效，默认扫描不因此改变退出码。）
  - 纯 stdlib；零外部依赖。
"""
from __future__ import annotations

import json
import os
from typing import Any

_ART_DIR = os.path.join("data", "scan_artifacts")


def _latest_task_id() -> str | None:
    try:
        from core.scan_store import list_scans
        scans = list_scans(limit=1)
        if scans:
            return scans[0].get("task_id")
    except Exception:
        pass
    return None


def evaluate_ci_gate(task_id: str | None = None) -> tuple[int, dict[str, Any]]:
    """评估 CI 门禁。

    Returns:
        (exit_code, result_dict)：exit_code 0=通过 / 1=阻断。
    """
    if not task_id:
        task_id = _latest_task_id()
    if not task_id:
        res = {"passed": True, "reasons": ["无扫描记录，跳过门禁"],
               "high_count": 0, "coverage_failed": False, "task_id": None}
        return 0, res

    # 1) 优先用 G4 落盘的 ci_gate_result.json
    art = os.path.join(_ART_DIR, task_id, "ci_gate_result.json")
    if os.path.exists(art):
        try:
            with open(art, encoding="utf-8") as f:
                res = json.load(f)
            return (0 if res.get("passed") else 1, res)
        except Exception:
            pass

    # 2) 回退实算
    high_count = 0
    cov_failed = False
    cov_reason = ""
    try:
        from core.scan_store import get_vulns
        vulns = get_vulns(task_id)
        high_count = sum(
            1 for v in vulns
            if (str(v.get("severity") or "").lower() in ("high", "critical"))
        )
    except Exception:
        pass

    cov_json = os.path.join(_ART_DIR, task_id, "coverage_report.json")
    if os.path.exists(cov_json):
        try:
            from core.loops.coverage_ledger import gate_uncovered_high
            with open(cov_json, encoding="utf-8") as f:
                ledger = json.load(f)
            passed, cov_reason = gate_uncovered_high(ledger)
            cov_failed = not passed
        except Exception:
            pass

    # 2b) §1.5 P0：覆盖率闸门 L6–L10（独立产物；仅在 enforced 时影响判定）
    gate_payload: dict[str, Any] = {}
    gate_json = os.path.join(_ART_DIR, task_id, "coverage_gate_result.json")
    if os.path.exists(gate_json):
        try:
            with open(gate_json, encoding="utf-8") as f:
                gate_payload = json.load(f)
        except Exception:
            gate_payload = {}

    reasons: list[str] = []
    if cov_failed:
        reasons.append(cov_reason or "覆盖门控未过")
    if gate_payload.get("enforced") and gate_payload.get("exit_code"):
        reasons.append(
            f"覆盖率闸门 L6–L10 有 {gate_payload.get('error_count', 0)} 项 ERROR"
        )
    if high_count > 0:
        reasons.append(f"发现 {high_count} 个 High/Critical 漏洞")
    if not reasons:
        reasons.append("覆盖门控通过且无非高危漏洞")

    passed = (
        (high_count == 0)
        and (not cov_failed)
        and not (gate_payload.get("enforced") and gate_payload.get("exit_code"))
    )
    res = {
        "passed": passed,
        "high_count": high_count,
        "coverage_failed": cov_failed,
        "coverage_reason": cov_reason,
        "coverage_gate": gate_payload,
        "reasons": reasons,
        "task_id": task_id,
    }
    return (0 if passed else 1, res)


__all__ = ["evaluate_ci_gate"]
