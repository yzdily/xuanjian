"""
core/loops/fp_governance.py — 误报治理闭环（§2.6.6 防漏报护城河）。

## 为什么需要（grep 核验）
玄鉴 `core/false_positive_manager.py` 仅做"用户标记→规则过滤"单向闭环，
无治理校验：
- 无"误报规则是否过宽"检测（URL pattern 命中过广 → 真漏洞被静默过滤 → 漏报）
- 无"高危 finding 不可自动抑制"铁律（Critical/High 被误标 FP → 漏报）
- 无"二次确认"门槛（单次标记即生效 → 误标即漏报）

误报治理是漏报护城河的最后一道闸：FP 规则过宽 = 真漏洞被静默吞掉。
本模块补齐：
1. FP 规则过宽检测（pattern 命中占比 ≥ 阈值 → 告警，阻止静默过滤）
2. 高危 finding 不可自动抑制铁律（Critical/High 须二次确认）
3. 抑制决策三态：auto_suppress / require_confirm / block_suppress

## 复用
- `core/false_positive_manager.py`（FP 规则存储/命中）
- `core/fp_rate_tracker.py`（误报率统计反馈）
- 上层 LOOP 编排负责拉取 findings + FP 规则，本模块仅做治理判定

## 零依赖
纯 stdlib；不模块级 import httpx/fastapi。参数为可注入 dict（测试 mock）。
"""
from __future__ import annotations

from typing import Any

# CWE 映射（本模块不直接产 CWE，但治理决策影响是否保留带 CWE 的 finding）
CWE_IMPROPER_AUTHZ = "CWE-862"  # 治理失效导致鉴权漏报的关联 CWE

# 抑制决策三态
DECISION_AUTO_SUPPRESS = "auto_suppress"        # 低危 + 规则精确 → 自动抑制
DECISION_REQUIRE_CONFIRM = "require_confirm"     # 中危或规则较宽 → 须二次确认
DECISION_BLOCK_SUPPRESS = "block_suppress"      # 高危 → 禁止抑制（防漏报）

# 严重度分级（与 severity_rules.py 对齐，本模块自包含不耦合）
HIGH_SEVERITY = ("Critical", "High")

# FP 规则过宽阈值：规则命中数 / 总 finding 数 ≥ 此值 → 规则过宽告警
RULE_TOO_BROAD_RATIO = 0.5


def _severity(finding: dict[str, Any]) -> str:
    """取 finding 严重度（兼容 severity/level 字段，缺省 Medium）。"""
    sev = finding.get("severity") or finding.get("level") or "Medium"
    return str(sev).capitalize()


def _is_high_severity(finding: dict[str, Any]) -> bool:
    """finding 是否为高危（Critical/High）。"""
    return _severity(finding) in HIGH_SEVERITY


def evaluate_rule_breadth(
    rule_hits: int,
    total_findings: int,
    ratio_threshold: float = RULE_TOO_BROAD_RATIO,
) -> dict[str, Any]:
    """检测 FP 规则是否过宽（命中占比 ≥ 阈值 → 过宽告警）。

    误报治理核心：FP 规则过宽 = 真漏洞被静默吞掉 = 漏报。
    当一条 FP 规则命中了 ≥50% 的 finding，说明 pattern 太泛，
    可能把不同根因的真漏洞一起过滤掉。

    Args:
        rule_hits: 该 FP 规则命中的 finding 数
        total_findings: 本次扫描的 finding 总数
        ratio_threshold: 过宽阈值（默认 0.5）

    Returns:
        {"too_broad": bool, "ratio": float, "evidence": str}
    """
    if total_findings <= 0:
        return {"too_broad": False, "ratio": 0.0, "evidence": "无 finding，无法评估规则宽度"}
    ratio = rule_hits / total_findings
    too_broad = ratio >= ratio_threshold
    evidence = (
        f"规则命中 {rule_hits}/{total_findings} ({ratio:.0%}) "
        f"{'≥' if too_broad else '<'} 阈值 {ratio_threshold:.0%} "
        f"→ {'过宽，可能吞掉真漏洞' if too_broad else '宽度可接受'}"
    )
    return {"too_broad": too_broad, "ratio": ratio, "evidence": evidence}


def decide_suppression(
    finding: dict[str, Any],
    fp_rule: dict[str, Any] | None = None,
    *,
    confirmed: bool = False,
) -> dict[str, Any]:
    """误报治理抑制决策三态（防高危 finding 被误标 FP 而漏报）。

    铁律：Critical/High finding 不可自动抑制，须二次确认。
    - 高危 + 未确认 → block_suppress（禁止抑制，防漏报）
    - 高危 + 已确认 → require_confirm（即使确认也标记需复核）
    - 中低危 + 规则精确 → auto_suppress
    - 中低危 + 规则过宽/无规则 → require_confirm

    Args:
        finding: 待抑制的 finding（含 severity/level）
        fp_rule: 匹配的 FP 规则（含 pattern/hit_count），None=无规则匹配
        confirmed: 是否经二次确认（默认 False）

    Returns:
        {
            "decision": str,           # auto_suppress / require_confirm / block_suppress
            "severity": str,           # finding 严重度
            "evidence": str,          # 决策依据
            "rule_too_broad": bool,    # 规则是否过宽（仅当有规则时）
        }
    """
    sev = _severity(finding)
    is_high = _is_high_severity(finding)

    # 1. 高危铁律：不可自动抑制（防漏报护城河核心）
    if is_high and not confirmed:
        return {
            "decision": DECISION_BLOCK_SUPPRESS,
            "severity": sev,
            "evidence": f"{sev} 级 finding 未二次确认 → 禁止自动抑制（防漏报）",
            "rule_too_broad": False,
        }

    # 2. 规则宽度评估（有规则时）
    rule_too_broad = False
    if fp_rule is not None:
        # 规则命中次数过高 → 过宽
        hit_count = int(fp_rule.get("hit_count", 0))
        if hit_count >= 10:  # 命中 ≥10 次视为过宽（保守阈值）
            rule_too_broad = True

    # 3. 高危 + 已确认 → 仍需复核（require_confirm，不直接 auto_suppress）
    if is_high and confirmed:
        return {
            "decision": DECISION_REQUIRE_CONFIRM,
            "severity": sev,
            "evidence": f"{sev} 级 finding 已确认但须复核 → require_confirm",
            "rule_too_broad": rule_too_broad,
        }

    # 4. 中低危 + 规则过宽/无规则 → 须确认
    if fp_rule is None or rule_too_broad:
        reason = "无 FP 规则匹配" if fp_rule is None else "FP 规则过宽"
        return {
            "decision": DECISION_REQUIRE_CONFIRM,
            "severity": sev,
            "evidence": f"{sev} 级 finding {reason} → 须二次确认",
            "rule_too_broad": rule_too_broad,
        }

    # 5. 中低危 + 规则精确 → 自动抑制
    return {
        "decision": DECISION_AUTO_SUPPRESS,
        "severity": sev,
        "evidence": f"{sev} 级 finding 规则精确 → 自动抑制",
        "rule_too_broad": False,
    }


def audit_suppression(
    suppressed_findings: list[dict[str, Any]],
    high_severity_blocked: int = 0,
) -> dict[str, Any]:
    """误报治理审计：汇总抑制决策，确保高危未被误抑制。

    治理闭环最后一环：审计本轮抑制决策，统计：
    - auto_suppress 数（中低危自动抑制）
    - require_confirm 数（待确认）
    - block_suppress 数（高危被拦截，防漏报）
    - 高危漏报风险（若 high_severity_blocked=0 但有高危 finding → 告警）

    Args:
        suppressed_findings: 已做抑制决策的 finding 列表（含 decision 字段）
        high_severity_blocked: 被拦截的高危 finding 数

    Returns:
        {
            "auto_suppressed": int,
            "require_confirm": int,
            "block_suppressed": int,
            "fn_risk": bool,        # 是否存在漏报风险
            "evidence": str,
        }
    """
    auto = sum(1 for f in suppressed_findings if f.get("decision") == DECISION_AUTO_SUPPRESS)
    confirm = sum(1 for f in suppressed_findings if f.get("decision") == DECISION_REQUIRE_CONFIRM)
    blocked = sum(1 for f in suppressed_findings if f.get("decision") == DECISION_BLOCK_SUPPRESS)

    # 漏报风险：有待确认但无人确认 → 可能漏报
    fn_risk = confirm > 0 and high_severity_blocked == 0 and blocked == 0
    evidence = (
        f"自动抑制={auto} 待确认={confirm} 拦截={blocked} "
        f"高危拦截={high_severity_blocked} "
        f"→ {'存在漏报风险（待确认未处理）' if fn_risk else '无漏报风险'}"
    )
    return {
        "auto_suppressed": auto,
        "require_confirm": confirm,
        "block_suppressed": blocked,
        "fn_risk": fn_risk,
        "evidence": evidence,
    }


__all__ = [
    "evaluate_rule_breadth",
    "decide_suppression",
    "audit_suppression",
    "CWE_IMPROPER_AUTHZ",
    "DECISION_AUTO_SUPPRESS",
    "DECISION_REQUIRE_CONFIRM",
    "DECISION_BLOCK_SUPPRESS",
    "HIGH_SEVERITY",
    "RULE_TOO_BROAD_RATIO",
]
