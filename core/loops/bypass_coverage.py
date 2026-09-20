"""
core/loops/bypass_coverage.py — WAF 绕过覆盖率账本（§2.7 防漏报护城河）。

## 为什么需要（grep 核验）
玄鉴 `core/loops/waf_bypass.py` 有三态验证（verify_bypass）但无覆盖率记账：
- 无"绕过原语是否全部测过"门禁 → 只测 2/23 条原语 → 漏报未测绕过技术
- 无"注入类型×绕过原语"矩阵 → SQL 绕过测了但 XSS/Command 未测 → 漏报
- 无"已测/应测"覆盖率统计 → 不知道绕过测试是否完整

绕过覆盖率是漏报护城河的注入面闸：未测绕过原语 = 漏报可绕过的注入漏洞。
本模块补齐：
1. `build_bypass_matrix` — 注入类型×绕过原语 矩阵构建
2. `evaluate_coverage` — 覆盖率门禁（已测/应测 ≥ 阈值 → pass）
3. `identify_untested_primitives` — 识别未测绕过原语（漏报风险点）

## 复用
- `core/loops/waf_bypass_primitives.yaml`（23 条静态绕过原语）
- `core/loops/waf_bypass.py`（verify_bypass 三态验证）
- `core/loops/coverage_ledger.py`（覆盖率账本模式）
- 上层 LOOP 编排负责发绕过请求 + 收集三态，本模块仅做覆盖率记账

## 零依赖
纯 stdlib；不模块级 import httpx/fastapi/yaml。原语列表为模块级常量（可注入覆盖）。
"""
from __future__ import annotations

from typing import Any

# 注入类型
INJECT_SQL = "sql"
INJECT_XSS = "xss"
INJECT_COMMAND = "command"

# 绕过三态（与 waf_bypass.py 对齐，本模块自包含不耦合）
BYPASS_WAF_BLOCKED = "waf_blocked"
BYPASS_PASSED = "passed_waf"
BYPASS_CONFIRMED = "confirmed"

# 绕过原语矩阵（与 waf_bypass_primitives.yaml 对齐，本模块自包含不耦合）
BYPASS_PRIMITIVES: dict[str, list[str]] = {
    INJECT_SQL: [
        "UNION/**/SELECT",
        "/*!UNION*/SELECT",
        "UNI%4fN SEL%45CT",
        "/*!50000UNION*/SELECT",
        "%23%0aUNION",
        "/*%0a*/UNION/*%0a*/SELECT",
        "UNION%20ALL%20SELECT",
        "uNiOn%0AaLl%0AsElEcT",
        "/*!%55nion*/%20/*!%53elect*/",
        "concat(0x union 0x select)",
    ],
    INJECT_XSS: [
        "<img/src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript&#58;alert(1)",
        "<script>alert(1)</script>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
    ],
    INJECT_COMMAND: [
        ";id", "|id", "||id", "&&id",
        "`id`", "$(id)", "%0aid", "\nid",
    ],
}

# 覆盖率门禁阈值：已测原语 / 应测原语 ≥ 此值 → pass
COVERAGE_THRESHOLD = 0.6


def build_bypass_matrix(
    primitives: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """构建 注入类型×绕过原语 矩阵（全未测初始化）。

    Args:
        primitives: 绕过原语矩阵（默认用 BYPASS_PRIMITIVES）

    Returns:
        {
            "matrix": {inject_type: {primitive: {"tested": False, "result": None}}},
            "total": int,         # 应测原语总数
            "by_type": dict,      # 各类型原语数
        }
    """
    prims = primitives if primitives is not None else BYPASS_PRIMITIVES
    matrix: dict[str, dict[str, dict[str, Any]]] = {}
    total = 0
    by_type: dict[str, int] = {}

    for inject_type, prim_list in prims.items():
        matrix[inject_type] = {}
        for prim in prim_list:
            matrix[inject_type][prim] = {"tested": False, "result": None}
        by_type[inject_type] = len(prim_list)
        total += len(prim_list)

    return {"matrix": matrix, "total": total, "by_type": by_type}


def record_bypass_result(
    matrix: dict[str, Any],
    inject_type: str,
    primitive: str,
    result: str,
) -> dict[str, Any]:
    """记录一条绕过测试结果到矩阵。

    Args:
        matrix: build_bypass_matrix 返回的矩阵
        inject_type: 注入类型（sql/xss/command）
        primitive: 绕过原语
        result: 绕过三态（waf_blocked/passed_waf/confirmed）

    Returns:
        更新后的矩阵
    """
    mat = matrix.get("matrix", {})
    if inject_type in mat and primitive in mat[inject_type]:
        mat[inject_type][primitive]["tested"] = True
        mat[inject_type][primitive]["result"] = result
    return matrix


def evaluate_coverage(
    matrix: dict[str, Any],
    threshold: float = COVERAGE_THRESHOLD,
) -> dict[str, Any]:
    """绕过覆盖率门禁（已测/应测 ≥ 阈值 → pass）。

    门禁核心：绕过原语是否都测了。
    - 应测 = 全部原语（SQL×10 + XSS×5 + Command×8 = 23）
    - 已测 = tested=True 的原语
    - 覆盖率 < 阈值 → fail（存在漏报风险）

    Args:
        matrix: build_bypass_matrix 返回的矩阵
        threshold: 覆盖率门禁阈值（默认 0.6）

    Returns:
        {
            "pass": bool,
            "coverage": float,
            "total": int,          # 应测总数
            "tested": int,         # 已测总数
            "by_type": dict,       # 各类型覆盖率
            "evidence": str,
        }
    """
    mat = matrix.get("matrix", {})
    total = matrix.get("total", 0)
    tested = 0
    by_type: dict[str, dict[str, Any]] = {}

    for inject_type, prim_map in mat.items():
        type_total = len(prim_map)
        type_tested = sum(1 for p in prim_map.values() if p.get("tested"))
        tested += type_tested
        type_coverage = type_tested / type_total if type_total > 0 else 0.0
        by_type[inject_type] = {
            "total": type_total,
            "tested": type_tested,
            "coverage": type_coverage,
        }

    coverage = tested / total if total > 0 else 0.0
    passed = coverage >= threshold

    evidence = (
        f"应测={total} 已测={tested} 覆盖率={coverage:.0%} "
        f"{'≥' if passed else '<'} 阈值 {threshold:.0%} "
        f"→ {'pass' if passed else 'fail（存在漏报风险）'}"
    )
    return {
        "pass": passed,
        "coverage": coverage,
        "total": total,
        "tested": tested,
        "by_type": by_type,
        "evidence": evidence,
    }


def identify_untested_primitives(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    """识别未测绕过原语（漏报风险点）。

    漏报定位：应测但未测的原语清单，供上层补测。

    Args:
        matrix: build_bypass_matrix 返回的矩阵

    Returns:
        未测原语列表（含 inject_type + primitive）
    """
    mat = matrix.get("matrix", {})
    untested: list[dict[str, Any]] = []

    for inject_type, prim_map in mat.items():
        for prim, state in prim_map.items():
            if not state.get("tested"):
                untested.append({
                    "inject_type": inject_type,
                    "primitive": prim,
                    "evidence": f"{inject_type} 原语 '{prim}' 未测 → 漏报风险",
                })
    return untested


def summarize_results(matrix: dict[str, Any]) -> dict[str, Any]:
    """汇总绕过三态分布（confirmed/passed_waf/waf_blocked 计数）。

    Args:
        matrix: build_bypass_matrix 返回的矩阵（含已记录结果）

    Returns:
        {
            "confirmed": int,      # 确认绕过（可利用）
            "passed_waf": int,     # 穿过 WAF（未确认）
            "waf_blocked": int,   # 被 WAF 拦截
            "untested": int,       # 未测
            "evidence": str,
        }
    """
    mat = matrix.get("matrix", {})
    confirmed = 0
    passed = 0
    blocked = 0
    untested = 0

    for prim_map in mat.values():
        for state in prim_map.values():
            if not state.get("tested"):
                untested += 1
            elif state.get("result") == BYPASS_CONFIRMED:
                confirmed += 1
            elif state.get("result") == BYPASS_PASSED:
                passed += 1
            elif state.get("result") == BYPASS_WAF_BLOCKED:
                blocked += 1

    evidence = (
        f"确认绕过={confirmed} 穿过WAF={passed} 被拦截={blocked} 未测={untested}"
    )
    return {
        "confirmed": confirmed,
        "passed_waf": passed,
        "waf_blocked": blocked,
        "untested": untested,
        "evidence": evidence,
    }


__all__ = [
    "build_bypass_matrix",
    "record_bypass_result",
    "evaluate_coverage",
    "identify_untested_primitives",
    "summarize_results",
    "BYPASS_PRIMITIVES",
    "INJECT_SQL",
    "INJECT_XSS",
    "INJECT_COMMAND",
    "BYPASS_WAF_BLOCKED",
    "BYPASS_PASSED",
    "BYPASS_CONFIRMED",
    "COVERAGE_THRESHOLD",
]
