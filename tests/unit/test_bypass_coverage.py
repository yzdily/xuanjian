"""§2.7 WAF 绕过覆盖率账本：矩阵构建 + 记录 + 门禁 + 未测识别。"""
from __future__ import annotations

from core.loops.bypass_coverage import (
    build_bypass_matrix,
    record_bypass_result,
    evaluate_coverage,
    identify_untested_primitives,
    summarize_results,
    BYPASS_PRIMITIVES,
    BYPASS_WAF_BLOCKED,
    BYPASS_PASSED,
    BYPASS_CONFIRMED,
    INJECT_SQL,
    INJECT_XSS,
    INJECT_COMMAND,
)


# ---- build_bypass_matrix ----

def test_matrix_total_23():
    """默认原语矩阵总数 23（SQL×10 + XSS×5 + Command×8）。"""
    m = build_bypass_matrix()
    assert m["total"] == 23
    assert m["by_type"][INJECT_SQL] == 10
    assert m["by_type"][INJECT_XSS] == 5
    assert m["by_type"][INJECT_COMMAND] == 8


def test_matrix_all_untested():
    """初始化全未测。"""
    m = build_bypass_matrix()
    for prim_map in m["matrix"].values():
        for state in prim_map.values():
            assert state["tested"] is False
            assert state["result"] is None


def test_matrix_custom_primitives():
    """自定义原语矩阵。"""
    custom = {"test": ["a", "b"]}
    m = build_bypass_matrix(custom)
    assert m["total"] == 2
    assert m["by_type"]["test"] == 2


# ---- record_bypass_result ----

def test_record_result():
    """记录一条绕过结果。"""
    m = build_bypass_matrix()
    record_bypass_result(m, INJECT_SQL, "UNION/**/SELECT", BYPASS_CONFIRMED)
    assert m["matrix"][INJECT_SQL]["UNION/**/SELECT"]["tested"] is True
    assert m["matrix"][INJECT_SQL]["UNION/**/SELECT"]["result"] == BYPASS_CONFIRMED


def test_record_result_unknown_type():
    """未知注入类型不报错（静默忽略）。"""
    m = build_bypass_matrix()
    record_bypass_result(m, "unknown_type", "payload", BYPASS_PASSED)
    # 不影响已有矩阵
    assert m["total"] == 23


# ---- evaluate_coverage ----

def test_coverage_fail_all_untested():
    """全部未测 → 覆盖率 0% → fail。"""
    m = build_bypass_matrix()
    r = evaluate_coverage(m)
    assert r["pass"] is False
    assert r["coverage"] == 0.0
    assert r["total"] == 23
    assert r["tested"] == 0


def test_coverage_pass_some_tested():
    """测了 14/23 → 覆盖率 61% → pass（≥0.6）。"""
    m = build_bypass_matrix()
    # 测 14 条（SQL×10 + XSS×4）
    for prim in BYPASS_PRIMITIVES[INJECT_SQL]:
        record_bypass_result(m, INJECT_SQL, prim, BYPASS_WAF_BLOCKED)
    for prim in BYPASS_PRIMITIVES[INJECT_XSS][:4]:
        record_bypass_result(m, INJECT_XSS, prim, BYPASS_PASSED)
    r = evaluate_coverage(m)
    assert r["pass"] is True
    assert r["tested"] == 14
    assert r["coverage"] > 0.6


def test_coverage_by_type():
    """各类型覆盖率正确。"""
    m = build_bypass_matrix()
    # 只测 SQL 的 5 条
    for prim in BYPASS_PRIMITIVES[INJECT_SQL][:5]:
        record_bypass_result(m, INJECT_SQL, prim, BYPASS_WAF_BLOCKED)
    r = evaluate_coverage(m)
    assert r["by_type"][INJECT_SQL]["coverage"] == 0.5
    assert r["by_type"][INJECT_XSS]["coverage"] == 0.0
    assert r["by_type"][INJECT_COMMAND]["coverage"] == 0.0


def test_coverage_full():
    """全部已测 → 覆盖率 100% → pass。"""
    m = build_bypass_matrix()
    for inject_type, prims in BYPASS_PRIMITIVES.items():
        for prim in prims:
            record_bypass_result(m, inject_type, prim, BYPASS_WAF_BLOCKED)
    r = evaluate_coverage(m)
    assert r["pass"] is True
    assert r["coverage"] == 1.0


# ---- identify_untested_primitives ----

def test_untested_all():
    """全部未测 → 23 条未测。"""
    m = build_bypass_matrix()
    untested = identify_untested_primitives(m)
    assert len(untested) == 23


def test_untested_none():
    """全部已测 → 0 条未测。"""
    m = build_bypass_matrix()
    for inject_type, prims in BYPASS_PRIMITIVES.items():
        for prim in prims:
            record_bypass_result(m, inject_type, prim, BYPASS_WAF_BLOCKED)
    untested = identify_untested_primitives(m)
    assert untested == []


def test_untested_partial():
    """部分未测 → 仅未测的被识别。"""
    m = build_bypass_matrix()
    record_bypass_result(m, INJECT_SQL, "UNION/**/SELECT", BYPASS_CONFIRMED)
    untested = identify_untested_primitives(m)
    assert len(untested) == 22
    # 已测的不在未测列表
    tested_prims = [u["primitive"] for u in untested]
    assert "UNION/**/SELECT" not in tested_prims


# ---- summarize_results ----

def test_summary_all_blocked():
    """全部被拦截。"""
    m = build_bypass_matrix()
    for inject_type, prims in BYPASS_PRIMITIVES.items():
        for prim in prims:
            record_bypass_result(m, inject_type, prim, BYPASS_WAF_BLOCKED)
    s = summarize_results(m)
    assert s["waf_blocked"] == 23
    assert s["confirmed"] == 0
    assert s["passed_waf"] == 0
    assert s["untested"] == 0


def test_summary_mixed():
    """混合三态。"""
    m = build_bypass_matrix()
    record_bypass_result(m, INJECT_SQL, "UNION/**/SELECT", BYPASS_CONFIRMED)
    record_bypass_result(m, INJECT_SQL, "/*!UNION*/SELECT", BYPASS_PASSED)
    record_bypass_result(m, INJECT_SQL, "UNI%4fN SEL%45CT", BYPASS_WAF_BLOCKED)
    s = summarize_results(m)
    assert s["confirmed"] == 1
    assert s["passed_waf"] == 1
    assert s["waf_blocked"] == 1
    assert s["untested"] == 20
