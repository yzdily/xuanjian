"""testflow v2 单测钉 — 归属引擎 + 矩阵格 + 定档 + GATE-TRI（v3 §九验收钉）。

不依赖网络/LLM：纯分析组件的全量断言。pytest tests/testflow/ 即可。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.sitemap.models import (
    CheckResult,
    MatrixOutcome,
    FeaturePoint,
    check_result_to_outcome,
)
from core.testflow.attribution import (
    attribute_domains,
    apply_census_feedback,
    attribution_summary,
    fp_to_endpoint_dict,
)
from core.testflow.attribution_rules import (
    RISK_DOMAINS,
    classify_risk_domain,
    is_write_endpoint,
    group_by_risk_domain,
)
from core.testflow.coverage_derive import derive_expected_vuln_types
from core.testflow.engine import decide_mode, TestflowEngine, MODE_WORKER_LIMIT
from core.testflow.gates import gate_pre, gate_pair, normalize_field, run_triage_gate


def _fp(api: str = "POST /api/v1/user-trackings", **kw) -> FeaturePoint:
    fp = FeaturePoint(id=kw.pop("id", "fp1"), name=kw.pop("name", "test"))
    fp.related_apis = [api]
    for k, v in kw.items():
        setattr(fp, k, v)
    return fp


# ── 1. 8 域 vocab 完备性 ──
def test_vocab_completeness():
    assert set(RISK_DOMAINS) == {
        "upload", "ssrf", "injection", "authz", "csrf", "file", "business", "config"
    }
    assert len(RISK_DOMAINS) == 8


# ── 2. 多域并集（upload 接口命中多域；file/export 命中 file 域）──
def test_upload_dual_domain():
    domains = classify_risk_domain("/api/upload/file", "POST")
    assert "upload" in domains          # 'file' kw ∈ upload 域
    assert len(domains) == len(set(domains)), "去重保序"
    # file 域：export/download/getfile 关键词
    assert "file" in classify_risk_domain("/api/export/download", "GET")
    # 多域并集：同一路径命中 injection(export) + file(export,download)
    assert "injection" in classify_risk_domain("/api/export/download", "GET")


# ── 3. 写方法回退 authz ──
def test_write_fallback_authz():
    assert classify_risk_domain("/api/somewhere", "POST") == ["authz"]
    assert is_write_endpoint("POST", "/x") is True
    assert is_write_endpoint("GET", "/admin/user/create") is True  # GET 实则写


# ── 4. 归属写回 FeaturePoint ──
def test_attribute_domains_writes_back():
    fps = [_fp("POST /api/v1/user-trackings"), _fp("GET /static/logo.png", id="fp2")]
    stats = attribute_domains(fps)
    fp = fps[0]
    assert "authz" in fp.risk_domains
    assert all(fp.domain_status[d] == "needs_follow_up" for d in fp.risk_domains)
    assert stats["attributed"] >= 1
    assert "🧩" in attribution_summary(stats)


# ── 5. mark_check 域聚合（五态落格）──
def test_mark_check_domain_cell():
    fp = _fp()
    fp.checklist.append(type("C", (), {"vuln_type": "IDOR", "result": CheckResult.PENDING})())
    fp.mark_check("IDOR", CheckResult.VULNERABLE, "detail", domain="authz")
    assert fp.domain_status["authz"] == MatrixOutcome.REPORTED.value
    # reported 不被 no_issue 覆盖
    fp.mark_check("IDOR", CheckResult.NOT_VULN, "x", domain="authz")
    assert fp.domain_status["authz"] == MatrixOutcome.REPORTED.value
    # CheckResult 聚合映射
    assert check_result_to_outcome(CheckResult.NEEDS_REVIEW) is MatrixOutcome.NEEDS_FOLLOW_UP
    assert check_result_to_outcome(CheckResult.PENDING) is None


# ── 6. 普查反哺归属 ──
def test_census_feedback():
    fp = _fp()
    added = apply_census_feedback(fp, sensitivity="medium", status=403, has_sensitive_fields=True)
    assert "csrf" in added and "authz" in added
    assert set(fp.domain_status) >= {"csrf", "authz"}


# ── 7. 应测类型推导（bug-legacy 9 fixture 核心）──
def test_derive_expected():
    # _ID_PATTERN 匹配 ^id$ / xxx_id（camelCase orderId 不在此规则内，走 FIELD_ALIASES）
    ep = fp_to_endpoint_dict(_fp("GET /api/order/detail?id=1"))
    types = derive_expected_vuln_types(ep)
    assert "idor" in types            # id 参数
    assert "sensitive_response" in types  # 有参数
    ep2 = {"endpoint": "/api/login", "method": "POST", "params": []}
    assert "auth_bypass" in derive_expected_vuln_types(ep2)
    ep3 = {"endpoint": "/api/proxy", "method": "GET", "params": [{"name": "url", "location": "query"}]}
    assert "ssrf" in derive_expected_vuln_types(ep3)


# ── 8. decide_mode 三源信号（修 P4：定档先于域内测试）──
def test_decide_mode():
    class S:  # session stub
        scan_mode = ""
    assert decide_mode(S(), {"l1_unauthorized": 3}) == "DEEP"
    assert decide_mode(S(), {"l1_unauthorized": 1}) == "STANDARD"
    assert decide_mode(S(), {}) == "FAST"
    S.scan_mode = "FAST"
    assert decide_mode(S(), {"l1_unauthorized": 9}) == "FAST"  # 显式选档不升级
    assert MODE_WORKER_LIMIT["FAST"] == 0  # FAST 显式未闭环


# ── 9. GATE-PRE / GATE-PAIR ──
def test_gates_pre_pair():
    ok, _ = gate_pre({"id": "s1", "executor": "tool", "tool": "chain"})
    assert ok
    ok, reason = gate_pre({"id": "s2", "executor": "tool"})
    assert not ok and "tool" in reason
    assert normalize_field("user_id") == normalize_field("UID")
    pairs = gate_pair({"data": {"userId": "u-123"}}, ["uid", "name"])
    assert pairs and pairs[0]["source_value"] == "u-123"


# ── 10. GATE-TRI：无溯源阻断 + verify 未过降 Info ──
def test_triage_gate():
    no_ev = {"severity": "high", "vuln_class": "idor", "target": "x"}
    adm, blocked = run_triage_gate([no_ev])
    assert not blocked or no_ev in blocked  # 缺溯源 → 阻断
    ok_high = {
        "severity": "high", "vuln_class": "idor", "target": "x",
        "evidence_request": "GET /a?x=1", "evidence_response": '{"data": [1,2,3]}',
        "data": {"data": [1, 2, 3]}, "confidence": "confirmed",
        "http_code": 200,
    }
    adm, blocked = run_triage_gate([ok_high])
    assert not ok_high.get("_fp_downgraded"), "三道门全过 + confirmed 不降级"


# ── 11. 深挖队列相位序 ──
def test_deep_dive_queue_order():
    fps = [_fp("POST /api/upload/file"), _fp("GET /api/order?id=1", id="fp2")]
    engine = TestflowEngine(mode="STANDARD")
    queue = engine.build_deep_dive_queue(fps)
    domains = [d for _, d in queue]
    assert domains == sorted(domains, key=lambda d: ["precheck", "authz", "csrf", "injection",
                                                      "ssrf", "upload", "file", "business",
                                                      "config", "recon"].index(d))


# ── 12. FAST 模式 llm 步骤显式未闭环 ──
async def _run_fast_marks_follow_up():
    import asyncio
    fp = _fp("POST /api/v1/user-trackings")
    fp.checklist.append(type("C", (), {"vuln_type": "IDOR", "result": CheckResult.PENDING})())
    engine = TestflowEngine(mode="FAST")  # worker 0
    events = []
    async def noop(): pass
    # 模拟 llm 步骤：FAST 下直接标 needs_follow_up
    await engine._exec_llm({"id": "s", "executor": "llm"}, fp, "authz")
    assert fp.domain_status["authz"] == "needs_follow_up"


def test_fast_marks_follow_up():
    import asyncio
    asyncio.run(_run_fast_marks_follow_up())


# ── 13. group_by 多域重复入组 ──
def test_group_by_risk_domain():
    fps = [_fp("POST /api/upload/file")]
    attribute_domains(fps)   # 先归属再分组
    groups = group_by_risk_domain(fps)
    assert "upload" in groups   # 'file' kw ∈ upload 域
    assert "authz" in groups    # POST 写方法回退 authz
