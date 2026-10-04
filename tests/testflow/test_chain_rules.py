"""testflow 链式规则单测钉 — 链引擎 + 词表跨映射对拍 + 采集/渲染（v4 §8 验收钉）。

不依赖网络/LLM：纯分析组件的全量断言。pytest tests/testflow/test_chain_rules.py 即可。

覆盖：
- 模板契约门（缺 hops/min_hops/verdicts → 拒绝；词表越界即红）
- 12 条打包模板词表契约 + strix 双向可解析
- 匹配内核：值池/能力/隐式联动、降级铁律、反证坍缩、fan_in 前置、min_hops
- 四源归一：verdict dict / CheckResult / 第四套词表（reviewer）/ confidence 永不读
- TYPE_DOMAINS ↔ G3 覆盖推导对拍（漂移检测，白名单钉死）
- collect_triage_findings 字段契约 + 作用域隔离
- 双实现域分类对拍（endpoint vs attribution_rules）
- 渲染器冒烟
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.sitemap.models import CheckResult, FeaturePoint
from core.testflow import chain_engine as ce
from core.testflow.chain_engine import (
    load_all_chains,
    load_capabilities,
    match_all,
    match_chain,
    score_chain,
    to_three_state,
    validate_chain,
)
from core.testflow.chain_render import write_attack_chain_report
from core.testflow.chain_rules import (
    RISK_DOMAINS,
    STRIX_INDEX,
    TYPE_DOMAINS,
    XUANJIAN_VULN_TYPES,
    _STRIX_SLUGS,
    resolve_vuln_type,
    strix_to_xuanjian,
    vuln_type_domains,
)
from core.testflow.findings import collect_triage_findings


# ── 构造辅助 ──────────────────────────────────────────────────────────────
def _hop(hid, role="entry", doms=(), vts=(), verdicts=("confirmed", "open_proof_gap"), **kw):
    m: dict = {"verdicts": list(verdicts)}
    if doms:
        m["domains"] = list(doms)
    if vts:
        m["vuln_types"] = list(vts)
    h: dict = {"id": hid, "role": role, "match": m}
    for k in ("consumes", "produces", "counter_evidence", "fan_in"):
        if kw.get(k):
            h[k] = list(kw[k])
    return h


def _tpl(**over) -> dict:
    """最小合法 2 跳模板（值池贯穿：h1 产 token，h2 消 token）。"""
    t = {
        "chain": "t_chain",
        "name": "测试链",
        "min_hops": 2,
        "hops": [
            _hop("h1", "entry", doms=["ssrf"], produces=["token"]),
            _hop("h2", "sink", vts=["sensitive_response"], consumes=["token"]),
        ],
    }
    t.update(over)
    return t


def _f(vt, doms=(), url="", sev="high", verdict=None, fid="", **kw) -> dict:
    d = {
        "vuln_type": vt,
        "domains": list(doms),
        "url": url,
        "method": "GET",
        "severity": sev,
        "verdict": {"verdict": "vulnerable"} if verdict is None else verdict,
        "feature_id": fid,
        "detail": kw.pop("detail", ""),
        "response": kw.pop("response", {}),
    }
    d.update(kw)
    return d


# ── 1. 模板契约门：结构不完备 → 拒绝（§8）────────────────────────────────
def test_chain_gate_structure():
    ok, reason = validate_chain(_tpl())
    assert ok and not reason
    no_verdict_hop = {"id": "h2", "role": "sink", "match": {"vuln_types": ["sqli"]}}
    bad = [
        {},  # 全缺
        {"chain": "x"},  # 缺 name/hops/min_hops
        {"chain": "x", "name": "n", "min_hops": 2,
         "hops": [_hop("h1", doms=["ssrf"])]},  # hops < 2
        {"chain": "x", "name": "n", "min_hops": 2,
         "hops": [_hop("h1", doms=["ssrf"]), no_verdict_hop]},  # hop 缺 verdicts
        {"chain": "x", "name": "n", "min_hops": 1,
         "hops": [_hop("h1", doms=["ssrf"]), _hop("h2", vts=["sqli"])]},  # min_hops < 2
        {"chain": "x", "name": "n", "min_hops": 3,
         "hops": [_hop("h1", doms=["ssrf"]), _hop("h2", vts=["sqli"])]},  # min_hops > hops
        {"chain": "x", "name": "n", "min_hops": 2,
         "hops": [_hop("h1", doms=["ssrf"]),
                  _hop("h1", role="sink", vts=["sqli"])]},  # hop id 重复
        {"chain": "x", "name": "n", "min_hops": 2,
         "hops": [_hop("h1", doms=["ssrf"]),
                  _hop("h2", role="middle", vts=["sqli"])]},  # 未知 role
        {"chain": "x", "name": "n", "min_hops": 2,
         "hops": [_hop("h1", doms=["ssrf"]),
                  _hop("h2", role="sink", vts=["sqli"], fan_in=["nope"])]},  # fan_in 引用不存在
    ]
    for t in bad:
        ok, reason = validate_chain(t)
        assert not ok and reason, f"应拒绝: {reason}"


# ── 2. 契约门：词表越界即红 ──────────────────────────────────────────────
def test_chain_gate_vocab():
    ok, reason = validate_chain(_tpl(hops=[
        _hop("h1", "entry", doms=["nope"]), _hop("h2", "sink", vts=["sqli"]),
    ]))
    assert not ok and "domain" in reason
    ok, reason = validate_chain(_tpl(hops=[
        _hop("h1", "entry", doms=["ssrf"]), _hop("h2", "sink", vts=["no_such_type"]),
    ]))
    assert not ok and "taxonomy" in reason


# ── 3. 12 条打包模板词表契约 ────────────────────────────────────────────
def test_packaged_templates_contract():
    chains = load_all_chains()
    assert len(chains) == 12, f"应为 12 条链模板，实际 {len(chains)}"
    for tpl in chains:
        ok, reason = validate_chain(tpl)
        assert ok, f"{tpl.get('chain')}: {reason}"
        for h in tpl["hops"]:
            m = h.get("match") or {}
            for d in m.get("domains") or []:
                assert d in RISK_DOMAINS, f"{tpl['chain']}/{h['id']} 域越界: {d}"
            for vt in m.get("vuln_types") or []:
                r = resolve_vuln_type(str(vt))
                assert r in set(XUANJIAN_VULN_TYPES) | set(_STRIX_SLUGS), vt
                assert vuln_type_domains(r), f"{vt} 无 8 域落点"
    caps = load_capabilities()
    assert isinstance(caps, dict) and caps, "能力表应可加载"


# ── 4. strix 双向可解析 ─────────────────────────────────────────────────
def test_strix_bridge_bidirectional():
    for e in STRIX_INDEX:
        slug, xt = e["slug"], e["xuanjian_type"]
        assert resolve_vuln_type(slug) in set(XUANJIAN_VULN_TYPES) | set(_STRIX_SLUGS), slug
        if xt:
            assert strix_to_xuanjian(slug) == xt, slug
            assert set(vuln_type_domains(xt)) <= set(RISK_DOMAINS), xt


# ── 5. 值池联动（GATE-PAIR 贯穿）────────────────────────────────────────
def test_value_pool_link():
    findings = [
        _f("ssrf", doms=["ssrf"], fid="fp1", response={"access_token": "AT-1"}),
        _f("sensitive_response", doms=["config"], fid="fp2"),
    ]
    cm = match_chain(_tpl(), findings)
    assert cm is not None
    h2 = cm.hops[1]
    assert h2.link_kind == "value_pool"
    assert cm.value_pool and cm.value_pool[0].get("source_value") == "AT-1"
    assert cm.completeness == 1.0
    assert cm.severity == "critical"  # high×2 + confirmed≥2 升档


# ── 6. 能力池联动（produces ∩ consumes）─────────────────────────────────
def test_capability_link():
    tpl = _tpl(hops=[
        _hop("h1", "entry", doms=["ssrf"], produces=["credential"]),
        _hop("h2", "sink", vts=["sensitive_response"], consumes=["credential"]),
    ])
    findings = [
        _f("ssrf", doms=["ssrf"], fid="fp1"),  # 无 token 响应 → 值池不命中
        _f("sensitive_response", doms=["config"], fid="fp2"),
    ]
    cm = match_chain(tpl, findings)
    assert cm is not None
    assert cm.hops[1].link_kind == "capability"
    assert cm.value_pool == []


# ── 7. 隐式联动：强制 open_proof_gap + 整链降档 ─────────────────────────
def test_implicit_link_demotes():
    hops = [_hop("h1", "entry", doms=["authz"]), _hop("h2", "sink", vts=["sensitive_response"])]
    findings = [
        _f("idor", doms=["authz"], fid="fp1", url="/api/admin/list", sev="high"),
        _f("sensitive_response", doms=["config"], fid="fp2", url="/api/admin/export", sev="medium"),
    ]
    cm = match_chain(_tpl(implicit_link=True, hops=hops), findings)
    assert cm is not None
    assert cm.hops[1].link_kind == "implicit"
    assert cm.hops[1].state == "open_proof_gap"
    assert cm.severity == "medium"  # high 整链降一档
    # 未声明 implicit_link → 非入口跳无联动 → 不成链
    assert match_chain(_tpl(hops=hops), findings) is None


# ── 8. 降级铁律：入口 ruled_out → 链不成立 ──────────────────────────────
def test_ruled_out_entry_no_chain():
    findings = [
        _f("ssrf", doms=["ssrf"], fid="fp1", verdict={"verdict": "safe"}),
        _f("sensitive_response", doms=["config"], fid="fp2"),
    ]
    assert match_chain(_tpl(), findings) is None


# ── 9. 降级铁律：候选跳 ruled_out → 链坍缩 ──────────────────────────────
def test_ruled_out_hop_collapse():
    findings = [
        _f("ssrf", doms=["ssrf"], fid="fp1"),
        _f("sensitive_response", doms=["config"], fid="fp2", verdict={"verdict": "safe"}),
    ]
    assert match_chain(_tpl(), findings) is None


# ── 10. open_proof_gap → 部分链（completeness 0.5）──────────────────────
def test_open_proof_gap_partial():
    nf = {"verdict": "needs_follow_up"}
    findings = [
        _f("ssrf", doms=["ssrf"], fid="fp1", verdict=nf),
        _f("sensitive_response", doms=["config"], fid="fp2", verdict=nf),
    ]
    cm = match_chain(_tpl(), findings)
    assert cm is not None
    assert cm.completeness == 0.5
    assert all(h.state == "open_proof_gap" for h in cm.hops)


# ── 11. confidence 永不读 + 降档铁律 ────────────────────────────────────
def test_confidence_never_read_and_demotion():
    # verdict dict 子键优先，confidence 不参与（漏3）
    assert to_three_state({
        "verdict": {"verdict": "vulnerable"}, "confidence": "confirmed", "severity": "high",
    }) == "confirmed"
    # severity info / 空 → confirmed 封顶 open_proof_gap（漏V3-4）
    assert to_three_state({"verdict": {"verdict": "vulnerable"}, "severity": "info"}) == "open_proof_gap"
    assert to_three_state({"verdict": {"verdict": "vulnerable"}, "severity": ""}) == "open_proof_gap"
    # [GATE-TRI] 降级前缀 → confirmed 封顶 open_proof_gap
    assert to_three_state({
        "verdict": {"verdict": "vulnerable"}, "severity": "high", "detail": "[GATE-TRI] 降级",
    }) == "open_proof_gap"
    # ruled_out 不受降档影响
    assert to_three_state({"verdict": {"verdict": "safe"}, "severity": "info"}) == "ruled_out"


# ── 12. verdict dict 四子键映射（漏V3-1）────────────────────────────────
def test_verdict_dict_mapping():
    # vulnerable 需带非 info severity，否则命中降档铁律（见用例 11）
    assert to_three_state({"verdict": {"verdict": "vulnerable"}, "severity": "high"}) == "confirmed"
    assert to_three_state({"verdict": {"verdict": "safe"}, "severity": "high"}) == "ruled_out"
    assert to_three_state({"verdict": {"verdict": "needs_follow_up"}, "severity": "high"}) == "open_proof_gap"
    assert to_three_state({"verdict": {"verdict": "unknown"}, "severity": "high"}) == "open_proof_gap"


# ── 13. CheckResult 兜底（GATE-TRI 关闭漏V3-3）──────────────────────────
def test_result_enum_mapping():
    assert to_three_state({"result": CheckResult.VULNERABLE, "severity": "high"}) == "confirmed"
    assert to_three_state({"result": CheckResult.NEEDS_REVIEW, "severity": "high"}) == "open_proof_gap"
    assert to_three_state({"result": CheckResult.NOT_VULN, "severity": "high"}) == "ruled_out"
    assert to_three_state({"result": CheckResult.SKIPPED, "severity": "high"}) == "ruled_out"
    assert to_three_state({"severity": "high"}) == ""  # 全缺 → 不参与匹配


# ── 14. 第四套词表（reviewer accepted/rejected，复用 three_state_verdict）──
def test_reviewer_wordlist(monkeypatch):
    monkeypatch.setattr(ce, "three_state_verdict", None)  # 强制降级路径
    assert to_three_state({"verdict": "accepted", "severity": "high"}) == "confirmed"
    assert to_three_state({"verdict": "rejected", "severity": "high"}) == "open_proof_gap"
    monkeypatch.setattr(
        ce, "three_state_verdict", lambda s, r: type("V", (), {"value": "ruled_out"})()
    )
    assert to_three_state({
        "verdict": "rejected", "severity": "high", "reason": "证据充分排除",
    }) == "ruled_out"


# ── 15. 反证命中 → 链坍缩（§3.3）───────────────────────────────────────
def test_counter_evidence_collapses():
    hops = [
        _hop("h1", "entry", doms=["ssrf"], produces=["token"]),
        _hop("h2", "sink", vts=["sensitive_response"], consumes=["token"],
             counter_evidence=["统一登录页"]),
    ]
    findings = [
        _f("ssrf", doms=["ssrf"], fid="fp1", response={"access_token": "AT-1"}),
        _f("sensitive_response", doms=["config"], fid="fp2",
           detail="响应为统一登录页 catch_all 壳"),
    ]
    assert match_chain(_tpl(hops=hops), findings) is None


# ── 16. fan_in 前置门：声明的父跳未匹配 → 链不成立 ───────────────────────
def test_fan_in_gating():
    hops = [
        _hop("h1", "entry", doms=["ssrf"], produces=["credential"]),
        _hop("h2", "relay", vts=["sensitive_response"], consumes=["credential"],
             produces=["config_leak"]),
        _hop("h3", "sink", doms=["authz"], vts=["auth_bypass"],
             fan_in=["h2"], consumes=["config_leak"]),
    ]
    tpl = _tpl(chain="t_fanin", min_hops=3, hops=hops)
    findings = [
        _f("ssrf", doms=["ssrf"], fid="fp1"),
        _f("sensitive_response", doms=["config"], fid="fp2"),
        _f("auth_bypass", doms=["authz"], fid="fp3"),
    ]
    cm = match_chain(tpl, findings)
    assert cm is not None
    assert sum(1 for h in cm.hops if h.matched is not None) == 3
    assert cm.completeness == 1.0
    # h2 缺 → h3 fan_in 前置不满足 → 链不成立
    assert match_chain(tpl, [findings[0], findings[2]]) is None


# ── 17. min_hops 门：只命中入口跳 → None ────────────────────────────────
def test_min_hops_gate():
    assert match_chain(_tpl(), [_f("ssrf", doms=["ssrf"], fid="fp1")]) is None


# ── 18. match_all：幂等登记 + 排序稳定 ──────────────────────────────────
def test_match_all_idempotent_and_sorted():
    from core.loops.chained_finding import count_unique_chains, reset_registry

    reset_registry()
    chains = [
        _tpl(),
        _tpl(chain="t_weak", implicit_link=True, hops=[
            _hop("h1", "entry", doms=["authz"]),
            _hop("h2", "sink", vts=["sensitive_response"]),
        ]),
    ]
    findings = [
        _f("ssrf", doms=["ssrf"], fid="fp1", response={"access_token": "AT-1"}),
        _f("sensitive_response", doms=["config"], fid="fp2"),
        _f("idor", doms=["authz"], fid="fp3", url="/api/admin/list"),
        _f("sensitive_response", doms=["config"], fid="fp4", url="/api/admin/list", sev="medium"),
    ]
    r1 = match_all(chains, findings)
    n1 = count_unique_chains()
    ids1 = [c.chain_id for c in r1]
    r2 = match_all(chains, findings)
    assert len(r1) == 2
    assert count_unique_chains() == n1, "同链重复登记应幂等"
    assert [c.chain_id for c in r2] == ids1, "重复跑结果稳定"
    scores = [score_chain(c) for c in r1]
    assert scores == sorted(scores, reverse=True), "score 降序"
    assert ids1[0] == "t_chain", "强链在前"


# ── 19. TYPE_DOMAINS ↔ G3 覆盖推导对拍（漂移检测，白名单钉死）────────────
def test_type_domains_g3_drift():
    from core.loops.coverage_derive import _DOMAIN_VULN_TYPES as G3

    # 内部一致性：TYPE_DOMAINS 键 ∈ 18 类型，值域 ⊆ 8 域
    for t, doms in TYPE_DOMAINS.items():
        assert t in set(XUANJIAN_VULN_TYPES), t
        assert set(doms) <= set(RISK_DOMAINS), t
    # G3 权威源逐类型对拍：已解析的必须落对域；未解析的必须在白名单内（新增即红）
    known_gaps = {
        "file_upload_unrestricted", "rfi", "info_disclosure", "bola", "bfla",
        "broken_object_level_authorization", "session_fixation", "weak_auth",
        "file_read", "race_condition", "misconfig", "default_credentials",
    }
    unresolved: list[tuple[str, str]] = []
    for dom, names in G3.items():
        if dom not in RISK_DOMAINS:  # general / authz_default 兜底域跳过
            continue
        for n in names:
            r = resolve_vuln_type(n)
            if r not in set(XUANJIAN_VULN_TYPES) | set(_STRIX_SLUGS):
                unresolved.append((dom, n))
                continue
            assert dom in vuln_type_domains(r), f"G3 {dom}:{n} 未落 TYPE_DOMAINS[{r}]"
    assert {n for _d, n in unresolved} <= known_gaps, \
        f"新增未映射类型，先并入 chain_rules 再放行: {unresolved}"


# ── 20. collect_triage_findings 字段契约 + 作用域隔离 ────────────────────
def _check(vt, sev="high", detail="", req="", resp="", flow="", result=CheckResult.VULNERABLE):
    return SimpleNamespace(
        vuln_type=vt, result=result, severity=sev, detail=detail,
        evidence_request=req, evidence_response=resp, evidence_flow_id=flow,
    )


def _fp(fid="fp1", checks=(), ghost=False, oos=False):
    fp = FeaturePoint(id=fid, name="t")
    fp.related_apis = ["GET /api/v1/user-trackings"]
    fp.risk_domains = ["authz"]
    fp.ghost = ghost
    fp.oos = oos
    fp.checklist = list(checks)
    return fp


def test_collect_fields_and_scope():
    ok_fp = _fp("fp1", [_check("idor", req="GET /api/a", resp='{"data": 1}', flow="flow-9")])
    ghost_fp = _fp("fp2", [_check("idor")], ghost=True)
    oos_fp = _fp("fp3", [_check("idor")], oos=True)
    blocked_fp = _fp("fp4", [_check("idor", result=CheckResult.NEEDS_REVIEW)])
    sitemap = SimpleNamespace(
        features={"fp1": ok_fp, "fp2": ghost_fp, "fp3": oos_fp, "fp4": blocked_fp},
        _fp_is_ghost=lambda p: getattr(p, "ghost", False),
        _fp_out_of_scope=lambda p: getattr(p, "oos", False),
    )
    out = collect_triage_findings(sitemap)
    assert len(out) == 1, "ghost / 越界 / NEEDS_REVIEW 均不采集"
    f = out[0]
    assert set(f) == {
        "vuln_type", "severity", "url", "method", "detail", "evidence_request",
        "evidence_response", "evidence", "response", "feature_id", "risk_domains",
        "evidence_flow_id", "result", "_check",
    }
    assert f["url"] == "GET /api/v1/user-trackings"
    assert f["risk_domains"] == ["authz"]
    assert f["evidence_flow_id"] == "flow-9"
    assert f["result"] is CheckResult.VULNERABLE
    # 无谓词属性的 sitemap（向后兼容）→ 不过滤
    plain = SimpleNamespace(features={"fp1": _fp("fp1", [_check("idor")])})
    assert len(collect_triage_findings(plain)) == 1
    assert collect_triage_findings(None) == []


# ── 21. 双实现域分类对拍（endpoint vs attribution_rules 漂移检测）─────────
def test_classify_dual_impl_parity():
    from core.endpoint.risk_domain import classify_risk_domain as ep_cls
    from core.testflow.attribution_rules import classify_risk_domain as tf_cls

    samples = [
        ("/api/upload/file", "POST"),
        ("/api/export/download", "GET"),
        ("/api/somewhere", "POST"),
        ("/api/order/detail?id=1", "GET"),
        ("/api/proxy?url=http://x", "GET"),
        ("/api/login", "POST"),
    ]
    for path, method in samples:
        assert ep_cls(path, method) == tf_cls(path, method), f"{method} {path} 双实现不一致"
    assert tf_cls("/api/somewhere", "POST") == ["authz"]


# ── 22. 渲染器冒烟 ──────────────────────────────────────────────────────
def test_render_smoke():
    findings = [
        _f("ssrf", doms=["ssrf"], fid="fp1", response={"access_token": "AT-1"}),
        _f("sensitive_response", doms=["config"], fid="fp2"),
    ]
    camps = match_all([_tpl()], findings)
    path = write_attack_chain_report(camps)
    assert path.endswith("attack_chain_report.md")
    assert Path(path).is_file()


# ── 23. ssrf 负向钉子（v4 §8 漂移事故回归锁）────────────────────────────
def test_upload_path_never_classifies_ssrf():
    """回归钉：旧复制件含过宽关键字 "load"，子串误命中 "upload" → ssrf 假阳。

    根因已由单点维护消除（attribution_rules 转发 risk_domain），此钉把事故
    锁死：upload 类路径绝不允许判出 ssrf；query 参数也绝不允许参与匹配
    （旧实现全路径匹配，"?url=" 会诱发 ssrf 假阳）。
    """
    from core.endpoint.risk_domain import classify_risk_domain as ep_cls
    from core.testflow.attribution_rules import classify_risk_domain as tf_cls

    # 本次事故钉子（实机确认的 root cause 路径）
    upload_samples = [
        ("/api/file/upload", "POST"),
        ("/api/upload/file", "POST"),  # 原始 parity 失败样本
    ]
    # query 截断钉子：path 部分只该判 injection；旧全路径匹配会因 "url=" 误判 ssrf
    query_samples = [("/api/report/list?url=http://x", "GET", "injection")]

    for cls in (ep_cls, tf_cls):
        for path, method in upload_samples:
            doms = cls(path, method)
            assert "upload" in doms, f"{method} {path} 应含 upload，实际 {doms}"
            assert "ssrf" not in doms, f"{method} {path} 不允许 ssrf 假阳，实际 {doms}"
        for path, method, expect in query_samples:
            doms = cls(path, method)
            assert expect in doms, f"{method} {path} 应含 {expect}，实际 {doms}"
            assert "ssrf" not in doms, f"{method} {path} 不允许 ssrf 假阳，实际 {doms}"


def test_parity_gate_no_shadow_copies():
    """pytest 壳：CI 门禁 scripts/risk_domain_parity_gate.py 必须随套件执行。

    任何模块在 core.endpoint.risk_domain 之外私定义 RISK_DOMAIN_RULES /
    classify_risk_domain，或 import 源头无法追溯到权威源 → 此测试红。
    """
    from scripts.risk_domain_parity_gate import scan_repo

    violations = scan_repo()
    detail = "\n".join(f"{v['rule']} {v['file']}:{v['line']} {v['symbol']}" for v in violations)
    assert violations == [], f"风险域符号复制件/野 import（详见 risk_domain_parity_gate.py）:\n{detail}"


# ── 25. 门禁自身缺陷回归锁（相对导入解析 + 归档目录跳过 + 兜底分支）──────
def test_gate_resolves_relative_import_to_authority():
    """门禁必须把相对导入归一为绝对模块名，而非幽灵模块。

    事故：旧 `_module_name_of` 对 __init__.py 未折叠，
    core/endpoint/__init__.py 被算成 core.endpoint.__init__，
    其内 `from .risk_domain import` 解析成 core.endpoint.__init__.risk_domain
    → 权威源所在包被判"复制件的复制件"（误报）。
    """
    from scripts.risk_domain_parity_gate import AUTHORITY_MODULE, _resolve_from

    # 包内 level=1 相对导入 → 同包绝对名
    assert _resolve_from("core.endpoint", is_package=True, level=1,
                         module="risk_domain") == AUTHORITY_MODULE
    # 非包模块 level=1 → 其所在包
    assert _resolve_from("core.loops.coverage_derive", is_package=False, level=1,
                         module="risk_domain") == "core.loops.risk_domain"
    # 越界（超出仓库根）→ None
    assert _resolve_from("core", is_package=True, level=3, module="x") is None


def test_gate_skips_archived_reference_projects():
    """归档参考项目（非本项目代码）不得进入扫描范围。

    事故：hollowing-optimization-plan/strix-main 下的分片源码
    曾触发 G0-unparseable 噪声，掩盖真实违规。
    """
    from scripts.risk_domain_parity_gate import _PROJECT_ROOT, _is_skipped

    for seg in ("hollowing-optimization-plan/strix-main/a/__init__.py",
                "hollowing-optimization-plan/plan/b.py",
                ".venv-test/Lib/site-packages/c.py"):
        assert _is_skipped(_PROJECT_ROOT / seg, _PROJECT_ROOT), f"{seg} 应被跳过"
    # 本项目代码绝不跳过
    assert not _is_skipped(_PROJECT_ROOT / "core/loops/coverage_derive.py", _PROJECT_ROOT)


def test_unlabeled_str_endpoint_does_not_crash():
    """未打标兜底分支（str 端点）必须可运行，不得 ModuleNotFoundError。

    事故：coverage_derive L75 曾写 `from .risk_domain import`，指向不存在的
    core.loops.risk_domain；任何走该分支的调用当场崩溃。
    """
    from core.loops.coverage_derive import derive_expected_vuln_types

    out = derive_expected_vuln_types("/api/login")  # 字符串端点 → 走兜底分支
    assert isinstance(out, list) and out, "str 端点推导不得为空"
    assert "info_disclosure" in out
