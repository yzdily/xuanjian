"""0918 v1.7 主规格 9 项缺口闭合的防回退钉（2026-09-19）。

## 为什么这组钉子与以往不同（防假绿契约）

`0919_验证报告.md` 指出：0918 原称"缺失"的 9 个单测补齐后**全绿**，
但它们多为**对独立函数/参数签名的直测**，不覆盖"生产是否真的调用" →
绿 ≠ 缺口闭合。本文件因此采用两条更硬的断言口径：

1. **源码级接线断言**：用 `inspect.getsource` 取**生产函数**源码，
   断言其中确实出现对目标模块的调用（不是"模块存在"，而是"被调用"）。
2. **行为级断言**：真调生产函数/真跑落盘，断言可观测产物。

覆盖 9 项缺口 + 过程中发现的 3 个既有 bug。
"""
from __future__ import annotations

import inspect
import json
import os
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _src(rel: str) -> str:
    return (PROJECT_ROOT / rel).read_text(encoding="utf-8")


def _code_only(text: str) -> str:
    """去掉整行注释（避免"修复说明注释"里提到的符号名把断言打绿）。"""
    out = []
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


# =====================================================================
# 缺口 8：DOMAIN_LIST 导出
# =====================================================================
def test_gap8_domain_list_exported():
    from core.endpoint.risk_domain import DOMAIN_LIST, RISK_DOMAIN_RULES
    from core.endpoint import DOMAIN_LIST as FROM_PKG

    assert DOMAIN_LIST == [d for d, _ in RISK_DOMAIN_RULES]
    assert len(DOMAIN_LIST) == 8
    assert "upload" in DOMAIN_LIST and "authz" in DOMAIN_LIST
    assert FROM_PKG == DOMAIN_LIST, "包级未导出 DOMAIN_LIST（编排/UI 引用不到）"


# =====================================================================
# 缺口 1：Track A 按域派活（P0 最高杠杆）
# =====================================================================
def test_gap1_track_a_is_wired_into_orchestration():
    """★ 核心防假绿：`group_by_risk_domain` 必须在**编排路径**被调用。

    接线链（两跳，缺任一跳即空转）：
      `_run_parallel_test.run_parallel_test`
        → `core.endpoint.track_a.apply_track_a`
          → `group_by_risk_domain`
    """
    from core.endpoint import track_a
    from core.parallel._orch_phases import _run_parallel_test as rpt

    ta_src = _code_only(inspect.getsource(track_a))
    assert "group_by_risk_domain(" in ta_src, \
        "track_a 未调用 group_by_risk_domain（Track A 空转）"
    assert "classify_risk_domain(" in ta_src, "track_a 未做域分类"
    assert "XJ_TRACK_A" in ta_src, "track_a 缺少回滚开关 XJ_TRACK_A"

    orch_src = _code_only(inspect.getsource(rpt))
    assert "from core.endpoint.track_a import" in orch_src, \
        "编排未引入 Track A 适配层"
    entry_src = _code_only(inspect.getsource(rpt.run_parallel_test))
    assert "apply_track_a(" in entry_src, \
        "run_parallel_test 未调用按域分批（空转）"


def test_gap1_track_a_actually_batches_by_domain():
    from core.endpoint.track_a import batch_groups_by_risk_domain

    class _FP:
        def __init__(self, i, url):
            self.id = i
            self.name = i
            self.related_apis = [url]
            self.page_url = ""

    groups = [
        ("g1", [_FP("a", "POST /api/upload/avatar")]),
        ("g2", [_FP("b", "GET /api/report/export")]),
        ("g3", [_FP("c", "POST /api/upload/photo")]),
    ]
    new_groups, stats = batch_groups_by_risk_domain(groups, host="shop.example.com")
    names = [n for n, _ in new_groups]

    # 同域聚拢：两个 upload 组必须相邻（域序优先）
    assert sum(1 for n in names if n.startswith("[upload]")) == 2
    assert names[0].startswith("[upload]") and names[1].startswith("[upload]"), names
    # 派活覆盖度可观测
    assert "upload" in stats["dispatched_domains"]
    assert stats["total_endpoints"] == 3
    assert stats["domains"]["upload"], "域 → 组映射为空"


def test_gap1_track_a_rollback_switch(monkeypatch):
    from core.endpoint.track_a import apply_track_a, track_a_enabled

    monkeypatch.setenv("XJ_TRACK_A", "0")
    assert track_a_enabled() is False

    class _S:
        target_url = "https://shop.example.com"
        sitemap = None

        def _event(self, k, m):
            return {"type": k, "msg": m}

    g = [("g1", [])]
    out, evt = apply_track_a(_S(), g)
    assert out == g and evt is None, "关闭开关后仍有副作用（未完全回滚）"

    monkeypatch.setenv("XJ_TRACK_A", "1")
    assert track_a_enabled() is True


def test_gap1_worker_id_carries_domain():
    from core.endpoint.track_a import worker_id_for

    assert worker_id_for("[upload] 上传组", 3) == "upload-w3"
    assert worker_id_for("无前缀组", 4) == "w4", "无域标注时应退化为旧格式"


# =====================================================================
# 缺口 2：覆盖闸门 L6–L10 落盘前接线
# =====================================================================
def test_gap2_coverage_gate_wired_in_export():
    from core.loops import coverage_integration as ci

    entry = _code_only(inspect.getsource(ci.export_scan_artifacts))
    assert "run_coverage_gate(" in entry, "export_scan_artifacts 未调 run_coverage_gate"
    assert "coverage_gate_result.json" in entry, "闸门结果未落盘"
    assert "coverage_gate" in entry, "ci_gate_result 未并入闸门判定"
    assert "expected_coverage_matrix(surfaces)" in entry, "缺少执行期期望矩阵交叉验证"


def test_gap2_coverage_gate_payload_and_blocking_switch():
    """闸门结果结构 + 回滚开关语义（XJ_COVERAGE_GATE_BLOCK）。"""
    from core.loops.coverage_gate import ERROR, GateResult, gate_exit_code, run_coverage_gate

    results = run_coverage_gate({"expected": [{"key": "GET /a"}], "matrix": []}, [], [])
    assert gate_exit_code(results) == 1
    assert any(r.level == "L6" and r.severity == ERROR and not r.passed for r in results)

    ok = [GateResult("L6", ERROR, True, "")]
    assert gate_exit_code(ok) == 0


def test_gap2_gate_env_default_is_enforced():
    """默认 enforced：XJ_COVERAGE_GATE_BLOCK 未设 → 阻断（仅影响 --ci-gate 用户）。"""
    src = _code_only(_src("core/loops/coverage_integration.py"))
    assert 'os.getenv("XJ_COVERAGE_GATE_BLOCK", "1")' in src, \
        "闸门默认应为 enforced=1；改默认值会静默改变 --ci-gate 行为"


# =====================================================================
# 既有 bug 1：_SAFE 字面量与 CheckResult 枚举名不符 → NOT_VULN 从未入账本
# =====================================================================
def test_bugfix_not_vuln_recorded_in_coverage():
    from core.loops.coverage_integration import derive_coverage_entries
    from core.sitemap.models import CheckItem, CheckResult, FeaturePoint

    fp = FeaturePoint(id="f1", name="x", related_apis=["GET /api/user/list"])
    fp.checklist = [CheckItem(vuln_type="越权访问", result=CheckResult.NOT_VULN)]
    entries = derive_coverage_entries([fp], surface_methods={"/api/user/list": "GET"})

    assert len(entries) == 1, "NOT_VULN（测过且无问题）必须进入覆盖账本"
    assert entries[0].outcome == "no_issue_found"


def test_bugfix_reported_takes_precedence():
    from core.loops.coverage_integration import derive_coverage_entries
    from core.sitemap.models import CheckItem, CheckResult, FeaturePoint

    fp = FeaturePoint(id="f1", name="x", related_apis=["GET /api/user/list"])
    fp.checklist = [
        CheckItem(vuln_type="越权访问", result=CheckResult.NOT_VULN),
        CheckItem(vuln_type="越权访问", result=CheckResult.VULNERABLE),
    ]
    entries = derive_coverage_entries([fp], surface_methods={"/api/user/list": "GET"})
    assert [e.outcome for e in entries] == ["reported"]


# =====================================================================
# 既有 bug 2：矩阵键（含 host）与覆盖键（去 host）不对齐 → recorded 恒空
# =====================================================================
def test_bugfix_surface_key_alignment():
    """`derive_coverage_entries` 必须支持表面键对齐，且 export 真的传了。

    用**真实主流格式** `"METHOD https://host/path"`（实测 1181/1192 条）验证：
    `normalize_path` 对该形态会解析失败退化为原样小写，故必须先剥方法前缀。
    """
    from core.loops.coverage_integration import derive_coverage_entries, split_api_ref
    from core.sitemap.models import CheckItem, CheckResult, FeaturePoint

    assert split_api_ref("GET https://h/api/user/list") == ("GET", "https://h/api/user/list")
    assert split_api_ref("/api/user/list") == ("", "/api/user/list")

    fp = FeaturePoint(id="f1", name="x", related_apis=["GET https://h/api/user/list"])
    fp.checklist = [CheckItem(vuln_type="越权访问", result=CheckResult.NOT_VULN)]

    # 不传 surface_keys → 旧路径（键由归一化路径拼出）
    old = derive_coverage_entries([fp], surface_methods={"/api/user/list": "GET"})
    assert len(old) == 1, "方法前缀未剥离 → 端点数被漏算"
    assert old[0].surface == "GET /api/user/list"

    # 传 surface_keys → 对齐矩阵键（含 host）
    new = derive_coverage_entries(
        [fp],
        surface_methods={"/api/user/list": "GET"},
        surface_keys={"/api/user/list": "GET https://h/api/user/list"},
    )
    assert new[0].surface == "GET https://h/api/user/list"

    src = _code_only(_src("core/loops/coverage_integration.py"))
    assert "surface_keys=surface_keys" in src, "export_scan_artifacts 未传 surface_keys（键仍错位）"


def test_bugfix_api_ref_method_prefix_stripped():
    """既有 bug 2b：真实 `related_apis` 主流格式 `"METHOD 绝对URL"` 必须被正确拆分。

    实测分布 1181 条含绝对 URL / 11 条 METHOD+相对路径 —— 若不拦方法前缀，
    `normalize_path("GET https://...")` 因 scheme 含空格解析失败 → 键全线错位。
    """
    from core.loops.coverage_integration import normalize_path, split_api_ref

    # 反证：不拆前缀会得到"废键"
    assert normalize_path("GET https://h/api/user/list").startswith("get "), \
        "normalize_path 行为已变（本钉的前提失效，需复核对齐逻辑）"

    m, u = split_api_ref("GET https://h/api/user/list")
    assert m == "GET" and normalize_path(u) == "/api/user/list"

    m2, u2 = split_api_ref("post /api/upload/avatar?v=1")
    assert m2 == "POST" and normalize_path(u2) == "/api/upload/avatar"

    m3, u3 = split_api_ref("/api/plain")
    assert m3 == "" and normalize_path(u3) == "/api/plain"


def test_bugfix_ledger_recorded_index_no_longer_empty():
    """端到端：对齐后 `build_coverage_ledger` 的 recorded 索引必须非空。"""
    from core.loops.coverage_integration import derive_coverage_entries
    from core.loops.coverage_ledger import build_coverage_ledger
    from core.sitemap.models import CheckItem, CheckResult, FeaturePoint

    surfaces = [{"method": "GET", "url": "https://h/api/user/list",
                 "_surface_key": "GET https://h/api/user/list",
                 "_tags": {"risk_domain": ["authz"]}}]
    fp = FeaturePoint(id="f1", name="x",
                      related_apis=["GET https://h/api/user/list"])
    fp.checklist = [CheckItem(vuln_type="越权访问", result=CheckResult.NOT_VULN)]
    entries = derive_coverage_entries(
        [fp],
        surface_methods={"/api/user/list": "GET"},
        surface_keys={"/api/user/list": "GET https://h/api/user/list"},
    )
    ledger = build_coverage_ledger(surfaces, entries)
    recorded = ledger["per_surface"][0]["recorded"]
    assert recorded, "recorded 索引为空 → 覆盖账本系统性误判（既有 bug 未修）"


# =====================================================================
# 缺口 3：授权 SOFT 门
# =====================================================================
def test_gap3_enforce_pre_scan_gate_semantics(tmp_path):
    from web.api.auth_gate import AuthScopeError, enforce_pre_scan_gate

    # 未提供 scope → 降级放行（SOFT）
    info = enforce_pre_scan_gate("https://shop.example.com")
    assert info["degraded"] is True and info["enforced"] is False

    # strict=True → 阻断
    with pytest.raises(AuthScopeError):
        enforce_pre_scan_gate("https://shop.example.com", strict=True)

    # 合法 scope → 通过
    sf = tmp_path / "scope.json"
    sf.write_text(json.dumps({
        "signed": True, "domains": ["https://*.example.com"],
        "expires_at": "2099-12-31T23:59:59",
    }), encoding="utf-8")
    assert enforce_pre_scan_gate("https://shop.example.com", sf)["enforced"] is True

    # 越域 → 阻断
    with pytest.raises(AuthScopeError):
        enforce_pre_scan_gate("https://evil.test", sf)


def test_gap3_gate_wired_into_both_scan_entrypoints():
    from core.parallel._orch_phases import _browser_test, _run_parallel_test

    for mod, fn in ((_run_parallel_test, _run_parallel_test.run_parallel_test),
                    (_browser_test, _browser_test.start_browser_feature_test)):
        assert "apply_pre_scan_gate" in _code_only(inspect.getsource(mod)), \
            f"{mod.__name__} 未接入授权门"
        assert "apply_pre_scan_gate(" in _code_only(inspect.getsource(fn)), \
            f"{fn.__name__} 未实际调用授权门"


def test_gap3_gate_is_idempotent_per_session():
    from core.parallel._orchestrator_helpers import apply_pre_scan_gate

    class _SM:
        pass

    class _S:
        target_url = "https://shop.example.com"
        sitemap = _SM()

        def _event(self, k, m):
            return {"type": k, "msg": m}

    s = _S()
    apply_pre_scan_gate(s)
    blocked2, evt2 = apply_pre_scan_gate(s)
    assert (blocked2, evt2) == (False, None), "授权门未做幂等（会重复校验/重复告警）"


def test_gap3_gate_off_switch(monkeypatch):
    from web.api.auth_gate import enforce_pre_scan_gate

    monkeypatch.setenv("XJ_AUTH_GATE", "0")
    info = enforce_pre_scan_gate("https://shop.example.com", strict=True)
    assert info["skipped"] is True


# =====================================================================
# 缺口 4：CLI --scope-file
# =====================================================================
def test_gap4_cli_scope_file_arg():
    from cli.main import _build_parser

    args = _build_parser().parse_args(
        ["run", "--url", "https://a.test", "--scope-file", "/tmp/s.json"]
    )
    assert args.scope_file == "/tmp/s.json"
    assert _build_parser().parse_args(["run", "--url", "https://a.test"]).scope_file is None

    src = _code_only(_src("cli/main.py"))
    assert "XUANJIAN_SCOPE_FILE" in src, "CLI 未把 scope 文件传给编排层"


# =====================================================================
# 缺口 5：F3 完整 Cookie 集注册 + 喂入
# =====================================================================
def test_gap5_credential_store_required_cookies(tmp_path):
    from core.credential_store import CredentialStore

    cred_file = tmp_path / "auth_credentials.json"
    cred_file.write_text(json.dumps({
        "credentials": [{
            "id": "c1", "applicable_domains": ["shop.example.com"],
            "required_cookies": ["JSESSIONID", "token"],
        }],
        "tenant_required_cookies": {"t1": ["sid", "uid"]},
    }, ensure_ascii=False), encoding="utf-8")

    store = CredentialStore(cred_file=cred_file)
    assert store.get_required_cookies("c1") == {"JSESSIONID", "token"}
    assert store.required_cookies_for(tenant="t1") == {"sid", "uid"}          # 租户优先
    assert store.required_cookies_for(url="https://shop.example.com/x") == {"JSESSIONID", "token"}
    assert store.required_cookies_for(url="https://other.test/x") == set()    # 安全默认=空集

    # 保形回写：dict 容器形态下兄弟字段不被写丢
    assert store.set_required_cookies("c1", ["JSESSIONID"]) is True
    reloaded = json.loads(cred_file.read_text(encoding="utf-8"))
    assert "tenant_required_cookies" in reloaded, "回写把 dict 容器的兄弟字段写丢了"


def test_gap5_injector_receives_required_cookies():
    """★ 核心防假绿：参数必须真的**被传入** `_wait_for_login_result`。"""
    from core.credential_injector import CredentialInjector

    inj = CredentialInjector(required_cookies={"JSESSIONID", "token"})
    assert inj.required_cookies == {"JSESSIONID", "token"}

    login_src = _code_only(inspect.getsource(CredentialInjector.login))
    assert "required_cookies=self.required_cookies" in login_src, \
        "_wait_for_login_result 未收到 required_cookies（参数就绪但零实参）"


def test_gap5_api_resolves_required_cookies():
    from web.api import credential_injection_api as api

    src = _code_only(_src("web/api/credential_injection_api.py"))
    assert "required_cookies_for(" in src, "注入 API 未解析 required_cookies"
    assert "required_cookies=_required" in src, "注入 API 未把结果喂给 CredentialInjector"


# =====================================================================
# 缺口 6：多源并集
# =====================================================================
def test_gap6_union_sources_dedup_and_provenance():
    from core.endpoint.surface_inventory import union_sources

    u = union_sources(
        ("apis", [{"method": "GET", "url": "http://h/a"}]),
        ("js", [{"method": "GET", "url": "http://h/a?v=2"},
                {"method": "POST", "url": "http://h/b"}]),
    )
    assert u["unique"] == 2
    assert u["duplicates"] == 1
    assert u["sources"] == {"apis": 1, "js": 2}
    merged_a = next(e for e in u["endpoints"] if e["url"].endswith("/a"))
    assert merged_a["_sources"] == ["apis", "js"], "未保留来源 provenance"


def test_gap6_union_wired_into_surface_build():
    from core.loops import coverage_integration as ci

    src = _code_only(inspect.getsource(ci._build_surfaces))
    assert "union_sources(" in src, "_build_surfaces 未做多源并集（仍单一来源）"
    for src_name in ("sitemap.apis", "js_api_calls", "js_routes", "features.related_apis"):
        assert src_name in src, f"并集缺少来源 {src_name}"


# =====================================================================
# 缺口 7：BUSINESS_CODE_KEYS + 配置真的被消费
# =====================================================================
def test_gap7_business_code_keys_and_config_driven():
    from core.config import (
        BUSINESS_CODE_KEYS,
        active_business_domain,
        build_business_deny_patterns,
        resolve_business_deny_patterns,
    )

    assert isinstance(BUSINESS_CODE_KEYS, list) and BUSINESS_CODE_KEYS
    assert "code" in BUSINESS_CODE_KEYS
    assert resolve_business_deny_patterns("profile_a") == build_business_deny_patterns("profile_a")
    assert active_business_domain()  # 非空


def test_gap7_fp_filters_consumes_config_not_hardcoded():
    """★ 核心防假绿：`_is_business_deny` 必须走配置，而不是只 import 常量。

    等价性用**行为差分**判定（而非正则字符串相等——配置 materialize 会加分组括号，
    文本不同但语义等价；实测 140 样本 0 差异）。
    """
    import re

    from core.fast_scanner import _fp_filters
    from core.fast_scanner._constants import BUSINESS_DENY_PATTERNS

    src = _code_only(inspect.getsource(_fp_filters))
    assert "active_business_deny_patterns()" in src, \
        "_is_business_deny 仍读硬编码常量（配置存在但没生效）"
    assert "resolve_business_deny_patterns" in src, "未接 core.config 的配置解析"

    active = _fp_filters.active_business_deny_patterns()

    def hit(text, pats):
        return any(re.search(p, text, re.IGNORECASE) for p in pats)

    samples = [
        '{"code": 401}', '{"code": 403}', '{"code": 500}', '{"code": 40100}',
        '{"code": 40300}', '{"code": 40001}', '{"code": 40003}', '{"code": 200}',
        '{"code": 0}', '{"errorCode": 403}', '{"errno": 401}', '{"status_code": 500}',
        '{"message": "未登录"}', '{"message": "未授权"}', '{"msg": "无权限"}',
        '{"msg": "权限不足"}', '{"errMsg": "登录失效"}', '{"error_msg": "token已过期"}',
        '{"message": "access denied"}', '{"message": "unauthorized"}',
        '{"message": "please login"}', '{"message": "OK"}', '{"message": "success"}',
        '{"success": false}', '{"success": true}', '{"status": "false"}',
        '{success:false}', 'ret:403', 'code:401',
        '{}', '{"data": [1,2,3]}', '{"code":200,"message":"操作成功"}',
    ]
    diffs = [s for s in samples if hit(s, BUSINESS_DENY_PATTERNS) != hit(s, active)]
    assert not diffs, f"默认域与硬编码行为不等价（会静默改变检测行为）: {diffs[:5]}"


def test_gap7_domain_switch_takes_effect(monkeypatch):
    from core.config import active_business_code_keys, resolve_business_deny_patterns

    monkeypatch.setenv("XUANJIAN_BUSINESS_DOMAIN", "profile_b")
    keys = active_business_code_keys()
    assert "ret" in keys, "切换到域B 后字段名未变化（配置未生效）"
    assert resolve_business_deny_patterns() != resolve_business_deny_patterns("profile_a")


# =====================================================================
# 缺口 9：WAF 厂商签名库
# =====================================================================
def test_gap9_signature_file_exists_and_loaded():
    from core.loops.identify_waf import WAF_SIGNATURES, signature_source

    sig_file = PROJECT_ROOT / "core" / "loops" / "waf_signatures.json"
    assert sig_file.exists(), "core/loops/waf_signatures.json 不存在（§2.7 签名库）"
    payload = json.loads(sig_file.read_text(encoding="utf-8"))
    assert isinstance(payload.get("vendors"), dict)
    assert len(payload["vendors"]) == 23

    assert signature_source() == "json", "identify_waf 未加载外部 JSON（仍在用内置副本）"
    assert len(WAF_SIGNATURES) == 23


def test_gap9_identify_attribution():
    from core.loops.identify_waf import identify

    r = identify(status=403, headers={"cf-ray": "x", "server": "cloudflare"},
                 body="blocked by cloudflare")
    assert r["waf"] == "Cloudflare"
    assert r["confidence"] >= 0.9
    assert r["suggested_tamper"], "未给出建议绕过原语"

    r2 = identify(status=403, headers={"server": "safedog"}, body="blocked by safedog waf")
    assert r2["waf"] == "SafeDog", "共享措辞不应跨厂商误报"


def test_gap9_wired_into_production_waf_detection():
    """★ 核心防假绿：接在**生产判定** `_is_waf_block_page` 上，而非死方法。"""
    from core.fast_scanner import _fp_filters

    src = _code_only(inspect.getsource(_fp_filters._is_waf_block_page))
    assert "identify_waf_from_response(" in src, \
        "_is_waf_block_page 未产出厂商归因（§2.7 未接线）"

    class _R:
        status_code = 403
        headers = {"server": "safedog"}
        text = "blocked by safedog waf security firewall"

    assert _fp_filters._is_waf_block_page(_R()) is True
    assert _fp_filters.last_waf_attribution().get("waf") == "SafeDog"


def test_gap9_fuzz_bool_api_preserved():
    """`_detect_waf` 返回类型契约不变（bool），避免破坏调用方。"""
    from core.fuzz.base import BaseFuzzer

    class _F(BaseFuzzer):
        VULN_TYPES = ("sqli",)

    f = _F()
    out = f._detect_waf(200, "hello", {})
    assert out is False
    assert f.last_waf_attribution == {}
    out2 = f._detect_waf(403, "blocked by cloudflare waf", {"cf-ray": "x"})
    assert out2 is True
    assert f.last_waf_attribution.get("waf") == "Cloudflare"
