"""924 修复回归钉子 —— task_1790223312_c75b16（e.aibank 探针/幽灵/上下文预算）。

本文件把 924 复盘方案 §3「测试视角」的 5 条回归钉子落成可执行断言，
外加空解析熔断与 system 块裁剪两条单元验证。

对应问题一句话版：
- 模型 `wuwen` 返回非标准 SSE → 解析全空 → 主循环盲跑，最终 0 已证明漏洞；
- 子 Agent 固定提示词 17351 > 预算 15564，且 compress() 对 system 无效 → 第 1 轮必崩；
- 子域接管特征表字面含 `"404 not found"` → 普通 404 页被标 🟠高危；
- 幽灵端点的 404 判定只打在 feature 层 → 进入期望矩阵把 L6 拉红；
- L7 闸门引用 schema 里不存在的 `payloads` 字段 → 稳定误阻断。
"""
from __future__ import annotations

import httpx
import pytest

from core.fast_scanner import FastScanner, ScanTarget
from core.fast_scanner._checks_p2 import (
    GENERIC_ERROR_PAGE_HINTS,
    SUBDOMAIN_TAKEOVER_MARKERS,
    SUBDOMAIN_TAKEOVER_VENDORS,
)


def _scanner(fake):
    s = FastScanner(max_workers=1)
    s._request = fake
    return s


def _resp(status=200, text="", **headers):
    return httpx.Response(status, text=text, headers=headers)


# ============================================================
# 钉子 1 — 子域接管特征表不含通用文案
# ============================================================
def test_markers_have_no_generic_phrases():
    """`404 not found` / `doesn't exist` 必须已从特征表移除。

    它们是任何站点错误页都会出现的通用文案；目标自己的 nginx 404 页正文就是
    `<title>404 not found</title>`，命中即误报 🟠高危（实测 V-ORPHAN-4/11/15）。
    """
    low = [m.lower() for m in SUBDOMAIN_TAKEOVER_MARKERS]
    assert "404 not found" not in low
    assert "doesn't exist" not in low
    assert "does not exist" not in low          # 同为通用措辞
    # 保留的特征必须能对应到具体服务商（可解释的强特征）
    for m in low:
        assert m in SUBDOMAIN_TAKEOVER_VENDORS, f"特征 {m!r} 缺少服务商归属"
    assert "there is no app configured" in low   # Heroku
    assert "no such bucket" in low               # S3/GCS
    assert "404 not found" in [h.lower() for h in GENERIC_ERROR_PAGE_HINTS]


# ============================================================
# 钉子 2 — 子域接管只对裸域 + 200 + 服务商专属文案成立
# ============================================================
@pytest.mark.asyncio
async def test_subdomain_takeover_positive_root_200():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "There is no app configured at that hostname.")
    s = _scanner(fake)
    f = await s._check_subdomain_takeover(ScanTarget(url="http://sub.x/", method="GET"))
    assert f and f[0].vuln_type == "子域接管"
    assert "Heroku" in f[0].detail


@pytest.mark.asyncio
async def test_subdomain_takeover_deep_path_returns_empty():
    """深路径不应判定子域接管（那是 DNS/CNAME 层问题）。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "There is no app configured at that hostname.")
    s = _scanner(fake)
    for _u in ("http://x/QueryLogin", "http://x/Loginkey",
               "http://x/audit/FinanTransAudit", "http://x/a/b/c"):
        assert await s._check_subdomain_takeover(ScanTarget(url=_u, method="GET")) == [], _u


@pytest.mark.asyncio
async def test_subdomain_takeover_plain_404_page_not_flagged():
    """目标自己的 nginx 404 页（旧实现的最大误报源）不得被判为高危。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "<html><head><title>404 not found</title></head>"
                          "<body><center><h1>404 not found</h1></center></body></html>")
    s = _scanner(fake)
    assert await s._check_subdomain_takeover(ScanTarget(url="http://x/", method="GET")) == []


@pytest.mark.asyncio
async def test_subdomain_takeover_requires_200():
    """4xx 不是服务商默认页（默认页是 200）。"""
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(404, "There is no app configured at that hostname.")
    s = _scanner(fake)
    assert await s._check_subdomain_takeover(ScanTarget(url="http://x/", method="GET")) == []


# ============================================================
# 钉子 3 — 幽灵端点必须从期望面剔除（endpoint 层）
# ============================================================
def test_ghost_surface_keys_from_skipped_features():
    from core.loops.coverage_integration import _ghost_surface_keys, _normalize_surface_key

    class _FP:
        def __init__(self, desc, apis, status, page=""):
            self.description, self.related_apis = desc, apis
            self.test_status, self.page_url = status, page

    class _SM:
        features: list = []

        @staticmethod
        def _fp_is_ghost(fp):
            return fp.test_status == "skipped" or "[GHOST-ENDPOINT]" in (fp.description or "")

    sm = _SM()
    sm.features = [
        _FP("API 端点 GET https://h/QueryLogin [GHOST-ENDPOINT]",
            ["GET https://h/QueryLogin"], "skipped", "https://h/QueryLogin"),
        _FP("API 端点 GET https://h/", ["GET https://h/"], "tested", "https://h/"),
    ]
    keys = _ghost_surface_keys(sm)
    assert keys == {"GET https://h/QueryLogin"}
    assert _normalize_surface_key("GET https://h/a?b=1") == "GET https://h/a"
    assert _normalize_surface_key("https://h/a") == "GET https://h/a"


def test_build_surface_inventory_excludes_ghosts():
    from core.endpoint.surface_inventory import build_surface_inventory

    eps = [
        {"method": "GET", "url": "https://h/"},
        {"method": "GET", "url": "https://h/QueryLogin"},
        {"method": "GET", "url": "https://h/Loginkey"},
    ]
    inv = build_surface_inventory(
        eps, host="h",
        exclude_keys={"GET https://h/QueryLogin", "GET https://h/Loginkey"})
    assert inv["ghost_excluded"] == 2
    assert inv["unique"] == 1
    assert [s["_surface_key"] for s in inv["surfaces"]] == ["GET https://h/"]


def test_expected_coverage_matrix_skips_ghosts():
    """ghost 过滤后的 surfaces 不应再产出期望行。"""
    from core.endpoint.surface_inventory import build_surface_inventory
    from core.loops.coverage_derive import expected_coverage_matrix

    eps = [
        {"method": "GET", "url": "https://h/"},
        {"method": "GET", "url": "https://h/QueryLogin"},
    ]
    inv = build_surface_inventory(eps, host="h", exclude_keys={"GET https://h/QueryLogin"})
    matrix = expected_coverage_matrix(inv["surfaces"])
    keys = {r["surface_key"] for r in matrix}
    assert "GET https://h/QueryLogin" not in keys
    assert "GET https://h/" in keys


# ============================================================
# 钉子 4 — L7 闸门：无 payloads 字段的 finding 不参与判定
# ============================================================
def test_l7_gate_skips_findings_without_payloads_field():
    from core.loops.coverage_gate import run_coverage_gate

    # 本项目 confirmed 的 schema 无 payloads 字段 → 不应产生 L7 ERROR
    findings = [{"id": "V-1", "url": "https://h/", "vuln_type": "信息泄露"}]
    results = run_coverage_gate({"expected": [], "matrix": []}, findings, [])
    assert [r for r in results if r.level == "L7"] == []


def test_l7_gate_still_errors_when_payloads_present_but_few():
    from core.loops.coverage_gate import run_coverage_gate

    findings = [{"id": "V-1", "url": "https://h/x", "payloads": ["only-one"]}]
    results = run_coverage_gate({"expected": [], "matrix": []}, findings, [])
    l7 = [r for r in results if r.level == "L7"]
    assert len(l7) == 1 and not l7[0].passed
    # id 兜底链应能定位（不再输出 finding(?)）
    assert "V-1" in l7[0].message


def test_l7_gate_uses_url_when_id_and_rule_missing():
    from core.loops.coverage_gate import run_coverage_gate

    findings = [{"url": "https://h/only-url", "payloads": []}]
    results = run_coverage_gate({"expected": [], "matrix": []}, findings, [])
    l7 = [r for r in results if r.level == "L7"]
    assert l7 and "https://h/only-url" in l7[0].message


# ============================================================
# 钉子 5 — 固定开销超预算 → 走 system 裁剪，而不是 compress 重试
# ============================================================
def test_budget_infeasible_triggers_system_shrink():
    from core.context import (
        ContextManager, SYSTEM_PRIORITY_CRITICAL, SYSTEM_PRIORITY_SKILL,
    )
    from core.context_budget import compute_fit, ensure_context_fits, infeasible_message

    def _ctx():
        c = ContextManager()
        c.add_system("X" * 2000, kind="prompt:worker", priority=SYSTEM_PRIORITY_CRITICAL)
        # CJK 约 1 token/char → 24000 chars ≈ 24000 tok，远超 wuwen 的可行上限
        c.add_system("方法论" * 8000, kind="skill:idor", priority=SYSTEM_PRIORITY_SKILL)
        return c

    # wuwen 未登记窗口 → 预算 15564；上面固定开销远超 → 判定不可行
    c = _ctx()
    fit = compute_fit(c, "wuwen", None)
    assert fit["budget"] == 15564
    assert fit["ok"] is False

    # ensure_* 应裁剪 system 块使其可行
    stats = ensure_context_fits(c, "wuwen", None, who="t1")
    assert stats["ok"] is True
    assert stats["shrunk"]["dropped"] >= 1
    assert "skill:idor" in stats["shrunk"]["dropped_kinds"]

    # 大窗口模型（128K）本来就可行，不应裁剪
    c2 = _ctx()
    fit2 = compute_fit(c2, "kimi-k2", None)
    assert fit2["budget"] > 60000 and fit2["ok"] is True
    st2 = ensure_context_fits(c2, "kimi-k2", None, who="t2")
    assert st2.get("shrunk") is None

    assert infeasible_message({"model": "wuwen", "before": 9, "budget": 1, "after": 9})


def test_shrink_keeps_critical_and_drops_skill_body_first():
    from core.context import (
        ContextManager, SYSTEM_PRIORITY_CRITICAL,
        SYSTEM_PRIORITY_SKILL, SYSTEM_PRIORITY_SKILL_CONSTRAINT,
    )

    c = ContextManager()
    c.add_system("P" * 4000, kind="prompt:worker", priority=SYSTEM_PRIORITY_CRITICAL)
    c.add_system("B" * 20000, kind="skill:idor", priority=SYSTEM_PRIORITY_SKILL)
    c.add_system("C" * 3000, kind="skill-constraint:idor",
                 priority=SYSTEM_PRIORITY_SKILL_CONSTRAINT)

    st = c.shrink_system_messages(5000)
    kinds = [b["kind"] for b in c.system_blocks()]
    assert st["ok"] is True
    assert "skill:idor" in st["dropped_kinds"]            # 主体先丢
    assert "prompt:worker" in kinds                       # CRITICAL 保留
    assert "skill-constraint:idor" in kinds               # 约束清单晚于主体被丢

    # 只剩 CRITICAL 仍超限 → 显式不可行（不假装成功）
    c2 = ContextManager()
    c2.add_system("P" * 40000, kind="prompt:worker", priority=SYSTEM_PRIORITY_CRITICAL)
    st2 = c2.shrink_system_messages(1000)
    assert st2["ok"] is False


# ============================================================
# 附加 — 空解析熔断（模型链路不兼容的显式化）
# ============================================================
def test_empty_parse_breaker_trips_and_resets():
    from core.llm import _health

    _health.reset()
    _health.record_ok_parse("wuwen")
    _health.reset_llm_health()
    th = _health.breaker_threshold()
    assert th >= 1
    tripped = [_health.record_empty_parse("wuwen") for _ in range(th)]
    assert tripped[-1] is True and _health.is_tripped()
    # 一次健康响应即复位
    _health.record_ok_parse("wuwen")
    assert _health.empty_parse_streak() == 0 and not _health.is_tripped()


def test_empty_parse_breaker_disabled_by_env(monkeypatch):
    from core.llm import _health

    monkeypatch.setenv("XUANJIAN_LLM_EMPTY_PARSE_BREAKER", "0")
    _health.reset()
    assert [_health.record_empty_parse("m") for _ in range(10)][-1] is False


def test_looks_empty_semantics():
    from core.llm import _health

    class _M:
        pass

    m = _M()
    m.content, m.tool_calls, m.reasoning_content = "", [], None
    assert _health.looks_empty(m) is True
    m.content = "hi"
    assert _health.looks_empty(m) is False
    m.content = ""
    m.tool_calls = [{"id": "1"}]
    assert _health.looks_empty(m) is False
    m.tool_calls = []
    m.reasoning_content = "thinking..."
    assert _health.looks_empty(m) is False        # 纯 reasoning 不算空
    assert _health.looks_empty(None) is True


# ============================================================
# 附加 — 公开兜底页短路 & 预检文案口径
# ============================================================
def test_available_input_budget_single_source():
    from core.llm import _CONTEXT_PRECHECK_SAFETY, available_input_budget, get_model_context_window

    for _m in ("wuwen", "kimi-k2", "deepseek-chat"):
        assert available_input_budget(_m) == (
            int(get_model_context_window(_m) * _CONTEXT_PRECHECK_SAFETY) - 4096)
    assert available_input_budget("wuwen") == 15564


def test_preflight_blocks_protocol_kind():
    from core.llm._failure import BLOCKING_KINDS, LLM_PROTOCOL_MESSAGE

    assert "llm_protocol" in BLOCKING_KINDS
    assert "更换" in LLM_PROTOCOL_MESSAGE


def test_dirscan_normalization_probe_helpers():
    from core.dir_scanner._finding_policy import (
        CATCH_ALL_PROBE_MIN_CLUSTER, is_normalization_probe_path,
    )

    assert is_normalization_probe_path("/..;/actuator/env")
    assert is_normalization_probe_path("/;/actuator/env")
    assert is_normalization_probe_path("/%2e%2e/actuator/env")
    assert not is_normalization_probe_path("/actuator/env")
    assert not is_normalization_probe_path("/audit/FinanTransAudit")
    assert CATCH_ALL_PROBE_MIN_CLUSTER < 3   # 探针阈值比通用阈值更宽松


def test_dirscan_probe_cluster_lowers_threshold():
    """同一兜底体在探针子集里只出现 2 次，也应被判为兜底（通用阈值要 ≥3）。"""
    from core.dir_scanner._finding_policy import (
        CATCH_ALL_PROBE_MIN_CLUSTER, CATCH_ALL_PROBE_MIN_RATE,
        compute_catch_all_clusters,
    )

    hashes = ["h1", "h1"]
    assert compute_catch_all_clusters(hashes) == {}          # 默认阈值不命中
    got = compute_catch_all_clusters(
        hashes, min_total=CATCH_ALL_PROBE_MIN_CLUSTER,
        min_cluster=CATCH_ALL_PROBE_MIN_CLUSTER,
        min_rate=CATCH_ALL_PROBE_MIN_RATE)
    assert got == {"h1": 2}


# ============================================================
# 附加 — 单例归一化探针（S1：成簇法的"1 条探针"盲区）
# ============================================================
# ★ 924 评审 §1.1 S1：apply_catch_all_veto 的探针子集判定要求「≥2 条探针共享
#   同一 body_hash」，`..;/actuator/env` 若为**唯一**命中兜底体的探针（兄弟路径
#   404 / 异体）聚不成簇 → 漏判 → 照旧挂成 alive API → 进权威 API 表与期望矩阵。
#   修复后对单条探针做"内容指纹校验"语义判定，以下钉子锁死该行为。

def _dir_entry(path, status, body, body_hash="h1"):
    from core.dir_scanner._models import DirEntry
    return DirEntry(
        path=path, url=f"https://h{path or '/'}", status=status,
        length=len(body), content_type="text/html", redirect="",
        is_directory=False, title="", body_hash=body_hash, body_text=body,
    )


def test_single_probe_catch_all_marked_without_cluster():
    """S1 主场景：唯一探针 `..;/actuator/env` 返回 SPA 兜底 HTML → 必须标记。

    回归旧实现：单条探针的 body_hash 聚不成簇（需要 ≥2 条），标记恒 False，
    该探针逃逸到 sitemap/期望矩阵。
    """
    from core.dir_scanner._finding_policy import apply_catch_all_veto
    from core.dir_scanner._models import DirScanResult

    entry = _dir_entry("/..;/actuator/env", 200,
                       "<html><body><div id='root'>spa fallback page</div></body></html>")
    result = DirScanResult(target="https://h/", entries=[entry])
    apply_catch_all_veto(result)

    # 单例语义判定命中（无需成簇，也无需 catch_all_detected）
    assert entry.probe_suspected_catch_all is True
    assert result.catch_all_detected is False      # 单例不触发通用簇告警
    assert result.catch_all_probe_clusters == {}   # 成簇法确实没判出来


def test_single_probe_catch_all_positive_content_not_marked():
    """S1 正例保护：探针返回**真实** actuator/env JSON → 不得标记。"""
    from core.dir_scanner._finding_policy import apply_catch_all_veto
    from core.dir_scanner._models import DirScanResult

    entry = _dir_entry(
        "/..;/actuator/env", 200,
        '{"activeProfiles":[],"propertySources":[{"name":"system"}],'
        '"spring":{"application":{"name":"x"}}}')
    apply_catch_all_veto(DirScanResult(target="https://h/", entries=[entry]))
    assert entry.probe_suspected_catch_all is False   # 指纹 content_match → 保留挂载


def test_single_probe_catch_all_non_probe_path_not_marked():
    """S1 边界：非归一化探针路径不受单例判定影响（仍走成簇法）。"""
    from core.dir_scanner._finding_policy import apply_catch_all_veto
    from core.dir_scanner._models import DirScanResult

    # 直接路径同兜底体：单条时无簇证据，不标记 —— 单例判定只对探针构造生效
    entry = _dir_entry("/api/login", 200,
                       "<html><body><div id='root'>spa fallback page</div></body></html>")
    apply_catch_all_veto(DirScanResult(target="https://h/", entries=[entry]))
    assert entry.probe_suspected_catch_all is False


def test_dirscan_single_probe_not_registered_as_api():
    """S2 短链锁：单例兜底探针经 explore_mixin 同款门控 → 不进 sitemap（API/页面）。

    探针「存活」来自绕网关构造（..;/）而非真实业务端点；一旦挂进 sitemap.apis
    就会派生进覆盖矩阵与补测队列。本测试锁死：标记 → 不挂载。
    """
    from core.dir_scanner._finding_policy import apply_catch_all_veto
    from core.dir_scanner._models import DirScanResult
    from core.sitemap import Sitemap

    entry = _dir_entry("/..;/actuator/env", 200,
                       "<html><body><div id='root'>spa fallback page</div></body></html>")
    apply_catch_all_veto(DirScanResult(target="https://h/", entries=[entry]))
    assert entry.probe_suspected_catch_all is True

    sm = Sitemap(target="https://h/", task_id="task_s2_short_chain")
    # 与 explore_mixin.py:196 的门控同款：probe_suspected_catch_all=True → 跳过
    if sm and not getattr(entry, "probe_suspected_catch_all", False):
        sm.add_page(entry.url, title=entry.path)
        sm.add_api("GET", entry.url, discovered_by="dir_scan")
    assert len(sm.apis) == 0 and len(sm.pages) == 0   # 无源可入（矩阵/补测队列派生为 0）

    # 对照组：未标记的普通路径照常挂载 —— 证明门控是"探针专属"而非误伤全部
    entry2 = _dir_entry("/api/login", 200, "<html><body>login page</body></html>")
    apply_catch_all_veto(DirScanResult(target="https://h/", entries=[entry2]))
    assert entry2.probe_suspected_catch_all is False
    if sm and not getattr(entry2, "probe_suspected_catch_all", False):
        sm.add_page(entry2.url, title=entry2.path)
        sm.add_api("GET", entry2.url, discovered_by="dir_scan")
    assert len(sm.apis) == 1 and len(sm.pages) == 1


# ============================================================
# 附加 — FastScanner 公开兜底页短路（S4：_engine 字节级同体熔断）
# ============================================================
def test_public_fallback_breaker_trips_on_repeat_body(monkeypatch):
    """同一 2xx 响应体连续 N 次原样返回 → 判为兜底页并置 detected（后续规则短路）。"""
    from core.fast_scanner import FastScanner
    from core.fast_scanner._engine import _public_fallback_threshold

    monkeypatch.setenv("XUANJIAN_FASTSCAN_FALLBACK_BREAKER", "3")
    assert _public_fallback_threshold() == 3

    s = FastScanner(max_workers=1)
    s._public_fallback_hits = 0
    s._public_fallback_detected = False
    s._public_fallback_hash = ""
    resp = _resp(200, "same fallback body" * 50)
    for _ in range(3):
        s._record_scan_response_log("xss", "GET", "http://h/..;/actuator/env", "p", resp)
    assert s._public_fallback_detected is True
    assert s._public_fallback_hits == 3


def test_public_fallback_breaker_ignores_404_and_varying_bodies(monkeypatch):
    """4xx 与逐次变化的响应体不得触发熔断（避免误伤真实多态响应）。"""
    from core.fast_scanner import FastScanner
    from core.fast_scanner._engine import _public_fallback_threshold

    monkeypatch.setenv("XUANJIAN_FASTSCAN_FALLBACK_BREAKER", "3")
    s = FastScanner(max_workers=1)
    s._public_fallback_hits = 0
    s._public_fallback_detected = False
    s._public_fallback_hash = ""

    for _ in range(5):  # 404 不计入兜底统计（兜底页是 200）
        s._record_scan_response_log("xss", "GET", "http://h/x", "p", _resp(404, "not found"))
    assert s._public_fallback_detected is False

    for i in range(5):  # 每次 body 都不同 → 计数恒为 1
        s._record_scan_response_log("xss", "GET", "http://h/x", "p", _resp(200, f"body-{i}"))
    assert s._public_fallback_detected is False


# ============================================================
# 附加 — 报告"结果不可用"横幅（S5a：LLM 空解析熔断显式化）
# ============================================================
def test_report_llm_failure_banner(monkeypatch):
    """主循环 LLM 连续空解析达到熔断阈值 → 报告头部必须出现「结果不可用」。

    回归旧行为：模型返回非标准流 → 危害验证全空 → 报告安静印「0 已证明漏洞」，
    用户以为"扫完了、基本安全"（实证 task_1790223312_c75b16）。
    """
    from core.llm import _health
    from core.sitemap import Sitemap

    monkeypatch.setenv("XUANJIAN_LLM_EMPTY_PARSE_BREAKER", "2")
    _health.reset()
    for _ in range(2):
        _health.record_empty_parse("wuwen", caller="flush-report-test")
    assert _health.is_tripped()

    sm = Sitemap(target="https://h/", task_id="task_llm_banner")
    sm.apis = {}
    txt = sm.flush_report()
    assert "本次结果不可用" in txt
    assert "0 已证明漏洞 ≠ 目标安全" in txt
    assert "LLM 空响应熔断" in txt          # 同步进 §1.2 能力降级清单
    _health.reset()


def test_report_no_llm_banner_when_healthy():
    """健康状态（有 content/tool_calls）不得误报「结果不可用」。"""
    from core.llm import _health
    from core.sitemap import Sitemap

    _health.reset()
    _health.record_ok_parse("wuwen")

    sm = Sitemap(target="https://h/", task_id="task_llm_healthy")
    sm.apis = {}
    txt = sm.flush_report()
    assert "本次结果不可用" not in txt
    assert "LLM 空响应熔断" not in txt


# ============================================================
# 附加 — §6 API 端点清单角标 + 来源列（S5b）
# ============================================================
def test_report_api_table_badges_and_source():
    """§6 表格带「探针 / 幽灵 / 未验证推测」角标与来源列，消除并列误读。"""
    from core.sitemap import Sitemap
    from core.sitemap.models import FeaturePoint, TestStatus

    sm = Sitemap(target="https://h/", task_id="task_table_badges")
    sm.apis = {
        "GET https://h/api/login": _mk_ep(
            "GET", "https://h/api/login", "phase2_flow", "real_flow", 0.95, '{"ok":1}'),
        "GET https://h/..;/actuator/env": _mk_ep(
            "GET", "https://h/..;/actuator/env", "dir_scan_active", "unknown", 0.4),
        "GET https://h/js/hint": _mk_ep(
            "GET", "https://h/js/hint", "js_analysis", "js_static", 0.55),
        "GET https://h/ghost-api": _mk_ep(
            "GET", "https://h/ghost-api", "crawler_flow", "real_flow", 0.9, 'x'),
    }
    sm.features = {
        "fp_ghost": FeaturePoint(
            id="fp_ghost", name="幽灵端点",
            description="API 端点 GET https://h/ghost-api [GHOST-ENDPOINT]",
            related_apis=["GET https://h/ghost-api"],
            test_status=TestStatus.SKIPPED,
        ),
    }
    txt = sm.flush_report()
    assert "| 方法 | URL | 需认证 | 来源 |" in txt        # 来源列
    assert "[探针]" in txt                                  # 探针角标
    assert "[GHOST-404]" in txt                             # 幽灵角标
    assert "[未验证推测]" in txt                            # 推测角标
    assert "| GET | https://h/api/login | 否 | 真实流量 |" in txt
    assert "| GET | https://h/js/hint [未验证推测] | 否 | JS 静态分析 |" in txt


def _mk_ep(method, url, db, st, conf, sample=""):
    from core.sitemap.models import APIEndpoint
    return APIEndpoint(method=method, url=url, discovered_by=db,
                       source_type=st, confidence=conf, response_sample=sample)


def test_classify_api_surface_splits_sources():
    """★ 924：旧实现用 `isinstance(a, dict)` 判断，而 apis 存的是 APIEndpoint 对象
    → "业务 API 仅 0 个"横幅恒真。分类器必须基于真实来源字段。"""
    from core.sitemap.surface_classify import classify_api_surface

    apis = {
        "root": _mk_ep("GET", "https://h/", "anonymous", "unknown", 0.4),
        "ghost": _mk_ep("GET", "https://h/audit/X", "js_analysis", "js_static", 0.55),
        "probe": _mk_ep("GET", "https://h/..;/actuator/env", "dir_scan_active", "unknown", 0.4),
        # real_flow 但只是 301 静态目录、没有任何观测内容 → 不算业务面
        "staticdir": _mk_ep("GET", "https://h/images", "phase2_flow", "real_flow", 0.95),
        # real_flow 且有响应体 → 真正的业务 API
        "biz": _mk_ep("GET", "https://h/api/login", "phase2_flow", "real_flow", 0.95, '{"ok":1}'),
        "asset": _mk_ep("GET", "https://h/app.js", "x", "unknown", 0.4),
    }
    got = classify_api_surface(apis)
    assert got["business"] == 1, got          # 只有带响应体的那条
    assert got["probe"] == 1
    assert got["speculative"] == 1
    assert got["static"] == 1
    assert got["unverified"] == 2             # root + 301 静态目录
    assert got["total"] == 6

    # 兼容 dict 形态（历史数据/测试桩）
    assert classify_api_surface(
        {"x": {"url": "https://h/..;/a", "discovered_by": "dir_scan_active"}})["probe"] == 1


def test_report_declares_anonymous_only_scan():
    """★ 924（§7 代码化）：无凭证时报告必须直说「仅匿名面」并给出可执行下一步。"""
    from core.sitemap import Sitemap

    sm = Sitemap(target="https://h/", task_id="task_anon_check")
    sm.apis = {"x": _mk_ep("GET", "https://h/..;/actuator/env",
                           "dir_scan_active", "unknown", 0.4)}
    sm._has_credentials = False
    sm.login_status = {}

    txt = sm.flush_report()
    assert "仅匿名面" in txt
    assert "补凭证" in txt or "重新扫描" in txt
    # 横幅必须给出分类明细，让"为什么是 0"自解释
    assert "未验证推测" in txt and "静态资源" in txt


def test_report_omits_anonymous_banner_when_credentials_present():
    """有凭证且登录成功时不得误报「仅匿名面」。"""
    from core.sitemap import Sitemap

    sm = Sitemap(target="https://h/", task_id="task_cred_check")
    sm.apis = {"biz": _mk_ep("GET", "https://h/api/list",
                             "phase2_flow", "real_flow", 0.95, '{"ok":1}')}
    sm._has_credentials = True
    sm.login_status = {"role": "user"}

    txt = sm.flush_report()
    assert "仅匿名面" not in txt
