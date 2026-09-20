"""testflow 批次 2/3 纯函数回归钉（2026-09-20）。

覆盖：
- batch_test._census_test_urls / _census_filter_static / _classify_noauth_response（G2 四铁律分层）
- baseline.waf_probe / catch_all_baseline / baseline_events（mock http，零真实请求）
- matrix_render.render_sparse_matrix（五态格 + 部分覆盖声明）
- worker_agent.check_matches_domain（(fp,domain) 任务单元）
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest


class FakeResp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


# ── census URL 推导与静态过滤 ──

class _FP:
    def __init__(self, related_apis=None, page_url=""):
        self.related_apis = related_apis or []
        self.page_url = page_url


def test_census_test_urls_related_apis():
    from core.parallel.batch_test import _census_test_urls
    fp = _FP(related_apis=["GET /api/v1/users", "POST http://x.com/api/order"])
    urls = _census_test_urls(fp, "http://t.com")
    assert ("GET", "http://t.com/api/v1/users") in urls
    assert ("POST", "http://x.com/api/order") in urls


def test_census_test_urls_spa_fallback():
    from core.parallel.batch_test import _census_test_urls
    fp = _FP(page_url="http://t.com/admin/monitor/battery")
    urls = _census_test_urls(fp, "http://t.com")
    assert any("/api/monitor/battery" in u for _, u in urls)


def test_census_filter_static():
    from core.parallel.batch_test import _census_filter_static
    urls = [("GET", "http://t.com/api/a.js"), ("GET", "http://t.com/api/users"),
            ("GET", "http://t.com/static/app.css")]
    out = _census_filter_static(urls)
    assert out == [("GET", "http://t.com/api/users")]


# ── G2 响应真实性门分层（四铁律复用）──

def test_classify_l3_gateway():
    from core.parallel.batch_test import _classify_noauth_response
    level, verdict = _classify_noauth_response(200, FakeResp(403, ""))
    assert (level, verdict) == ("L3", "gateway_deny")


def test_classify_l3_login_redirect():
    from core.parallel.batch_test import _classify_noauth_response
    level, _ = _classify_noauth_response(200, FakeResp(302, "", {"location": "/login"}))
    assert level == "L3"


def test_classify_phantom():
    from core.parallel.batch_test import _classify_noauth_response
    level, verdict = _classify_noauth_response(200, FakeResp(404, "x"))
    assert (level, verdict) == ("PHANTOM", "not_found")


def test_classify_l2_business_deny():
    from core.parallel.batch_test import _classify_noauth_response
    body = '{"code": 401, "msg": "用户未登录", "data": null}'
    level, verdict = _classify_noauth_response(200, FakeResp(200, body, {"content-type": "application/json"}))
    assert level in ("L2", "L3")  # 四铁律命中其一即可（具体层由关键词表定）
    assert verdict in ("business_deny", "auth_wall_page")


def test_classify_l1_sensitive():
    from core.parallel.batch_test import _classify_noauth_response
    body = '{"code":200,"data":[{"id":1,"phone":"13800000001","id_card":"110101199001011234"}]}'
    level, verdict = _classify_noauth_response(200, FakeResp(200, body, {"content-type": "application/json"}))
    assert level == "L1"
    assert verdict in ("sensitive_data", "suspected_200")


def test_classify_spa_fallback():
    from core.parallel.batch_test import _classify_noauth_response
    html = "<!DOCTYPE html><html><body><div id=app></div></body></html>"
    level, verdict = _classify_noauth_response(200, FakeResp(200, html, {"content-type": "text/html"}))
    # SPA 壳被四铁律（public_data）或 SPA fallback 分支捕获均为 L0 公开结论
    assert level == "L0"
    assert verdict in ("spa_fallback", "public_data")


# ── baseline：WAF 预检 + catch-all 共享 ──

def test_waf_probe_no_waf():
    from core.testflow.baseline import waf_probe

    async def http(method, url, headers):
        return FakeResp(200, '{"code":200,"data":[]}', {"content-type": "application/json"})

    b = asyncio.run(waf_probe(http, ["http://t.com/api/users"]))
    assert not b.waf_detected
    assert b.block_ratio == 0.0


def test_waf_probe_blocks_attacks():
    from core.testflow.baseline import waf_probe

    async def http(method, url, headers):
        if "AND%201%3D1" in url:
            return FakeResp(403, "Forbidden by WAF")
        return FakeResp(200, "ok")

    b = asyncio.run(waf_probe(http, ["http://t.com/api/users", "http://t.com/api/items"]))
    assert b.waf_detected
    assert b.block_ratio == 1.0
    assert b.injection_domains_degrade


def test_catch_all_baseline_matches():
    from core.testflow.baseline import catch_all_baseline

    def norm(s):
        return " ".join(s.split())

    ca = catch_all_baseline(detected=True, rate=100.0,
                            sample_body="  <html>  not found  </html>  ", normalize=norm)
    assert ca.matches(" <html> not found </html> ", norm)
    assert not ca.matches("real data")


def test_baseline_events_text():
    from core.testflow.baseline import WafBaseline, EnvConsistency, baseline_events
    evs = baseline_events(WafBaseline(block_ratio=0.0))
    assert any("无 WAF" in e for e in evs)
    evs2 = baseline_events(WafBaseline(waf_detected=True, vendor="Cloudflare", block_ratio=0.8))
    assert any("注入类域降权" in e for e in evs2)


# ── 矩阵渲染 ──

class _MatrixFP:
    def __init__(self, fid, name, risk_domains, domain_status, related_apis=None, page_url=""):
        self.id = fid
        self.name = name
        self.risk_domains = risk_domains
        self.domain_status = domain_status
        self.related_apis = related_apis or []
        self.page_url = page_url


class _Sitemap:
    def __init__(self, features):
        self.features = features


def test_matrix_render_cells_and_domain_summary():
    from core.testflow.matrix_render import render_sparse_matrix
    fp1 = _MatrixFP("f1", "用户列表", ["authz"],
                    {"authz": "reported", "_census": "needs_follow_up"},
                    related_apis=["GET /api/v1/users"])
    fp2 = _MatrixFP("f2", "代理", ["ssrf"], {"ssrf": "needs_follow_up"},
                    related_apis=["GET /api/proxy?url=x"])
    md = render_sparse_matrix(_Sitemap({"f1": fp1, "f2": fp2}))
    assert "| GET /api/v1/users |" in md
    assert "✓" in md and "⚠" in md
    assert "### 域级结论" in md
    assert "authz**: 覆盖 1 格 → 产出 1" in md


def test_matrix_render_partial_coverage_declaration():
    from core.testflow.matrix_render import render_sparse_matrix
    fp = _MatrixFP("f1", "上传", ["upload"], {"upload": "needs_follow_up"})
    md = render_sparse_matrix(_Sitemap({"f1": fp}), session=None)
    assert "部分覆盖声明" in md
    assert "需人工复核" in md


def test_matrix_render_unauth_only_session():
    from core.testflow.matrix_render import render_sparse_matrix

    class _S:
        auth_surface_mode = "unauth_only"

    fp = _MatrixFP("f1", "登录页", [], {})
    md = render_sparse_matrix(_Sitemap({"f1": fp}), session=_S())
    assert "登录面未测" in md


# ── (fp, domain) 任务单元 ──

def test_check_matches_domain():
    from core.worker_agent import check_matches_domain
    assert check_matches_domain("IDOR越权", "authz")
    assert check_matches_domain("SQL注入", "injection")
    assert not check_matches_domain("SQL注入", "upload")
    assert check_matches_domain("SQL注入", "")        # domain 空 = 全匹配
    assert check_matches_domain("SQL注入", "unknown")  # 未知域 = 全匹配（宽松）


def test_domain_to_rules_mapping():
    from core.testflow.local_runner import DOMAIN_TO_RULES
    assert DOMAIN_TO_RULES["upload"] == ["file_upload"]
    assert DOMAIN_TO_RULES["injection"] == ["sql_injection", "command_injection", "xxe", "ssti"]
    assert DOMAIN_TO_RULES["business"] == []  # business 无本地规则 → llm 承接


# ── gates：FIELD_ALIASES 值池归一（G3 联动抽查）──

def test_gate_pair_alias_normalization():
    from core.testflow.gates import gate_pair
    pairs = gate_pair({"data": {"userId": 42}}, ["order_id"])
    assert any(p["normalized"] == "id" and p["source_value"] == 42 for p in pairs)
