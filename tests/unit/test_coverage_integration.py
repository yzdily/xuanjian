"""G4/G5/G6/G7/G8 集成层回归测试（锁本轮新 gate）。

不依赖完整扫描会话：用 types.SimpleNamespace 构造最小 session/sitemap/feature。
"""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# 辅助：构造最小对象
# ---------------------------------------------------------------------------
def _chk(vuln_type, result_name, severity="high", detail=""):
    return SimpleNamespace(
        vuln_type=vuln_type, result=SimpleNamespace(name=result_name),
        severity=severity, detail=detail,
    )


def _feature(fid, name, related_apis, checklist):
    return SimpleNamespace(
        id=fid, name=name, related_apis=related_apis, checklist=checklist,
    )


def _sitemap(apis, features):
    return SimpleNamespace(apis=apis, features=features, save=lambda: None)


def _session(task_id, sitemap, target_url="http://example.com/"):
    return SimpleNamespace(task_id=task_id, sitemap=sitemap, target_url=target_url)


# ---------------------------------------------------------------------------
# G4/G5: 漏洞类型归一化 + 路径归一化
# ---------------------------------------------------------------------------
class TestNormalization:
    def test_chinese_to_canonical(self):
        from core.loops.coverage_integration import vuln_type_to_canonical as c
        assert c("SQL注入") == "sqli"
        assert c("IDOR越权") == "idor"
        assert c("未授权访问") == "bola"
        assert c("垂直越权") == "bfla"
        assert c("文件上传绕过") == "file_upload_unrestricted"
        assert c("信息泄露") == "info_disclosure"
        assert c("服务端请求伪造") == "ssrf"

    def test_english_passthrough(self):
        from core.loops.coverage_integration import vuln_type_to_canonical as c
        assert c("sqli") == "sqli"
        assert c("idor") == "idor"

    def test_normalize_path(self):
        from core.loops.coverage_integration import normalize_path as n
        assert n("http://x.com/api/users/123?a=1") == "/api/users/123"
        assert n("HTTPS://X.COM/Admin") == "/admin"


# ---------------------------------------------------------------------------
# G4: 从 features.checklist 推导真实 coverage 行
# ---------------------------------------------------------------------------
class TestDeriveCoverageEntries:
    def test_reported_and_safe(self):
        from core.loops.coverage_integration import derive_coverage_entries
        fp = _feature("f1", "用户详情", ["http://x.com/api/users/123"],
                      [_chk("SQL注入", "VULNERABLE"), _chk("IDOR越权", "SAFE")])
        entries = derive_coverage_entries([fp], surface_methods={"/api/users/123": "GET"})
        by = {(e.surface, e.risk_area): e.outcome for e in entries}
        assert by[("GET /api/users/123", "sqli")] == "reported"
        assert by[("GET /api/users/123", "idor")] == "no_issue_found"

    def test_pending_not_recorded_is_uncovered(self):
        from core.loops.coverage_integration import derive_coverage_entries
        fp = _feature("f1", "用户详情", ["http://x.com/api/users/123"],
                      [_chk("SQL注入", "PENDING")])
        entries = derive_coverage_entries([fp], surface_methods={"/api/users/123": "GET"})
        # PENDING 不记录 → 该 surface 无 coverage 行（负空间）
        assert entries == []


# ---------------------------------------------------------------------------
# G5: 发现的新 API 补打风险域标签
# ---------------------------------------------------------------------------
class TestEnrichApis:
    def test_enrich_tags_discovered_api(self):
        from core.loops.coverage_integration import enrich_sitemap_apis
        apis = {
            "GET http://x.com/api/users/avatar/upload": {
                "method": "GET", "url": "http://x.com/api/users/avatar/upload",
            },
        }
        sm = _sitemap(apis, {})
        n = enrich_sitemap_apis(sm)
        assert n == 1
        tags = apis["GET http://x.com/api/users/avatar/upload"]["_risk_domain"]
        assert "upload" in tags


# ---------------------------------------------------------------------------
# G4/G6/G7/G8: export_scan_artifacts 落盘 + 结构校验
# ---------------------------------------------------------------------------
class TestExportArtifacts:
    def test_exports_all_artifacts(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from core.loops.coverage_integration import export_scan_artifacts

        apis = {
            "GET http://example.com/api/users/123": {
                "method": "GET", "url": "http://example.com/api/users/123",
            },
        }
        fp = _feature("f1", "用户详情", ["http://example.com/api/users/123"],
                      [_chk("SQL注入", "VULNERABLE", severity="high",
                            detail="union select")])
        sm = _sitemap(apis, {"f1": fp})
        sess = _session("taskX", sm)

        summary = export_scan_artifacts(sess)
        assert summary  # 非空摘要

        base = tmp_path / "data" / "scan_artifacts" / "taskX"
        assert (base / "coverage_report.json").exists()
        assert (base / "coverage_report.md").exists()
        assert (base / "report.sarif").exists()
        assert (base / "stride_summary.md").exists()
        assert (base / "ci_gate_result.json").exists()

    def test_sarif_schema(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from core.loops.coverage_integration import export_scan_artifacts
        import core.harm_validation.sarif_builder as sb

        fp = _feature("f1", "登录", ["http://example.com/login"],
                      [_chk("SQL注入", "VULNERABLE", severity="critical")])
        sm = _sitemap({}, {"f1": fp})
        sess = _session("taskS", sm)
        export_scan_artifacts(sess)

        doc = json.loads((tmp_path / "data/scan_artifacts/taskS/report.sarif").read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        assert doc["runs"][0]["tool"]["driver"]["rules"]
        res = doc["runs"][0]["results"][0]
        assert res["ruleId"] == "CWE-89"
        assert res["level"] == "error"

    def test_ci_gate_result_structure(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from core.loops.coverage_integration import export_scan_artifacts
        fp = _feature("f1", "用户详情", ["http://example.com/api/users/123"],
                      [_chk("SQL注入", "VULNERABLE", severity="high")])
        sm = _sitemap({}, {"f1": fp})
        sess = _session("taskC", sm)
        export_scan_artifacts(sess)
        res = json.loads((tmp_path / "data/scan_artifacts/taskC/ci_gate_result.json").read_text(encoding="utf-8"))
        assert "passed" in res and "high_count" in res and "reasons" in res
        assert res["high_count"] == 1  # 命中 High → 阻断


# ---------------------------------------------------------------------------
# G7: STRIDE 映射
# ---------------------------------------------------------------------------
class TestStride:
    def test_legs(self):
        from core.harm_validation.stride import stride_legs_for, aggregate_by_stride
        assert "I" in stride_legs_for("SQL注入")
        assert "E" in stride_legs_for("IDOR越权")
        buckets = aggregate_by_stride([{"vuln_type": "SQL注入", "severity": "high"}])
        assert buckets["I"] and buckets["T"]

    def test_unknown_falls_to_info_disclosure(self):
        from core.harm_validation.stride import stride_legs_for
        assert stride_legs_for("某个未知类型") == ["I"]


# ---------------------------------------------------------------------------
# G8: CI 门禁评估
# ---------------------------------------------------------------------------
class TestCiGate:
    def test_no_scan_record_passes(self):
        from core.ci_gate import evaluate_ci_gate
        code, res = evaluate_ci_gate(task_id="does-not-exist")
        assert code == 0
        assert res["passed"] is True

    def test_reads_artifact(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        art = tmp_path / "data" / "scan_artifacts" / "abc"
        art.mkdir(parents=True)
        (art / "ci_gate_result.json").write_text(
            json.dumps({"passed": False, "high_count": 2,
                        "reasons": ["发现 2 个 High/Critical 漏洞"]}), encoding="utf-8")
        from core.ci_gate import evaluate_ci_gate
        code, res = evaluate_ci_gate(task_id="abc")
        assert code == 1
        assert res["high_count"] == 2
