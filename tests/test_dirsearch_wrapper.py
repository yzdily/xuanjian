"""
dirsearch_only_wrapper.py 的回归测试。

覆盖：
1. classify_vuln_type — 路径→中文漏洞类型推导
2. classify_severity — 路径→严重级别推导
3. convert_findings_to_jsonl — Finding dict → normalize_finding 兼容格式
4. dedup_findings — 去重逻辑
5. _make_request_text / _make_response_text — 证据文本构造
6. normalize_finding 兼容性 — 转换后的 findings 能被 types.normalize_finding 正常处理
7. locate_dirsearch_script — 脚本定位（含默认路径）
8. extract_target_from_openapi — target 提取
"""

import json
import sys
from pathlib import Path

import pytest

# 确保能 import external 模块
sys.path.insert(0, str(Path(__file__).parent.parent))

from external.dirsearch_only_wrapper import (
    classify_severity,
    classify_vuln_type,
    convert_findings_to_jsonl,
    dedup_findings,
    extract_target_from_openapi,
    locate_dirsearch_script,
    _make_request_text,
    _make_response_text,
    DEFAULT_SKILLS_DIR,
)
from core.scripted_scan.types import normalize_finding


# ============================================================
# 1. classify_vuln_type
# ============================================================

class TestClassifyVulnType:
    def test_env_file_is_sensitive_leak(self):
        assert classify_vuln_type("/.env") == "敏感信息泄露"
        assert classify_vuln_type("/.env.local") == "敏感信息泄露"
        assert classify_vuln_type("/.env.production") == "敏感信息泄露"

    def test_credentials_is_sensitive_leak(self):
        assert classify_vuln_type("/credentials.json") == "敏感信息泄露"
        assert classify_vuln_type("/secrets.json") == "敏感信息泄露"

    def test_git_is_source_leak(self):
        assert classify_vuln_type("/.git/HEAD") == "源代码泄露"
        assert classify_vuln_type("/.svn/entries") == "源代码泄露"
        assert classify_vuln_type("/.hg/store") == "源代码泄露"

    def test_actuator_env_is_actuator_exposure(self):
        assert classify_vuln_type("/actuator/env") == "Actuator端点暴露"
        assert classify_vuln_type("/actuator/heapdump") == "Actuator端点暴露"

    def test_actuator_generic_is_debug(self):
        assert classify_vuln_type("/actuator") == "调试端点暴露"
        assert classify_vuln_type("/actuator/health") == "调试端点暴露"

    def test_admin_is_admin_panel(self):
        assert classify_vuln_type("/admin") == "管理面板暴露"
        assert classify_vuln_type("/wp-admin/") == "管理面板暴露"

    def test_swagger_is_api_docs(self):
        assert classify_vuln_type("/swagger.json") == "API文档泄露"
        assert classify_vuln_type("/openapi.json") == "API文档泄露"
        assert classify_vuln_type("/api-docs") == "API文档泄露"

    def test_backup_is_backup_leak(self):
        assert classify_vuln_type("/backup.zip") == "备份文件泄露"
        assert classify_vuln_type("/backup.sql") == "备份文件泄露"
        assert classify_vuln_type("/dump.sql") == "备份文件泄露"

    def test_config_is_config_leak(self):
        assert classify_vuln_type("/config.php") == "配置文件泄露"
        assert classify_vuln_type("/wp-config.php") == "配置文件泄露"
        assert classify_vuln_type("/database.yml") == "配置文件泄露"
        assert classify_vuln_type("/nginx.conf") == "配置文件泄露"

    def test_log_is_log_leak(self):
        assert classify_vuln_type("/access.log") == "日志文件泄露"
        assert classify_vuln_type("/error.log") == "日志文件泄露"

    def test_default_is_info_leak(self):
        assert classify_vuln_type("/api/v1/users") == "信息泄露"
        assert classify_vuln_type("/random-path") == "信息泄露"
        assert classify_vuln_type("/robots.txt") == "信息泄露"


# ============================================================
# 2. classify_severity
# ============================================================

class TestClassifySeverity:
    def test_critical_patterns(self):
        assert classify_severity("/.env") == "critical"
        assert classify_severity("/.git/HEAD") == "critical"
        assert classify_severity("/actuator/env") == "critical"
        assert classify_severity("/backup.sql") == "critical"
        assert classify_severity("/id_rsa") == "critical"

    def test_high_patterns(self):
        assert classify_severity("/admin") == "high"
        assert classify_severity("/actuator") == "high"
        assert classify_severity("/phpmyadmin") == "high"
        assert classify_severity("/config.php") == "high"

    def test_medium_default(self):
        assert classify_severity("/api/v1/users") == "medium"
        assert classify_severity("/random") == "medium"
        assert classify_severity("/swagger.json") == "medium"


# ============================================================
# 3. convert_findings_to_jsonl
# ============================================================

class TestConvertFindings:
    def test_basic_conversion(self):
        """单个 Finding dict → normalize_finding 兼容格式。"""
        findings = [{
            "phase": "recon",
            "title": "[200] Discovered: /admin",
            "severity": "high",
            "description": "Discovered path: /admin | HTTP status: 200",
            "endpoint": "https://target.example.com/admin",
            "evidence": {
                "path": "/admin",
                "status": 200,
                "content_type": "text/html",
                "content_length": 1234,
                "body_preview": "<html><title>Admin</title></html>",
            },
            "recommendation": "Restrict admin panel access.",
        }]

        result = convert_findings_to_jsonl(findings, "https://target.example.com")
        assert len(result) == 1
        item = result[0]

        # 核心字段
        assert item["url"] == "https://target.example.com/admin"
        assert item["method"] == "GET"
        assert item["vuln_type"] == "管理面板暴露"
        assert item["severity"] == "high"
        assert item["severity_original"] == "high"
        assert item["source"] == "dirsearch"
        assert item["phase"] == "recon"
        assert item["title"] == "[200] Discovered: /admin"
        assert item["detail"] == "Discovered path: /admin | HTTP status: 200"
        assert item["fix_suggestion"] == "Restrict admin panel access."

        # evidence 字段
        assert "GET /admin HTTP/1.1" in item["evidence_request"]
        assert "Host: target.example.com" in item["evidence_request"]
        assert "HTTP/1.1 200" in item["evidence_response"]
        assert "Content-Type: text/html" in item["evidence_response"]
        assert "Admin" in item["evidence_response"]

    def test_multiple_findings_different_types(self):
        """多个不同类型的路径 → 不同的 vuln_type。"""
        findings = [
            {"endpoint": "https://t.com/.env", "severity": "critical",
             "evidence": {"path": "/.env", "status": 200}},
            {"endpoint": "https://t.com/.git/HEAD", "severity": "critical",
             "evidence": {"path": "/.git/HEAD", "status": 200}},
            {"endpoint": "https://t.com/swagger.json", "severity": "medium",
             "evidence": {"path": "/swagger.json", "status": 200}},
            {"endpoint": "https://t.com/admin", "severity": "high",
             "evidence": {"path": "/admin", "status": 200}},
        ]

        result = convert_findings_to_jsonl(findings, "https://t.com")
        assert len(result) == 4
        vuln_types = [r["vuln_type"] for r in result]
        assert "敏感信息泄露" in vuln_types
        assert "源代码泄露" in vuln_types
        assert "API文档泄露" in vuln_types
        assert "管理面板暴露" in vuln_types

    def test_empty_findings(self):
        """空列表 → 空结果。"""
        assert convert_findings_to_jsonl([], "https://t.com") == []

    def test_non_dict_filtered(self):
        """非 dict 元素被过滤。"""
        findings = ["not a dict", None, 123,
                    {"endpoint": "https://t.com/admin", "evidence": {"path": "/admin"}}]
        result = convert_findings_to_jsonl(findings, "https://t.com")
        assert len(result) == 1

    def test_missing_evidence_uses_endpoint_path(self):
        """evidence 缺失时从 endpoint URL 提取 path。"""
        findings = [{
            "endpoint": "https://t.com/api/v1/users",
            "severity": "medium",
        }]
        result = convert_findings_to_jsonl(findings, "https://t.com")
        assert len(result) == 1
        assert result[0]["vuln_type"] == "信息泄露"

    def test_vuln_id_incremental(self):
        """vuln_id 应递增。"""
        findings = [
            {"endpoint": f"https://t.com/path{i}", "evidence": {"path": f"/path{i}"}}
            for i in range(5)
        ]
        result = convert_findings_to_jsonl(findings, "https://t.com")
        ids = [r["vuln_id"] for r in result]
        assert ids == ["DIRSEARCH-0001", "DIRSEARCH-0002", "DIRSEARCH-0003",
                        "DIRSEARCH-0004", "DIRSEARCH-0005"]


# ============================================================
# 4. dedup_findings
# ============================================================

class TestDedupFindings:
    def test_dedup_same_path(self):
        """相同 method + path + vuln_type → 去重。"""
        findings = [
            {"method": "GET", "url": "https://t.com/admin",
             "vuln_type": "管理面板暴露"},
            {"method": "GET", "url": "https://t.com/admin/",
             "vuln_type": "管理面板暴露"},
            {"method": "GET", "url": "https://t.com/admin",
             "vuln_type": "管理面板暴露"},
        ]
        result = dedup_findings(findings)
        assert len(result) == 1  # /admin 和 /admin/ 去尾斜杠后相同

    def test_dedup_different_vuln_type_kept(self):
        """相同 path 但不同 vuln_type → 保留。"""
        findings = [
            {"method": "GET", "url": "https://t.com/actuator/env",
             "vuln_type": "Actuator端点暴露"},
            {"method": "GET", "url": "https://t.com/actuator/env",
             "vuln_type": "信息泄露"},
        ]
        result = dedup_findings(findings)
        assert len(result) == 2


# ============================================================
# 5. _make_request_text / _make_response_text
# ============================================================

class TestEvidenceText:
    def test_request_text(self):
        text = _make_request_text("https://api.example.com/admin/login")
        assert "GET /admin/login HTTP/1.1" in text
        assert "Host: api.example.com" in text
        assert "User-Agent:" in text

    def test_request_text_with_query(self):
        text = _make_request_text("https://api.example.com/search?q=test&page=1")
        assert "GET /search?q=test&page=1 HTTP/1.1" in text

    def test_request_text_empty_url(self):
        text = _make_request_text("")
        assert "GET / HTTP/1.1" in text

    def test_response_text(self):
        evidence = {
            "status": 200,
            "content_type": "application/json",
            "content_length": 42,
            "body_preview": '{"status":"ok"}',
        }
        text = _make_response_text(evidence)
        assert "HTTP/1.1 200" in text
        assert "Content-Type: application/json" in text
        assert "Content-Length: 42" in text
        assert '{"status":"ok"}' in text

    def test_response_text_empty_evidence(self):
        assert "HTTP/1.1 200" in _make_response_text({})
        assert _make_response_text(None) == ""
        assert _make_response_text("string") == "string"


# ============================================================
# 6. normalize_finding 兼容性
# ============================================================

class TestNormalizeFindingCompat:
    def test_converted_finding_passes_normalize(self):
        """转换后的 finding 能被 normalize_finding 正常处理。"""
        raw_findings = [{
            "phase": "recon",
            "title": "[200] Discovered: /actuator/env",
            "severity": "critical",
            "description": "Discovered path: /actuator/env | HTTP status: 200",
            "endpoint": "https://target.example.com/actuator/env",
            "evidence": {
                "path": "/actuator/env",
                "status": 200,
                "content_type": "application/json",
                "content_length": 500,
                "body_preview": '{"propertySources":[]}',
            },
            "recommendation": "Disable or restrict debug endpoints.",
        }]

        converted = convert_findings_to_jsonl(raw_findings, "https://target.example.com")
        assert len(converted) == 1

        # normalize_finding 应返回非 None
        normalized = normalize_finding(converted[0], index=0)
        assert normalized is not None
        assert normalized["url"] == "https://target.example.com/actuator/env"
        assert normalized["method"] == "GET"
        assert normalized["vuln_type"] == "Actuator端点暴露"
        assert normalized["severity_original"] == "critical"
        assert normalized["source"] == "scripted_scan"  # normalize_finding 固定设置
        assert normalized["candidate_level"] == "suspected"
        assert "HTTP/1.1 200" in normalized["evidence_response"]
        assert "GET /actuator/env HTTP/1.1" in normalized["evidence_request"]

    def test_multiple_converted_findings_all_normalize(self):
        """多个转换后的 findings 都能被 normalize_finding 处理。"""
        raw_findings = [
            {"endpoint": "https://t.com/.env", "severity": "critical",
             "evidence": {"path": "/.env", "status": 200, "body_preview": "DB_PASS=secret"}},
            {"endpoint": "https://t.com/admin", "severity": "high",
             "evidence": {"path": "/admin", "status": 200}},
            {"endpoint": "https://t.com/swagger.json", "severity": "medium",
             "evidence": {"path": "/swagger.json", "status": 200}},
            {"endpoint": "https://t.com/backup.sql", "severity": "critical",
             "evidence": {"path": "/backup.sql", "status": 200}},
        ]

        converted = convert_findings_to_jsonl(raw_findings, "https://t.com")
        for i, item in enumerate(converted):
            normalized = normalize_finding(item, index=i)
            assert normalized is not None
            assert normalized["url"]
            assert normalized["method"] == "GET"
            assert normalized["vuln_type"]


# ============================================================
# 7. locate_dirsearch_script
# ============================================================

class TestLocateScript:
    def test_default_skills_dir_exists(self):
        """用户本地 api-pentest-extension 目录存在。"""
        skills_dir = Path(DEFAULT_SKILLS_DIR)
        assert skills_dir.exists(), f"skills 目录不存在: {skills_dir}"

    def test_locate_dirsearch_in_default_path(self):
        """在默认路径能找到 dirsearch_scanner.py。"""
        skills_dir = Path(DEFAULT_SKILLS_DIR)
        if not skills_dir.exists():
            pytest.skip(f"skills 目录不存在: {skills_dir}")
        script_path = locate_dirsearch_script(skills_dir)
        assert script_path is not None
        assert script_path.exists()
        assert script_path.name == "dirsearch_scanner.py"

    def test_locate_returns_none_for_missing(self):
        """不存在时返回 None。"""
        result = locate_dirsearch_script(Path("/nonexistent/path"))
        assert result is None


# ============================================================
# 8. extract_target_from_openapi
# ============================================================

class TestExtractTarget:
    def test_extract_from_servers(self, tmp_path):
        api_file = tmp_path / "openapi.json"
        api_file.write_text(json.dumps({
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {},
        }), encoding="utf-8")
        target = extract_target_from_openapi(api_file)
        assert target == "https://api.example.com/v1"

    def test_extract_no_servers(self, tmp_path):
        api_file = tmp_path / "openapi.json"
        api_file.write_text(json.dumps({"openapi": "3.0.0", "paths": {}}),
                            encoding="utf-8")
        target = extract_target_from_openapi(api_file)
        assert target == ""

    def test_extract_invalid_json(self, tmp_path):
        api_file = tmp_path / "openapi.json"
        api_file.write_text("not json", encoding="utf-8")
        target = extract_target_from_openapi(api_file)
        assert target == ""
