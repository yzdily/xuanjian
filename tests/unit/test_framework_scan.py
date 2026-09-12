"""F5/F6/F7/F10 框架级扫描单元测试。"""
from __future__ import annotations

import base64

import pytest

from core.framework_scan.framework_scan import FrameworkScanner, FRAMEWORK_ENDPOINTS
from core.framework_scan.shiro_detect import detect_shiro_rememberme, DEFAULT_SHIRO_KEYS
from core.framework_scan.heapdump_analyzer import download_and_analyze_heapdump, _scan_secrets
from core.framework_scan.path_normalization import scan_path_variants, NORMALIZATION_VARIANTS


class TestFrameworkScan:
    """F5: 端点矩阵。"""

    def test_actuator_endpoints_present(self):
        assert "spring_boot_actuator" in FRAMEWORK_ENDPOINTS
        assert "/actuator/env" in FRAMEWORK_ENDPOINTS["spring_boot_actuator"]
        assert "/actuator/heapdump" in FRAMEWORK_ENDPOINTS["spring_boot_actuator"]

    def test_swagger_endpoints_present(self):
        assert "swagger" in FRAMEWORK_ENDPOINTS
        assert "/swagger-ui.html" in FRAMEWORK_ENDPOINTS["swagger"]
        assert "/v3/api-docs" in FRAMEWORK_ENDPOINTS["swagger"]

    def test_common_files_present(self):
        assert "common_files" in FRAMEWORK_ENDPOINTS
        assert "/.env" in FRAMEWORK_ENDPOINTS["common_files"]

    def test_classify_finding_critical(self):
        scanner = FrameworkScanner()
        result = scanner.classify_finding("spring_boot_actuator", "/actuator/env", 200)
        assert result["severity"] == "Critical"
        assert result["vuln_type"] == "FrameworkExposure"

    def test_classify_finding_heapdump(self):
        scanner = FrameworkScanner()
        result = scanner.classify_finding("spring_boot_actuator", "/actuator/heapdump", 200)
        assert result["severity"] == "Critical"

    @pytest.mark.asyncio
    async def test_scan_without_request_fn(self):
        scanner = FrameworkScanner()
        results = await scanner.scan("http://localhost:8080")
        assert len(results) > 0
        # Without request_fn, entries should have status="not_scanned" or "pending_shiro_detect"
        for r in results:
            assert r["status"] in ("not_scanned", "pending_shiro_detect")


class TestShiroDetect:
    """F6: Shiro RememberMe。"""

    def test_inactive_without_request_fn(self):
        result = detect_shiro_rememberme("http://localhost:8080")
        assert result["status"] == "inactive"

    def test_default_keys_present(self):
        assert "kPH+bIxk5D2deZiIxcaaaA==" in DEFAULT_SHIRO_KEYS
        assert len(DEFAULT_SHIRO_KEYS) >= 5


class TestHeapdumpAnalyzer:
    """F7: heapdump 分析。"""

    def test_scan_secrets_finds_password(self):
        content = b'password="admin123456"\njdbc:mysql://10.0.0.1:3306/db'
        secrets = _scan_secrets(content)
        types = [s["type"] for s in secrets]
        assert "password" in types
        assert "jdbc" in types

    def test_scan_secrets_finds_aws_key(self):
        content = b"aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        secrets = _scan_secrets(content)
        aws = [s for s in secrets if s["type"] == "aws_key"]
        assert len(aws) >= 1

    def test_scan_secrets_finds_private_key(self):
        content = b"-----BEGIN RSA PRIVATE KEY-----\nMII..."
        secrets = _scan_secrets(content)
        pk = [s for s in secrets if s["type"] == "private_key"]
        assert len(pk) >= 1

    def test_download_empty_without_fn(self):
        result = download_and_analyze_heapdump("http://localhost:8080/actuator")
        assert result["status"] == "empty"
        assert result["secrets"] == []

    def test_download_with_content(self):
        def mock_download(url):
            return b'password="secret123"\ncipherKey="kPH+bIxk5D2deZiIxcaaaA=="'
        result = download_and_analyze_heapdump(
            "http://localhost:8080/actuator",
            download_fn=mock_download,
        )
        assert result["status"] == "ok"
        assert len(result["secrets"]) >= 1


class TestPathNormalization:
    """F10: 路径规范化绕过。"""

    def test_variants_count(self):
        assert len(NORMALIZATION_VARIANTS) >= 8

    def test_dot_dot_variant_present(self):
        assert any("../" in v for v in NORMALIZATION_VARIANTS)

    def test_url_encoded_variant_present(self):
        assert any("%2e%2e" in v for v in NORMALIZATION_VARIANTS)

    def test_test_variants_without_request_fn(self):
        bypasses = scan_path_variants(
            "http://localhost:8080", "admin", 403,
        )
        assert len(bypasses) == 0  # Without request_fn, no bypasses detected
