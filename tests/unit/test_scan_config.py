"""
ScanConfig 单元测试

验证点：
- dedup_vuln_type：精确 / 大小写空格归一 / 英文混排 同义词归一
- priority：已知类型取映射值，未知取默认值
- derive_path_vulns：路径正则特征推导（去重）
- build_feature_checklist：功能点 + 方法 + 路径 合并，按优先级排序并裁剪到上限
"""

from __future__ import annotations

import pytest

from core.config_runtime import ScanConfig


@pytest.fixture
def cfg() -> ScanConfig:
    return ScanConfig()


# ============================================================
# 同义词归一
# ============================================================
class TestDedup:
    def test_exact_synonym(self, cfg):
        assert cfg.dedup_vuln_type("SQLi") == "SQL注入"
        assert cfg.dedup_vuln_type("反射型XSS") == "XSS"
        assert cfg.dedup_vuln_type("IDOR") == "IDOR越权"

    def test_chinese_with_space(self, cfg):
        assert cfg.dedup_vuln_type("越权漏洞") == "IDOR越权"
        assert cfg.dedup_vuln_type("IDOR 越权") == "IDOR越权"

    def test_english_mixed_case_and_underscore(self, cfg):
        assert cfg.dedup_vuln_type("Horizontal Privilege Escalation") == "IDOR越权"
        assert cfg.dedup_vuln_type("open-redirect") == "开放重定向"

    def test_strip_whitespace(self, cfg):
        assert cfg.dedup_vuln_type("  逻辑漏洞  ") == "业务逻辑"

    def test_unknown_passthrough(self, cfg):
        assert cfg.dedup_vuln_type("某种未知漏洞") == "某种未知漏洞"
        assert cfg.dedup_vuln_type("") == ""


# ============================================================
# 优先级
# ============================================================
class TestPriority:
    def test_known_priority(self, cfg):
        assert cfg.priority("SQL注入") == 1
        assert cfg.priority("IDOR越权") == 2
        assert cfg.priority("XSS") == 3

    def test_unknown_priority_default(self, cfg):
        assert cfg.priority("某种未知漏洞") == cfg.vuln_priority_default


# ============================================================
# 路径特征推导
# ============================================================
class TestPathVulns:
    def test_id_path_derives_idor(self, cfg):
        result = cfg.derive_path_vulns("/api/users/123")
        assert "IDOR越权" in result
        assert "信息泄露" in result

    def test_search_path_derives_sqli_xss(self, cfg):
        result = cfg.derive_path_vulns("/search?q=1")
        assert "SQL注入" in result
        assert "XSS" in result

    def test_download_path_derives_export_leak(self, cfg):
        result = cfg.derive_path_vulns("/export/report.xlsx")
        assert "越权导出" in result
        assert "信息泄露" in result

    def test_no_path_returns_empty(self, cfg):
        assert cfg.derive_path_vulns("") == []


# ============================================================
# Checklist 推导（合并 + 排序 + 裁剪）
# ============================================================
class TestChecklist:
    def test_login_feature_ordered_by_priority(self, cfg):
        result = cfg.build_feature_checklist(["登录", "login"])
        assert "SQL注入" in result
        # 第一个应是优先级最高的 SQL注入（priority=1）
        assert result[0] == "SQL注入"
        # 不超过保险丝上限
        assert len(result) <= cfg.max_checklist_per_fp

    def test_method_post_derives_base_types(self, cfg):
        result = cfg.build_feature_checklist([], method="POST")
        assert "SQL注入" in result
        assert "XSS" in result
        assert "CSRF" in result

    def test_dedup_across_sources(self, cfg):
        # 登录功能不含 XSS，但 POST 方法含 XSS；合并后 XSS 只出现一次
        result = cfg.build_feature_checklist(["登录"], method="POST")
        assert result.count("XSS") == 1

    def test_path_merged_into_checklist(self, cfg):
        result = cfg.build_feature_checklist([], method="GET", path="/search?q=1")
        assert "SQL注入" in result
        assert "XSS" in result

    def test_pruning_respects_limit(self, cfg):
        limited = ScanConfig()
        limited.max_checklist_per_fp = 3
        result = limited.build_feature_checklist(["登录"])
        assert len(result) == 3

    def test_injected_config_is_isolated(self, cfg):
        # 修改实例配置不应影响其它实例（验证非全局可变状态）
        cfg2 = ScanConfig()
        cfg.max_checklist_per_fp = 2
        assert cfg2.max_checklist_per_fp != cfg.max_checklist_per_fp
        assert cfg2.max_checklist_per_fp == ScanConfig().max_checklist_per_fp
