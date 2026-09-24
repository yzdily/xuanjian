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

import core.config as _cfg
from core.config_runtime import ScanConfig


@pytest.fixture
def cfg() -> ScanConfig:
    """每个用例拿到**确定基线**的配置（与测试执行顺序无关）。

    ★ 924 修复：``ScanConfig`` 构造时从 ``core.config`` 拷贝三个映射表
    （``VULN_TO_SKILL`` / ``FEATURE_VULN_MAPPING`` / ``VULN_SYNONYMS``），
    而这三张表会被 ``apply_skill_registry()`` **原地替换** —— 只要有任何用例
    先导入了 ``web.server``（例如 ``tests/unit/test_telemetry_whitelist.py``），
    119 个 SKILL 的 frontmatter 就会合并进来，``逻辑漏洞`` 的规范名从
    ``业务逻辑`` 变成 ``业务逻辑漏洞``，本文件的断言随之失败。

    实测：单独跑 → 通过；与 ``test_telemetry_whitelist.py`` 同跑 → 必挂。
    这是**测试隔离**问题，不是产品缺陷（SKILL 合并后的状态才是生产态）。

    这里显式 pin 到 ``.py`` 默认值，用例结束后**恢复现场**，
    避免污染后续用例（它们可能依赖 SKILL 合并后的状态）。
    """
    with _cfg._mapping_lock:
        saved_skill = dict(_cfg.VULN_TO_SKILL)
        saved_mapping = [list(x) if isinstance(x, (list, tuple)) else x
                         for x in _cfg.FEATURE_VULN_MAPPING]
        saved_syn = dict(_cfg.VULN_SYNONYMS)

    _cfg.reset_to_defaults()
    try:
        yield ScanConfig()
    finally:
        with _cfg._mapping_lock:
            _cfg.VULN_TO_SKILL.clear()
            _cfg.VULN_TO_SKILL.update(saved_skill)
            _cfg.FEATURE_VULN_MAPPING[:] = saved_mapping
            _cfg.VULN_SYNONYMS.clear()
            _cfg.VULN_SYNONYMS.update(saved_syn)


def test_cfg_fixture_is_order_independent(cfg):
    """★ 924 回归钉子：基线必须确定，不随"别的测试有没有合并 SKILL"漂移。"""
    assert cfg.dedup_vuln_type("  逻辑漏洞  ") == "业务逻辑"


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
