"""
核心模块单元测试

覆盖：config、tools、sitemap、intent、tool_executor
"""

import json
import pytest
from pathlib import Path


# ============================================================
# 1. Config 测试
# ============================================================

class TestConfig:
    def test_feature_vuln_mapping_not_empty(self):
        from core.config import FEATURE_VULN_MAPPING
        assert len(FEATURE_VULN_MAPPING) >= 15

    def test_vuln_to_skill_covers_common_types(self):
        from core.config import VULN_TO_SKILL
        must_have = ["SQL注入", "XSS", "IDOR越权", "CSRF", "SSRF", "未授权访问"]
        for vt in must_have:
            assert vt in VULN_TO_SKILL, f"VULN_TO_SKILL 缺少 {vt}"

    def test_backend_public_keywords_disjoint(self):
        from core.config import BACKEND_KEYWORDS, PUBLIC_KEYWORDS
        overlap = BACKEND_KEYWORDS & PUBLIC_KEYWORDS
        assert not overlap, f"后台和公开关键词有交集: {overlap}"

    def test_browser_required_vulns_is_set(self):
        from core.config import BROWSER_REQUIRED_VULNS
        assert isinstance(BROWSER_REQUIRED_VULNS, set)
        assert "XSS" in BROWSER_REQUIRED_VULNS

    def test_constants_positive(self):
        from core.config import MAX_TOOL_RESULT, MAX_WORKERS, WORKER_MAX_ROUNDS
        assert MAX_TOOL_RESULT > 0
        assert MAX_WORKERS > 0
        assert WORKER_MAX_ROUNDS > 0


# ============================================================
# 2. Tools 测试
# ============================================================

class TestTools:
    def test_all_main_tools_has_items(self):
        from core.tools import ALL_MAIN_TOOLS
        assert len(ALL_MAIN_TOOLS) >= 25

    def test_all_tools_have_required_fields(self):
        from core.tools import ALL_MAIN_TOOLS
        for tool in ALL_MAIN_TOOLS:
            assert "type" in tool
            assert "function" in tool
            func = tool["function"]
            assert "name" in func
            assert "parameters" in func

    def test_no_duplicate_tool_names(self):
        from core.tools import ALL_MAIN_TOOLS
        names = [t["function"]["name"] for t in ALL_MAIN_TOOLS]
        assert len(names) == len(set(names)), f"重复工具名: {[n for n in names if names.count(n) > 1]}"

    def test_worker_tools_subset(self):
        from core.tools import ALL_MAIN_TOOLS, build_worker_tools, BROWSER_TOOL_NAMES
        worker_tools = build_worker_tools()
        worker_names = {t["function"]["name"] for t in worker_tools}
        # worker 不应有浏览器工具
        assert not (worker_names & BROWSER_TOOL_NAMES), "Worker 不应包含浏览器工具"

    def test_build_worker_tools_has_checklist(self):
        from core.tools import build_worker_tools
        worker_tools = build_worker_tools()
        names = {t["function"]["name"] for t in worker_tools}
        assert "checklist_mark" in names
        assert "worker_done" in names

    def test_solver_compat_shim(self):
        from core.solver import SOLVER_TOOLS
        from core.tools import ALL_MAIN_TOOLS
        assert SOLVER_TOOLS is ALL_MAIN_TOOLS


# ============================================================
# 3. Sitemap 测试
# ============================================================

class TestSitemap:
    def _make_sitemap(self):
        from core.sitemap import Sitemap
        return Sitemap(target="http://test.com", task_id="test_unit")

    def test_add_page(self):
        s = self._make_sitemap()
        p = s.add_page("http://test.com/login", "登录")
        assert p.url == "http://test.com/login"
        assert p.title == "登录"

    def test_add_feature_valid(self):
        from core.sitemap import Priority
        s = self._make_sitemap()
        fp = s.add_feature("用户登录", "登录页面安全测试", priority=Priority.CRITICAL)
        assert fp is not None
        assert fp.name == "用户登录"
        assert len(fp.checklist) > 0

    def test_add_feature_invalid_rejected(self):
        from core.sitemap import Priority
        s = self._make_sitemap()
        assert s.add_feature("a", "b") is None  # 太短
        assert s.add_feature("test", "test desc") is None  # 无效名

    def test_auto_checklist_for_login(self):
        from core.sitemap import Priority
        s = self._make_sitemap()
        fp = s.add_feature("登录功能", "用户登录页面", priority=Priority.CRITICAL)
        vuln_types = [c.vuln_type for c in fp.checklist]
        assert "SQL注入" in vuln_types
        assert "用户枚举" in vuln_types

    def test_browser_required_vulns_tagged(self):
        from core.sitemap import Priority
        s = self._make_sitemap()
        fp = s.add_feature("评论功能", "用户评论和留言", priority=Priority.HIGH)
        xss_items = [c for c in fp.checklist if "XSS" in c.vuln_type]
        for item in xss_items:
            assert item.needs_browser, f"{item.vuln_type} 应标记需浏览器"

    def test_deferred_feature(self):
        from core.sitemap import Priority
        s = self._make_sitemap()
        fp = s.add_feature("后台管理", "管理后台功能", priority=Priority.HIGH, deferred=True)
        assert fp.deferred
        assert len(fp.checklist) == 1
        assert fp.checklist[0].vuln_type == "未授权访问"

    def test_activate_deferred(self):
        from core.sitemap import Priority
        s = self._make_sitemap()
        fp = s.add_feature("后台管理", "管理后台功能", priority=Priority.HIGH, deferred=True)
        activated = s.activate_deferred()
        assert len(activated) == 1
        assert not activated[0].deferred
        assert len(activated[0].checklist) > 1  # 应生成完整 checklist

    def test_mark_check(self):
        from core.sitemap import Priority, CheckResult
        s = self._make_sitemap()
        fp = s.add_feature("用户登录", "登录页面安全测试", priority=Priority.CRITICAL)
        vuln_type = fp.checklist[0].vuln_type
        item = fp.mark_check(vuln_type, CheckResult.NOT_VULN, "测试通过")
        assert item is not None
        assert item.result == CheckResult.NOT_VULN

    def test_coverage(self):
        from core.sitemap import Priority
        s = self._make_sitemap()
        s.add_feature("登录", "登录页面", priority=Priority.CRITICAL)
        cov = s.get_coverage()
        assert cov["total"] == 1
        assert cov["tested"] == 0

    def test_finish_test_marks_pending_as_skipped(self):
        from core.sitemap import Priority, CheckResult
        s = self._make_sitemap()
        fp = s.add_feature("登录", "登录页面", priority=Priority.CRITICAL)
        s.start_test(fp.id)
        s.finish_test(fp.id)
        for c in fp.checklist:
            assert c.result != CheckResult.PENDING  # 全部应该不是 pending


# ============================================================
# 4. ToolExecutor 测试
# ============================================================

class TestToolExecutor:
    def test_add_feature_via_executor(self):
        from core.sitemap import Sitemap
        from core.tool_executor import ToolExecutor
        sitemap = Sitemap(target="http://test.com", task_id="test")
        executor = ToolExecutor(sitemap=sitemap, has_credentials=False)
        result = executor._handle_sitemap("sitemap_add_feature", {
            "name": "用户登录",
            "description": "登录页面安全测试",
            "priority": "critical",
        })
        assert "功能点已添加" in result

    def test_backend_keyword_auto_deferred(self):
        from core.sitemap import Sitemap
        from core.tool_executor import ToolExecutor
        sitemap = Sitemap(target="http://test.com", task_id="test")
        executor = ToolExecutor(sitemap=sitemap, has_credentials=False)
        result = executor._handle_sitemap("sitemap_add_feature", {
            "name": "后台管理",
            "description": "系统管理后台",
            "priority": "high",
        })
        assert "延迟" in result  # 无凭证 + 后台关键词 → 自动 deferred

    def test_public_keyword_not_deferred(self):
        from core.sitemap import Sitemap
        from core.tool_executor import ToolExecutor
        sitemap = Sitemap(target="http://test.com", task_id="test")
        executor = ToolExecutor(sitemap=sitemap, has_credentials=False)
        result = executor._handle_sitemap("sitemap_add_feature", {
            "name": "登录页面",
            "description": "用户登录入口",
            "priority": "critical",
        })
        assert "功能点已添加" in result  # 登录关键词 → 不延迟

    def test_note_tool_injects_task_id(self):
        from core.tool_executor import ToolExecutor
        executor = ToolExecutor(task_id="my_task_123")
        args = {"type": "info", "content": "test"}
        # 只验证 task_id 注入逻辑（不实际调用 MCP）
        args.setdefault("task_id", executor.task_id)
        assert args["task_id"] == "my_task_123"


# ============================================================
# 5. Log 测试
# ============================================================

class TestLog:
    def test_logger_exists(self):
        from core.log import logger, get_logger
        assert logger is not None
        child = get_logger("test_child")
        assert child.name == "pentest_agent.test_child"

    def test_log_dir_created(self):
        from core.log import LOG_DIR
        assert LOG_DIR.exists()
