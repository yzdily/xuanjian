"""
经验记忆库模块测试

覆盖：memory 的 record、recall、list_all、update、delete、stats、format_for_prompt、
      _vt_match 模糊匹配、_path_match 通配符
"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestMemoryModule:
    """测试 memory 模块的核心功能。"""

    @pytest.fixture(autouse=True)
    def _isolate_memory(self, tmp_path, monkeypatch):
        """每个测试使用独立的临时文件和清空缓存。"""
        import core.memory as mem
        monkeypatch.setattr(mem, "_LESSONS_FILE", tmp_path / "test_lessons.jsonl")
        monkeypatch.setattr(mem, "_CACHE", None)
        yield
        monkeypatch.setattr(mem, "_CACHE", None)

    def test_record_basic(self):
        from core.memory import record, _load
        item = record(
            scope="global",
            scope_value="",
            trigger="sql 注入 bypass",
            lesson="遇到 WAF 拦截时先尝试大小写混合",
        )
        assert item["id"].startswith("lsn_")
        assert item["scope"] == "global"
        assert item["lesson"] == "遇到 WAF 拦截时先尝试大小写混合"
        assert item["enabled"] is True
        # 验证持久化
        items = _load()
        assert len(items) == 1

    def test_record_invalid_scope(self):
        from core.memory import record
        with pytest.raises(ValueError, match="scope"):
            record(scope="invalid", scope_value="", trigger="x", lesson="y")

    def test_record_empty_lesson(self):
        from core.memory import record
        with pytest.raises(ValueError, match="lesson"):
            record(scope="global", scope_value="", trigger="x", lesson="")

    def test_record_dedup_merge(self):
        """相似 lesson 应合并而非新增。"""
        from core.memory import record, _load
        record(scope="host", scope_value="example.com", trigger="idor", lesson="改 ID 参数测越权")
        record(scope="host", scope_value="example.com", trigger="越权 bola", lesson="改 ID 参数测越权")
        items = _load()
        assert len(items) == 1  # 合并了
        # trigger 应合并
        assert "idor" in items[0]["trigger"]
        assert "越权" in items[0]["trigger"]

    def test_recall_global(self):
        from core.memory import record, recall
        record(scope="global", scope_value="", trigger="通用", lesson="全局经验")
        results = recall(target_url="http://any.com/path")
        assert len(results) >= 1
        assert results[0]["lesson"] == "全局经验"

    def test_recall_host_match(self):
        from core.memory import record, recall
        record(scope="host", scope_value="target.com", trigger="target", lesson="针对 target.com 的经验")
        results = recall(target_url="http://target.com/api/user")
        assert any("target.com" in r["lesson"] for r in results)

    def test_recall_host_no_match(self):
        from core.memory import record, recall
        record(scope="host", scope_value="other.com", trigger="other", lesson="其他站点经验")
        results = recall(target_url="http://target.com/api")
        # 不应命中（除非 trigger 匹配）
        host_matches = [r for r in results if r["scope_value"] == "other.com" and r["scope"] == "host"]
        assert len(host_matches) == 0

    def test_recall_vuln_type_match(self):
        from core.memory import record, recall
        record(scope="vuln_type", scope_value="idor", trigger="越权", lesson="IDOR 测试经验")
        results = recall(vuln_type="IDOR越权")
        assert len(results) >= 1

    def test_recall_path_match(self):
        from core.memory import record, recall
        record(scope="path", scope_value="/api/user/*", trigger="user", lesson="用户接口经验")
        results = recall(target_url="http://x.com/api/user/123")
        assert any("用户接口" in r["lesson"] for r in results)

    def test_list_all(self):
        from core.memory import record, list_all
        record(scope="global", scope_value="", trigger="a", lesson="经验A")
        record(scope="host", scope_value="x.com", trigger="b", lesson="经验B")
        all_items = list_all()
        assert len(all_items) == 2

    def test_list_all_filter_scope(self):
        from core.memory import record, list_all
        record(scope="global", scope_value="", trigger="a", lesson="全局")
        record(scope="host", scope_value="x.com", trigger="b", lesson="主机")
        global_only = list_all(scope="global")
        assert len(global_only) == 1
        assert global_only[0]["scope"] == "global"

    def test_update(self):
        from core.memory import record, update, get
        item = record(scope="global", scope_value="", trigger="old", lesson="旧经验")
        success = update(item["id"], lesson="新经验", trigger="new")
        assert success
        updated = get(item["id"])
        assert updated["lesson"] == "新经验"
        assert updated["trigger"] == "new"

    def test_update_invalid_field(self):
        from core.memory import record, update
        item = record(scope="global", scope_value="", trigger="x", lesson="y")
        with pytest.raises(ValueError, match="不允许"):
            update(item["id"], id="hacked")

    def test_toggle(self):
        from core.memory import record, toggle, get
        item = record(scope="global", scope_value="", trigger="x", lesson="y")
        toggle(item["id"], False)
        assert get(item["id"])["enabled"] is False
        toggle(item["id"], True)
        assert get(item["id"])["enabled"] is True

    def test_delete(self):
        from core.memory import record, delete, list_all
        item = record(scope="global", scope_value="", trigger="x", lesson="y")
        assert delete(item["id"])
        assert len(list_all()) == 0

    def test_delete_nonexistent(self):
        from core.memory import delete
        assert not delete("lsn_nonexistent")

    def test_stats(self):
        from core.memory import record, stats
        record(scope="global", scope_value="", trigger="a", lesson="A")
        record(scope="host", scope_value="x.com", trigger="b", lesson="B")
        s = stats()
        assert s["total"] == 2
        assert s["enabled"] == 2
        assert s["by_scope"]["global"] == 1
        assert s["by_scope"]["host"] == 1

    def test_format_for_prompt_empty(self):
        from core.memory import format_for_prompt
        assert format_for_prompt([]) == ""

    def test_format_for_prompt_with_lessons(self):
        from core.memory import format_for_prompt
        lessons = [
            {"scope": "global", "scope_value": "", "lesson": "经验1"},
            {"scope": "host", "scope_value": "x.com", "lesson": "经验2"},
        ]
        result = format_for_prompt(lessons)
        assert "历史经验" in result
        assert "经验1" in result
        assert "经验2" in result
        assert "x.com" in result

    def test_reload(self):
        from core.memory import record, reload
        record(scope="global", scope_value="", trigger="x", lesson="y")
        count = reload()
        assert count == 1


class TestVtMatch:
    """测试 vuln_type 模糊匹配。"""

    def test_exact_match(self):
        from core.memory import _vt_match
        assert _vt_match("idor", "idor")

    def test_chinese_alias(self):
        from core.memory import _vt_match
        assert _vt_match("idor", "IDOR越权")
        assert _vt_match("越权", "IDOR")

    def test_english_alias(self):
        from core.memory import _vt_match
        assert _vt_match("sql_injection", "SQL注入")
        assert _vt_match("sqli", "sql注入")

    def test_no_match(self):
        from core.memory import _vt_match
        assert not _vt_match("xss", "sql注入")
        assert not _vt_match("csrf", "idor")

    def test_empty_strings(self):
        from core.memory import _vt_match
        assert not _vt_match("", "idor")
        assert not _vt_match("idor", "")
        assert not _vt_match("", "")

    def test_substring_fallback(self):
        from core.memory import _vt_match
        assert _vt_match("file_upload", "文件上传绕过")


class TestPathMatch:
    """测试路径通配符匹配。"""

    def test_exact(self):
        from core.memory import _path_match
        assert _path_match("/api/user", "/api/user")

    def test_wildcard(self):
        from core.memory import _path_match
        assert _path_match("/api/user/*", "/api/user/123")
        assert _path_match("/api/*/detail", "/api/order/detail")

    def test_prefix(self):
        from core.memory import _path_match
        assert _path_match("/api/user", "/api/user/profile")

    def test_no_match(self):
        from core.memory import _path_match
        assert not _path_match("/api/admin/*", "/api/user/123")
