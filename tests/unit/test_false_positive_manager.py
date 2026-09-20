"""
FalsePositiveManager 单元测试

验证点：
- 注入 MemoryRuleStore 后零文件系统副作用
- mark / is_false_positive / delete 全链路
- 正则命中、非正则子串兜底、大小写不敏感
- hit_count 累加与持久化
- 可控时钟（clock 注入）产生的 created_at
- 向后兼容：默认构造仍落到 JsonFileRuleStore
"""

from __future__ import annotations

import pytest

from core.false_positive_manager import (
    FalsePositiveManager,
    FalsePositiveRule,
    JsonFileRuleStore,
    MemoryRuleStore,
)


# ============================================================
# 构造 / 存储后端
# ============================================================
class TestConstruction:
    def test_default_uses_json_store(self):
        mgr = FalsePositiveManager()
        assert isinstance(mgr._store, JsonFileRuleStore)

    def test_injected_memory_store(self, fp_manager):
        assert isinstance(fp_manager._store, MemoryRuleStore)

    def test_memory_store_roundtrip(self, fp_memory_store):
        r = FalsePositiveRule(id="fp-1", vuln_type="XSS", pattern="xss")
        fp_memory_store.save([r])
        loaded = fp_memory_store.load()
        assert len(loaded) == 1
        assert loaded[0].id == "fp-1"


# ============================================================
# 标记 / 命中 / 删除
# ============================================================
class TestMarkAndMatch:
    def test_mark_creates_rule(self, fp_manager):
        rule = fp_manager.mark_as_false_positive("XSS", "/search")
        assert rule.id.startswith("fp-")
        assert rule.vuln_type == "XSS"
        assert rule.pattern == "/search"
        assert len(fp_manager.get_rules()) == 1

    def test_is_false_positive_match(self, fp_manager):
        fp_manager.mark_as_false_positive("XSS", "/search")
        assert fp_manager.is_false_positive({"url": "http://t/a/search?q=1", "type": "XSS"}) is True

    def test_is_false_positive_no_match(self, fp_manager):
        fp_manager.mark_as_false_positive("XSS", "/search")
        assert fp_manager.is_false_positive({"url": "http://t/a/login", "type": "XSS"}) is False

    def test_vuln_type_mismatch_not_matched(self, fp_manager):
        fp_manager.mark_as_false_positive("XSS", "/search")
        # 同 URL 但不同类型 → 不命中（避免跨类型错误抑制）
        assert fp_manager.is_false_positive({"url": "http://t/a/search", "type": "SQL注入"}) is False

    def test_case_insensitive_url(self, fp_manager):
        fp_manager.mark_as_false_positive("XSS", "/Search")
        assert fp_manager.is_false_positive({"url": "http://t/a/SEARCH", "type": "XSS"}) is True

    def test_regex_pattern(self, fp_manager):
        fp_manager.mark_as_false_positive("IDOR越权", r"/user/\d+")
        assert fp_manager.is_false_positive({"url": "http://t/user/42", "type": "IDOR越权"}) is True
        assert fp_manager.is_false_positive({"url": "http://t/user/admin", "type": "IDOR越权"}) is False

    def test_invalid_regex_falls_back_to_substring(self, fp_manager):
        # 形如 "(*" 不是合法正则 → 退化为子串匹配
        fp_manager.mark_as_false_positive("XSS", "(*")
        assert fp_manager.is_false_positive({"url": "http://t/a/(*)", "type": "XSS"}) is True

    def test_delete_rule(self, fp_manager):
        rule = fp_manager.mark_as_false_positive("XSS", "/search")
        assert fp_manager.delete_rule(rule.id) is True
        assert fp_manager.is_false_positive({"url": "http://t/a/search", "type": "XSS"}) is False

    def test_delete_missing_rule(self, fp_manager):
        assert fp_manager.delete_rule("nope") is False

    def test_hit_count_increments_and_persists(self, fp_manager, fp_memory_store):
        from core.false_positive_manager import MemoryRuleStore

        # 用同一个 store 构造，确保命中计数写回存储
        mgr = FalsePositiveManager(store=fp_memory_store)
        mgr.mark_as_false_positive("XSS", "/search")
        assert mgr.is_false_positive({"url": "http://t/a/search", "type": "XSS"}) is True
        assert mgr.is_false_positive({"url": "http://t/a/search", "type": "XSS"}) is True
        # 存储中该规则的 hit_count 应为 2
        saved = fp_memory_store.load()
        assert saved[0].hit_count == 2


# ============================================================
# 可控时钟
# ============================================================
class TestClock:
    def test_created_at_from_injected_clock(self, fake_clock):
        from core.false_positive_manager import MemoryRuleStore

        mgr = FalsePositiveManager(store=MemoryRuleStore(), clock=fake_clock.now)
        rule = mgr.mark_as_false_positive("XSS", "/x")
        assert rule.created_at == "2026-01-01T00:00:00"
        fake_clock.advance(3600)
        rule2 = mgr.mark_as_false_positive("SQL注入", "/y")
        assert rule2.created_at == "2026-01-01T01:00:00"


# ============================================================
# 异常健壮性
# ============================================================
class TestRobustness:
    def test_corrupt_store_load_returns_empty(self):
        class BoomStore(MemoryRuleStore):
            def load(self):
                raise RuntimeError("corrupt")

        mgr = FalsePositiveManager(store=BoomStore())
        assert mgr.get_rules() == []

    def test_save_failure_does_not_raise(self):
        class BoomSave(MemoryRuleStore):
            def save(self, rules):
                raise RuntimeError("disk full")

        mgr = FalsePositiveManager(store=BoomSave())
        # 不应抛出，只记录日志
        rule = mgr.mark_as_false_positive("XSS", "/x")
        assert rule.id.startswith("fp-")
