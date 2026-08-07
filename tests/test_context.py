"""
上下文管理模块测试

覆盖：ContextManager 的消息管理、压缩触发（轮次 + token 双触发）、
      tool_calls 配对修复、token 估算缓存
"""

import pytest
from unittest.mock import MagicMock

from core.context import ContextManager, COMPRESS_THRESHOLD, CONTEXT_TOKEN_COMPRESS_THRESHOLD
from core.llm import Message


class TestContextManager:
    def _make_ctx(self, compress_mode="default"):
        llm = MagicMock()
        llm.chat = MagicMock(return_value=MagicMock(content="压缩摘要内容"))
        return ContextManager(llm, compress_mode=compress_mode)

    def test_add_system(self):
        ctx = self._make_ctx()
        ctx.add_system("你是渗透测试员")
        assert len(ctx.system_messages) == 1
        assert ctx.system_messages[0].role == "system"

    def test_add_user_and_assistant(self):
        ctx = self._make_ctx()
        ctx.add_user("测试消息")
        ctx.add_assistant(Message(role="assistant", content="回复"))
        assert len(ctx.history) == 2
        assert ctx.history[0].role == "user"
        assert ctx.history[1].role == "assistant"

    def test_add_tool_result(self):
        ctx = self._make_ctx()
        ctx.add_tool_result("call_123", "工具结果")
        assert ctx.history[0].role == "tool"
        assert ctx.history[0].tool_call_id == "call_123"

    def test_turn_count(self):
        ctx = self._make_ctx()
        ctx.add_user("q1")
        ctx.add_assistant(Message(role="assistant", content="a1"))
        ctx.add_user("q2")
        ctx.add_assistant(Message(role="assistant", content="a2"))
        assert ctx.turn_count == 2

    def test_should_compress_false(self):
        ctx = self._make_ctx()
        for i in range(COMPRESS_THRESHOLD - 1):
            ctx.add_user(f"q{i}")
            ctx.add_assistant(Message(role="assistant", content=f"a{i}"))
        assert not ctx.should_compress()

    def test_should_compress_true(self):
        ctx = self._make_ctx()
        for i in range(COMPRESS_THRESHOLD + 1):
            ctx.add_user(f"q{i}")
            ctx.add_assistant(Message(role="assistant", content=f"a{i}"))
        assert ctx.should_compress()

    def test_get_messages_includes_system(self):
        ctx = self._make_ctx()
        ctx.add_system("系统提示")
        ctx.add_user("用户消息")
        msgs = ctx.get_messages()
        assert msgs[0].role == "system"
        assert msgs[0].content == "系统提示"

    def test_ensure_tool_pairing_valid(self):
        """完整配对的 tool_calls 应保留。"""
        history = [
            Message(role="user", content="test"),
            Message(role="assistant", content="", tool_calls=[
                {"id": "call_1", "function": {"name": "test", "arguments": "{}"}}
            ]),
            Message(role="tool", content="result", tool_call_id="call_1"),
        ]
        result = ContextManager._ensure_tool_pairing(history)
        assert len(result) == 3

    def test_ensure_tool_pairing_orphan_tool(self):
        """孤立的 tool 消息应被移除。"""
        history = [
            Message(role="user", content="test"),
            Message(role="tool", content="orphan", tool_call_id="call_999"),
        ]
        result = ContextManager._ensure_tool_pairing(history)
        assert len(result) == 1
        assert result[0].role == "user"

    def test_ensure_tool_pairing_incomplete(self):
        """不完整配对的 assistant+tool 应被移除。"""
        history = [
            Message(role="user", content="test"),
            Message(role="assistant", content="", tool_calls=[
                {"id": "call_1", "function": {"name": "a", "arguments": "{}"}},
                {"id": "call_2", "function": {"name": "b", "arguments": "{}"}},
            ]),
            Message(role="tool", content="result1", tool_call_id="call_1"),
            # call_2 的 tool 结果缺失
            Message(role="user", content="next"),
        ]
        result = ContextManager._ensure_tool_pairing(history)
        # 不完整的 assistant+tool 被跳过，只保留 user 消息
        assert len(result) == 2
        assert all(m.role == "user" for m in result)

    def test_compress_short_history_noop(self):
        """历史太短时不压缩。"""
        ctx = self._make_ctx()
        ctx.add_user("q1")
        ctx.add_assistant(Message(role="assistant", content="a1"))
        result = ctx.compress()
        assert result == ""

    def test_compress_long_history(self):
        """历史足够长时触发压缩。"""
        ctx = self._make_ctx()
        for i in range(15):
            ctx.add_user(f"question {i}")
            ctx.add_assistant(Message(role="assistant", content=f"answer {i}"))
        result = ctx.compress()
        assert result == "压缩摘要内容"
        # 压缩后历史应被截断（keep_count=20，30条消息压缩后保留最近 20 条）
        assert len(ctx.history) <= 20

    def test_compress_mode_browse(self):
        """browse 模式应使用 BROWSE_COMPRESS_PROMPT。"""
        ctx = self._make_ctx(compress_mode="browse")
        for i in range(15):
            ctx.add_user(f"q{i}")
            ctx.add_assistant(Message(role="assistant", content=f"a{i}"))
        ctx.compress()
        # 验证 LLM 被调用
        assert ctx.llm.chat.called

    def test_get_messages_with_summary(self):
        """压缩后 get_messages 应包含摘要。"""
        ctx = self._make_ctx()
        ctx._compressed_summary = "之前的摘要"
        ctx.add_user("新问题")
        msgs = ctx.get_messages()
        # 应有一条包含摘要的 system 消息
        summaries = [m for m in msgs if "摘要" in (m.content or "")]
        assert len(summaries) == 1


class TestTokenEstimation:
    """Token 估算与 token 触发压缩测试。"""

    def _make_ctx(self, compress_mode="default"):
        llm = MagicMock()
        llm.chat = MagicMock(return_value=MagicMock(content="压缩摘要内容"))
        return ContextManager(llm, compress_mode=compress_mode)

    def test_estimate_tokens_basic(self):
        """estimate_tokens 返回正整数。"""
        ctx = self._make_ctx()
        ctx.add_system("系统提示")
        ctx.add_user("用户消息")
        tokens = ctx.estimate_tokens()
        assert tokens > 0

    def test_estimate_tokens_empty(self):
        """空上下文 token 估算为 0。"""
        ctx = self._make_ctx()
        # 无任何消息时，get_messages 返回空列表
        tokens = ctx.estimate_tokens()
        assert tokens == 0

    def test_estimate_tokens_grows_with_content(self):
        """内容增加时 token 估算应增长。"""
        ctx = self._make_ctx()
        ctx.add_user("短消息")
        tokens_small = ctx.estimate_tokens()

        ctx.add_user("A" * 1000)  # 添加长消息
        tokens_large = ctx.estimate_tokens()
        assert tokens_large > tokens_small

    def test_estimate_tokens_cache(self):
        """token 估算有缓存，不变化时返回缓存值。"""
        ctx = self._make_ctx()
        ctx.add_user("测试消息")
        tokens1 = ctx.estimate_tokens()
        # 未添加新消息，应返回缓存值
        tokens2 = ctx.estimate_tokens()
        assert tokens1 == tokens2

    def test_estimate_tokens_cache_invalidation(self):
        """添加新消息后缓存失效，重新估算。"""
        ctx = self._make_ctx()
        ctx.add_user("消息1")
        tokens1 = ctx.estimate_tokens()

        ctx.add_user("消息2" + "A" * 500)
        tokens2 = ctx.estimate_tokens()
        assert tokens2 > tokens1

    def test_should_compress_by_tokens_false(self):
        """token 未超阈值时不触发。"""
        ctx = self._make_ctx()
        ctx.add_user("短消息")
        assert not ctx.should_compress_by_tokens()

    def test_should_compress_by_tokens_true(self):
        """token 超过阈值时触发。"""
        ctx = self._make_ctx()
        # 构造超大上下文：每条消息 1000 字符，添加足够多消息超阈值
        big_content = "A" * 1000  # ~250 tokens per message
        for i in range(CONTEXT_TOKEN_COMPRESS_THRESHOLD // 200 + 10):
            ctx.add_user(big_content)
            ctx.add_assistant(Message(role="assistant", content=big_content))
        assert ctx.should_compress_by_tokens()

    def test_should_compress_token_trigger_low_turns(self):
        """轮次很少但 token 很高时也应触发压缩。"""
        ctx = self._make_ctx()
        # 只加 2 轮（远低于 COMPRESS_THRESHOLD=30），但内容巨大
        huge = "X" * 50000  # ~12500 tokens per message
        ctx.add_user(huge)
        ctx.add_assistant(Message(role="assistant", content=huge))
        ctx.add_user(huge)
        ctx.add_assistant(Message(role="assistant", content=huge))
        # 轮次只有 2，但 token 远超阈值
        assert ctx.turn_count < COMPRESS_THRESHOLD
        assert ctx.should_compress()

    def test_should_compress_round_fallback(self):
        """token 未超阈值但轮次超阈值时也触发（兜底）。"""
        ctx = self._make_ctx()
        # 添加短消息，token 低但轮次超阈值
        for i in range(COMPRESS_THRESHOLD + 1):
            ctx.add_user(f"q{i}")
            ctx.add_assistant(Message(role="assistant", content=f"a{i}"))
        # token 应该不高（每条消息很短）
        assert not ctx.should_compress_by_tokens()
        # 但轮次超阈值
        assert ctx.should_compress()

    def test_compress_invalidates_token_cache(self):
        """压缩后 token 缓存应失效。"""
        ctx = self._make_ctx()
        for i in range(15):
            ctx.add_user(f"question {i} " * 50)
            ctx.add_assistant(Message(role="assistant", content=f"answer {i} " * 50))
        tokens_before = ctx.estimate_tokens()
        ctx.compress()
        # 压缩后缓存应失效
        assert ctx._token_estimate_dirty
        tokens_after = ctx.estimate_tokens()
        # 压缩后 token 应减少
        assert tokens_after < tokens_before

    def test_add_methods_set_dirty_flag(self):
        """所有 add_* 方法应设置 _token_estimate_dirty = True。"""
        ctx = self._make_ctx()
        # 先清除 dirty 标记
        ctx._token_estimate_dirty = False

        ctx.add_system("系统")
        assert ctx._token_estimate_dirty

        ctx._token_estimate_dirty = False
        ctx.add_user("用户")
        assert ctx._token_estimate_dirty

        ctx._token_estimate_dirty = False
        ctx.add_assistant(Message(role="assistant", content="助手"))
        assert ctx._token_estimate_dirty

        ctx._token_estimate_dirty = False
        ctx.add_tool_result("call_1", "结果")
        assert ctx._token_estimate_dirty
