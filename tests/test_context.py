"""
上下文管理模块测试

覆盖：ContextManager 的消息管理、压缩触发、tool_calls 配对修复
"""

import pytest
from unittest.mock import MagicMock

from core.context import ContextManager, COMPRESS_THRESHOLD
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
        # 压缩后历史应被截断
        assert len(ctx.history) <= 10

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
