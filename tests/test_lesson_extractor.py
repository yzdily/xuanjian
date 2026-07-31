"""
经验提取模块测试

覆盖：looks_like_correction、maybe_extract_lesson
"""

import asyncio
import json
import pytest
from unittest.mock import MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.lesson_extractor import looks_like_correction, maybe_extract_lesson


class TestLooksLikeCorrection:
    def test_correction_keywords(self):
        assert looks_like_correction("不对，这个不是 SQL 注入")
        assert looks_like_correction("你错了，应该先测越权")
        assert looks_like_correction("其实这是误报")
        assert looks_like_correction("记住，以后遇到这种情况要先测 IDOR")
        assert looks_like_correction("This is wrong, should be SSRF")

    def test_non_correction(self):
        assert not looks_like_correction("帮我测一下这个网站")
        assert not looks_like_correction("https://example.com")
        assert not looks_like_correction("继续")
        assert not looks_like_correction("")

    def test_empty_and_none(self):
        assert not looks_like_correction("")
        assert not looks_like_correction(None)


class TestMaybeExtractLesson:
    def _make_llm(self, response_content):
        llm = MagicMock()
        llm.chat = MagicMock(return_value=MagicMock(content=response_content))
        return llm

    def test_correction_detected(self):
        llm = self._make_llm(json.dumps({
            "is_correction": True,
            "scope": "vuln_type",
            "scope_value": "idor",
            "lesson": "改 ID 时要同时改 Cookie 中的 user_id",
            "trigger": "idor 越权 cookie",
            "confidence": 0.9,
        }))
        result = asyncio.run(maybe_extract_lesson(
            llm, "不对，你忘了改 Cookie 里的 user_id", "我测试了 IDOR..."
        ))
        assert result is not None
        assert result["is_correction"] is True
        assert result["scope"] == "vuln_type"
        assert "Cookie" in result["lesson"] or "cookie" in result["lesson"]

    def test_not_correction(self):
        llm = self._make_llm('{"is_correction": false}')
        result = asyncio.run(maybe_extract_lesson(
            llm, "不是这样的，我想测另一个接口", ""
        ))
        assert result is None

    def test_short_message_no_hint(self):
        """短消息且不含纠正词应跳过（不调 LLM）。"""
        llm = MagicMock()
        result = asyncio.run(maybe_extract_lesson(llm, "好的", ""))
        assert result is None
        llm.chat.assert_not_called()

    def test_no_correction_hint(self):
        """不含纠正口吻关键词应跳过。"""
        llm = MagicMock()
        result = asyncio.run(maybe_extract_lesson(
            llm, "帮我测一下 https://example.com 这个网站", ""
        ))
        assert result is None
        llm.chat.assert_not_called()

    def test_empty_message(self):
        llm = MagicMock()
        result = asyncio.run(maybe_extract_lesson(llm, "", ""))
        assert result is None

    def test_llm_returns_invalid_json(self):
        llm = self._make_llm("无法解析的文本")
        result = asyncio.run(maybe_extract_lesson(
            llm, "不对，这个判断错了", "之前的输出"
        ))
        assert result is None

    def test_invalid_scope_normalized(self):
        """非法 scope 应被归一化为 global。"""
        llm = self._make_llm(json.dumps({
            "is_correction": True,
            "scope": "invalid_scope",
            "scope_value": "",
            "lesson": "测试经验",
            "trigger": "test",
            "confidence": 0.8,
        }))
        result = asyncio.run(maybe_extract_lesson(
            llm, "不对，应该这样做", ""
        ))
        assert result is not None
        assert result["scope"] == "global"

    def test_empty_lesson_returns_none(self):
        """空 lesson 应返回 None。"""
        llm = self._make_llm(json.dumps({
            "is_correction": True,
            "scope": "global",
            "scope_value": "",
            "lesson": "",
            "trigger": "test",
        }))
        result = asyncio.run(maybe_extract_lesson(
            llm, "错了，应该这样", ""
        ))
        assert result is None
