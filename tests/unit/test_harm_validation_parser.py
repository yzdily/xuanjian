"""
harm_validation/parser 单元测试 — core.harm_validation.parser

覆盖：
- parse_response：空串 / json 代码块 / 无标记代码块 / think 推理块 / 尾随逗号 /
  未转义引号 / 嵌套数组 / 无效 JSON / 提取审核员总评 / verdict 默认值兜底 / 非法元素过滤
- _fix_unescaped_quotes：正常不变 / 修复内嵌引号 / 保留已转义引号 / 结构符前的引号视为结束
- _try_loads_json：仅接受 list，dict/scalar/非法均返回 None
- _extract_balanced_json_array：字符串内方括号忽略 / 嵌套数组 / 无括号 / 不闭合 / 转义引号
- finalize_harm_result：正常解析合并 / header_only accepted→rejected /
  无实测复现 accepted→borderline / body_confirmed 不降级 / content_match 不降级 /
  tool_trace 关联 / 无法解析返回 error / stats 统计

设计原则：纯函数级测试，零网络、零 LLM；不依赖 pytest-asyncio。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# 确保项目根目录可导入（parser.py 内部 `from .tools import format_tool_request` 需要 package 上下文）
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.harm_validation.parser import (  # noqa: E402
    _extract_balanced_json_array,
    _fix_unescaped_quotes,
    _try_loads_json,
    finalize_harm_result,
    parse_response,
)


# ============================================================
# 1. parse_response
# ============================================================
class TestParseResponse:
    def test_empty_string(self):
        verdicts, summary = parse_response("")
        assert verdicts is None
        assert summary == ""

    def test_none_like_empty(self):
        # 仅空白
        verdicts, summary = parse_response("   \n  ")
        assert verdicts is None

    def test_standard_json_code_block(self):
        raw = '```json\n[{"verdict": "accepted", "vuln_id": "v1"}]\n```'
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert len(verdicts) == 1
        assert verdicts[0]["verdict"] == "accepted"
        assert verdicts[0]["vuln_id"] == "v1"

    def test_no_marker_code_block(self):
        raw = '```\n[{"verdict": "rejected"}]\n```'
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert verdicts[0]["verdict"] == "rejected"

    def test_with_think_block_stripped(self):
        raw = (
            "<think>让我分析一下这些漏洞，第一个是 SQL 注入...</think>\n"
            '```json\n[{"verdict": "accepted"}]\n```'
        )
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert verdicts[0]["verdict"] == "accepted"

    def test_think_block_with_fake_brackets_does_not_interfere(self):
        # think 块内含伪 JSON 数组，应被剥离而不干扰真正解析
        raw = (
            "<think>我考虑过 [1,2,3] 但那不是答案</think>\n"
            '```json\n[{"verdict": "borderline"}]\n```'
        )
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert len(verdicts) == 1
        assert verdicts[0]["verdict"] == "borderline"

    def test_trailing_comma_fixed(self):
        raw = '```json\n[{"verdict": "accepted",},]\n```'
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert verdicts[0]["verdict"] == "accepted"

    def test_unescaped_quotes_fixed(self):
        raw = '[{"verdict": "accepted", "note": "he said "hi""}]'
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert verdicts[0]["note"] == 'he said "hi"'

    def test_nested_array(self):
        raw = '```json\n[{"verdict": "accepted", "tags": ["a", "b", {"k": [1, 2]}]}]\n```'
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert verdicts[0]["tags"][0] == "a"
        assert verdicts[0]["tags"][2]["k"] == [1, 2]

    def test_invalid_json_plain_text(self):
        raw = "这是一段纯文本，没有任何JSON数组结构"
        verdicts, summary = parse_response(raw)
        assert verdicts is None

    def test_invalid_json_with_brackets(self):
        raw = "随机文字 [这不是合法JSON] 随机文字"
        verdicts, summary = parse_response(raw)
        assert verdicts is None

    def test_extract_summary(self):
        raw = (
            '```json\n[{"verdict": "accepted"}]\n```\n'
            "审核员总评：\n这些漏洞均确认可复现，建议优先修复。"
        )
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert "确认可复现" in summary
        assert "建议优先修复" in summary

    def test_extract_summary_english_keyword(self):
        raw = (
            '```json\n[{"verdict": "rejected"}]\n```\n'
            "summary: all rejected due to lack of evidence."
        )
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert "rejected" in summary.lower() or "evidence" in summary.lower()

    def test_verdict_defaults(self):
        raw = '```json\n[{"verdict": "accepted"}]\n```'
        verdicts, _ = parse_response(raw)
        vd = verdicts[0]
        assert vd["vuln_id"] == ""
        assert vd["platform_level"] == "no_value"
        assert vd["harm_story"] == ""
        assert vd["evidence_strength"] == "weak"
        assert vd["broken_promises"] == []
        assert vd["would_be_accepted_by"] == []
        assert vd["reject_reason"] == ""
        assert vd["fix_priority"] == "加固建议"

    def test_filters_non_dict_and_missing_verdict(self):
        raw = '```json\n[{"verdict": "accepted"}, "not_a_dict", {"no_verdict": 1}, 123, null]\n```'
        verdicts, _ = parse_response(raw)
        assert len(verdicts) == 1
        assert verdicts[0]["verdict"] == "accepted"

    def test_summary_strips_markdown_bold(self):
        raw = (
            '```json\n[{"verdict": "accepted"}]\n```\n'
            "总评：**这是加粗的总评**"
        )
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert summary == "这是加粗的总评"

    def test_summary_truncated_to_500(self):
        long_text = "总评：" + ("x" * 800)
        raw = f'```json\n[{{"verdict": "accepted"}}]\n```\n{long_text}'
        verdicts, summary = parse_response(raw)
        assert verdicts is not None
        assert len(summary) <= 500


# ============================================================
# 2. _fix_unescaped_quotes
# ============================================================
class TestFixUnescapedQuotes:
    def test_normal_json_unchanged(self):
        text = '[{"a": "b", "c": "d"}]'
        assert _fix_unescaped_quotes(text) == text

    def test_fixes_unescaped_inner_quote(self):
        text = '[{"note": "say "hi""}]'
        fixed = _fix_unescaped_quotes(text)
        assert json.loads(fixed)[0]["note"] == 'say "hi"'

    def test_preserves_escaped_quotes(self):
        text = r'[{"note": "say \"hi\""}]'
        fixed = _fix_unescaped_quotes(text)
        # 已正确转义，应保持可解析且值不变
        assert json.loads(fixed)[0]["note"] == 'say "hi"'

    def test_quote_before_structural_char_treated_as_end(self):
        text = '[{"a": "b"}, {"c": "d"}]'
        # 引号后跟 , } ] : 视为字符串结束，不应被错误转义
        fixed = _fix_unescaped_quotes(text)
        assert json.loads(fixed) == [{"a": "b"}, {"c": "d"}]

    def test_quote_before_colon_is_end(self):
        # "key":"value" 中 key 后的引号后跟 : → 视为结束
        text = '{"key": "value"}'
        fixed = _fix_unescaped_quotes(text)
        assert json.loads(fixed) == {"key": "value"}

    def test_multiple_unescaped_quotes_in_one_string(self):
        text = '[{"x": "a"b"c"}]'
        fixed = _fix_unescaped_quotes(text)
        assert json.loads(fixed)[0]["x"] == 'a"b"c'

    def test_empty_string_value(self):
        text = '[{"a": ""}]'
        assert _fix_unescaped_quotes(text) == text
        assert json.loads(_fix_unescaped_quotes(text))[0]["a"] == ""


# ============================================================
# 3. _try_loads_json
# ============================================================
class TestTryLoadsJson:
    def test_valid_list(self):
        assert _try_loads_json("[1, 2, 3]") == [1, 2, 3]

    def test_valid_empty_list(self):
        assert _try_loads_json("[]") == []

    def test_dict_returns_none(self):
        assert _try_loads_json('{"a": 1}') is None

    def test_string_returns_none(self):
        assert _try_loads_json('"hello"') is None

    def test_number_returns_none(self):
        assert _try_loads_json("42") is None

    def test_bool_returns_none(self):
        assert _try_loads_json("true") is None

    def test_null_returns_none(self):
        assert _try_loads_json("null") is None

    def test_invalid_json_returns_none(self):
        assert _try_loads_json("not json at all") is None

    def test_empty_string_returns_none(self):
        assert _try_loads_json("") is None

    def test_list_of_objects(self):
        assert _try_loads_json('[{"a":1},{"b":2}]') == [{"a": 1}, {"b": 2}]


# ============================================================
# 4. _extract_balanced_json_array
# ============================================================
class TestExtractBalancedJsonArray:
    def test_brackets_inside_string_ignored(self):
        text = 'prefix [{"a": "b]c"}] suffix'
        result = _extract_balanced_json_array(text)
        assert result is not None
        assert result[0]["a"] == "b]c"

    def test_nested_arrays(self):
        text = "x [[1, 2], [3, 4]] y"
        result = _extract_balanced_json_array(text)
        assert result == [[1, 2], [3, 4]]

    def test_no_bracket_returns_none(self):
        assert _extract_balanced_json_array("no brackets here") is None

    def test_unbalanced_returns_none(self):
        assert _extract_balanced_json_array("[1, 2, 3") is None

    def test_escaped_quote_in_string(self):
        text = r'[{"a": "b\"c]d"}]'
        result = _extract_balanced_json_array(text)
        assert result is not None
        assert result[0]["a"] == 'b"c]d'

    def test_first_array_extracted_when_multiple(self):
        text = "[1, 2] and [3, 4]"
        result = _extract_balanced_json_array(text)
        assert result == [1, 2]

    def test_empty_array(self):
        text = "[]"
        result = _extract_balanced_json_array(text)
        assert result == []

    def test_brace_inside_string_ignored(self):
        # 字符串内的 } 不影响数组深度
        text = '[{"a": "}"}]'
        result = _extract_balanced_json_array(text)
        assert result is not None
        assert result[0]["a"] == "}"


# ============================================================
# 5. finalize_harm_result
# ============================================================
class TestFinalizeHarmResult:
    def test_normal_parse_and_merge(self):
        raw = '```json\n[{"vuln_id": "v1", "verdict": "accepted"}]\n```'
        vulns = [
            {
                "vuln_id": "v1",
                "url": "http://x/api",
                "vuln_type": "SQL注入",
                "evidence_quality": "body_confirmed",  # 强证据，避免 accepted 被降级
            }
        ]
        # tool_trace=[] —— 源码直接迭代 tool_trace，不能传 None
        result = finalize_harm_result(raw, vulns, [], 1.5)

        assert result["status"] == "ok"
        assert result["mode"] == "with_tools"
        assert result["elapsed"] == 1.5
        assert result["total_vulns"] == 1
        vd = result["verdicts"][0]
        assert vd["verdict"] == "accepted"  # body_confirmed 未降级
        # _original 合并
        assert vd["_original"]["url"] == "http://x/api"
        assert vd["_original"]["vuln_type"] == "SQL注入"
        assert result["stats"]["accepted"] == 1

    def test_header_only_accepted_downgraded_to_rejected(self):
        raw = '```json\n[{"vuln_id": "v1", "verdict": "accepted"}]\n```'
        vulns = [{"vuln_id": "v1", "evidence_quality": "header_only", "url": "http://x/api"}]
        result = finalize_harm_result(raw, vulns, [], 1.0)

        assert result["status"] == "ok"
        vd = result["verdicts"][0]
        assert vd["verdict"] == "rejected"
        assert "header_only" in vd["poc_note"]
        assert vd["reject_reason"] != ""
        assert result["stats"]["rejected"] == 1
        assert result["stats"]["accepted"] == 0

    def test_no_real_poc_accepted_downgraded_to_borderline(self):
        raw = '```json\n[{"vuln_id": "v1", "verdict": "accepted"}]\n```'
        # evidence_quality 为空 → 走 elif 降级为 borderline
        vulns = [{"vuln_id": "v1", "evidence_quality": "", "url": "http://x/api"}]
        result = finalize_harm_result(raw, vulns, [], 1.0)

        vd = result["verdicts"][0]
        assert vd["verdict"] == "borderline"
        assert "未实际调" in vd["poc_note"]
        assert result["stats"]["borderline"] == 1
        # poc_request 应被标记为不可信
        assert "非实测" in vd["poc_request"]

    def test_body_confirmed_not_downgraded(self):
        raw = '```json\n[{"vuln_id": "v1", "verdict": "accepted"}]\n```'
        vulns = [{"vuln_id": "v1", "evidence_quality": "body_confirmed", "url": "http://x/api"}]
        result = finalize_harm_result(raw, vulns, [], 1.0)

        vd = result["verdicts"][0]
        assert vd["verdict"] == "accepted"
        assert result["stats"]["accepted"] == 1

    def test_content_match_not_downgraded(self):
        raw = '```json\n[{"vuln_id": "v1", "verdict": "accepted"}]\n```'
        vulns = [{"vuln_id": "v1", "evidence_quality": "content_match", "url": "http://x/api"}]
        result = finalize_harm_result(raw, vulns, [], 1.0)

        vd = result["verdicts"][0]
        assert vd["verdict"] == "accepted"
        assert result["stats"]["accepted"] == 1

    def test_tool_trace_association(self):
        raw = (
            '```json\n[{"vuln_id": "v1", "verdict": "accepted", '
            '"poc_request": "GET http://x/api"}]\n```'
        )
        vulns = [{"vuln_id": "v1", "url": "http://x/api"}]
        tool_trace = [
            {
                "tool": "proxy_send_request",
                "args": {"url": "http://x/api", "method": "GET"},
                "result_preview": "200 OK leaked data",
            },
        ]
        result = finalize_harm_result(raw, vulns, tool_trace, 2.0)

        vd = result["verdicts"][0]
        # 有匹配 trace → 不降级
        assert vd["verdict"] == "accepted"
        assert vd["_raw_traces"]  # 关联了 trace
        assert "GET http://x/api" in vd["poc_request"]
        assert vd["poc_response"] == "200 OK leaked data"
        assert vd["poc_note"] == "实测复现（工具调用结果自动注入）"
        # tool_trace 原样留作审计
        assert result["tool_trace"] == tool_trace

    def test_tool_trace_association_via_target_url(self):
        # fuzz_exploit 用 target_url 而非 url
        raw = '```json\n[{"vuln_id": "v1", "verdict": "accepted"}]\n```'
        vulns = [{"vuln_id": "v1", "url": "http://x/api/upload"}]
        tool_trace = [
            {
                "tool": "fuzz_exploit",
                "args": {"target_url": "http://x/api/upload", "vuln_type": "SQL注入"},
                "result_preview": "confirmed",
            },
        ]
        result = finalize_harm_result(raw, vulns, tool_trace, 2.0)

        vd = result["verdicts"][0]
        assert vd["_raw_traces"]
        assert vd["verdict"] == "accepted"
        assert "FuzzRouter" in vd["poc_request"]

    def test_unparseable_returns_error(self):
        raw = "这不是JSON，没有数组"
        vulns = [{"vuln_id": "v1"}]
        result = finalize_harm_result(raw, vulns, [], 0.5)

        assert result["status"] == "error"
        assert "无法解析" in result["error"]
        assert result["raw_response"] == raw  # 短文本原样
        assert result["tool_trace"] == []
        assert result["elapsed"] == 0.5

    def test_stats_counting_mixed(self):
        raw = (
            '```json\n['
            '{"vuln_id": "v1", "verdict": "rejected"},'
            '{"vuln_id": "v2", "verdict": "borderline"},'
            '{"vuln_id": "v3", "verdict": "accepted"}'
            ']\n```'
        )
        vulns = [
            {"vuln_id": "v1"},
            {"vuln_id": "v2"},
            {"vuln_id": "v3", "evidence_quality": "body_confirmed"},  # 避免 accepted 被降级
        ]
        result = finalize_harm_result(raw, vulns, [], 1.0)

        assert result["stats"]["accepted"] == 1
        assert result["stats"]["borderline"] == 1
        assert result["stats"]["rejected"] == 1
        assert result["total_vulns"] == 3

    def test_summary_passed_through(self):
        raw = (
            '```json\n[{"vuln_id": "v1", "verdict": "accepted"}]\n```\n'
            "审核员总评：\n总体可复现"
        )
        result = finalize_harm_result(
            raw, [{"vuln_id": "v1", "evidence_quality": "body_confirmed"}], [], 0.0
        )
        assert result["status"] == "ok"
        assert "可复现" in result["summary"]

    def test_verdict_without_matching_vuln_has_no_original(self):
        raw = '```json\n[{"vuln_id": "ghost", "verdict": "rejected"}]\n```'
        vulns = [{"vuln_id": "v1", "url": "http://x/api"}]
        result = finalize_harm_result(raw, vulns, [], 0.0)

        vd = result["verdicts"][0]
        assert vd["verdict"] == "rejected"
        assert "_original" not in vd
        assert result["stats"]["rejected"] == 1

    def test_header_only_with_real_poc_not_downgraded(self):
        # header_only 但有实测复现 → 不降级（仅响应头证据且无实测才降级）
        raw = '```json\n[{"vuln_id": "v1", "verdict": "accepted"}]\n```'
        vulns = [{"vuln_id": "v1", "evidence_quality": "header_only", "url": "http://x/api"}]
        tool_trace = [
            {
                "tool": "proxy_send_request",
                "args": {"url": "http://x/api", "method": "GET"},
                "result_preview": "200 OK",
            },
        ]
        result = finalize_harm_result(raw, vulns, tool_trace, 1.0)
        vd = result["verdicts"][0]
        assert vd["verdict"] == "accepted"
