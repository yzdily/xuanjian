"""
意图识别改造后验证脚本

验证改造后（信任 LLM intent_kind，删掉硬编码规则）的行为是否正确。
"""

import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core.intent import (
    _validate_intent_kind, has_http_request_packet, _looks_like_curl,
    parse_http_request_packet, parse_curl_command, _merge_packet_into_intent,
)


# ============================================================
# 测试用例
# ============================================================

TEST_CASES = [
    # (name, user_message, llm_intent_kind, expected_final_kind)
    (
        "1. 纯URL-整站测试",
        "https://example.com 帮我测这个网站，账号 admin/123",
        "site", "site",
    ),
    (
        "2. HTTP包-单接口测试",
        "POST /api/order HTTP/1.1\nHost: x.com\nCookie: sid=abc\n\n{\"id\":1} 这个接口有越权吗？",
        "packet", "packet",
    ),
    (
        "3. cURL-单接口测试",
        "看看这个 cURL 有啥问题：curl -X POST https://x.com/api -d 'a=1'",
        "packet", "packet",
    ),
    (
        "4. 纯HTTP包-无附加文字",
        "POST /api/user HTTP/1.1\nHost: x.com\nAuthorization: Bearer eyJxxx\n\n{}",
        "packet", "packet",
    ),
    (
        "5. 登录态-整站渗透",
        "登录后帮我整站渗透，cookie：sessionid=abc123",
        "site", "site",
    ),
    (
        "6. 包+整站措辞（LLM判site）",
        "POST /api/login HTTP/1.1\nHost: x.com\n\nuser=admin&pwd=123  测整站",
        "site", "site",
    ),
    (
        "7. 包+歧义措辞",
        "POST /api/data HTTP/1.1\nHost: x.com\n\n{} 先看看，再决定要不要全测",
        "ambiguous", "ambiguous",
    ),
    (
        "8. 闲聊-无目标",
        "你好，渗透测试一般怎么收费？",
        "site", "site",
    ),
    (
        "9. URL+凭证-无包",
        "目标 https://app.freshservice.com 账号 admin@xx.com 密码 Test1234",
        "site", "site",
    ),
    (
        "10. 无包+LLM误判packet → 强制site",
        "帮我测 https://example.com 整站，这是登录后的 cookie: sid=abc",
        "packet", "site",  # ★ 没有HTTP包数据，packet不合法→强制site
    ),
    (
        "11. 有包+LLM判site → 信任LLM",
        "POST /api/login HTTP/1.1\nHost: x.com\nCookie: sid=abc\n\n{} 目标 https://x.com 整站渗透",
        "site", "site",  # 有包+LLM判site→信任（凭证导入场景）
    ),
    (
        "12. LLM返回非法值 → 兜底site",
        "随便说点什么",
        "unknown_value", "site",
    ),
]


def _has_packet(msg: str) -> dict | None:
    if has_http_request_packet(msg):
        return parse_http_request_packet(msg)
    elif _looks_like_curl(msg):
        return parse_curl_command(msg)
    return None


@pytest.mark.parametrize(
    "name,user_message,llm_intent_kind,expected_final_kind",
    TEST_CASES,
    ids=[tc[0] for tc in TEST_CASES],
)
def test_intent_validation(name, user_message, llm_intent_kind, expected_final_kind):
    """验证意图识别改造后的行为。"""
    packet = _has_packet(user_message)
    result = {"intent_kind": llm_intent_kind}
    _validate_intent_kind(result, packet)
    actual = result["intent_kind"]
    assert actual == expected_final_kind, f"{name}: expected {expected_final_kind}, got {actual}"


def test_http_packet_parsing():
    """验证 HTTP 包解析正常。"""
    pkt = parse_http_request_packet(
        "POST /api/test HTTP/1.1\nHost: x.com\nCookie: a=1\nAuthorization: Bearer t\n\n{}"
    )
    assert pkt is not None
    assert pkt["method"] == "POST"
    assert pkt["host"] == "x.com"


def test_curl_parsing():
    """验证 cURL 解析正常。"""
    curl_pkt = parse_curl_command(
        "curl -X POST 'https://x.com/api' -H 'Auth: Bearer x' -d 'a=1'"
    )
    assert curl_pkt is not None
    assert curl_pkt["method"] == "POST"


def test_merge_packet_into_intent():
    """验证 _merge_packet_into_intent 正常。"""
    pkt = parse_http_request_packet(
        "POST /api/test HTTP/1.1\nHost: x.com\nCookie: a=1\nAuthorization: Bearer t\n\n{}"
    )
    intent = {
        "target_url": "",
        "has_target": False,
        "session_cookies": "",
        "auth_header": "",
        "extra_headers": {},
        "extra_scope": [],
    }
    _merge_packet_into_intent(intent, pkt)
    assert intent["session_cookies"] == "a=1"
    assert intent["auth_header"] == "Bearer t"
