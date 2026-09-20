"""§1.3 补测：LLM 状态机滥用识别（core/loops/llm_state_machine_probe.py）。

防漏报护城河的业务逻辑闸：传统规则无法检测"状态跳转滥用"。
覆盖 detect_state_skip / compare_state_responses / analyze_state_reachability /
evaluate_state_machine_abuse。
"""
from __future__ import annotations

from core.loops.llm_state_machine_probe import (
    CWE_AUTHZ_BYPASS,
    CWE_BUSINESS_LOGIC,
    CWE_IDOR,
    STATE_BACKWARD,
    STATE_REPLAY,
    STATE_SKIP,
    analyze_state_reachability,
    compare_state_responses,
    detect_state_skip,
    evaluate_state_machine_abuse,
)


def test_skip_pay_reach_complete():
    """[create, complete] vs 期望 [create, pay, complete] → 跳过 pay。"""
    r = detect_state_skip(["create", "complete"], ["create", "pay", "complete"])
    assert r["anomaly"] == STATE_SKIP
    assert r["cwe"] == CWE_BUSINESS_LOGIC
    assert "pay" in r["skipped"]


def test_state_replay_detected():
    r = detect_state_skip(["create", "pay", "pay", "complete"], ["create", "pay", "complete"])
    assert r["anomaly"] == STATE_REPLAY


def test_state_backward_detected():
    r = detect_state_skip(["complete", "create"], ["create", "pay", "complete"])
    assert r["anomaly"] == STATE_BACKWARD


def test_normal_sequence_no_anomaly():
    r = detect_state_skip(["create", "pay", "complete"], ["create", "pay", "complete"])
    assert r["anomaly"] is None


def test_empty_sequence_no_anomaly():
    r = detect_state_skip([], ["create", "pay", "complete"])
    assert r["anomaly"] is None


def test_compare_state_responses_diverged():
    """不同身份同状态响应内容不同 → 越权 CWE-639。"""
    r = compare_state_responses(
        "order_detail",
        {"body": "order#100 userA"},
        {"body": "order#200 userB"},
    )
    assert r["diverged"] is True
    assert r["cwe"] == CWE_IDOR


def test_compare_state_responses_same():
    r = compare_state_responses("order_detail", {"body": "same"}, {"body": "same"})
    assert r["diverged"] is False


def test_reachability_200_with_data():
    """未授权 200+数据 → 鉴权绕过 CWE-862。"""
    r = analyze_state_reachability("complete", {"http_code": 200, "body": "order paid"}, ["create", "pay", "complete"])
    assert r["reachable"] is True
    assert r["cwe"] == CWE_AUTHZ_BYPASS


def test_reachability_403_blocked():
    r = analyze_state_reachability("complete", {"http_code": 403, "body": ""}, ["create", "pay", "complete"])
    assert r["reachable"] is False
    assert r["cwe"] is None


def test_reachability_200_empty_data():
    """200 但空数据 → 保守不可达（防误报）。"""
    r = analyze_state_reachability("complete", {"http_code": 200, "body": ""}, ["create", "pay", "complete"])
    assert r["reachable"] is False


def test_evaluate_aggregates_findings():
    """全链评估：跳过中间态 + 未授权可达终态 → 2 条发现。"""
    r = evaluate_state_machine_abuse(
        ["create", "complete"],
        ["create", "pay", "complete"],
        state_responses={"complete": {"http_code": 200, "body": "data"}},
    )
    rules = {f["rule"] for f in r["findings"]}
    assert "state_machine_abuse" in rules
    assert "unauthorized_state_reach" in rules
    assert r["anomaly"] == STATE_SKIP


def test_evaluate_no_state_responses():
    """未提供状态响应 → 只产出跳转异常。"""
    r = evaluate_state_machine_abuse(["create", "complete"], ["create", "pay", "complete"])
    assert len(r["findings"]) == 1
    assert r["findings"][0]["rule"] == "state_machine_abuse"
