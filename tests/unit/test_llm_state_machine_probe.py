"""§2.6.5 LLM 状态机响应差异识别：跳转异常 + 响应差异 + 可达性。"""
from __future__ import annotations

from core.loops.llm_state_machine_probe import (
    detect_state_skip,
    compare_state_responses,
    analyze_state_reachability,
    evaluate_state_machine_abuse,
    CWE_BUSINESS_LOGIC,
    CWE_AUTHZ_BYPASS,
    CWE_IDOR,
    STATE_SKIP,
    STATE_REPLAY,
    STATE_BACKWARD,
)


def _cwes(findings):
    return [f["cwe"] for f in findings]


# ---- detect_state_skip ----

def test_skip_detected():
    """跳过中间态直达终态 → 业务逻辑漏洞。"""
    r = detect_state_skip(
        transition_seq=["create", "complete"],
        expected_seq=["create", "pay", "complete"],
    )
    assert r["anomaly"] == STATE_SKIP
    assert r["cwe"] == CWE_BUSINESS_LOGIC
    assert "pay" in r["skipped"]


def test_no_skip_normal():
    """正常跳转序列 → 无异常。"""
    r = detect_state_skip(
        transition_seq=["create", "pay", "complete"],
        expected_seq=["create", "pay", "complete"],
    )
    assert r["anomaly"] is None
    assert r["cwe"] is None


def test_replay_detected():
    """状态重放（同一状态重复出现）→ 业务逻辑异常。"""
    r = detect_state_skip(
        transition_seq=["create", "pay", "pay"],
        expected_seq=["create", "pay", "complete"],
    )
    assert r["anomaly"] == STATE_REPLAY
    assert r["cwe"] == CWE_BUSINESS_LOGIC


def test_backward_detected():
    """状态回退（终态后回退到中间态）→ 业务逻辑异常。"""
    r = detect_state_skip(
        transition_seq=["create", "complete", "pay"],
        expected_seq=["create", "pay", "complete"],
    )
    assert r["anomaly"] == STATE_BACKWARD
    assert r["cwe"] == CWE_BUSINESS_LOGIC


def test_skip_multiple_states():
    """跳过多个中间态。"""
    r = detect_state_skip(
        transition_seq=["init", "execute"],
        expected_seq=["init", "verify", "auth", "execute"],
    )
    assert r["anomaly"] == STATE_SKIP
    assert "verify" in r["skipped"]
    assert "auth" in r["skipped"]


def test_empty_sequence():
    """空实际序列 → 无异常。"""
    r = detect_state_skip([], ["create", "pay"])
    assert r["anomaly"] is None


# ---- compare_state_responses ----

def test_responses_diverged():
    """不同身份同状态响应内容不同 → 越权。"""
    r = compare_state_responses(
        "order_detail",
        {"http_code": 200, "body": '{"order_id":1,"user":"A"}'},
        {"http_code": 200, "body": '{"order_id":2,"user":"B"}'},
    )
    assert r["diverged"] is True
    assert r["cwe"] == CWE_IDOR


def test_responses_same():
    """不同身份同状态响应一致 → 无越权。"""
    r = compare_state_responses(
        "order_detail",
        {"http_code": 200, "body": '{"order_id":1}'},
        {"http_code": 200, "body": '{"order_id":1}'},
    )
    assert r["diverged"] is False


def test_responses_diverged_data_field():
    """data 字段（非 body）响应不同 → 越权。"""
    r = compare_state_responses(
        "profile",
        {"http_code": 200, "data": {"name": "Alice"}},
        {"http_code": 200, "data": {"name": "Bob"}},
    )
    assert r["diverged"] is True
    assert r["cwe"] == CWE_IDOR


# ---- analyze_state_reachability ----

def test_reachable_unauthorized():
    """未授权 200+数据 → 可达 → 鉴权绕过。"""
    r = analyze_state_reachability(
        "complete",
        {"http_code": 200, "body": '{"status":"completed"}'},
        ["create", "pay", "complete"],
    )
    assert r["reachable"] is True
    assert r["cwe"] == CWE_AUTHZ_BYPASS


def test_reachable_terminal():
    """未授权可达终态 → 鉴权绕过（终态直达）。"""
    r = analyze_state_reachability(
        "complete",
        {"http_code": 200, "body": "done"},
        ["create", "pay", "complete"],
    )
    assert r["reachable"] is True
    assert "终态直达" in r["evidence"]


def test_not_reachable_401():
    """未授权 401 → 不可达（鉴权生效）。"""
    r = analyze_state_reachability(
        "complete",
        {"http_code": 401, "body": "unauthorized"},
        ["create", "pay", "complete"],
    )
    assert r["reachable"] is False


def test_not_reachable_403():
    """未授权 403 → 不可达。"""
    r = analyze_state_reachability(
        "pay",
        {"http_code": 403, "body": "forbidden"},
    )
    assert r["reachable"] is False


def test_not_reachable_no_data():
    """未授权 200 但无数据 → 不可达。"""
    r = analyze_state_reachability(
        "complete",
        {"http_code": 200, "body": ""},
    )
    assert r["reachable"] is False


# ---- evaluate_state_machine_abuse ----

def test_abuse_skip_only():
    """仅跳转异常 → 1 个 finding。"""
    r = evaluate_state_machine_abuse(
        transition_seq=["create", "complete"],
        expected_seq=["create", "pay", "complete"],
    )
    assert len(r["findings"]) == 1
    assert CWE_BUSINESS_LOGIC in _cwes(r["findings"])
    assert r["anomaly"] == STATE_SKIP


def test_abuse_skip_and_reachable():
    """跳转异常 + 未授权可达 → 2 个 finding。"""
    r = evaluate_state_machine_abuse(
        transition_seq=["create", "complete"],
        expected_seq=["create", "pay", "complete"],
        state_responses={
            "complete": {"http_code": 200, "body": '{"done":true}'},
        },
    )
    assert len(r["findings"]) == 2
    cwes = _cwes(r["findings"])
    assert CWE_BUSINESS_LOGIC in cwes
    assert CWE_AUTHZ_BYPASS in cwes


def test_abuse_no_anomaly():
    """无异常 → 无 finding。"""
    r = evaluate_state_machine_abuse(
        transition_seq=["create", "pay", "complete"],
        expected_seq=["create", "pay", "complete"],
        state_responses={
            "complete": {"http_code": 401, "body": "unauthorized"},
        },
    )
    assert r["findings"] == []
    assert r["anomaly"] is None


def test_abuse_reachable_only():
    """无跳转异常但有未授权可达 → 1 个 finding。"""
    r = evaluate_state_machine_abuse(
        transition_seq=["create", "pay", "complete"],
        expected_seq=["create", "pay", "complete"],
        state_responses={
            "pay": {"http_code": 200, "body": '{"paid":true}'},
        },
    )
    assert len(r["findings"]) == 1
    assert CWE_AUTHZ_BYPASS in _cwes(r["findings"])
