"""§3.7 verify_bypass 三态 + 静默剥离检测。"""
from __future__ import annotations

from core.loops.waf_bypass import (
    CONFIRMED,
    PASSED_WAF,
    WAF_BLOCKED,
    detect_silent_strip,
    verify_bypass,
)


# ---- detect_silent_strip ----

def test_detect_silent_strip_detected():
    """基线有响应体、WAF 后响应空 → 静默丢包告警。"""
    baseline = {"http_code": 200, "body": '{"uid":1}'}
    after = {"http_code": 200, "body": ""}
    assert detect_silent_strip(baseline, after) is True


def test_detect_silent_strip_not_detected():
    """两者均有响应体 → 非静默剥离。"""
    baseline = {"http_code": 200, "body": "data"}
    after = {"http_code": 200, "body": "data2"}
    assert detect_silent_strip(baseline, after) is False


def test_detect_silent_strip_baseline_empty():
    """基线本就无内容 → 不告警（无证据）。"""
    baseline = {"http_code": 200, "body": ""}
    after = {"http_code": 200, "body": ""}
    assert detect_silent_strip(baseline, after) is False


# ---- verify_bypass 三态 ----

def test_verify_bypass_waf_blocked():
    """403 拦截 → waf_blocked。"""
    resp = {"http_code": 403, "body": "request blocked"}
    assert verify_bypass(resp, "UNION SELECT") == WAF_BLOCKED


def test_verify_bypass_passed_waf():
    """穿过 WAF（200）但 --confirm 未命中 → passed_waf（不轻易判 confirmed）。"""
    resp = {"http_code": 200, "body": "normal page"}
    assert verify_bypass(resp, "<script>", confirm="alert_marker") == PASSED_WAF


def test_verify_bypass_confirmed():
    """穿过 WAF 且 --confirm 标记出现在响应体 → confirmed。"""
    resp = {"http_code": 200, "body": "output: root:x:0:0:root"}
    assert verify_bypass(resp, ";id", confirm="root:x:0:0") == CONFIRMED
