"""§3.11.3 鉴权配置开关根因探测：配置开关关闭/网关缺失/代码遗漏 三分类。"""
from __future__ import annotations

from core.loops.config_switch_probe import (
    classify_root_cause,
    ROOT_CONFIG_DISABLED,
    ROOT_GATEWAY_MISSING,
    ROOT_CODE_OMISSION,
    ROOT_UNKNOWN,
)


# ---- classify_root_cause ----

def test_config_disabled():
    """未授权端点 200+数据 且 网关已过滤 → 鉴权配置开关关闭（默认）。"""
    http_resp = {"http_code": 200, "body": '{"user":"admin","data":"sensitive"}'}
    gateway_resp = {"gateway_deployed": True, "filtering": True}
    r = classify_root_cause(http_resp, gateway_resp)
    assert r["root_cause"] == ROOT_CONFIG_DISABLED
    assert "配置开关关闭" in r["evidence"]


def test_gateway_missing():
    """网关无过滤/缺失 → 网关未部署。"""
    http_resp = {"http_code": 200, "body": "sensitive_data"}
    gateway_resp = {"gateway_deployed": False}
    r = classify_root_cause(http_resp, gateway_resp)
    assert r["root_cause"] == ROOT_GATEWAY_MISSING
    assert "网关" in r["evidence"]


def test_gateway_missing_when_none():
    """无网关响应（None）→ 视为网关未部署。"""
    http_resp = {"http_code": 200, "body": "sensitive_data"}
    r = classify_root_cause(http_resp, None)
    assert r["root_cause"] == ROOT_GATEWAY_MISSING


def test_code_omission():
    """响应体含 stacktrace → 代码层遗漏（缺 @PreAuthorize）。"""
    http_resp = {
        "http_code": 200,
        "body": '{"error":"NPE","stacktrace":"at com.xxx.Controller.findOne()"}',
    }
    r = classify_root_cause(http_resp, {"gateway_deployed": True, "filtering": True})
    assert r["root_cause"] == ROOT_CODE_OMISSION
    assert "代码层遗漏" in r["evidence"]


def test_unknown():
    """403 响应 → 无法判定根因。"""
    http_resp = {"http_code": 403, "body": "forbidden"}
    r = classify_root_cause(http_resp, {"gateway_deployed": True, "filtering": True})
    assert r["root_cause"] == ROOT_UNKNOWN


def test_unknown_when_no_data():
    """200 但无数据 → 无法判定根因。"""
    http_resp = {"http_code": 200, "body": ""}
    r = classify_root_cause(http_resp, {"gateway_deployed": True, "filtering": True})
    assert r["root_cause"] == ROOT_UNKNOWN
