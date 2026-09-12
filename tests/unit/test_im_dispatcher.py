"""tests/unit/test_im_dispatcher.py — 中期 M3 验收。

按 XUANJIAN_ROADMAP_MID_TERM §4.3 4 断言：
1. 命令解析：/scan url=... mode=...
2. tenant 提取
3. 非指令忽略
4. IMConnector 抽象类不可直接实例化
+ 4 个 connector 都能 send（webhook 未设 → skipped，不抛）
+ dispatcher 关闸（XUANJIAN_IM_DISABLED=1）后忽略
"""
from __future__ import annotations

import pytest

from core.im import (
    DingtalkConnector,
    FeishuConnector,
    IMConnector,
    IMDispatcher,
    SlackConnector,
    WecomConnector,
    _parse_slash_cmd,
)


def test_parse_url_mode():
    cmd = _parse_slash_cmd("/scan url=http://x mode=deep")
    assert cmd == {"cmd": "scan", "args": {"url": "http://x", "mode": "deep"}}


def test_parse_with_tenant():
    cmd = _parse_slash_cmd("/scan url=http://x mode=standard tenant=acme")
    assert cmd["args"]["tenant"] == "acme"


def test_non_command_returns_none():
    assert _parse_slash_cmd("hello world") is None
    assert _parse_slash_cmd("") is None
    assert _parse_slash_cmd(None) is None


def test_im_connector_abstract():
    """IMConnector 抽象类不能直接实例化。"""
    with pytest.raises(TypeError):
        IMConnector()


def test_all_four_connectors_have_methods():
    """4 个 connector 都有 send/receive/parse_command。"""
    for cls in (FeishuConnector, WecomConnector, DingtalkConnector, SlackConnector):
        # 用空 webhook 实例化，避开外部副作用
        c = cls(webhook_url="")
        assert hasattr(c, "send") and callable(c.send)
        assert hasattr(c, "receive") and callable(c.receive)
        assert hasattr(c, "parse_command") and callable(c.parse_command)
        # 且是 IMConnector 子类
        assert isinstance(c, IMConnector)


def test_send_without_webhook_returns_skipped():
    """webhook 未设 → send 返回 skipped，不抛异常。"""
    for cls in (FeishuConnector, WecomConnector, DingtalkConnector, SlackConnector):
        c = cls(webhook_url="")
        r = c.send("chat_id", "test")
        assert r["status"] == "skipped"


def test_dispatcher_ignores_non_command():
    """非 /scan 指令 → ignored。"""
    c = FeishuConnector(webhook_url="")
    d = IMDispatcher([c])
    out = d.handle_message("feishu", {"content": {"text": "hi"}})
    assert "ignored" in out


def test_dispatcher_builds_plan_with_url(monkeypatch):
    """/scan url=... → plan 含 argv/url/mode/tenant。"""
    c = FeishuConnector(webhook_url="")
    d = IMDispatcher([c])
    monkeypatch.setenv("XUANJIAN_TENANT", "acme")
    raw = {"content": {"text": "/scan url=http://x mode=deep tenant=acme"}, "sender": "u1"}
    out = d.handle_message("feishu", raw)
    assert "argv" in out
    assert out["url"] == "http://x"
    assert out["mode"] == "deep"
    assert out["tenant"] == "acme"
    assert out["connector"] == "feishu"


def test_dispatcher_respects_disabled(monkeypatch):
    """XUANJIAN_IM_DISABLED=1 → 整体忽略。"""
    monkeypatch.setenv("XUANJIAN_IM_DISABLED", "1")
    c = FeishuConnector(webhook_url="")
    d = IMDispatcher([c])
    out = d.handle_message("feishu", {"content": {"text": "/scan url=http://x"}, "sender": "u1"})
    assert "ignored" in out


def test_dispatcher_missing_url():
    """/scan 无 url → 报错。"""
    c = FeishuConnector(webhook_url="")
    d = IMDispatcher([c])
    out = d.handle_message("feishu", {"content": {"text": "/scan mode=deep"}, "sender": "u1"})
    assert "error" in out
    assert "url" in out["error"]
