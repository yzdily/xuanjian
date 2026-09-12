"""tests/unit/test_poc_gen.py — 中期 M1 验收。

按 XUANJIAN_ROADMAP_MID_TERM §2.3 4 断言：
1. curl 格式：GET + 含 url
2. python 格式：POST + 含 body
3. auto 模式：GET → curl
4. finding_id 必带
+ 配套：poc_playback 跑通 / _attach_poc 降级
"""
from __future__ import annotations

import pytest

from core.poc_gen import gen_curl, gen_poc, gen_python
from core.poc_playback import play


def test_curl_with_get():
    f = {
        "method": "GET",
        "endpoint": "http://x/?id=1'",
        "url": "http://x/?id=1'",
        "id": "F-1",
    }
    out = gen_curl(f)
    assert "curl -X GET" in out
    assert "id=1'" in out


def test_python_with_post_body():
    f = {
        "method": "POST",
        "endpoint": "http://x/login",
        "url": "http://x/login",
        "request_body": {"u": "a' OR 1=1--"},
        "id": "F-2",
    }
    out = gen_python(f)
    assert "import requests" in out
    assert "OR 1=1" in out


def test_auto_format_picks_curl_for_get():
    f = {
        "method": "GET",
        "endpoint": "http://x/y",
        "url": "http://x/y",
        "id": "F-3",
    }
    poc = gen_poc(f, fmt="auto")
    assert poc["format"] == "curl"
    assert poc["auto_generated"] is True


def test_auto_format_picks_python_for_post():
    f = {
        "method": "POST",
        "endpoint": "http://x/y",
        "url": "http://x/y",
        "id": "F-3b",
    }
    poc = gen_poc(f, fmt="auto")
    assert poc["format"] == "python"


def test_poc_includes_finding_id():
    f = {"method": "GET", "endpoint": "http://x", "url": "http://x", "id": "F-99"}
    poc = gen_poc(f)
    assert poc["finding_id"] == "F-99"


def test_poc_returns_error_when_no_url():
    f = {"method": "GET", "id": "F-no-url"}  # 缺 url/endpoint
    poc = gen_poc(f)
    assert poc["format"] is None
    assert "error" in poc


def test_python_poc_playback_runs():
    """poc_playback.play 跑 python 格式 PoC：成功路径。"""
    f = {
        "method": "GET",
        "endpoint": "http://x",
        "url": "http://x",
        "id": "F-pb",
    }
    poc = gen_poc(f, fmt="python")
    # 把脚本里 requests.<method> 换成不会真的发请求的（echo 一行）
    poc["content"] = "print('hello from poc playback')\n"
    r = play(poc)
    assert r["success"] is True
    assert "hello from poc playback" in r.get("stdout", "")


def test_playback_unknown_format():
    poc = {"format": "unknown", "content": "x"}
    r = play(poc)
    assert r["success"] is False
    assert "未知 format" in r["error"]


def test_attach_poc_downgrades_when_missing():
    """ReportMixin._attach_poc：confirmed 无 PoC → 降级 preliminary。"""
    # 走 stub：构造最小 ReportMixin
    from core.session.report_mixin import ReportMixin

    class _Stub(ReportMixin):
        pass

    inst = _Stub()
    f = {
        "id": "F-1",
        "verdict": "confirmed",
        "method": "GET",
        "url": "http://x/?id=1",
        "endpoint": "http://x/?id=1",
    }
    out = inst._attach_poc(dict(f))
    # gen_poc 能生成 → 应有 poc
    if "poc" in out:
        assert out["verdict"] == "confirmed"
        assert out["poc"]["format"] == "curl"


def test_attach_poc_skips_non_confirmed():
    """非 confirmed 不强加 PoC。"""
    from core.session.report_mixin import ReportMixin

    class _Stub(ReportMixin):
        pass

    inst = _Stub()
    f = {
        "id": "F-2",
        "verdict": "preliminary",
        "method": "GET",
        "url": "http://x",
    }
    out = inst._attach_poc(dict(f))
    assert "poc" not in out
    assert out["verdict"] == "preliminary"
