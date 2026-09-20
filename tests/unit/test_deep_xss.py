"""§2.5 XSS 深挖漏斗 + 量化定级（技术方案 3.10.2）。"""
from __future__ import annotations

from core.xss.deep_xss import (
    XssFunnel,
    XSS_PRIMITIVES,
    PAYLOAD_DEEP,
    build_deep_payloads,
)


# ---- XssFunnel.level() ----

def test_level_not_reflected():
    """payload 未反射 → level=0。"""
    funnel = XssFunnel()
    resp = {"http_code": 200, "body": "<html>no payload here</html>"}
    assert funnel.level('<script>alert(1)</script>', resp) == 0


def test_level_reflected():
    """payload 反射 → level >= 1。"""
    funnel = XssFunnel()
    resp = {"http_code": 200, "body": '<html>here: <script>alert(1)</script></html>'}
    level = funnel.level('<script>alert(1)</script>', resp)
    assert level >= 1


def test_level_reflected_variant_case_insensitive():
    """大小写不敏感反射也命中。"""
    funnel = XssFunnel()
    resp = {"http_code": 200, "body": '<html>here: <SCRIPT>ALERT(1)</SCRIPT></html>'}
    level = funnel.level('<script>alert(1)</script>', resp)
    assert level >= 1


def test_level_in_comment_not_executable():
    """在 HTML 注释中 → level=1（不可执行上下文）。"""
    funnel = XssFunnel()
    resp = {"http_code": 200, "body": "<!-- <script>alert(1)</script> -->"}
    level = funnel.level('<script>alert(1)</script>', resp)
    assert level == 1


# ---- XssFunnel.level_from_browser() ----

def test_level_from_browser_confirmed():
    """浏览器证实执行 → L5。"""
    funnel = XssFunnel()
    assert funnel.level_from_browser(3, True) == 5


def test_level_from_browser_not_confirmed():
    """未证实 → 保持原 level。"""
    funnel = XssFunnel()
    assert funnel.level_from_browser(3, False) == 3


# ---- XssFunnel.grade() ----

def test_grade_critical():
    """读回可执行 + 未鉴权 + 浏览器证实 → Critical。"""
    funnel = XssFunnel()
    assert funnel.grade(exec_confirmed=True, unauthed_readback=True, whitelist_loose=False) == "Critical"


def test_grade_high_not_critical():
    """浏览器证实但需鉴权 → High（非 Critical）。"""
    funnel = XssFunnel()
    assert funnel.grade(exec_confirmed=True, unauthed_readback=False, whitelist_loose=False) == "High"


def test_grade_low_whitelist_loose():
    """白名单过宽 → Low。"""
    funnel = XssFunnel()
    assert funnel.grade(exec_confirmed=False, unauthed_readback=False, whitelist_loose=True) == "Low"


def test_grade_medium_not_confirmed():
    """未证实执行 → Medium。"""
    funnel = XssFunnel()
    assert funnel.grade(exec_confirmed=False, unauthed_readback=False, whitelist_loose=False) == "Medium"


# ---- XSS_PRIMITIVES ----

def test_xss_primitives_has_5_categories():
    """5 原语类别完整。"""
    assert len(XSS_PRIMITIVES) == 5
    for name in ("quote_variant", "tag_mutation", "event_handler", "js_encode", "double_encode"):
        assert name in XSS_PRIMITIVES
        assert len(XSS_PRIMITIVES[name]) >= 3


# ---- PAYLOAD_DEEP ----

def test_deep_payloads_content():
    """深度窃会话 payload 包含 localStorage/fetch。"""
    payloads = build_deep_payloads()
    assert len(payloads) >= 5
    payloads_str = " ".join(payloads)
    assert "localStorage" in payloads_str
    assert "fetch" in payloads_str


def test_payload_deep_constant():
    """PAYLOAD_DEEP 常量与 build_deep_payloads 一致。"""
    assert build_deep_payloads() == list(PAYLOAD_DEEP)
