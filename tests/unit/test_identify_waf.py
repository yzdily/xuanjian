"""§2.7：WAF 厂商签名识别（升级 _detect_waf 布尔）。"""
from __future__ import annotations

from core.loops.identify_waf import WAF_SIGNATURES, identify


def test_cloudflare_by_cf_ray():
    r = identify(200, {"cf-ray": "abc-LHR"}, "")
    assert r["waf"] == "Cloudflare"
    assert r["confidence"] >= 0.9


def test_safedog_by_server_value():
    r = identify(200, {"server": "safedog"}, "")
    assert r["waf"] == "SafeDog"
    assert r["confidence"] == 0.9


def test_yunsuo_by_body():
    r = identify(403, {}, "网站防火墙 yunsuo")
    assert r["waf"] in ("YunSuo", "SafeDog")  # 共享措辞时取分高者
    assert r["confidence"] >= 0.8


def test_no_cross_vendor_false_positive():
    # server=safedog 不应被判成 Cloudflare
    r = identify(200, {"server": "safedog"}, "")
    assert r["waf"] != "Cloudflare"


def test_unknown_block_page_fallback():
    r = identify(403, {}, "request blocked")
    assert r["waf"] == "Unknown WAF (generic block page)"
    assert r["confidence"] == 0.5
    assert r["blocked"] is True


def test_no_match_returns_none():
    r = identify(200, {"server": "nginx"}, "hello")
    assert r["waf"] is None
    assert r["confidence"] == 0.0
    assert r["blocked"] is False


def test_blocked_flag_on_429():
    assert identify(429, {}, "")["blocked"] is True


def test_suggested_tamper_present_for_known_vendor():
    r = identify(200, {"cf-ray": "x"}, "")
    assert r["suggested_tamper"]


def test_signature_library_has_23_vendors():
    assert len(WAF_SIGNATURES) == 23
