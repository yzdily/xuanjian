"""§3.6 环境采样 N≥6 + LB 定性：交替即判 LB，不轻易判鉴权漏洞。"""
from __future__ import annotations

import asyncio

from core.loops.env_sampling import SampleResult, is_load_balanced, sample_endpoint


def test_is_load_balanced_alternating():
    """200/302 交替 → 判 LB 不一致（非鉴权漏洞）。"""
    assert is_load_balanced([200, 302, 200, 302]) is True


def test_is_load_balanced_consistent():
    """全 200 一致 → 非 LB。"""
    assert is_load_balanced([200, 200, 200, 200]) is False


def test_is_load_balanced_empty():
    """空序列 → 非 LB。"""
    assert is_load_balanced([]) is False


def test_is_load_balanced_dict_input():
    """dict 响应（取 http_code）交替 → 判 LB。"""
    seq = [{"http_code": 200}, {"http_code": 302}, {"http_code": 200}, {"http_code": 302}]
    assert is_load_balanced(seq) is True


def _fake_http(codes):
    """按调用序返回指定状态码的 async http mock（零网络）。"""
    it = iter(codes)

    async def _http(req):
        try:
            c = next(it)
        except StopIteration:
            c = 200
        return {"http_code": c, "body": "x"}

    return _http


def test_sample_endpoint_detects_lb():
    """同接口 6 次采样 200/302 交替 → SampleResult.is_lb=True。"""
    http = _fake_http([200, 302, 200, 302, 200, 302])
    r = asyncio.run(sample_endpoint(http, {"url": "/api/x"}, n=6))
    assert isinstance(r, SampleResult)
    assert r.is_lb is True
    assert r.authz_consistent is False
    assert len(r.responses) == 6
