"""§3.12.1 (6)：chain_search 单元测试。"""
from __future__ import annotations

import pytest

from core.loops.chain_search import (
    CONFIRMED,
    PASSED_WAF,
    WAF_BLOCKED,
    ChainResult,
    StoredXssResult,
    chain_enumerate,
    chain_multi_payload,
    verify_stored_xss,
)


@pytest.mark.asyncio
async def test_chain_enumerate_all_blocked():
    async def fake_req(params):
        return {"http_code": 403, "body": "blocked"}
    results = await chain_enumerate(fake_req, {"a": "1", "b": "2"}, "' OR 1=1--")
    assert len(results) == 2
    assert all(r.status == WAF_BLOCKED for r in results)
    assert {r.param for r in results} == {"a", "b"}


@pytest.mark.asyncio
async def test_chain_enumerate_one_confirmed():
    async def fake_req(params):
        if params.get("a", "").startswith("'"):
            return {"http_code": 200, "body": "result MARKER done"}
        return {"http_code": 403, "body": "blocked"}
    results = await chain_enumerate(fake_req, {"a": "1", "b": "2"},
                                    "' OR 1=1--", confirm="MARKER")
    statuses = {r.param: r.status for r in results}
    assert statuses["a"] == CONFIRMED
    assert statuses["b"] == WAF_BLOCKED


@pytest.mark.asyncio
async def test_chain_multi_payload_cartesian():
    calls = []
    async def fake_req(params):
        calls.append(dict(params))
        return {"http_code": 200, "body": "ok"}
    results = await chain_multi_payload(fake_req, {"a": "1", "b": "2"},
                                        ["p1", "p2"])
    assert len(results) == 4  # 2 params × 2 payloads
    assert len(calls) == 4


@pytest.mark.asyncio
async def test_verify_stored_xss_confirmed():
    submitted = []
    async def submit(payload):
        submitted.append(payload)
        return {"http_code": 200, "body": "ok"}
    async def read():
        return {"http_code": 200, "body": f"<div>{submitted[0]}</div>"}
    result = await verify_stored_xss(submit, read, "<script>alert(1)</script>")
    assert result.confirmed is True
    assert result.submitted_at == "submit"
    assert result.reflected_at == "list"


@pytest.mark.asyncio
async def test_verify_stored_xss_not_reflected():
    async def submit(payload):
        return {"http_code": 200, "body": "ok"}
    async def read():
        return {"http_code": 200, "body": "clean page"}
    result = await verify_stored_xss(submit, read, "<script>x</script>")
    assert result.confirmed is False
