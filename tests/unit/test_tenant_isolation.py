"""§4 Phase 2 item 5：tenant_isolation 单元测试。"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.loops.tenant_isolation import replay_across_tenants


def _make_resp(status, text):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


@pytest.mark.asyncio
async def test_isolation_pass_when_a_rejected():
    """tenant-A 被 403 拒绝 → 隔离正常。"""
    async def req(method, url, headers, body):
        if "tenant-b" in str(headers):
            return _make_resp(200, '{"code":0,"data":{"id":1}}')
        return _make_resp(403, '{"code":403,"msg":"forbidden"}')

    result = await replay_across_tenants(
        "http://x/api/resource/1", "GET",
        tenant_a_headers={"X-Tenant": "tenant-a", "Token": "a-tok"},
        tenant_b_headers={"X-Tenant": "tenant-b", "Token": "b-tok"},
        request_fn=req,
    )
    assert result["isolated"] is True
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_bola_breach_when_a_gets_b_data():
    """tenant-A 拿到 tenant-B 数据 → 越权。"""
    async def req(method, url, headers, body):
        return _make_resp(200, '{"code":0,"data":{"id":1,"secret":"b-data"}}')

    result = await replay_across_tenants(
        "http://x/api/resource/1", "GET",
        tenant_a_headers={"Token": "a-tok"},
        tenant_b_headers={"Token": "b-tok"},
        request_fn=req,
    )
    assert result["isolated"] is False
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "BOLA跨租户越权"
    assert result["severity"] == "high"


@pytest.mark.asyncio
async def test_soft_reject_isolated():
    """tenant-A 200 但 data 为空 → 软拒绝，隔离正常。"""
    async def req(method, url, headers, body):
        if "b-tok" in str(headers):
            return _make_resp(200, '{"code":0,"data":{"id":1}}')
        return _make_resp(200, '{"code":0,"data":null}')

    result = await replay_across_tenants(
        "http://x/api/resource/1", "GET",
        tenant_a_headers={"Token": "a-tok"},
        tenant_b_headers={"Token": "b-tok"},
        request_fn=req,
    )
    assert result["isolated"] is True


@pytest.mark.asyncio
async def test_response_dimensions_recorded():
    async def req(method, url, headers, body):
        return _make_resp(403, '{"code":403,"msg":"forbidden"}')

    result = await replay_across_tenants(
        "http://x/", "GET",
        tenant_a_headers={}, tenant_b_headers={},
        request_fn=req,
    )
    assert "status" in result["tenant_a_response"]
    assert "business_code" in result["tenant_a_response"]
    assert "data_len" in result["tenant_a_response"]
