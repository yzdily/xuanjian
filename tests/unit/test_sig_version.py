"""§3.12.1 (7)：sig_version 单元测试。"""
from __future__ import annotations

import pytest

from core.loops.sig_version import (
    CONFIRMED,
    PASSED_WAF,
    WAF_BLOCKED,
    is_bypass_confirmed,
    is_waf_flaky,
    signature_check,
)


@pytest.mark.asyncio
async def test_signature_stable_blocked():
    async def fake_req(payload):
        return {"http_code": 403, "body": "blocked by waf"}
    report = await signature_check(fake_req, "' OR 1=1--", attempts=3)
    assert len(report.attempts) == 3
    assert report.consistency == "stable_blocked"
    assert report.confirmed is False


@pytest.mark.asyncio
async def test_signature_stable_passed():
    async def fake_req(payload):
        return {"http_code": 200, "body": "normal response"}
    report = await signature_check(fake_req, "benign", attempts=3)
    assert report.consistency == "stable_passed"


@pytest.mark.asyncio
async def test_signature_confirmed():
    async def fake_req(payload):
        return {"http_code": 200, "body": "MARKER confirmed"}
    report = await signature_check(fake_req, "payload", attempts=2, confirm="MARKER")
    assert report.confirmed is True
    assert report.consistency == "stable_passed"
    assert is_bypass_confirmed(report) is True


@pytest.mark.asyncio
async def test_signature_flaky():
    state = {"n": 0}
    async def fake_req(payload):
        state["n"] += 1
        if state["n"] % 2 == 0:
            return {"http_code": 403, "body": "blocked"}
        return {"http_code": 200, "body": "passed"}
    report = await signature_check(fake_req, "p", attempts=4)
    assert is_waf_flaky(report) is True


@pytest.mark.asyncio
async def test_signature_body_hash_consistency():
    async def fake_req(payload):
        return {"http_code": 200, "body": "same body"}
    report = await signature_check(fake_req, "p", attempts=3)
    hashes = {a.body_hash for a in report.attempts}
    assert len(hashes) == 1  # 相同 body → 相同 hash
