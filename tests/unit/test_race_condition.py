"""
RaceConditionFuzzer 单元测试 — 竞态条件验证器。

覆盖：
- 类常量
- _is_success_response 方法
- _has_state_change_hint 方法
- fuzz() 完整流程（基线请求→并发→分析→判定）
- 各种判定分支（confirmed/likely/not_vuln/inconclusive/error）
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.fuzz.base import FuzzTask, FuzzEvidence, FuzzResult
from core.fuzz.concurrent import ConcurrentResult
from core.fuzz.race_condition import RaceConditionFuzzer


# ============================================================
# 辅助函数
# ============================================================

def _make_task(**overrides) -> FuzzTask:
    """构造一个标准竞态测试任务。"""
    defaults = dict(
        vuln_type="竞态条件",
        target_url="http://example.com/api/coupon/claim",
        method="POST",
        headers={"Content-Type": "application/json"},
        body='{"coupon_id": 123}',
        max_requests=30,
        timeout=10.0,
    )
    defaults.update(overrides)
    return FuzzTask(**defaults)


def _make_response(status: int = 200, body: str = "", error: str = "") -> dict:
    return {"status": status, "body": body, "error": error}


def _make_concurrent_result(responses: list[dict], elapsed: float = 0.5) -> ConcurrentResult:
    return ConcurrentResult(
        responses=responses,
        total_requests=len(responses),
        elapsed_seconds=elapsed,
        success_count=sum(1 for r in responses if not r.get("error") and r.get("status", 0) < 400),
        error_count=sum(1 for r in responses if r.get("error")),
    )


# ============================================================
# 测试类
# ============================================================


class TestRaceConditionFuzzerConstants:
    """类常量正确性。"""

    def test_vuln_types(self):
        assert "竞态条件" in RaceConditionFuzzer.VULN_TYPES
        assert "双花" in RaceConditionFuzzer.VULN_TYPES
        assert len(RaceConditionFuzzer.VULN_TYPES) >= 5

    def test_name(self):
        assert RaceConditionFuzzer.NAME == "race_condition"

    def test_priority(self):
        assert RaceConditionFuzzer.PRIORITY == 8

    def test_default_concurrency(self):
        assert RaceConditionFuzzer.DEFAULT_CONCURRENCY == 30


class TestIsSuccessResponse:
    """_is_success_response 方法测试。"""

    @pytest.fixture
    def fuzzer(self):
        return RaceConditionFuzzer()

    def test_200_success(self, fuzzer):
        assert fuzzer._is_success_response(200, '{"ok": true}') is True

    def test_201_success(self, fuzzer):
        assert fuzzer._is_success_response(201, '{"ok": true}') is True

    def test_400_failure(self, fuzzer):
        assert fuzzer._is_success_response(400, '{"error": "bad request"}') is False

    def test_500_failure(self, fuzzer):
        assert fuzzer._is_success_response(500, "Internal Server Error") is False

    def test_302_not_success(self, fuzzer):
        """302 不在 (200, 201) 也不 >= 400 → False。"""
        assert fuzzer._is_success_response(302, "") is False

    def test_200_with_fail_code(self, fuzzer):
        """JSON body 中 code != 0 → 失败。"""
        body = json.dumps({"code": 1001, "message": "已领取"})
        assert fuzzer._is_success_response(200, body) is False

    def test_200_with_status_field_fail(self, fuzzer):
        body = json.dumps({"status": 500, "msg": "error"})
        assert fuzzer._is_success_response(200, body) is False

    def test_200_with_errcode_fail(self, fuzzer):
        body = json.dumps({"errcode": -1, "error": "fail"})
        assert fuzzer._is_success_response(200, body) is False

    def test_200_with_fail_keyword(self, fuzzer):
        """body 中含失败关键词 → 失败。"""
        body = json.dumps({"code": 0, "message": "已领取过"})
        assert fuzzer._is_success_response(200, body) is False

    def test_200_with_already_keyword(self, fuzzer):
        body = json.dumps({"code": 0, "message": "already claimed"})
        assert fuzzer._is_success_response(200, body) is False

    def test_200_with_duplicate_keyword(self, fuzzer):
        body = json.dumps({"code": 0, "message": "duplicate request"})
        assert fuzzer._is_success_response(200, body) is False

    def test_200_with_exceeded_keyword(self, fuzzer):
        body = json.dumps({"code": 0, "message": "limit exceeded"})
        assert fuzzer._is_success_response(200, body) is False

    def test_200_with_insufficient_keyword(self, fuzzer):
        body = json.dumps({"code": 0, "message": "insufficient balance"})
        assert fuzzer._is_success_response(200, body) is False

    def test_200_with_code_zero_success(self, fuzzer):
        body = json.dumps({"code": 0, "message": "success"})
        assert fuzzer._is_success_response(200, body) is True

    def test_200_with_code_200_success(self, fuzzer):
        body = json.dumps({"code": 200, "message": "ok"})
        assert fuzzer._is_success_response(200, body) is True

    def test_200_non_json_body(self, fuzzer):
        """非 JSON body 且 200 → True。"""
        assert fuzzer._is_success_response(200, "OK") is True

    def test_200_empty_body(self, fuzzer):
        assert fuzzer._is_success_response(200, "") is True


class TestHasStateChangeHint:
    """_has_state_change_hint 方法测试。"""

    @pytest.fixture
    def fuzzer(self):
        return RaceConditionFuzzer()

    def test_post_method(self, fuzzer):
        task = _make_task(method="POST")
        assert fuzzer._has_state_change_hint(task, "") is True

    def test_put_method(self, fuzzer):
        task = _make_task(method="PUT")
        assert fuzzer._has_state_change_hint(task, "") is True

    def test_delete_method(self, fuzzer):
        task = _make_task(method="DELETE")
        assert fuzzer._has_state_change_hint(task, "") is True

    def test_patch_method(self, fuzzer):
        task = _make_task(method="PATCH")
        assert fuzzer._has_state_change_hint(task, "") is True

    def test_get_method_no_hint(self, fuzzer):
        """GET 无关键词 → False。"""
        task = _make_task(method="GET", target_url="http://example.com/api/info", body="")
        assert fuzzer._has_state_change_hint(task, "") is False

    def test_url_contains_claim(self, fuzzer):
        task = _make_task(method="GET", target_url="http://example.com/api/claim", body="")
        assert fuzzer._has_state_change_hint(task, "") is True

    def test_url_contains_redeem(self, fuzzer):
        task = _make_task(method="GET", target_url="http://example.com/redeem", body="")
        assert fuzzer._has_state_change_hint(task, "") is True

    def test_body_contains_transfer(self, fuzzer):
        task = _make_task(method="GET", target_url="http://example.com/api", body="transfer=100")
        assert fuzzer._has_state_change_hint(task, "") is True

    def test_hints_contains_consume(self, fuzzer):
        task = _make_task(method="GET", target_url="http://example.com/api", body="", hints=["consume"])
        assert fuzzer._has_state_change_hint(task, "") is True

    def test_chinese_keyword_deduct(self, fuzzer):
        task = _make_task(method="GET", target_url="http://example.com/api", body="扣减积分")
        assert fuzzer._has_state_change_hint(task, "") is True


class TestFuzzBaselineError:
    """基线请求失败时返回 ERROR。"""

    def test_baseline_network_error(self):
        fuzzer = RaceConditionFuzzer()

        async def fake_send(**kwargs):
            return _make_response(error="Connection refused")

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = fake_send
            task = _make_task()
            evidence = asyncio.run(fuzzer.fuzz(task))

        assert evidence.result == FuzzResult.ERROR
        assert "基线请求失败" in evidence.summary

    def test_baseline_dns_error(self):
        fuzzer = RaceConditionFuzzer()

        async def fake_send(**kwargs):
            return _make_response(error="DNS resolution failed")

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = fake_send
            task = _make_task()
            evidence = asyncio.run(fuzzer.fuzz(task))

        assert evidence.result == FuzzResult.ERROR


class TestFuzzConfirmedRaceCondition:
    """并发多个成功 → CONFIRMED。"""

    def test_multiple_success_confirmed(self):
        """3/10 成功 → CONFIRMED。"""
        fuzzer = RaceConditionFuzzer()

        baseline_resp = _make_response(status=200, body='{"code": 0, "message": "success"}')
        concurrent_resps = [
            _make_response(status=200, body='{"code": 0, "message": "success", "id": 1}'),
            _make_response(status=200, body='{"code": 0, "message": "success", "id": 2}'),
            _make_response(status=200, body='{"code": 0, "message": "success", "id": 3}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
        ] * 3  # 12 个响应，9 成功 3 失败

        concurrent_result = _make_concurrent_result(concurrent_resps)

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send, \
             patch("core.fuzz.race_condition.send_repeated", new_callable=AsyncMock) as mock_repeated:
            mock_send.return_value = baseline_resp
            mock_repeated.return_value = concurrent_result

            task = _make_task(method="POST")
            evidence = asyncio.run(fuzzer.fuzz(task))

        assert evidence.result == FuzzResult.CONFIRMED
        assert evidence.confidence == 0.88
        assert "竞态条件确认" in evidence.summary
        assert evidence.poc_curl  # 有 PoC
        assert "成功率" in evidence.impact_scope

    def test_confirmed_has_timeline(self):
        """CONFIRMED 结果包含完整 timeline。"""
        fuzzer = RaceConditionFuzzer()

        baseline_resp = _make_response(status=200, body='{"ok": true}')
        concurrent_resps = [
            _make_response(status=200, body='{"ok": true, "id": 1}'),
            _make_response(status=200, body='{"ok": true, "id": 2}'),
        ] * 5

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send, \
             patch("core.fuzz.race_condition.send_repeated", new_callable=AsyncMock) as mock_repeated:
            mock_send.return_value = baseline_resp
            mock_repeated.return_value = _make_concurrent_result(concurrent_resps)

            task = _make_task(method="POST")
            evidence = asyncio.run(fuzzer.fuzz(task))

        assert len(evidence.timeline) >= 3  # baseline + concurrent_send + analysis
        steps = [t["step"] for t in evidence.timeline]
        assert "baseline" in steps
        assert "concurrent_send" in steps
        assert "analysis" in steps


class TestFuzzLikelyIdempotent:
    """并发多次成功但响应完全相同 → LIKELY（可能幂等）。"""

    def test_idempotent_get_likely(self):
        """GET 请求多次成功但响应相同 → LIKELY。"""
        fuzzer = RaceConditionFuzzer()

        same_body = '{"ok": true, "data": "same"}'
        baseline_resp = _make_response(status=200, body=same_body)
        concurrent_resps = [_make_response(status=200, body=same_body)] * 10

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send, \
             patch("core.fuzz.race_condition.send_repeated", new_callable=AsyncMock) as mock_repeated:
            mock_send.return_value = baseline_resp
            mock_repeated.return_value = _make_concurrent_result(concurrent_resps)

            task = _make_task(method="GET", target_url="http://example.com/api/info", body="")
            evidence = asyncio.run(fuzzer.fuzz(task))

        assert evidence.result == FuzzResult.LIKELY
        assert evidence.confidence == 0.5
        assert "幂等" in evidence.summary


class TestFuzzNotVuln:
    """并发只有 1 次成功 → NOT_VULN。"""

    def test_single_success_not_vuln(self):
        fuzzer = RaceConditionFuzzer()

        baseline_resp = _make_response(status=200, body='{"code": 0, "message": "success"}')
        concurrent_resps = [
            _make_response(status=200, body='{"code": 0, "message": "success"}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
        ] * 4  # 12 个，4 成功 8 失败 → 但 _is_success_response 会过滤 "已领取"

        # 修正：只 1 次成功
        concurrent_resps = [
            _make_response(status=200, body='{"code": 0, "message": "success"}'),  # 1 成功
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),  # 失败
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
            _make_response(status=400, body='{"code": 1001, "message": "已领取"}'),
        ]

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send, \
             patch("core.fuzz.race_condition.send_repeated", new_callable=AsyncMock) as mock_repeated:
            mock_send.return_value = baseline_resp
            mock_repeated.return_value = _make_concurrent_result(concurrent_resps)

            task = _make_task(method="POST")
            evidence = asyncio.run(fuzzer.fuzz(task))

        assert evidence.result == FuzzResult.NOT_VULN
        assert evidence.confidence == 0.8
        assert "并发控制正常" in evidence.summary


class TestFuzzInconclusive:
    """并发 0 次成功 → INCONCLUSIVE。"""

    def test_zero_success_inconclusive(self):
        fuzzer = RaceConditionFuzzer()

        baseline_resp = _make_response(status=200, body='{"code": 0, "message": "success"}')
        # 全部失败
        concurrent_resps = [
            _make_response(status=500, body="Internal Server Error"),
        ] * 10

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send, \
             patch("core.fuzz.race_condition.send_repeated", new_callable=AsyncMock) as mock_repeated:
            mock_send.return_value = baseline_resp
            mock_repeated.return_value = _make_concurrent_result(concurrent_resps)

            task = _make_task(method="POST")
            evidence = asyncio.run(fuzzer.fuzz(task))

        assert evidence.result == FuzzResult.INCONCLUSIVE
        assert evidence.confidence == 0.3
        assert "无法判断" in evidence.summary

    def test_all_errors_inconclusive(self):
        """所有并发请求都 error → INCONCLUSIVE。"""
        fuzzer = RaceConditionFuzzer()

        baseline_resp = _make_response(status=200, body='{"ok": true}')
        concurrent_resps = [
            _make_response(error="timeout"),
        ] * 10

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send, \
             patch("core.fuzz.race_condition.send_repeated", new_callable=AsyncMock) as mock_repeated:
            mock_send.return_value = baseline_resp
            mock_repeated.return_value = _make_concurrent_result(concurrent_resps)

            task = _make_task(method="POST")
            evidence = asyncio.run(fuzzer.fuzz(task))

        assert evidence.result == FuzzResult.INCONCLUSIVE


class TestFuzzConcurrencyLimit:
    """并发数限制测试。"""

    def test_concurrency_capped_by_max_requests(self):
        """DEFAULT_CONCURRENCY > task.max_requests 时取 min。"""
        fuzzer = RaceConditionFuzzer()

        baseline_resp = _make_response(status=200, body='{"ok": true}')
        concurrent_resps = [_make_response(status=200, body='{"ok": true}')] * 5

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send, \
             patch("core.fuzz.race_condition.send_repeated", new_callable=AsyncMock) as mock_repeated:
            mock_send.return_value = baseline_resp
            mock_repeated.return_value = _make_concurrent_result(concurrent_resps)

            task = _make_task(max_requests=5)  # 比 DEFAULT_CONCURRENCY(30) 小
            evidence = asyncio.run(fuzzer.fuzz(task))

        # send_repeated 应以 count=5 调用
        call_args = mock_repeated.call_args
        assert call_args.kwargs.get("count") == 5

    def test_concurrency_uses_default_when_max_large(self):
        """max_requests > DEFAULT_CONCURRENCY 时用 DEFAULT_CONCURRENCY。"""
        fuzzer = RaceConditionFuzzer()

        baseline_resp = _make_response(status=200, body='{"ok": true}')
        concurrent_resps = [_make_response(status=400, body='{"code": 1, "message": "已领取"}')] * 30

        with patch.object(fuzzer, "_send_request", new_callable=AsyncMock) as mock_send, \
             patch("core.fuzz.race_condition.send_repeated", new_callable=AsyncMock) as mock_repeated:
            mock_send.return_value = baseline_resp
            mock_repeated.return_value = _make_concurrent_result(concurrent_resps)

            task = _make_task(max_requests=100)
            evidence = asyncio.run(fuzzer.fuzz(task))

        call_args = mock_repeated.call_args
        assert call_args.kwargs.get("count") == 30  # DEFAULT_CONCURRENCY
