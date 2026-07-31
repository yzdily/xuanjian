"""
Race Condition Verifier — 竞态条件验证器

验证策略：
1. 并发发送 N 个相同请求（利用 concurrent.py 的 barrier 同步）
2. 分析响应：是否出现了"不应该出现的成功"（如重复领取、余额异常）
3. 对比并发前后的状态变化

适用漏洞类型：竞态条件、并发漏洞、重复领取、双花攻击
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from core.fuzz.base import BaseFuzzer, FuzzTask, FuzzEvidence, FuzzResult
from core.fuzz.concurrent import send_repeated, ConcurrentResult
from core.log import get_logger

log = get_logger("fuzz.race_condition")


class RaceConditionFuzzer(BaseFuzzer):
    """竞态条件验证器

    核心逻辑：同时发送 N 个相同请求，检查是否产生了异常状态。
    """

    VULN_TYPES = ["竞态条件", "并发漏洞", "重复领取", "重复使用", "双花"]
    NAME = "race_condition"
    PRIORITY = 8

    # 默认并发数
    DEFAULT_CONCURRENCY = 30

    async def fuzz(self, task: FuzzTask) -> FuzzEvidence:
        t0 = time.time()
        timeline: list[dict[str, Any]] = []
        requests_sent = 0

        # ============================================================
        # Step 1: 单次基线请求（确认接口可用）
        # ============================================================
        baseline = await self._send_request(
            method=task.method, url=task.target_url,
            headers=task.headers, body=task.body, timeout=task.timeout,
        )
        requests_sent += 1

        if baseline["error"]:
            return self._make_error_evidence(f"基线请求失败: {baseline['error']}")

        baseline_status = baseline["status"]
        baseline_body = baseline["body"]
        timeline.append({
            "step": "baseline",
            "status": baseline_status,
            "body_preview": baseline_body[:100],
        })

        # 如果基线就失败了（如已经领取过），记录但继续
        baseline_success = self._is_success_response(baseline_status, baseline_body)

        # ============================================================
        # Step 2: 并发发送 N 个相同请求
        # ============================================================
        concurrency = min(self.DEFAULT_CONCURRENCY, task.max_requests)
        timeline.append({
            "step": "concurrent_send",
            "count": concurrency,
            "action": f"同时发送 {concurrency} 个相同请求",
        })

        concurrent_result = await send_repeated(
            method=task.method,
            url=task.target_url,
            headers=task.headers,
            body=task.body,
            count=concurrency,
            concurrency=concurrency,
            proxy_url=task.proxy_url or self.proxy_url,
            timeout=task.timeout,
        )
        requests_sent += concurrent_result.total_requests

        # ============================================================
        # Step 3: 分析并发结果
        # ============================================================
        success_count = 0
        fail_count = 0
        unique_responses: set[str] = set()
        success_bodies: list[str] = []

        for resp in concurrent_result.responses:
            if resp["error"]:
                continue
            is_success = self._is_success_response(resp["status"], resp["body"])
            if is_success:
                success_count += 1
                success_bodies.append(resp["body"][:200])
            else:
                fail_count += 1
            # 响应指纹（用于判断是否有不同的响应）
            fingerprint = f"{resp['status']}:{len(resp['body'])}"
            unique_responses.add(fingerprint)

        status_dist = concurrent_result.status_distribution()
        timeline.append({
            "step": "analysis",
            "success_count": success_count,
            "fail_count": fail_count,
            "unique_responses": len(unique_responses),
            "status_distribution": status_dist,
            "elapsed": round(concurrent_result.elapsed_seconds, 2),
        })

        # ============================================================
        # Step 4: 判定
        # ============================================================
        elapsed = time.time() - t0

        # 判定逻辑：
        # - 如果是"只能执行一次"的操作（如领取优惠券），正常情况下只有 1 次成功
        # - 如果并发后有多次成功 → 竞态条件
        # - 如果所有请求都成功且返回相同内容 → 可能是幂等接口（非漏洞）

        if success_count > 1:
            # 检查是否是幂等接口（所有成功响应完全相同）
            is_idempotent = len(set(success_bodies)) <= 1

            if is_idempotent and not self._has_state_change_hint(task, baseline_body):
                # 幂等接口 + 无状态变化暗示 → 可能不是漏洞
                return FuzzEvidence(
                    result=FuzzResult.LIKELY,
                    confidence=0.5,
                    summary=(
                        f"并发 {concurrency} 次中 {success_count} 次成功，"
                        f"但响应完全相同（可能是幂等接口）"
                    ),
                    fuzzer_name=self.NAME,
                    requests_sent=requests_sent,
                    elapsed_seconds=elapsed,
                    diff_highlight=f"成功次数: {success_count}/{concurrency}\n状态码分布: {status_dist}",
                    timeline=timeline,
                )
            else:
                # 多次成功 + 非幂等 → 确认竞态
                return FuzzEvidence(
                    result=FuzzResult.CONFIRMED,
                    confidence=0.88,
                    summary=(
                        f"竞态条件确认：并发 {concurrency} 次中 {success_count} 次成功"
                        f"（预期仅 1 次成功）"
                    ),
                    fuzzer_name=self.NAME,
                    requests_sent=requests_sent,
                    elapsed_seconds=elapsed,
                    poc_curl=self._build_curl(task.method, task.target_url, task.headers, task.body),
                    impact_scope=f"可通过并发请求重复执行操作（成功率 {success_count}/{concurrency}）",
                    diff_highlight=(
                        f"并发数: {concurrency}\n"
                        f"成功次数: {success_count}\n"
                        f"失败次数: {fail_count}\n"
                        f"状态码分布: {status_dist}\n"
                        f"不同响应数: {len(unique_responses)}"
                    ),
                    key_response=success_bodies[0] if success_bodies else "",
                    timeline=timeline,
                )

        elif success_count == 1:
            # 只有 1 次成功 → 正常（服务端有锁）
            return FuzzEvidence(
                result=FuzzResult.NOT_VULN,
                confidence=0.8,
                summary=f"并发 {concurrency} 次仅 1 次成功，服务端并发控制正常",
                fuzzer_name=self.NAME,
                requests_sent=requests_sent,
                elapsed_seconds=elapsed,
                timeline=timeline,
            )

        else:
            # 0 次成功 → 可能接口本身就不可用
            return FuzzEvidence(
                result=FuzzResult.INCONCLUSIVE,
                confidence=0.3,
                summary=f"并发 {concurrency} 次均未成功，无法判断是否存在竞态",
                fuzzer_name=self.NAME,
                requests_sent=requests_sent,
                elapsed_seconds=elapsed,
                timeline=timeline,
            )

    # ============================================================
    # 辅助方法
    # ============================================================

    def _is_success_response(self, status: int, body: str) -> bool:
        """判断响应是否表示"操作成功"。"""
        if status >= 400:
            return False
        if status in (200, 201):
            # 检查 JSON 中的成功标志
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    # 常见的失败标志
                    code = data.get("code", data.get("status", data.get("errcode", 0)))
                    if isinstance(code, int) and code != 0 and code != 200:
                        return False
                    msg = str(data.get("message", data.get("msg", data.get("error", "")))).lower()
                    fail_keywords = ["已领取", "已使用", "已过期", "不足", "失败",
                                     "exceeded", "already", "duplicate", "insufficient"]
                    if any(kw in msg for kw in fail_keywords):
                        return False
            except (json.JSONDecodeError, TypeError):
                pass
            return True
        return False

    def _has_state_change_hint(self, task: FuzzTask, baseline_body: str) -> bool:
        """判断请求是否暗示会产生状态变化（非幂等）。"""
        # POST/PUT/DELETE 通常有状态变化
        if task.method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
            return True
        # URL/Body 中含有暗示性关键词
        hints = ["领取", "兑换", "使用", "消费", "扣", "减", "转账",
                 "claim", "redeem", "use", "consume", "deduct", "transfer"]
        text = f"{task.target_url} {task.body} {' '.join(task.hints)}".lower()
        return any(h in text for h in hints)
