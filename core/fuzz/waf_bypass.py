"""
WAF Bypass Fuzzer — WAF 绕过 Fuzz 引擎

核心定位：
  批量发送 payload 变体，找到能绕过 WAF 的那个。
  像 Burp Intruder 一样工作：发现响应从 403 变 200（或 body 长度变化）就停止。

使用场景：
  1. LLM 确认目标有 WAF 拦截
  2. LLM 生成 payload 变体列表（编码绕过、注释绕过、分块传输等）
  3. 调用本 Fuzzer 批量发送
  4. Fuzzer 发现绕过 payload 后立即停止，返回给 LLM

停止条件：
  - 响应状态码从 403/拦截 变为 200
  - 响应 body 长度与被拦截时显著不同
  - 响应中不再包含 WAF 拦截特征
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse, urlunparse, quote

from core.fuzz.base import BaseFuzzer, FuzzTask, FuzzEvidence, FuzzResult
from core.log import get_logger

log = get_logger("fuzz.waf_bypass")

# WAF 拦截特征关键词
_WAF_BLOCK_KEYWORDS = [
    "blocked", "forbidden", "waf", "firewall", "security",
    "access denied", "请求被拦截", "安全拦截", "非法请求",
    "illegal request", "attack detected", "malicious",
    "not acceptable", "request rejected",
]


class WAFBypassFuzzer(BaseFuzzer):
    """WAF 绕过 Fuzzer

    核心逻辑：
    1. 先发一个已知会被拦截的 payload，确认 WAF 拦截的响应特征（基线）
    2. 批量发送 LLM 生成的 payload 变体
    3. 检测响应差异：状态码变化 / body 长度变化 / 拦截关键词消失
    4. 发现绕过 payload → 立即停止 → 返回给 LLM
    """

    VULN_TYPES = ["WAF绕过", "WAF Bypass", "waf_bypass", "绕过WAF"]
    NAME = "waf_bypass"
    PRIORITY = 10  # 最高优先级

    async def fuzz(self, task: FuzzTask) -> FuzzEvidence:
        t0 = time.time()
        timeline: list[dict[str, Any]] = []
        requests_sent = 0
        response_diffs: list[dict[str, Any]] = []
        working_payloads: list[str] = []

        if not task.payload_list:
            return FuzzEvidence(
                result=FuzzResult.INCONCLUSIVE,
                confidence=0.0,
                summary="未提供 payload 列表，无法执行 WAF 绕过 fuzz",
                fuzzer_name=self.NAME,
                stop_reason="no_payload_list",
            )

        # ============================================================
        # Step 1: 获取被拦截的基线响应
        # ============================================================
        # 先发原始请求获取正常基线
        baseline = await self._send_request(
            method=task.method, url=task.target_url,
            headers=task.headers, body=task.body, timeout=task.timeout,
        )
        requests_sent += 1

        if baseline["error"]:
            return self._make_error_evidence(f"基线请求失败: {baseline['error']}")

        # 记录被拦截时的特征
        blocked_status = task.baseline_status or baseline["status"]
        blocked_body_length = task.baseline_body_length or baseline["body_length"]
        blocked_body = task.baseline_response or baseline["body"]

        # 判断基线是否就是被拦截状态
        is_blocked_baseline = self._is_waf_blocked(blocked_status, blocked_body)

        timeline.append({
            "step": "baseline",
            "status": blocked_status,
            "body_length": blocked_body_length,
            "is_blocked": is_blocked_baseline,
        })

        log.info(
            "WAF fuzz 基线: status=%d, body_len=%d, is_blocked=%s, payloads=%d",
            blocked_status, blocked_body_length, is_blocked_baseline, len(task.payload_list),
        )

        # ============================================================
        # Step 2: 批量发送 payload 变体
        # ============================================================
        for i, payload in enumerate(task.payload_list):
            if requests_sent >= task.max_requests:
                timeline.append({"step": "max_requests_reached", "count": requests_sent})
                break

            # 构造注入请求
            inject_url, inject_body = self._inject_payload(
                task.target_url, task.body, task.param_name,
                task.original_value, payload
            )

            resp = await self._send_request(
                method=task.method, url=inject_url,
                headers=task.headers, body=inject_body, timeout=task.timeout,
            )
            requests_sent += 1

            if resp["error"]:
                response_diffs.append({
                    "index": i, "payload": payload[:100],
                    "error": resp["error"], "is_different": False,
                })
                continue

            # ★ 核心：检测响应差异
            is_different = self._is_bypass_success(
                blocked_status, blocked_body_length, blocked_body,
                resp["status"], resp["body_length"], resp["body"],
            )

            response_diffs.append({
                "index": i,
                "payload": payload[:100],
                "status": resp["status"],
                "body_length": resp["body_length"],
                "is_different": is_different,
            })

            if is_different:
                working_payloads.append(payload)
                timeline.append({
                    "step": f"bypass_found_{len(working_payloads)}",
                    "payload_index": i,
                    "payload": payload[:100],
                    "status": resp["status"],
                    "body_length": resp["body_length"],
                })

                log.info(
                    "WAF 绕过成功! payload[%d]=%s, status=%d, body_len=%d",
                    i, payload[:60], resp["status"], resp["body_length"],
                )

                # ★ 智能停止：找到足够的绕过 payload 就停
                if len(working_payloads) >= task.max_success_count:
                    break

        # ============================================================
        # Step 3: 构造结果
        # ============================================================
        elapsed = time.time() - t0

        if working_payloads:
            # 找到绕过 payload
            best_payload = working_payloads[0]
            inject_url, inject_body = self._inject_payload(
                task.target_url, task.body, task.param_name,
                task.original_value, best_payload
            )

            return FuzzEvidence(
                result=FuzzResult.CONFIRMED,
                confidence=0.90,
                summary=f"WAF 绕过成功：在 {requests_sent} 个请求中找到 {len(working_payloads)} 个有效 payload",
                fuzzer_name=self.NAME,
                requests_sent=requests_sent,
                elapsed_seconds=elapsed,
                working_payloads=working_payloads,
                extracted_data={
                    "bypass_count": len(working_payloads),
                    "total_tested": len(task.payload_list),
                    "best_payload": best_payload,
                },
                poc_curl=self._build_curl(task.method, inject_url, task.headers, inject_body),
                impact_scope="可绕过 WAF 防护执行攻击 payload",
                diff_highlight=(
                    f"被拦截: status={blocked_status}, body_len={blocked_body_length}\n"
                    f"绕过后: status={response_diffs[-1].get('status', '?')}, "
                    f"body_len={response_diffs[-1].get('body_length', '?')}"
                ),
                response_diffs=response_diffs,
                timeline=timeline,
                waf_detected=True,
                stop_reason="diff_detected" if len(working_payloads) >= task.max_success_count else "all_done",
            )
        else:
            # 未找到绕过
            stop_reason = "max_requests" if requests_sent >= task.max_requests else "all_tested_failed"
            return FuzzEvidence(
                result=FuzzResult.NOT_VULN,
                confidence=0.6,
                summary=f"WAF 绕过失败：测试了 {requests_sent} 个 payload 均被拦截",
                fuzzer_name=self.NAME,
                requests_sent=requests_sent,
                elapsed_seconds=elapsed,
                response_diffs=response_diffs[-10:],  # 只保留最后 10 条
                timeline=timeline,
                waf_detected=True,
                stop_reason=stop_reason,
            )

    # ============================================================
    # 辅助方法
    # ============================================================

    def _is_waf_blocked(self, status: int, body: str) -> bool:
        """判断响应是否是 WAF 拦截。"""
        if status in (403, 406, 429, 503):
            return True
        body_lower = body.lower()
        return any(kw in body_lower for kw in _WAF_BLOCK_KEYWORDS)

    def _is_bypass_success(
        self,
        blocked_status: int, blocked_body_length: int, blocked_body: str,
        resp_status: int, resp_body_length: int, resp_body: str,
    ) -> bool:
        """判断当前响应是否表示绕过成功。

        绕过成功的标志：
        1. 状态码从 403/拦截 变为 200
        2. body 长度显著变化（说明返回了不同内容）
        3. 响应中不再包含 WAF 拦截关键词
        """
        # 如果响应本身也是被拦截的，则不算绕过
        if self._is_waf_blocked(resp_status, resp_body):
            return False

        # 状态码变化：从拦截状态变为正常
        if blocked_status in (403, 406, 429, 503) and resp_status == 200:
            return True

        # body 长度显著变化
        if blocked_body_length > 0:
            diff_ratio = abs(resp_body_length - blocked_body_length) / max(blocked_body_length, 1)
            if diff_ratio > 0.3 and not self._is_waf_blocked(resp_status, resp_body):
                return True

        # 拦截关键词消失
        blocked_has_keywords = any(kw in blocked_body.lower() for kw in _WAF_BLOCK_KEYWORDS)
        resp_has_keywords = any(kw in resp_body.lower() for kw in _WAF_BLOCK_KEYWORDS)
        if blocked_has_keywords and not resp_has_keywords and resp_body_length > 50:
            return True

        return False

    def _inject_payload(
        self, url: str, body: str, param_name: str,
        original_value: str, payload: str
    ) -> tuple[str, str]:
        """将 payload 注入到参数中。"""
        import re as _re

        # 如果 payload 本身就是完整值（不需要拼接原始值）
        injected_value = payload

        # URL query 参数
        parsed = urlparse(url)
        if param_name and param_name in (parsed.query or ""):
            new_query = _re.sub(
                rf"({_re.escape(param_name)}=)[^&]*",
                rf"\g<1>{quote(injected_value, safe='')}",
                parsed.query,
            )
            return urlunparse(parsed._replace(query=new_query)), body

        # Body 中替换
        if body and original_value and original_value in body:
            return url, body.replace(original_value, injected_value, 1)

        # 兜底：追加到 URL
        if param_name:
            sep = "&" if "?" in url else "?"
            return f"{url}{sep}{param_name}={quote(injected_value, safe='')}", body

        return url, body
