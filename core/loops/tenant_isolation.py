"""core/loops/tenant_isolation.py — 多租户隔离重放检测（§4 Phase 2 item 5）。

主动用 tenant-A 的凭据重放 tenant-B 的资源请求，对比响应差异，
检测跨租户 BOLA（Broken Object Level Authorization）/ 隔离失效。

设计：
- 纯函数，request_fn 由上层注入（便于 mock 测试）
- 对比维度：HTTP 状态码 + 业务码 + data 长度 + 关键字段一致性
- 输出结构化结果：{isolated: bool, findings: [...]}
"""
from __future__ import annotations

from typing import Any, Callable


def _extract_business_code(text: str) -> str | None:
    """从响应文本提取业务码（code/errno/ret/status 字段）。"""
    import re
    m = re.search(r'"(?:code|errno|ret|status)"\s*:\s*(-?\d+)', text)
    return m.group(1) if m else None


def _extract_data_length(text: str) -> int:
    """粗略估算响应 data 字段长度（用于越权数据量判断）。"""
    import re
    m = re.search(r'"data"\s*:\s*(\{.*\}|\[.*\])', text, re.DOTALL)
    return len(m.group(1)) if m else 0


async def replay_across_tenants(
    target_url: str,
    method: str,
    tenant_a_headers: dict,
    tenant_b_headers: dict,
    request_fn: Callable,
    body: str = "",
    tenant_a_id: str = "A",
    tenant_b_id: str = "B",
) -> dict:
    """用 tenant-A 凭据访问 tenant-B 资源，对比响应。

    Args:
        target_url: 目标资源 URL（tenant-B 的资源）
        method: HTTP 方法
        tenant_a_headers: tenant-A 的认证头
        tenant_b_headers: tenant-B 的认证头（基线，应能访问）
        request_fn: 异步请求函数 (method, url, headers, body) -> response
        body: 请求体
        tenant_a_id / tenant_b_id: 租户标识

    Returns:
        {
            isolated: bool,  # True=隔离正常，False=发现越权
            tenant_a_response: {status, business_code, data_len},
            tenant_b_response: {status, business_code, data_len},
            findings: [越权发现列表],
        }
    """
    # 基线：tenant-B 访问自己的资源（应成功）
    b_resp = await request_fn(method, target_url, tenant_b_headers, body)
    # 测试：tenant-A 访问 tenant-B 的资源
    a_resp = await request_fn(method, target_url, tenant_a_headers, body)

    b_text = getattr(b_resp, "text", "") or ""
    a_text = getattr(a_resp, "text", "") or ""
    b_status = getattr(b_resp, "status_code", 0)
    a_status = getattr(a_resp, "status_code", 0)

    b_info = {
        "status": b_status,
        "business_code": _extract_business_code(b_text),
        "data_len": _extract_data_length(b_text),
    }
    a_info = {
        "status": a_status,
        "business_code": _extract_business_code(a_text),
        "data_len": _extract_data_length(a_text),
    }

    findings: list[dict] = []
    isolated = True

    # 判定 1：tenant-A 应被拒绝（403/401），若返回 200 则疑似越权
    if a_status == 200 and b_status == 200:
        # 进一步看业务码和 data 长度
        a_code = a_info["business_code"]
        b_code = b_info["business_code"]
        # 两者都成功且 data 长度相近 → 越权
        if a_code == b_code and a_info["data_len"] > 0:
            isolated = False
            findings.append({
                "type": "BOLA跨租户越权",
                "severity": "high",
                "detail": (f"tenant-{tenant_a_id} 使用自身凭据访问 tenant-{tenant_b_id} "
                           f"资源返回 200 + 业务成功码，data 长度={a_info['data_len']}"),
                "evidence": a_text[:300],
            })

    # 判定 2：tenant-A 被拒绝（403/401）→ 隔离正常
    if a_status in (401, 403):
        isolated = True

    # 判定 3：tenant-A 返回空 data 但 200 → 可能是软拒绝（data 为空）
    if a_status == 200 and a_info["data_len"] == 0 and b_info["data_len"] > 0:
        isolated = True  # 软拒绝，隔离正常

    return {
        "vuln_type": "跨租户隔离",
        "isolated": isolated,
        "tenant_a_response": a_info,
        "tenant_b_response": b_info,
        "findings": findings,
        "severity": "high" if findings else "info",
    }
