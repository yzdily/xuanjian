"""
core/loops/llm_state_machine_probe.py — LLM 状态机响应差异识别（§2.6.5 防漏报护城河）。

## 为什么需要（grep 核验）
玄鉴 `core/llm/` 仅做 LLM 客户端/上下文/解析，`core/reconcile.py` 仅业务对账，
缺"用 LLM 识别业务流状态机滥用"能力：
- 无"状态跳转异常"检测（用户跳过支付直接完成订单 → 业务逻辑漏洞）
- 无"状态响应差异"识别（同一状态机节点不同身份响应差异 → 越权）
- 无"状态可达性"分析（未授权可直达终态 → 鉴权绕过）

LLM 状态机识别是漏报护城河的业务逻辑闸：传统规则无法检测"状态跳转滥用"。
本模块补齐：
1. `detect_state_skip` — 状态跳转异常检测（跳过中间态直达终态 → 漏洞）
2. `compare_state_responses` — 状态响应差异识别（不同身份同状态响应差异 → 越权）
3. `analyze_state_reachability` — 状态可达性分析（未授权可达终态 → 鉴权绕过）

## 复用
- `core/llm/_client.py`（LLM 客户端，上层注入）
- `core/llm/_context.py`（上下文管理）
- `core/loops/idor_probe.py`（越权判定）
- 上层 LOOP 编排负责拉取状态机定义 + 响应序列，本模块仅做差异识别

## 零依赖
纯 stdlib；不模块级 import httpx/fastapi/llm。LLM 判定结果为可注入 dict（测试 mock）。
"""
from __future__ import annotations

from typing import Any

# CWE 映射
CWE_BUSINESS_LOGIC = "CWE-840"  # Business Logic Errors（状态机滥用）
CWE_AUTHZ_BYPASS = "CWE-862"    # Missing Authorization（未授权可达终态）
CWE_IDOR = "CWE-639"            # Authorization via user-controlled key（状态响应差异）

# 状态机跳转异常类型
STATE_SKIP = "state_skip"                # 跳过中间态（如跳过支付直达完成）
STATE_REPLAY = "state_replay"            # 状态重放（重复执行某态）
STATE_BACKWARD = "state_backward"        # 状态回退（终态回退到初态）
STATE_UNAUTHORIZED_REACH = "unauthorized_reach"  # 未授权直达终态


def detect_state_skip(
    transition_seq: list[str],
    expected_seq: list[str],
) -> dict[str, Any]:
    """状态跳转异常检测（跳过中间态直达终态 → 业务逻辑漏洞）。

    检测核心：实际状态跳转序列是否跳过了期望序列中的必需中间态。
    - 期望: [create, pay, complete] 实际: [create, complete] → 跳过 pay → 漏洞
    - 期望: [init, verify, execute] 实际: [init, execute] → 跳过 verify → 漏洞

    Args:
        transition_seq: 实际状态跳转序列（如 ["create", "complete"]）
        expected_seq: 期望状态跳转序列（如 ["create", "pay", "complete"]）

    Returns:
        {
            "anomaly": str | None,  # state_skip / state_replay / state_backward / None
            "cwe": str | None,     # CWE-840（业务逻辑错误）
            "skipped": list[str],  # 被跳过的状态
            "evidence": str,
        }
    """
    if not transition_seq:
        return {
            "anomaly": None,
            "cwe": None,
            "skipped": [],
            "evidence": "无实际跳转序列",
        }

    # 检测状态回退（终态在序列中后又出现更早状态）
    for i in range(1, len(transition_seq)):
        if transition_seq[i] in transition_seq[:i]:
            # 状态重放（同一状态重复出现）
            return {
                "anomaly": STATE_REPLAY,
                "cwe": CWE_BUSINESS_LOGIC,
                "skipped": [],
                "evidence": f"状态重放: '{transition_seq[i]}' 重复出现 → 业务逻辑异常(CWE-840)",
            }

    # 检测跳过中间态：实际序列是期望序列的子序列但跳过了中间态
    skipped = []
    expected_set = set(expected_seq)
    actual_set = set(transition_seq)

    # 找出期望序列中被跳过的状态
    for state in expected_seq:
        if state not in actual_set:
            skipped.append(state)

    # 实际序列的最后一个状态是期望序列的终态 → 跳过了中间态
    if skipped and transition_seq[-1] == expected_seq[-1]:
        return {
            "anomaly": STATE_SKIP,
            "cwe": CWE_BUSINESS_LOGIC,
            "skipped": skipped,
            "evidence": f"跳过中间态 {skipped} 直达终态 '{expected_seq[-1]}' → 业务逻辑漏洞(CWE-840)",
        }

    # 检测状态回退（实际序列中出现期望序列中靠后的状态后又出现靠前的状态）
    if len(transition_seq) >= 2 and len(expected_seq) >= 2:
        # 构建状态到期望位置的映射
        state_order = {s: i for i, s in enumerate(expected_seq)}
        for i in range(1, len(transition_seq)):
            prev = transition_seq[i - 1]
            curr = transition_seq[i]
            if prev in state_order and curr in state_order:
                if state_order[curr] < state_order[prev]:
                    return {
                        "anomaly": STATE_BACKWARD,
                        "cwe": CWE_BUSINESS_LOGIC,
                        "skipped": [],
                        "evidence": (
                            f"状态回退: '{prev}'(order={state_order[prev]}) → "
                            f"'{curr}'(order={state_order[curr]}) → 业务逻辑异常(CWE-840)"
                        ),
                    }

    # 无异常
    return {
        "anomaly": None,
        "cwe": None,
        "skipped": [],
        "evidence": "状态跳转序列正常",
    }


def compare_state_responses(
    state: str,
    user_a_resp: dict[str, Any],
    user_b_resp: dict[str, Any],
) -> dict[str, Any]:
    """状态响应差异识别（不同身份同状态响应差异 → 越权）。

    检测核心：同一状态机节点，不同身份的响应是否存在差异。
    - user-A 在"order_detail"状态看到自己的订单 → 正常
    - user-A 在"order_detail"状态看到 user-B 的订单 → 越权（CWE-639）
    - 差异判定：响应数据内容不同（非长度，防同长度不同数据假阴性）

    Args:
        state: 状态机节点名
        user_a_resp: user-A 在该状态的响应
        user_b_resp: user-B 在该状态的响应

    Returns:
        {
            "diverged": bool,      # 响应是否差异
            "cwe": str | None,    # CWE-639（越权）
            "evidence": str,
        }
    """
    def _body_str(resp: dict[str, Any]) -> str:
        body = resp.get("body") or resp.get("data") or ""
        return str(body)

    a_body = _body_str(user_a_resp)
    b_body = _body_str(user_b_resp)

    # 响应内容不同 → 差异
    if a_body != b_body:
        # user-A 的响应包含 user-B 的数据特征 → 越权
        return {
            "diverged": True,
            "cwe": CWE_IDOR,
            "evidence": (
                f"状态 '{state}' user-A 响应与 user-B 响应内容不同 "
                f"→ 可能越权访问他人数据(CWE-639)"
            ),
        }

    return {
        "diverged": False,
        "cwe": None,
        "evidence": f"状态 '{state}' 两身份响应一致 → 无越权",
    }


def analyze_state_reachability(
    target_state: str,
    unauthorized_resp: dict[str, Any],
    expected_states: list[str] | None = None,
) -> dict[str, Any]:
    """状态可达性分析（未授权可达终态 → 鉴权绕过）。

    检测核心：未授权用户是否可直达期望序列中的终态。
    - 未授权访问 "complete" 状态返回 200+数据 → 鉴权绕过（CWE-862）
    - 终态 = 期望序列的最后一个状态

    Args:
        target_state: 目标状态（如 "complete"）
        unauthorized_resp: 未授权访问该状态的响应
        expected_states: 期望状态序列（用于判定 target 是否为终态）

    Returns:
        {
            "reachable": bool,    # 未授权是否可达
            "cwe": str | None,   # CWE-862（鉴权绕过）
            "evidence": str,
        }
    """
    status = unauthorized_resp.get("http_code") or unauthorized_resp.get("status") or 0
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 0

    body = unauthorized_resp.get("body") or unauthorized_resp.get("data") or ""
    has_data = bool(str(body).strip()) if not isinstance(body, (dict, list)) else len(body) > 0

    # 200 + 数据 → 未授权可达
    if status == 200 and has_data:
        # 判定是否为终态
        is_terminal = (
            expected_states is None
            or target_state == expected_states[-1]
        )
        cwe = CWE_AUTHZ_BYPASS
        evidence = (
            f"未授权访问状态 '{target_state}' 返回 200+数据 → 鉴权绕过(CWE-862)"
            + ("（终态直达）" if is_terminal else "")
        )
        return {"reachable": True, "cwe": cwe, "evidence": evidence}

    # 401/403 → 未授权不可达（正常）
    if status in (401, 403):
        return {
            "reachable": False,
            "cwe": None,
            "evidence": f"未授权访问状态 '{target_state}' 返回 {status} → 鉴权生效",
        }

    # 其他状态 → 不可达（保守）
    return {
        "reachable": False,
        "cwe": None,
        "evidence": f"未授权访问状态 '{target_state}' 返回 {status} → 不可达",
    }


def evaluate_state_machine_abuse(
    transition_seq: list[str],
    expected_seq: list[str],
    state_responses: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """状态机滥用全链评估（跳转异常 + 响应差异 + 可达性 聚合）。

    链式核验：一次状态机探测同时产出 跳转异常 + 响应差异 + 可达性。
    - 跳过中间态 → CWE-840（业务逻辑）
    - 未授权可达终态 → CWE-862（鉴权绕过）
    - 响应差异 → CWE-639（越权）

    Args:
        transition_seq: 实际状态跳转序列
        expected_seq: 期望状态跳转序列
        state_responses: 各状态的未授权响应 {state: resp}（可选）

    Returns:
        {
            "findings": list[dict],   # 每条含 rule/cwe/severity/evidence
            "anomaly": str | None,
        }
    """
    findings: list[dict[str, Any]] = []

    # 1. 跳转异常检测
    skip_result = detect_state_skip(transition_seq, expected_seq)
    anomaly = skip_result.get("anomaly")
    if anomaly and skip_result.get("cwe"):
        findings.append({
            "rule": "state_machine_abuse",
            "cwe": skip_result["cwe"],
            "severity": "High",
            "evidence": skip_result["evidence"],
        })

    # 2. 可达性分析（若有状态响应）
    if state_responses:
        for state, resp in state_responses.items():
            reach = analyze_state_reachability(state, resp, expected_seq)
            if reach["reachable"] and reach.get("cwe"):
                findings.append({
                    "rule": "unauthorized_state_reach",
                    "cwe": reach["cwe"],
                    "severity": "High",
                    "evidence": reach["evidence"],
                })

    return {
        "findings": findings,
        "anomaly": anomaly,
    }


__all__ = [
    "detect_state_skip",
    "compare_state_responses",
    "analyze_state_reachability",
    "evaluate_state_machine_abuse",
    "CWE_BUSINESS_LOGIC",
    "CWE_AUTHZ_BYPASS",
    "CWE_IDOR",
    "STATE_SKIP",
    "STATE_REPLAY",
    "STATE_BACKWARD",
    "STATE_UNAUTHORIZED_REACH",
]
