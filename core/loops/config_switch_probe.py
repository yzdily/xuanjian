"""
core/loops/config_switch_probe.py — 鉴权配置开关根因探测（§3.11.3）。

## 为什么需要
xuanjian 无根因分类（grep 核验无 `root_cause` 分类）。整站未授权必须区分根因：
配置开关关闭 / 网关缺失 / 代码遗漏。报告写根因非仅列接口。

## 能力
- classify_root_cause — 配置开关关闭/网关缺失/代码遗漏 三分类

## 复用
- 与 `idor_probe.evaluate_*` / `sso_auth_probe` 同构：纯函数 + dict 响应入参
- 上层 LOOP 编排负责拉取 http_resp / gateway_resp，本模块仅做分类判定

## 零依赖
纯 stdlib；http/gateway 参数为可注入 dict（测试 mock），不模块级 import httpx。
"""
from __future__ import annotations

from typing import Any

# CWE 映射
CWE_MISSING_AUTHZ = "CWE-862"  # Missing Authorization

# 根因分类结果
ROOT_CONFIG_DISABLED = "config_disabled"
ROOT_GATEWAY_MISSING = "gateway_missing"
ROOT_CODE_OMISSION = "code_omission"
ROOT_UNKNOWN = "unknown"

# 代码层遗漏调试指纹（缺 @PreAuthorize 注解时响应常泄露的调试信息）
DEBUG_HINTS = ("debug", "stacktrace", "stack_trace", "traceback", "exception")


def _http_status(resp: dict[str, Any]) -> int:
    """统一取 http 状态码（兼容 http_code/status 字段，非数字→0）。"""
    status = resp.get("http_code") or resp.get("status") or 0
    try:
        return int(status)
    except (TypeError, ValueError):
        return 0


def _has_data(resp: dict[str, Any]) -> bool:
    """响应是否含业务数据（dict/list 非空，或字符串非空白）。"""
    body = resp.get("body") or resp.get("data") or ""
    if isinstance(body, (dict, list)):
        return len(body) > 0
    return bool(str(body).strip())


def _body_str(resp: dict[str, Any]) -> str:
    body = resp.get("body") or resp.get("data") or ""
    return str(body).lower()


def _gateway_filters(gateway_resp: dict[str, Any] | None) -> bool:
    """网关是否生效过滤（True=已部署且过滤；False=无过滤/缺失）。

    - None → False（无网关响应视为未部署）
    - 显式标记 gateway_deployed / filtering / auth_filter → 按标记
    - 缺省 → False（保守判定为未过滤，归因 gateway_missing 优先暴露问题）
    """
    if gateway_resp is None:
        return False
    deployed = gateway_resp.get("gateway_deployed")
    if deployed is not None:
        return bool(deployed)
    filtering = gateway_resp.get("filtering")
    if filtering is not None:
        return bool(filtering)
    auth_filter = gateway_resp.get("auth_filter")
    if auth_filter is not None:
        return bool(auth_filter)
    return False


def classify_root_cause(http_resp: dict, gateway_resp: dict | None = None) -> dict:
    """配置开关关闭/网关缺失/代码遗漏 三分类。

    整站未授权根因探测：把"未授权可访问"现象落到可修复的根因层。

    判定优先级（在 200+数据前提下）：
    1. code_omission：响应体含 debug/stacktrace 指纹 → 代码层遗漏（缺 @PreAuthorize）
    2. gateway_missing：网关未过滤/缺失 → 网关未部署
    3. config_disabled（默认）：网关已部署但仍未授权 200+数据 → 鉴权配置开关关闭
    4. unknown：非 200 或无数据 → 无法判定

    Args:
        http_resp: 未授权访问端点的响应（含 http_code/status + body/data）
        gateway_resp: 网关/探测响应（可选；含 gateway_deployed/filtering/auth_filter）

    Returns:
        {"root_cause": str, "evidence": str}
        root_cause ∈ {"config_disabled", "gateway_missing", "code_omission", "unknown"}
    """
    status = _http_status(http_resp)
    has_data = _has_data(http_resp)
    body_str = _body_str(http_resp)

    # 非成功访问（非 200 或无数据）→ 无法判定根因
    if not (status == 200 and has_data):
        return {
            "root_cause": ROOT_UNKNOWN,
            "evidence": f"状态={status}, 有数据={has_data} → 无法判定根因",
        }

    # 1. code_omission：响应体含调试指纹 → 代码层遗漏（缺 @PreAuthorize 注解）
    if any(hint in body_str for hint in DEBUG_HINTS):
        return {
            "root_cause": ROOT_CODE_OMISSION,
            "evidence": "响应体含调试指纹(debug/stacktrace) → 代码层遗漏(缺 @PreAuthorize)",
        }

    # 2. gateway_missing：网关未过滤/缺失 → 网关未部署
    if not _gateway_filters(gateway_resp):
        return {
            "root_cause": ROOT_GATEWAY_MISSING,
            "evidence": "端点 200+数据 且 网关无过滤/缺失 → 网关未部署",
        }

    # 3. config_disabled（默认）：网关已部署但仍未授权 200+数据 → 鉴权配置开关关闭
    return {
        "root_cause": ROOT_CONFIG_DISABLED,
        "evidence": "网关已部署但仍未授权 200+数据 → 鉴权配置开关关闭",
    }


__all__ = [
    "classify_root_cause",
    "CWE_MISSING_AUTHZ",
    "ROOT_CONFIG_DISABLED",
    "ROOT_GATEWAY_MISSING",
    "ROOT_CODE_OMISSION",
    "ROOT_UNKNOWN",
]
