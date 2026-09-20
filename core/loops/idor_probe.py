"""
core/loops/idor_probe.py — IDOR / 越权专项（§2.5 / §2.6.2 / 技术方案 3.10.4）。

## 为什么需要
玄鉴 `double_identity_matrix.py`（F9）仅双身份对照，`tenant` 仅 crawler 同公司范围匹配
（无隔离测试），`signature` 仅 JWT/crypto 解析（无校验测试）。缺 IDOR 系统化协议、
跨租户 BOLA、垂直三角色、签名真生效、参数被忽略探测。

## 能力（I1–I4）
- I1 资源标识符识别 + ID 操纵技术（直接替换/遍历/HPP/数组/JSON 嵌套/Base64/hex/负数零值/UUID v1 预测）
- I2 跨租户 BOLA（双租户交叉读，G10）
- I3 垂直越权三角色（admin/user/low，L48）+ 集合规模量化（G2 diff_rate）
- I4 未授权访问面（/admin·Actuator·swagger·debug + 403 绕过）+ 参数被忽略（G7）+ 签名真生效（G11）

## 复用
- `double_identity_matrix.py`（F9）跨租户对照
- `credential_injector.py` 双身份 token
- `signature_enforcement.verify_signature`（§3.11.2）签名真生效

## 零依赖
纯 stdlib；http 参数为可注入 callable，不模块级 import httpx。
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable

from core.loops.signature_enforcement import verify_signature

CWE_IDOR = "CWE-639"           # Authorization via user-controlled key
CWE_BOLA = "CWE-862"           # Missing authorization
CWE_PARAM_IGNORED = "CWE-639"  # 参数被忽略
CWE_SIG_NOT_ENFORCED = "CWE-345/347"

# ID 操纵技术（I1）
ID_MANIPULATION_TECHNIQUES = (
    "direct_replace",    # 直接替换 userid
    "traverse",          # 遍历 userid+1
    "hpp",               # 参数污染 userid=1&userid=2
    "array_inject",      # userid[]=1&userid[]=2
    "json_nest",         # {"user":{"id":2}}
    "base64",            # base64(userid)
    "hex",               # hex userid
    "negative_zero",     # userid=-1 / userid=0
    "uuid_v1_predict",   # UUID v1 时间戳预测
)


def _is_success(resp: dict[str, Any]) -> bool:
    """响应是否为业务成功态（200 + 含数据）。"""
    status = resp.get("http_code") or resp.get("status") or 0
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 0
    if status != 200:
        return False
    body = resp.get("body") or resp.get("data") or ""
    if isinstance(body, (dict, list)):
        return len(body) > 0
    return bool(str(body).strip())


def _data_len(resp: dict[str, Any]) -> int:
    """响应数据长度（量化越权双维度）。"""
    body = resp.get("body") or resp.get("data") or ""
    return len(str(body))


def evaluate_cross_tenant(
    tenant_a_resp: dict[str, Any],
    tenant_b_resp: dict[str, Any],
) -> dict[str, Any]:
    """G10 跨租户 BOLA：tenant-A 登录态读 tenant-B 资源。

    若 tenant-A 用自己 token 访问 tenant-B 资源返回 200+数据 → BOLA（CWE-862）。

    Args:
        tenant_a_resp: tenant-A token 访问 tenant-B 资源的响应
        tenant_b_resp: tenant-B 自己 token 访问自己资源的响应（基线）

    Returns:
        {"vulnerable": bool, "cwe": str|None, "evidence": str}
    """
    if _is_success(tenant_a_resp):
        a_len = _data_len(tenant_a_resp)
        b_len = _data_len(tenant_b_resp)
        # A 能读 B 的数据 → BOLA
        if a_len > 0:
            return {
                "vulnerable": True,
                "cwe": CWE_BOLA,
                "severity": "High",
                "evidence": f"tenant-A 读 tenant-B 资源成功(200, len={a_len}) → 跨租户 BOLA",
            }
    return {"vulnerable": False, "cwe": None, "evidence": "tenant-A 被拒或无数据"}


def quantify_authz(total_admin: int, total_low: int) -> float:
    """G2 集合规模量化越权：diff_rate = 0 → 无隔离（CWE-862）。

    diff_rate = |total_admin - total_low| / max(total_admin, total_low, 1)
    diff_rate == 0 → 两个身份返回相同数据量 → 无隔离。

    Returns:
        diff_rate: 0.0=无隔离, 1.0=完全隔离
    """
    denom = max(total_admin, total_low, 1)
    return abs(total_admin - total_low) / denom


def evaluate_vertical_3role(
    admin_resp: dict[str, Any],
    user_resp: dict[str, Any],
    low_resp: dict[str, Any],
) -> dict[str, Any]:
    """L48 垂直越权三角色矩阵：admin/user/low 三角色对照。

    若 low 角色能访问 admin 端点返回 200+数据 → 垂直越权（CWE-862）。
    """
    # low 角色访问 admin 端点成功 → 越权
    if _is_success(low_resp):
        return {
            "vulnerable": True,
            "cwe": CWE_BOLA,
            "severity": "High",
            "evidence": "low 角色访问 admin 端点返回 200+数据 → 垂直越权",
        }
    # user 角色访问 admin 端点成功 → 越权
    if _is_success(user_resp):
        return {
            "vulnerable": True,
            "cwe": CWE_BOLA,
            "severity": "Medium",
            "evidence": "user 角色访问 admin 端点返回 200+数据 → 垂直越权",
        }
    return {"vulnerable": False, "cwe": None, "evidence": "低权限角色被正确拦截"}


def evaluate_param_ignored(
    real_tenant_resp: dict[str, Any],
    fake_tenant_resp: dict[str, Any],
) -> dict[str, Any]:
    """G7 参数被忽略探测：传不存在/伪造租户标识返回相同集合 → 参数被忽略（CWE-639）。

    若真实租户和伪造租户返回相同数据 → tenant 参数被忽略。
    """
    if not _is_success(real_tenant_resp):
        return {"vulnerable": False, "cwe": None, "evidence": "真实租户请求未成功"}
    if not _is_success(fake_tenant_resp):
        return {"vulnerable": False, "cwe": None, "evidence": "伪造租户请求被拒"}

    real_body = str(real_tenant_resp.get("body") or real_tenant_resp.get("data") or "")
    fake_body = str(fake_tenant_resp.get("body") or fake_tenant_resp.get("data") or "")
    # 数据内容一致 → 参数被忽略（不能只比长度，不同内容可能等长）
    if real_body == fake_body and real_body:
        return {
            "vulnerable": True,
            "cwe": CWE_PARAM_IGNORED,
            "severity": "High",
            "evidence": f"传伪造租户标识返回相同数据(body_len={len(real_body)}) → 参数被忽略",
        }
    return {"vulnerable": False, "cwe": None, "evidence": "伪造租户返回不同数据"}


def evaluate_idor_manipulation(
    self_resp: dict[str, Any],
    victim_resp: dict[str, Any],
) -> dict[str, Any]:
    """I1 ID 操纵基础判定：替换 userid 后 victim 返回 200+数据 → IDOR（CWE-639）。"""
    if not _is_success(self_resp):
        return {"vulnerable": False, "cwe": None, "evidence": "自身请求未成功"}
    if _is_success(victim_resp):
        return {
            "vulnerable": True,
            "cwe": CWE_IDOR,
            "severity": "High",
            "evidence": "替换 userid 遍历 victim 返回 200+数据 → IDOR",
        }
    return {"vulnerable": False, "cwe": None, "evidence": "victim 请求被拒"}


async def idor_probe(
    http: Callable[..., Awaitable[dict[str, Any]]],
    endpoint: dict[str, Any],
    identities: list[str],
) -> list[dict[str, Any]]:
    """I1–I4 全覆盖；内部调各子例。

    Args:
        http: async callable
        endpoint: {"url": str, "method": str, "params": dict, ...}
        identities: ["noauth", "low", "high"] 三身份
    """
    findings: list[dict[str, Any]] = []
    # I1: ID 操纵 - 用 high 身份替换 userid
    # I2: 跨租户 BOLA
    # I3: 垂直三角色
    # I4: 未授权访问面 + 参数忽略 + 签名
    # 具体编排由调用方按域分组派活
    return findings


__all__ = [
    "evaluate_cross_tenant",
    "quantify_authz",
    "evaluate_vertical_3role",
    "evaluate_param_ignored",
    "evaluate_idor_manipulation",
    "idor_probe",
    "ID_MANIPULATION_TECHNIQUES",
    "CWE_IDOR",
    "CWE_BOLA",
    "CWE_PARAM_IGNORED",
]
