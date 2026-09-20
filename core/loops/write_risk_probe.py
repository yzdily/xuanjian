"""
core/loops/write_risk_probe.py — 写接口复合风险（§3.11.3）。

## 为什么需要
xuanjian 无写接口复合风险检测（grep 核验无 `write_risk` / `ssrf_write`）。
写接口匿名可写内网=SSRF 通道。未授权写 + SSRF + 明文凭证 三态×多 host
（10.x/127.x/169.254.x）。

## 能力
- build_ssrf_hosts — 内网探测 host 列表（10.x / 127.x / 169.254.x / 192.168.x）
- evaluate_write_risk — 三态×多host：未授权写(CWE-862) + SSRF(CWE-918) + 明文凭证(CWE-200)

## 复用
- 与 `idor_probe` / `sso_auth_probe` 同构：纯函数 + dict 响应入参
- 上层 LOOP 编排负责发未授权写请求 + 对内网 host 发 SSRF 探测，本模块仅做风险聚合判定

## 零依赖
纯 stdlib；http 参数为可注入 dict（测试 mock），不模块级 import httpx。
"""
from __future__ import annotations

from typing import Any

# CWE 映射
CWE_MISSING_AUTHZ = "CWE-862"    # Missing Authorization（未授权写）
CWE_SSRF = "CWE-918"             # Server-Side Request Forgery
CWE_INFO_EXPOSURE = "CWE-200"    # Information Exposure（明文凭证泄露）

# 内网探测 host 列表（覆盖 10.x / 127.x / 169.254.x / 192.168.x / 内网网段）
SSRF_HOSTS = (
    "10.0.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "192.168.1.1",
    "10.10.10.1",
)

# 写成功标志（未授权写 200 但可能无 body 数据时，作为写入成功旁证）
WRITE_SUCCESS_HINTS = ("created", "updated", "success", "saved", "ok")

# 明文凭证指纹
CREDENTIAL_HINTS = ("password", "credential", "token", "secret")


def build_ssrf_hosts() -> list[str]:
    """返回内网探测 host 列表（10.x / 127.x / 169.254.x 等）。"""
    return list(SSRF_HOSTS)


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


def evaluate_write_risk(write_resp: dict, ssrf_resps: list[dict]) -> dict:
    """三态×多host：未授权写 + SSRF + 明文凭证。

    写接口匿名可写内网=SSRF 通道，复合风险需三态聚合判定：
    - 未授权写成功（200+数据 或 200+写入成功标志）→ CWE-862
    - 任一 SSRF 探测 200+数据 → CWE-918
    - 任一 SSRF 响应体含 password/credential/token/secret → CWE-200

    Args:
        write_resp: 写端点（未授权）响应（含 http_code/status + body/data）
        ssrf_resps: SSRF 内网探测响应列表（可含 host/url 标识）

    Returns:
        {
            "findings": list[dict],      # 每条含 rule/cwe/severity/evidence
            "write_unauthorized": bool,  # 未授权写是否成功
            "ssrf_detected": bool,       # 是否命中 SSRF
            "credential_leak": bool,     # 是否泄露明文凭证
        }
    """
    findings: list[dict[str, Any]] = []
    write_unauthorized = False
    ssrf_detected = False
    credential_leak = False

    # ---- 未授权写：CWE-862 ----
    status = _http_status(write_resp)
    if status == 200 and _has_data(write_resp):
        write_unauthorized = True
        findings.append({
            "rule": "unauthorized_write",
            "cwe": CWE_MISSING_AUTHZ,
            "severity": "High",
            "evidence": "未授权写端点返回 200+数据 → 缺少鉴权(CWE-862)",
        })
    elif status == 200:
        # 200 但无 body 数据：以写入成功标志作为旁证
        body = _body_str(write_resp)
        if any(hint in body for hint in WRITE_SUCCESS_HINTS):
            write_unauthorized = True
            findings.append({
                "rule": "unauthorized_write",
                "cwe": CWE_MISSING_AUTHZ,
                "severity": "High",
                "evidence": "未授权写端点返回 200+成功标志 → 缺少鉴权(CWE-862)",
            })

    # ---- SSRF + 明文凭证：三态×多host ----
    for i, resp in enumerate(ssrf_resps or []):
        r_status = _http_status(resp)
        body = _body_str(resp)
        host = resp.get("host") or resp.get("url") or f"ssrf_target_{i}"

        # SSRF 命中：200 + 有数据 → CWE-918
        if r_status == 200 and _has_data(resp):
            ssrf_detected = True
            findings.append({
                "rule": "ssrf_write",
                "cwe": CWE_SSRF,
                "severity": "High",
                "evidence": f"写端点 SSRF 探测 host={host} 返回 200+数据 → SSRF(CWE-918)",
            })

        # 明文凭证泄露：响应体含 password/credential/token/secret → CWE-200
        if any(hint in body for hint in CREDENTIAL_HINTS):
            credential_leak = True
            findings.append({
                "rule": "credential_leak_via_ssrf",
                "cwe": CWE_INFO_EXPOSURE,
                "severity": "High",
                "evidence": (
                    f"SSRF 响应 host={host} 含明文凭证指纹"
                    f"({CREDENTIAL_HINTS}) → 信息泄露(CWE-200)"
                ),
            })

    return {
        "findings": findings,
        "write_unauthorized": write_unauthorized,
        "ssrf_detected": ssrf_detected,
        "credential_leak": credential_leak,
    }


__all__ = [
    "build_ssrf_hosts",
    "evaluate_write_risk",
    "CWE_MISSING_AUTHZ",
    "CWE_SSRF",
    "CWE_INFO_EXPOSURE",
    "SSRF_HOSTS",
]
