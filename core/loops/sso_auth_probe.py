"""
core/loops/sso_auth_probe.py — SSO / 单点登录专项（§2.5 / 技术方案 3.10.1）。

## 为什么需要
玄鉴 F3 `required_cookies` 仅单点 Cookie 判定，`crawler/login_mixin.py` 登录态混用。
缺"同 token 替换 userid 遍历任意账户 = 认证绕过"协议、OAuth client 凭证流、
双域凭据隔离、令牌续期。本模块补齐 SSO Token↔主体绑定探测 + 主认证因子推导。

## 能力
1. `probe_token_userid_binding` — 同 token 内替换 userid 参数遍历 victim，
   200 + 业务成功 → 认证绕过（CWE-287 + CWE-639）
2. `probe_oauth_client_credentials` — OAuth client 凭证流探测
3. `derive_primary_credential` — token_only=ACCESS & cookie_only=DENIED → 主因子=Token
   （§2.6.6 G-T6，不报绕过）

## 复用
- `CredentialInjector`（credential_injector.py:84）登录态注入
- `auth_matrix.cred_for(domain)`（§2.4）取 token
- `verdict.gate_business_code` / `gate_has_data` 判定业务成功

## 零依赖
纯 stdlib；http 参数为可注入 callable（测试 mock），不模块级 import httpx。
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable

# CWE 映射
CWE_AUTH_BYPASS = "CWE-287"     # Authentication bypass
CWE_IDOR_AUTHZ = "CWE-639"      # Authorization bypass via user-controlled key

# 令牌过期指示码（单飞续期，§2.5 tongye G-T5）
TOKEN_EXPIRED_CODES = (-100, 401, 419, 440)

# 主因子推导结果
PRIMARY_TOKEN = "Token"
PRIMARY_COOKIE = "Cookie"
PRIMARY_BOTH = "Both"
PRIMARY_UNKNOWN = "Unknown"


def _is_business_success(resp: dict[str, Any]) -> bool:
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


def evaluate_token_userid_binding(
    self_resp: dict[str, Any],
    victim_resps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """纯逻辑：比对"自己 userid 请求" vs "替换为 victim userid 请求"。

    若 victim 请求也返回 200 + 业务数据 → Token 未与主体绑定 → 认证绕过。

    Args:
        self_resp: 用自己 userid 的响应（基线，应成功）
        victim_resps: 替换为各 victim userid 的响应列表

    Returns:
        findings 列表（每条含 cwe / evidence / victim_id）
    """
    findings: list[dict[str, Any]] = []
    if not _is_business_success(self_resp):
        return findings  # 自身请求都没成功，无法判定

    for i, vresp in enumerate(victim_resps):
        if _is_business_success(vresp):
            findings.append({
                "rule": "sso_token_userid_binding",
                "cwe": f"{CWE_AUTH_BYPASS}+{CWE_IDOR_AUTHZ}",
                "severity": "High",
                "evidence": f"同 token 替换 userid 遍历 victim[{i}] 返回 200+数据 → 认证绕过",
                "victim_index": i,
            })
    return findings


async def probe_token_userid_binding(
    http: Callable[..., Awaitable[dict[str, Any]]],
    base: str,
    token: str,
    victim_ids: list[str],
    *,
    userid_param: str = "userid",
) -> list[dict[str, Any]]:
    """同 token 内替换 userid 参数遍历 victim，200 + 业务成功 → 认证绕过。

    Args:
        http: async callable，签名 http(url, *, headers=None, params=None) -> resp_dict
        base: 基础 URL
        token: 待测 token
        victim_ids: 待遍历的 victim userid 列表
        userid_param: userid 参数名
    """
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    self_resp = await http(base, headers=headers, params={userid_param: victim_ids[0]} if victim_ids else {})

    victim_resps: list[dict[str, Any]] = []
    for vid in victim_ids:
        vresp = await http(base, headers=headers, params={userid_param: vid})
        victim_resps.append(vresp)

    return evaluate_token_userid_binding(self_resp, victim_resps)


async def probe_oauth_client_credentials(
    http: Callable[..., Awaitable[dict[str, Any]]],
    token_url: str,
    client_id: str,
    *,
    client_secret: str = "",
) -> dict[str, Any]:
    """OAuth client 凭证流探测：用 client_id+secret 换 token。

    Returns:
        {"obtained": bool, "token": str|None, "risk": str}
    """
    resp = await http(token_url, headers={"Content-Type": "application/x-www-form-urlencoded"},
                      params={"grant_type": "client_credentials", "client_id": client_id,
                              "client_secret": client_secret})
    status = resp.get("http_code") or resp.get("status") or 0
    body = resp.get("body") or resp.get("data") or ""
    obtained = int(status) == 200 and "access_token" in str(body)
    return {
        "obtained": obtained,
        "token": str(body).split("access_token")[1].split('"')[1] if obtained and "access_token" in str(body) else None,
        "risk": "client_credentials_flow_exposed" if obtained else "none",
    }


def derive_primary_credential(token_only: str, cookie_only: str) -> str:
    """主认证因子推导（§2.6.6 G-T6）。

    token_only == ACCESS & cookie_only == DENIED → 主因子 = Token（不报绕过）
    token_only == DENIED & cookie_only == ACCESS → 主因子 = Cookie
    两者都 ACCESS → Both；两者都 DENIED → Unknown

    Args:
        token_only: 仅 token 无 cookie 时的结果（"ACCESS"/"DENIED"/"PARTIAL"）
        cookie_only: 仅 cookie 无 token 时的结果
    """
    tok_ok = token_only.upper() == "ACCESS"
    cook_ok = cookie_only.upper() == "ACCESS"
    tok_denied = token_only.upper() == "DENIED"
    cook_denied = cookie_only.upper() == "DENIED"

    if tok_ok and cook_denied:
        return PRIMARY_TOKEN
    if cook_ok and tok_denied:
        return PRIMARY_COOKIE
    if tok_ok and cook_ok:
        return PRIMARY_BOTH
    return PRIMARY_UNKNOWN


def detect_token_expiry(resp: dict[str, Any]) -> bool:
    """令牌过期检测（code=-100 / 401 / 419 / 440）→ 触发单飞续期。"""
    code = resp.get("code") or resp.get("retCode") or resp.get("business_code")
    if code is not None:
        try:
            if int(code) in TOKEN_EXPIRED_CODES:
                return True
        except (TypeError, ValueError):
            pass
    status = resp.get("http_code") or resp.get("status") or 0
    try:
        if int(status) in (401, 419, 440):
            return True
    except (TypeError, ValueError):
        pass
    return False


__all__ = [
    "evaluate_token_userid_binding",
    "probe_token_userid_binding",
    "probe_oauth_client_credentials",
    "derive_primary_credential",
    "detect_token_expiry",
    "CWE_AUTH_BYPASS",
    "CWE_IDOR_AUTHZ",
    "PRIMARY_TOKEN",
    "PRIMARY_COOKIE",
]
