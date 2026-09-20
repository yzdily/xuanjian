"""
core/loops/weakpwd_verify.py — 弱口令核验 + 登录成功三态（§2.6.6 防漏报护城河）。

## 为什么需要（grep 核验）
玄鉴 `rules/weak_password.yaml` 仅静态规则库（默认凭据/空口令/常见弱口令），
`core/fast_scanner/_checks_auth.py` 仅"命中即报"，缺：
- 登录成功三态核验（success / redirect_fake / blocked）→ 把 302 重定向误判为登录成功
- 弱口令覆盖矩阵（默认凭据 × 空口令 × 常见弱口令 三类覆盖率门禁）
- 凭证泄漏检测（登录成功后响应含明文密码 → CWE-200）

弱口令核验是漏报护城河的鉴权面闸：误判登录成功=假阳性，漏判登录成功=漏报。
本模块补齐：
1. `classify_login_result` — 登录成功三态（success / redirect_fake / blocked）
2. `verify_weakpwd_coverage` — 弱口令覆盖矩阵门禁（三类 ≥ 阈值 → pass）
3. `detect_credential_leak` — 登录成功后响应含明文凭证 → CWE-200

## 复用
- `rules/weak_password.yaml`（静态弱口令规则库）
- `core/auth_probe.is_auth_blocked`（认证拦截页判定）
- 上层 LOOP 编排负责发登录请求 + 收集响应，本模块仅做核验判定

## 零依赖
纯 stdlib；不模块级 import httpx/fastapi。参数为可注入 dict（测试 mock）。
"""
from __future__ import annotations

from typing import Any

# CWE 映射
CWE_WEAK_PASSWORD = "CWE-521"   # Weak Password Requirements
CWE_DEFAULT_CREDS = "CWE-798"   # Use of Hard-coded Credentials
CWE_INFO_EXPOSURE = "CWE-200"   # Information Exposure（明文凭证泄露）

# 登录成功三态
LOGIN_SUCCESS = "success"           # 真登录成功（token/session + 成功标志）
LOGIN_REDIRECT_FAKE = "redirect_fake"  # 302 重定向假成功（非真登录）
LOGIN_BLOCKED = "blocked"           # 登录被拒（401/403 + 失败标志）

# 弱口令三类（与 rules/weak_password.yaml 对齐）
WEAKPWD_DEFAULT = "default_creds"   # 默认凭据（admin/admin）
WEAKPWD_EMPTY = "empty_password"   # 空口令（admin/""）
WEAKPWD_COMMON = "common_weak"      # 常见弱口令（admin/12345678）

# 登录成功标志（响应体含这些 → 真成功）
SUCCESS_SIGNALS = (
    "token", "access_token", "session",
    "login success", "登录成功",
    '"code":0', '"code": 0',
    '"success":true', '"success": true',
)

# 登录失败标志（响应体含这些 → 被拒）
FAILURE_SIGNALS = (
    "error", "fail", "invalid", "wrong", "incorrect",
    "失败", "错误", "密码不正确",
    "username or password",
)

# 明文凭证指纹（登录成功后响应含这些 → CWE-200）
CREDENTIAL_LEAK_HINTS = ("password", "passwd", "credential", "secret", "pwd")

# 覆盖率门禁阈值：三类弱口令测试覆盖率 ≥ 此值 → pass
COVERAGE_THRESHOLD = 0.6


def _http_status(resp: dict[str, Any]) -> int:
    """统一取 http 状态码（兼容 http_code/status 字段，非数字→0）。"""
    status = resp.get("http_code") or resp.get("status") or 0
    try:
        return int(status)
    except (TypeError, ValueError):
        return 0


def _body_str(resp: dict[str, Any]) -> str:
    """取响应体字符串（小写）。"""
    body = resp.get("body") or resp.get("data") or ""
    return str(body).lower()


def classify_login_result(login_resp: dict[str, Any]) -> dict[str, Any]:
    """登录成功三态核验（success / redirect_fake / blocked）。

    核验核心：区分真登录成功与 302 重定向假成功。
    - 200 + 成功标志（token/session）→ success（真登录成功）
    - 302/301 重定向 → redirect_fake（非真成功，防误报）
    - 401/403 + 失败标志 → blocked（被拒）

    Args:
        login_resp: 登录请求响应（含 http_code/status + body/data）

    Returns:
        {
            "result": str,       # success / redirect_fake / blocked
            "cwe": str | None,  # success → CWE-521/CWE-798（由上层按凭据类型定）
            "evidence": str,
        }
    """
    status = _http_status(login_resp)
    body = _body_str(login_resp)

    # 302/301 重定向 → 假成功（非真登录，防误报）
    if status in (301, 302, 303, 307, 308):
        return {
            "result": LOGIN_REDIRECT_FAKE,
            "cwe": None,
            "evidence": f"HTTP {status} 重定向 → 非真登录成功（redirect_fake）",
        }

    # 401/403 + 失败标志 → 被拒
    if status in (401, 403):
        return {
            "result": LOGIN_BLOCKED,
            "cwe": None,
            "evidence": f"HTTP {status} → 登录被拒（blocked）",
        }

    # 200 + 成功标志 → 真登录成功
    if status == 200:
        if any(sig in body for sig in SUCCESS_SIGNALS):
            return {
                "result": LOGIN_SUCCESS,
                "cwe": CWE_WEAK_PASSWORD,
                "evidence": "HTTP 200 + 成功标志(token/session) → 真登录成功(CWE-521)",
            }
        # 200 但无成功标志 + 含失败标志 → 被拒
        if any(sig in body for sig in FAILURE_SIGNALS):
            return {
                "result": LOGIN_BLOCKED,
                "cwe": None,
                "evidence": "HTTP 200 但含失败标志 → 登录被拒（blocked）",
            }
        # 200 无标志 → 不确定，保守判 blocked（防误报）
        return {
            "result": LOGIN_BLOCKED,
            "cwe": None,
            "evidence": "HTTP 200 但无成功/失败标志 → 保守判 blocked（防误报）",
        }

    # 其他状态 → 被拒
    return {
        "result": LOGIN_BLOCKED,
        "cwe": None,
        "evidence": f"HTTP {status} → 登录被拒（blocked）",
    }


def verify_weakpwd_coverage(
    tested_categories: set[str],
    threshold: float = COVERAGE_THRESHOLD,
) -> dict[str, Any]:
    """弱口令覆盖矩阵门禁（三类 ≥ 阈值 → pass）。

    覆盖闸：默认凭据/空口令/常见弱口令 三类是否都测了。
    - 只测 admin/admin → 覆盖率 1/3 → fail（漏报空口令/常见弱口令）
    - 三类全测 → 覆盖率 3/3 → pass

    Args:
        tested_categories: 已测弱口令类别集合（含 default_creds/empty_password/common_weak）
        threshold: 覆盖率门禁阈值（默认 0.6，即至少测 2/3 类）

    Returns:
        {
            "pass": bool,
            "coverage": float,
            "tested": list[str],     # 已测类别
            "missing": list[str],   # 未测类别（漏报风险）
            "evidence": str,
        }
    """
    all_categories = {WEAKPWD_DEFAULT, WEAKPWD_EMPTY, WEAKPWD_COMMON}
    tested = tested_categories & all_categories
    missing = all_categories - tested
    coverage = len(tested) / len(all_categories)
    passed = coverage >= threshold

    evidence = (
        f"已测={sorted(tested)} 未测={sorted(missing)} "
        f"覆盖率={coverage:.0%} {'≥' if passed else '<'} 阈值 {threshold:.0%} "
        f"→ {'pass' if passed else 'fail（漏报未测类别）'}"
    )
    return {
        "pass": passed,
        "coverage": coverage,
        "tested": sorted(tested),
        "missing": sorted(missing),
        "evidence": evidence,
    }


def detect_credential_leak(login_resp: dict[str, Any]) -> dict[str, Any]:
    """登录成功后响应含明文凭证 → CWE-200。

    漏报护城河：登录成功不仅报弱口令，若响应还回显了明文密码/凭证，
    须额外报信息泄露（CWE-200），否则只报弱口令 = 漏报凭证泄露。

    Args:
        login_resp: 登录请求响应（含 http_code/status + body/data）

    Returns:
        {
            "leaked": bool,
            "cwe": str | None,
            "evidence": str,
        }
    """
    body = _body_str(login_resp)
    # 响应体含明文凭证指纹 → CWE-200
    leaked_hints = [h for h in CREDENTIAL_LEAK_HINTS if h in body]
    if leaked_hints:
        return {
            "leaked": True,
            "cwe": CWE_INFO_EXPOSURE,
            "evidence": f"登录响应含明文凭证指纹({leaked_hints}) → 信息泄露(CWE-200)",
        }
    return {
        "leaked": False,
        "cwe": None,
        "evidence": "登录响应无明文凭证指纹",
    }


def evaluate_weakpwd_chain(
    login_resp: dict[str, Any],
    cred_category: str = WEAKPWD_DEFAULT,
) -> dict[str, Any]:
    """弱口令核验全链：登录三态 + 凭证泄露 聚合判定。

    链式核验：一次登录请求同时产出 弱口令(CWE-521) + 凭证泄露(CWE-200)。
    - success + 无泄露 → CWE-521（弱口令）
    - success + 有泄露 → CWE-521 + CWE-200（弱口令 + 凭证泄露）
    - redirect_fake / blocked → 无 finding

    Args:
        login_resp: 登录请求响应
        cred_category: 凭据类别（default_creds/empty_password/common_weak）

    Returns:
        {
            "findings": list[dict],   # 每条含 rule/cwe/severity/evidence
            "result": str,            # 登录三态
            "leaked": bool,           # 是否凭证泄露
        }
    """
    findings: list[dict[str, Any]] = []

    login = classify_login_result(login_resp)
    leak = detect_credential_leak(login_resp)

    # 登录成功 → 弱口令 finding
    if login["result"] == LOGIN_SUCCESS:
        cwe = CWE_DEFAULT_CREDS if cred_category == WEAKPWD_DEFAULT else CWE_WEAK_PASSWORD
        findings.append({
            "rule": "weak_password",
            "cwe": cwe,
            "severity": "High",
            "evidence": login["evidence"],
        })

        # 凭证泄露 → 额外 finding
        if leak["leaked"]:
            findings.append({
                "rule": "credential_leak_in_login",
                "cwe": CWE_INFO_EXPOSURE,
                "severity": "High",
                "evidence": leak["evidence"],
            })

    return {
        "findings": findings,
        "result": login["result"],
        "leaked": leak["leaked"],
    }


__all__ = [
    "classify_login_result",
    "verify_weakpwd_coverage",
    "detect_credential_leak",
    "evaluate_weakpwd_chain",
    "CWE_WEAK_PASSWORD",
    "CWE_DEFAULT_CREDS",
    "CWE_INFO_EXPOSURE",
    "LOGIN_SUCCESS",
    "LOGIN_REDIRECT_FAKE",
    "LOGIN_BLOCKED",
    "WEAKPWD_DEFAULT",
    "WEAKPWD_EMPTY",
    "WEAKPWD_COMMON",
    "COVERAGE_THRESHOLD",
]
