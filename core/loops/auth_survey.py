"""
core/loops/auth_survey.py — 鉴权面普查 + 覆盖率门禁（§2.6.6 防漏报护城河）。

## 为什么需要（grep 核验）
玄鉴 `core/auth_probe.py`（F2）仅做"token 过期探活"单点检测，
`core/double_identity_matrix.py`（F9）仅双身份静态对照，缺：
- 鉴权面普查：未系统枚举"需鉴权接口"清单 → 漏测未授权访问面
- 覆盖率门禁：未校验"已发现接口是否全部做过鉴权测试" → 漏报
- 鉴权状态分类：未区分 no-auth-required / auth-required / auth-missing 三态

鉴权面普查是漏报护城河的覆盖闸：未普查 = 不知道有哪些接口需鉴权 = 漏报。
本模块补齐：
1. `classify_auth_surface` — 鉴权面三态分类（no_auth / auth_required / auth_missing）
2. `survey_coverage` — 普查覆盖率门禁（已测/应测 ≥ 阈值 → pass，否则 fail）
3. `identify_untested` — 识别未做鉴权测试的接口（漏报风险点）

## 复用
- `core/auth_probe.py`（F2 探活）
- `core/loops/idor_probe.py`（越权测试）
- `core/loops/coverage_gate.py`（覆盖率门禁基线）
- 上层 LOOP 编排负责拉取接口清单 + 鉴权探测响应，本模块仅做普查判定

## 零依赖
纯 stdlib；不模块级 import httpx/fastapi。参数为可注入 dict（测试 mock）。
"""
from __future__ import annotations

from typing import Any

# CWE 映射
CWE_MISSING_AUTHZ = "CWE-862"  # Missing Authorization（鉴权面漏报关联）

# 鉴权面三态
SURFACE_NO_AUTH = "no_auth_required"      # 公开接口，无需鉴权（如 /login /health）
SURFACE_AUTH_REQUIRED = "auth_required"   # 需鉴权接口（业务接口）
SURFACE_AUTH_MISSING = "auth_missing"     # 应鉴权但未鉴权 → 漏洞（未授权可访问）

# 覆盖率门禁阈值：已测鉴权接口 / 应测鉴权接口 ≥ 此值 → pass
COVERAGE_THRESHOLD = 0.8

# 公开接口指纹（无需鉴权，不应计入鉴权面漏报）
PUBLIC_ENDPOINT_HINTS = (
    "/login", "/signin", "/register", "/health", "/healthcheck",
    "/swagger", "/v2/api-docs", "/v3/api-docs", "/openapi",
    "/favicon", "/static", "/public", "/robots.txt",
)


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


def _is_public_endpoint(url: str) -> bool:
    """接口是否为公开接口（无需鉴权，如 /login /health）。"""
    if not url:
        return False
    url_lower = url.lower()
    return any(hint in url_lower for hint in PUBLIC_ENDPOINT_HINTS)


def classify_auth_surface(
    url: str,
    notoken_resp: dict[str, Any],
) -> dict[str, Any]:
    """鉴权面三态分类（no_auth / auth_required / auth_missing）。

    普查核心：对每个接口发无 token 请求，按响应分类：
    - 公开接口（/login /health）→ no_auth_required（不计漏报）
    - 无 token 返回 401/403 → auth_required（鉴权生效）
    - 无 token 返回 200+数据 → auth_missing（未授权可访问 → 漏洞）

    Args:
        url: 接口 URL
        notoken_resp: 无 token 请求的响应（含 http_code/status + body/data）

    Returns:
        {
            "surface": str,       # no_auth_required / auth_required / auth_missing
            "cwe": str | None,   # auth_missing → CWE-862
            "evidence": str,
        }
    """
    # 公开接口 → 无需鉴权
    if _is_public_endpoint(url):
        return {
            "surface": SURFACE_NO_AUTH,
            "cwe": None,
            "evidence": f"公开接口({url}) → 无需鉴权",
        }

    status = _http_status(notoken_resp)

    # 401/403 → 鉴权生效
    if status in (401, 403):
        return {
            "surface": SURFACE_AUTH_REQUIRED,
            "cwe": None,
            "evidence": f"无 token 返回 {status} → 鉴权生效",
        }

    # 200 + 数据 → 未授权可访问 → 漏洞
    if status == 200 and _has_data(notoken_resp):
        return {
            "surface": SURFACE_AUTH_MISSING,
            "cwe": CWE_MISSING_AUTHZ,
            "evidence": f"无 token 返回 200+数据 → 未授权可访问(CWE-862)",
        }

    # 其他状态（404/500/302）→ 视为需鉴权（保守，计入应测）
    return {
        "surface": SURFACE_AUTH_REQUIRED,
        "cwe": None,
        "evidence": f"无 token 返回 {status} → 视为需鉴权（保守）",
    }


def survey_coverage(
    endpoints: list[dict[str, Any]],
    tested_urls: set[str] | None = None,
    threshold: float = COVERAGE_THRESHOLD,
) -> dict[str, Any]:
    """普查覆盖率门禁（已测鉴权 / 应测鉴权 ≥ 阈值 → pass）。

    门禁核心：应测鉴权的接口是否都做了鉴权测试。
    - 应测 = auth_required + auth_missing（不含 no_auth_required 公开接口）
    - 已测 = tested_urls 中匹配应测接口的
    - 覆盖率 < 阈值 → fail（存在漏报风险）

    Args:
        endpoints: 接口普查结果列表（每项含 url + surface 字段）
        tested_urls: 已做鉴权测试的 URL 集合
        threshold: 覆盖率门禁阈值（默认 0.8）

    Returns:
        {
            "pass": bool,             # 覆盖率 ≥ 阈值
            "coverage": float,        # 覆盖率
            "should_test": int,       # 应测数
            "tested": int,            # 已测数
            "evidence": str,
        }
    """
    if tested_urls is None:
        tested_urls = set()

    # 应测鉴权的接口（auth_required + auth_missing）
    should_test = [
        ep for ep in endpoints
        if ep.get("surface") in (SURFACE_AUTH_REQUIRED, SURFACE_AUTH_MISSING)
    ]
    should_test_count = len(should_test)

    if should_test_count == 0:
        return {
            "pass": True,
            "coverage": 1.0,
            "should_test": 0,
            "tested": 0,
            "evidence": "无需鉴权测试的接口 → 覆盖率门禁 pass",
        }

    # 已测：应测接口的 url 在 tested_urls 中
    tested_count = sum(
        1 for ep in should_test
        if ep.get("url") in tested_urls
    )
    coverage = tested_count / should_test_count
    passed = coverage >= threshold

    evidence = (
        f"应测={should_test_count} 已测={tested_count} "
        f"覆盖率={coverage:.0%} {'≥' if passed else '<'} 阈值 {threshold:.0%} "
        f"→ {'pass' if passed else 'fail（存在漏报风险）'}"
    )
    return {
        "pass": passed,
        "coverage": coverage,
        "should_test": should_test_count,
        "tested": tested_count,
        "evidence": evidence,
    }


def identify_untested(
    endpoints: list[dict[str, Any]],
    tested_urls: set[str] | None = None,
) -> list[dict[str, Any]]:
    """识别未做鉴权测试的接口（漏报风险点）。

    漏报定位：应测鉴权但未测的接口清单，供上层补测。

    Args:
        endpoints: 接口普查结果列表（每项含 url + surface 字段）
        tested_urls: 已做鉴权测试的 URL 集合

    Returns:
        未测接口列表（含 url + surface + cwe）
    """
    if tested_urls is None:
        tested_urls = set()

    untested = []
    for ep in endpoints:
        surface = ep.get("surface")
        url = ep.get("url", "")
        # 仅应测接口（auth_required + auth_missing）未测才算漏报
        if surface in (SURFACE_AUTH_REQUIRED, SURFACE_AUTH_MISSING):
            if url not in tested_urls:
                untested.append({
                    "url": url,
                    "surface": surface,
                    "cwe": ep.get("cwe"),
                    "evidence": f"{url} 应测鉴权({surface})但未测 → 漏报风险",
                })
    return untested


__all__ = [
    "classify_auth_surface",
    "survey_coverage",
    "identify_untested",
    "CWE_MISSING_AUTHZ",
    "SURFACE_NO_AUTH",
    "SURFACE_AUTH_REQUIRED",
    "SURFACE_AUTH_MISSING",
    "COVERAGE_THRESHOLD",
    "PUBLIC_ENDPOINT_HINTS",
]
