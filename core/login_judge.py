"""F3 — 登录判定三重校验铁律（0901 P0-A 教训落地）。

失败响应也会下发 SESSION cookie，仅凭 cookie 存在 → 假阳性。
zhinenjqr 1176 个弱口令误报根因即此。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LoginJudgeResult:
    success: bool
    reason: str = ""
    matched_conditions: list[str] = field(default_factory=list)


def attempt_login(
    result: dict[str, Any],
    fail_url_pattern: str | None = None,
    required_cookies: set[str] | None = None,
    success_hints: list[str] | None = None,
) -> LoginJudgeResult:
    """三重校验判定登录是否成功。

    条件 1: 最终 URL 不含错误标志（error=true / login / 401）
    条件 2: 必须持有完整 Cookie 集（required_cookies 全命中）
    条件 3: body 命中成功关键词（辅助）
    """
    final_url = str(result.get("final_url", ""))
    set_cookies = set(result.get("set_cookies", []))
    body_lower = str(result.get("body", "")).lower()
    matched: list[str] = []

    # 条件 1: URL 不含失败标志
    if fail_url_pattern:
        if re.search(fail_url_pattern, final_url, re.IGNORECASE):
            return LoginJudgeResult(
                success=False,
                reason=f"URL 含失败标志: {final_url}",
            )
    if "login" in final_url.lower() and "error" in final_url.lower():
        return LoginJudgeResult(
            success=False,
            reason=f"URL 含 login+error: {final_url}",
        )
    matched.append("url_clean")

    # 条件 2: required_cookies 全命中
    if required_cookies:
        present = {c.lower() for c in set_cookies}
        needed = {c.lower() for c in required_cookies}
        missing = needed - present
        if missing:
            return LoginJudgeResult(
                success=False,
                reason=f"缺少 Cookie: {missing}",
            )
        matched.append("cookies_complete")

    # 条件 3: body 命中成功关键词
    if success_hints:
        hints_lower = [h.lower() for h in success_hints]
        if not any(h in body_lower for h in hints_lower):
            return LoginJudgeResult(
                success=False,
                reason="body 未命中任何成功关键词",
            )
        matched.append("body_hint_matched")

    return LoginJudgeResult(success=True, reason="三重校验通过", matched_conditions=matched)


__all__ = ["attempt_login", "LoginJudgeResult"]
