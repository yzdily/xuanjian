"""core.cwe_dict — OWASP Top 10 ↔ CWE 映射（中期 M2 配套）。

按 XUANJIAN_ROADMAP_MID_TERM §3.3 落地。
零外部依赖。
"""
from __future__ import annotations

# OWASP Top 10 2021 映射
OWASP_TO_CWE: dict[str, list[str]] = {
    "A01": ["CWE-284", "CWE-285", "CWE-862", "CWE-863"],  # Broken Access Control
    "A02": ["CWE-259", "CWE-287", "CWE-384"],              # Cryptographic Failures
    "A03": ["CWE-79", "CWE-89", "CWE-94"],                  # Injection（含 SQLi/XSS）
    "A04": ["CWE-20", "CWE-200", "CWE-352"],                # Insecure Design
    "A05": ["CWE-22", "CWE-59", "CWE-98"],                  # Security Misconfiguration
    "A06": ["CWE-1104", "CWE-829"],                         # Vulnerable Components
    "A07": ["CWE-307", "CWE-352", "CWE-862"],                # Auth Failures
    "A08": ["CWE-345", "CWE-352", "CWE-770"],                # Software & Data Integrity
    "A09": ["CWE-200", "CWE-209", "CWE-532"],                # Logging Failures
    "A10": ["CWE-918"],                                      # SSRF
}

# 反向：CWE -> OWASP（供反查）
CWE_TO_OWASP: dict[str, str] = {}
for _owasp, _cwes in OWASP_TO_CWE.items():
    for _cwe in _cwes:
        CWE_TO_OWASP.setdefault(_cwe, _owasp)


def validate_cwe(owasp_id: str, cwe_id: str) -> tuple[bool, str]:
    """检查 owasp_id 与 cwe_id 是否在标准映射内。

    Returns:
        (ok, msg): ok=True 表示映射合法
    """
    allowed = OWASP_TO_CWE.get(owasp_id, [])
    if cwe_id not in allowed:
        return False, f"OWASP {owasp_id} 不映射 {cwe_id}（允许: {allowed}）"
    return True, "ok"


__all__ = ["OWASP_TO_CWE", "CWE_TO_OWASP", "validate_cwe"]
