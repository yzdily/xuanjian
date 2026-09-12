"""core.finding_schema — Finding JSON schema 校验（中期 M2）。

按 XUANJIAN_ROADMAP_MID_TERM §3.3 落地，但**重写 30 行手写校验器**，零 jsonschema 依赖。
理由：守住 v1.6 / 0827 / 短中长期"零外部依赖优先"红线。
"""
from __future__ import annotations

import re

# 必填字段
REQUIRED = ("id", "owasp_id", "cwe_id", "severity", "endpoint", "method", "verdict")

# 枚举类
OWASP_VALUES = {f"A0{i}" for i in range(1, 10)} | {"A10"}
SEVERITY_VALUES = {"critical", "high", "medium", "low", "info"}
METHOD_VALUES = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
VERDICT_VALUES = {
    "confirmed", "preliminary", "rejected",
    "waf_blocked", "waf_silently_stripped", "passed_waf",
}

# 正则
ID_RE = re.compile(r"^F-\d+$")
CWE_RE = re.compile(r"^CWE-\d+$")


def _fail(msg: str) -> tuple[bool, str]:
    return False, f"schema 不符: {msg}"


def _ok() -> tuple[bool, str]:
    return True, "ok"


def validate(finding: dict) -> tuple[bool, str]:
    """校验 finding 是否符合 schema。

    Returns:
        (ok, msg): ok=True 表示通过
    """
    if not isinstance(finding, dict):
        return _fail("finding 不是 dict")

    # 1. 必填字段
    miss = [k for k in REQUIRED if k not in finding]
    if miss:
        return _fail(f"缺必填字段: {miss}")

    # 2. id 格式
    fid = finding["id"]
    if not isinstance(fid, str) or not ID_RE.match(fid):
        return _fail(f"id 格式不符 (需 ^F-\\d+$): {fid!r}")

    # 3. owasp_id
    if finding["owasp_id"] not in OWASP_VALUES:
        return _fail(f"owasp_id 非法: {finding['owasp_id']!r}")

    # 4. cwe_id 格式
    cwe = finding["cwe_id"]
    if not isinstance(cwe, str) or not CWE_RE.match(cwe):
        return _fail(f"cwe_id 格式不符 (需 ^CWE-\\d+$): {cwe!r}")

    # 5. severity
    if finding["severity"] not in SEVERITY_VALUES:
        return _fail(f"severity 非法: {finding['severity']!r}")

    # 6. endpoint 非空
    ep = finding["endpoint"]
    if not isinstance(ep, str) or not ep:
        return _fail("endpoint 非空字符串")

    # 7. method
    if finding["method"] not in METHOD_VALUES:
        return _fail(f"method 非法: {finding['method']!r}")

    # 8. verdict
    if finding["verdict"] not in VERDICT_VALUES:
        return _fail(f"verdict 非法: {finding['verdict']!r}")

    return _ok()


def guard_llm_output(raw_finding: dict) -> dict:
    """LLM 编排产生的 finding 校验：未通过标 rejected（不抛异常）。

    Args:
        raw_finding: LLM 产出的原始 finding

    Returns:
        校验后的 finding（不通过则 verdict 改 rejected + 加 rejection_reasons）
    """
    finding = dict(raw_finding)
    ok, msg = validate(finding)
    if ok:
        return finding
    finding["verdict"] = "rejected"
    finding["rejection_reasons"] = [msg]
    return finding


__all__ = ["validate", "guard_llm_output", "REQUIRED", "OWASP_VALUES", "SEVERITY_VALUES"]
