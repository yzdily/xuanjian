"""
core/loops/pii_grade.py — PII 字段分级（§2.6.4，对齐 tongye G-T4）。

## 分级口径
- `S1` 高敏：身份证 / 银行卡 / 密码 / 密钥 —— 明文出现 = high
- `S2` 中敏：手机号 / 邮箱 / 姓名
- `S3` 低敏：其他疑似个人信息
- `masked` 已脱敏（含 `****`）→ **降档**，不算明文泄露
- `empty` 空值 → 单列，不参与泄露判定
"""
from __future__ import annotations

import re

# 已脱敏特征：156****66 / 3201**********1234
_MASK_RE = re.compile(r"\*{2,}")

_S1_PATTERNS = (
    re.compile(r"\b\d{17}[\dXx]\b"),                  # 身份证
    re.compile(r"\b\d{16,19}\b"),                     # 银行卡
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api_?key)\s*[:=]\s*\S+"),
)

_S2_PATTERNS = (
    re.compile(r"\b1[3-9]\d{9}\b"),                   # 手机号
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),           # 邮箱
)


def grade_pii(field_value: str | None) -> str:
    """给单个字段值定 PII 等级。"""
    if field_value is None:
        return "empty"
    text = str(field_value).strip()
    if not text:
        return "empty"
    if _MASK_RE.search(text):
        return "masked"
    for pat in _S1_PATTERNS:
        if pat.search(text):
            return "S1"
    for pat in _S2_PATTERNS:
        if pat.search(text):
            return "S2"
    return "S3"


def severity_for(grade: str) -> str:
    """PII 等级 → 建议 severity（脱敏降档、空值不计）。"""
    return {
        "S1": "high",
        "S2": "medium",
        "S3": "low",
        "masked": "info",
        "empty": "info",
    }.get(grade, "info")


def grade_many(values: list[str] | None) -> dict[str, str]:
    """批量定级：返回 {原始值: 等级}。"""
    out: dict[str, str] = {}
    for v in values or []:
        out[str(v)] = grade_pii(v)
    return out


__all__ = ["grade_pii", "severity_for", "grade_many"]
