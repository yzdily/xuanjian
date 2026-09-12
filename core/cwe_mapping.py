"""CWE 映射表 — 统一「发现 → CWE → 定级」映射（优化.md 建议5）。

每个漏洞类型映射到 MITRE CWE 编号 + 官网链接 + 默认定级，避免 CWE-200 乱用。
设计为纯函数模块，无副作用，可被 compliance_report / render / harm_validation 复用。

参考：api-pentest-extension/skills/api-pentest-workflow/cwe_mapping.md
"""

from __future__ import annotations

import re
from typing import Any

# 漏洞类型 -> (CWE 编号, CWE 名称, MITRE URL, 默认定级)
# 默认定级仅作兜底；真实定级以 severity_rules 四维模型为准。
CWE_MAPPING: dict[str, tuple[str, str, str, str]] = {
    # 注入类
    "SQL注入":        ("CWE-89",  "SQL Injection",                     "https://cwe.mitre.org/data/definitions/89.html",   "High"),
    "命令注入":       ("CWE-78",  "OS Command Injection",              "https://cwe.mitre.org/data/definitions/78.html",   "High"),
    "SSTI":           ("CWE-1336", "Server-Side Template Injection",   "https://cwe.mitre.org/data/definitions/1336.html", "High"),
    "XXE":            ("CWE-611", "XML External Entity Reference",     "https://cwe.mitre.org/data/definitions/611.html",  "High"),
    "CRLF注入":       ("CWE-93",  "CRLF Injection",                    "https://cwe.mitre.org/data/definitions/93.html",   "Medium"),
    "表达式注入":     ("CWE-917", "Expression Language Injection",      "https://cwe.mitre.org/data/definitions/917.html",  "High"),
    # 客户端
    "XSS":            ("CWE-79",  "XSS",                               "https://cwe.mitre.org/data/definitions/79.html",   "Medium"),
    "CSRF":           ("CWE-352", "CSRF",                              "https://cwe.mitre.org/data/definitions/352.html",  "Medium"),
    "CORS配置错误":   ("CWE-942", "Permissive CORS Policy",            "https://cwe.mitre.org/data/definitions/942.html",  "Medium"),
    "点击劫持":       ("CWE-1021", "Clickjacking",                    "https://cwe.mitre.org/data/definitions/1021.html", "Low"),
    # 访问控制 / 认证
    "未授权访问":     ("CWE-306", "Missing Authentication for Critical Function", "https://cwe.mitre.org/data/definitions/306.html", "High"),
    "IDOR":           ("CWE-639", "IDOR / BOLA",                       "https://cwe.mitre.org/data/definitions/639.html",  "High"),
    "越权":           ("CWE-862", "Missing Authorization",             "https://cwe.mitre.org/data/definitions/862.html",  "High"),
    "认证绕过":       ("CWE-287", "Improper Authentication",           "https://cwe.mitre.org/data/definitions/287.html",  "High"),
    "弱口令":         ("CWE-521", "Weak Password Requirements",        "https://cwe.mitre.org/data/definitions/521.html",  "High"),
    "限流缺失":       ("CWE-307", "Missing Rate Limiting",            "https://cwe.mitre.org/data/definitions/307.html",  "Medium"),
    # 信息泄露 / 文件
    "信息泄露":       ("CWE-200", "Information Exposure",             "https://cwe.mitre.org/data/definitions/200.html",  "Medium"),
    "敏感文件泄露":   ("CWE-538", "File Info Exposure",               "https://cwe.mitre.org/data/definitions/538.html",  "Medium"),
    "目录穿越":       ("CWE-22",  "Path Traversal",                    "https://cwe.mitre.org/data/definitions/22.html",   "High"),
    "文件上传":       ("CWE-434", "Unrestricted File Upload",          "https://cwe.mitre.org/data/definitions/434.html",  "High"),
    # SSRF / 请求伪造
    "SSRF":           ("CWE-918", "SSRF",                              "https://cwe.mitre.org/data/definitions/918.html",  "High"),
    "SSRF_OOB":       ("CWE-918", "SSRF (OOB)",                        "https://cwe.mitre.org/data/definitions/918.html",  "High"),
    "HTTP请求走私":   ("CWE-444", "HTTP Request Smuggling",            "https://cwe.mitre.org/data/definitions/444.html",  "High"),
    "开放重定向":     ("CWE-601", "Open Redirect",                     "https://cwe.mitre.org/data/definitions/601.html",  "Medium"),
    # 业务逻辑
    "业务逻辑":       ("CWE-840", "Business Logic Errors",             "https://cwe.mitre.org/data/definitions/840.html",  "Medium"),
    "竞态条件":       ("CWE-362", "Race Condition",                    "https://cwe.mitre.org/data/definitions/362.html",  "Medium"),
}

# 别名 / 模糊关键词 -> 标准漏洞类型（处理 LLM/扫描器命名差异）
_ALIASES: list[tuple[str, str]] = [
    ("sql", "SQL注入"), ("sqli", "SQL注入"),
    ("xss", "XSS"), ("跨站脚本", "XSS"),
    ("csrf", "CSRF"), ("跨站请求", "CSRF"),
    ("ssrf", "SSRF"),
    ("xxe", "XXE"),
    ("ssti", "SSTI"), ("模板注入", "SSTI"),
    ("cors", "CORS配置错误"),
    ("命令注入", "命令注入"), ("command", "命令注入"), ("rce", "命令注入"),
    ("未授权", "未授权访问"), ("unauth", "未授权访问"),
    ("idor", "IDOR"), ("bola", "IDOR"), ("越权", "越权"),
    ("认证绕过", "认证绕过"), ("auth.bypass", "认证绕过"),
    ("弱口令", "弱口令"), ("weak.password", "弱口令"), ("弱密码", "弱口令"),
    ("信息泄露", "信息泄露"), ("info.disclosure", "信息泄露"), ("敏感文件", "敏感文件泄露"),
    ("目录穿越", "目录穿越"), ("path.traversal", "目录穿越"), ("lfi", "目录穿越"),
    ("文件上传", "文件上传"), ("upload", "文件上传"),
    ("竞态", "竞态条件"), ("race", "竞态条件"),
    ("业务逻辑", "业务逻辑"), ("logic", "业务逻辑"),
    ("开放重定向", "开放重定向"), ("redirect", "开放重定向"),
    ("请求走私", "HTTP请求走私"), ("smuggl", "HTTP请求走私"),
    ("限流", "限流缺失"), ("rate.limit", "限流缺失"),
]


def normalize_vuln_type(vuln_type: str) -> str:
    """把任意命名的漏洞类型归一到 CWE_MAPPING 的标准键。

    优先精确匹配，其次按别名关键词模糊匹配，匹配不到返回原值。
    """
    if not vuln_type:
        return ""
    if vuln_type in CWE_MAPPING:
        return vuln_type
    low = vuln_type.lower()
    for keyword, canonical in _ALIASES:
        if keyword in low:
            return canonical
    return vuln_type


def lookup_cwe(vuln_type: str) -> dict[str, str]:
    """返回漏洞类型的 CWE 信息。

    Returns:
        {"cwe_id", "cwe_name", "cwe_url", "default_severity"}；
        匹配不到时 cwe_id 为空字符串（不乱用 CWE-200）。
    """
    key = normalize_vuln_type(vuln_type)
    entry = CWE_MAPPING.get(key)
    if not entry:
        return {"cwe_id": "", "cwe_name": "", "cwe_url": "", "default_severity": ""}
    cwe_id, cwe_name, cwe_url, default_sev = entry
    return {
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "cwe_url": cwe_url,
        "default_severity": default_sev,
    }


def enrich_finding_with_cwe(finding: dict) -> dict:
    """给一个 finding/vuln 字典就地补上 CWE 字段，并返回该字典。

    幂等：已有 cwe_id 时不覆盖。
    """
    if not isinstance(finding, dict):
        return finding
    if finding.get("cwe_id"):
        return finding
    info = lookup_cwe(finding.get("vuln_type", "") or finding.get("type", ""))
    finding["cwe_id"] = info["cwe_id"]
    finding["cwe_name"] = info["cwe_name"]
    finding["cwe_url"] = info["cwe_url"]
    if not finding.get("severity") and info["default_severity"]:
        finding["severity"] = info["default_severity"]
    return finding


def enrich_findings(findings: list[dict]) -> list[dict]:
    """批量补 CWE 字段。"""
    return [enrich_finding_with_cwe(f) for f in findings]
