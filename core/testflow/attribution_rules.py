"""域归属规则 — bug-legacy RISK_DOMAIN_RULES 8 域复制件（v3 §2.1）。

来源：api-pentest-extension/skills/api-pentest-workflow/scripts/endpoint_analyzer.py:501-531
口径纪律：判定表照抄已验证实现（161 测试通过），只适配不改口径。

与 64 域方案的关系：本表是归属层的稳定 8 域 vocab；64 域目录在 playbook 层
按域展开（authz 域 playbook 内含 IDOR/Mass Assignment/Batch Survey 等子类），
归属层不需要 64 域全表。
"""
from __future__ import annotations

import re

__all__ = [
    "RISK_DOMAIN_RULES",
    "RISK_DOMAINS",
    "classify_risk_domain",
    "group_by_risk_domain",
    "PHASE_ORDER",
    "DOMAIN_PHASE",
    "script_applies_to_endpoint",
]

# bug-legacy §2 分类法（已落地 v1.0）：路径特征 → 归属域（多域并集）
RISK_DOMAIN_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("upload", ("upload", "uploads", "file", "files", "attachment", "attachments",
                "media", "import", "avatar", "头像", "oss", "s3")),
    ("ssrf", ("url", "fetch", "proxy", "webhook", "redirect", "callback",
              "link", "load", "remote")),
    ("injection", ("query", "search", "sql", "report", "export", "exec",
                   "cmd", "inject", "render", "template")),
    ("authz", ("user", "users", "order", "orders", "role", "roles", "admin",
               "permission", "account", "tenant", "org", "profile", "member",
               "customer", "agent", "dept")),
    ("csrf", ("conf", "config", "setting", "settings", "csrf", "token",
              "password", "reset", "oauth", "sso")),
    ("file", ("export", "download", "getfile", "path", "temp",
              "read", "document")),
    ("business", ("pay", "transfer", "stock", "coupon", "code", "batch", "recharge")),
    ("config", ("getparamconfiglist", "getconfig", "queryconfig", "actuator",
                "swagger", "rememberme", "env")),
]

# 8 域 vocab（vocab 完备性断言用）
RISK_DOMAINS: tuple[str, ...] = tuple(dom for dom, _ in RISK_DOMAIN_RULES)

# 域 → 相位序（engine PHASE_ORDER 调度；对齐 v3 §五映射）
PHASE_ORDER: list[str] = [
    "precheck", "authz", "csrf", "injection", "ssrf",
    "upload", "file", "business", "config", "recon",
]

DOMAIN_PHASE: dict[str, str] = {dom: dom for dom in RISK_DOMAINS}
DOMAIN_PHASE.update({"precheck": "precheck", "recon": "recon", "general": "authz"})

_STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
_WRITE_VERB_PATH = re.compile(
    r"/(create|add|update|delete|remove|edit|modify|save|submit|insert|import|upload)",
    re.IGNORECASE,
)


def classify_risk_domain(path: str, method: str = "GET") -> list[str]:
    """返回归属域列表（多域并集，去重保序）— bug-legacy §2.1 铁律。

    risk_domain 是列表而非单值：一个接口可同时命中多个域
    （如上传接口下载时弹 XSS → upload + file）。
    """
    p = (path or "").lower()
    matched = [dom for dom, kws in RISK_DOMAIN_RULES if any(k in p for k in kws)]
    if matched:
        return list(dict.fromkeys(matched))
    if str(method).upper() in _STATE_CHANGING_METHODS:
        return ["authz"]
    return ["general"]


def group_by_risk_domain(feature_points) -> dict[str, list]:
    """按 risk_domains 对功能点分组（轨道 A 编排用，多域重复入组）。"""
    groups: dict[str, list] = {}
    for fp in feature_points:
        domains = getattr(fp, "risk_domains", None) or ["general"]
        if isinstance(domains, str):
            domains = [domains]
        for d in domains:
            groups.setdefault(d, []).append(fp)
    return groups


def script_applies_to_endpoint(matchers: list[str], endpoint_chars: dict[str, bool]) -> bool:
    """布尔匹配内核 — bug-legacy endpoint_analyzer.py:473 逐字复制。

    matchers 任一命中即适用；"always" 恒真。
    """
    for matcher in matchers or ["always"]:
        if matcher == "always":
            return True
        if endpoint_chars.get(matcher, False):
            return True
    return False


def is_write_endpoint(method: str, path: str) -> bool:
    """写端点判定 — 0907 P0-2：状态变更方法 或 路径含写动词。"""
    m = (method or "GET").upper()
    return m in _STATE_CHANGING_METHODS or bool(_WRITE_VERB_PATH.search(path or ""))
