"""域归属规则 — 权威源转发件（v3 §2.1 → v4 漂移修正）。

判定表与分类函数**不再复制**，直接从权威源 `core.endpoint.risk_domain`
（链式规则 v4 词表 A 源）导入——v4 §8 双实现对拍发现本文件的旧复制件已过期：
缺 Security 修正（"link"/"load" 过宽关键字移除——"load" 子串误命中 "upload"
产生 ssrf 假阳）、缺中文关键字、缺 query 截断。复制件已删除，单点维护。

与 64 域方案的关系：本表是归属层的稳定 8 域 vocab；64 域目录在 playbook 层
按域展开（authz 域 playbook 内含 IDOR/Mass Assignment/Batch Survey 等子类），
归属层不需要 64 域全表。
"""
from __future__ import annotations

import re

from core.endpoint.risk_domain import RISK_DOMAIN_RULES  # noqa: E402  权威源，原样导入
from core.endpoint.risk_domain import classify_risk_domain  # noqa: E402  判定复用，不重复实现

__all__ = [
    "RISK_DOMAIN_RULES",
    "RISK_DOMAINS",
    "classify_risk_domain",
    "group_by_risk_domain",
    "PHASE_ORDER",
    "DOMAIN_PHASE",
    "script_applies_to_endpoint",
    "is_write_endpoint",
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
