"""端点信息识别包（domain × interface 骨架底座）。

模块：
  - risk_domain：8 风险域识别 + 多域并集 + 端点打标（G1）
  - surface_inventory：接口面完整度盘点（G2）
"""
from __future__ import annotations

from .risk_domain import (
    RISK_DOMAIN_RULES,
    DOMAIN_LIST,
    DOMAIN_LABELS,
    classify_risk_domain,
    tag_endpoints,
    group_by_risk_domain,
)

__all__ = [
    "RISK_DOMAIN_RULES",
    "DOMAIN_LIST",
    "DOMAIN_LABELS",
    "classify_risk_domain",
    "tag_endpoints",
    "group_by_risk_domain",
]
