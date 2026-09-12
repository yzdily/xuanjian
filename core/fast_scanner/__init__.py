"""fast_scanner — 本地快速规则引擎（包入口）。

原单文件 core/fast_scanner.py 已按职责机械拆分为多个子模块，
本 __init__.py 重新导出全部公开/契约名称，保持
``from core.fast_scanner import X`` 与 ``core.fast_scanner.X`` 属性查找可用。
"""

from ._constants import (
    DEFAULT_USER_AGENTS,
    MOBILE_USER_AGENTS,
    SQL_ERROR_PATTERNS,
    XSS_REFLECT_PATTERNS,
    SENSITIVE_PATHS,
    WEAK_CREDENTIALS,
    CMD_INJECTION_PATTERNS,
    CORS_VULN_HEADERS,
    INFO_LEAK_HEADERS,
    _HEADER_VERSION_RE,
    SENSITIVE_DATA_PATTERNS,
    PUBLIC_DATA_PATTERNS,
    _PUBLIC_CONTENT_TYPES,
    BUSINESS_DENY_PATTERNS,
    EMPTY_DATA_PATTERNS,
    WAF_BLOCK_KEYWORDS,
    SENSITIVE_PATH_FINGERPRINTS,
    log,
)
from ._models import VulnFinding, ScanTarget, ScanResult
from ._fp_filters import (
    _is_business_deny,
    _is_empty_data,
    _is_waf_block_page,
    _normalize_body,
    _bodies_similar,
    _is_xss_executable_context,
    _body_contains_sensitive_data,
    _is_public_data,
    _is_auth_wall_page,
    _header_value_leaks_version,
    _verify_sensitive_path_content,
)
from ._rules_loader import load_rules_from_yaml
from ._engine import FastScanner
from ._entry import quick_scan, batch_quick_scan, convert_findings_to_checklist_results

__all__ = [
    # 引擎与模型
    "FastScanner", "ScanTarget", "ScanResult", "VulnFinding",
    # 入口函数
    "quick_scan", "batch_quick_scan", "load_rules_from_yaml",
    "convert_findings_to_checklist_results",
    # 11 个 FP 铁律函数（契约要求保持可导入 + 可属性查找 patch）
    "_is_business_deny", "_is_empty_data", "_is_waf_block_page", "_normalize_body",
    "_bodies_similar", "_is_xss_executable_context", "_body_contains_sensitive_data",
    "_is_public_data", "_is_auth_wall_page", "_header_value_leaks_version",
    "_verify_sensitive_path_content",
    # 常量
    "DEFAULT_USER_AGENTS", "MOBILE_USER_AGENTS", "SQL_ERROR_PATTERNS",
    "XSS_REFLECT_PATTERNS", "SENSITIVE_PATHS", "WEAK_CREDENTIALS",
    "CMD_INJECTION_PATTERNS", "CORS_VULN_HEADERS", "INFO_LEAK_HEADERS",
    "_HEADER_VERSION_RE", "SENSITIVE_DATA_PATTERNS", "PUBLIC_DATA_PATTERNS",
    "_PUBLIC_CONTENT_TYPES", "BUSINESS_DENY_PATTERNS", "EMPTY_DATA_PATTERNS",
    "WAF_BLOCK_KEYWORDS", "SENSITIVE_PATH_FINGERPRINTS",
    "log",
]
