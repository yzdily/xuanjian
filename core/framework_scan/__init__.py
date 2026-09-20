"""core.framework_scan — 框架级端点专项扫描（0903 F5/F6/F7/F10）。

与 core.fuzz 正交：fuzz 做 payload 编码，framework_scan 做端点探测。
"""
from core.framework_scan.framework_scan import FrameworkScanner, FRAMEWORK_ENDPOINTS
from core.framework_scan.shiro_detect import detect_shiro_rememberme
from core.framework_scan.heapdump_analyzer import download_and_analyze_heapdump
from core.framework_scan.path_normalization import scan_path_variants

__all__ = [
    "FrameworkScanner",
    "FRAMEWORK_ENDPOINTS",
    "detect_shiro_rememberme",
    "download_and_analyze_heapdump",
    "scan_path_variants",
]
