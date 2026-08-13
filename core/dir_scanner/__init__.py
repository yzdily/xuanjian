"""DirectoryScanner — dirsearch 风格的目录/文件爆破模块。

当目标根路径不可达（5xx / 超时）或仅做被动侦察时，对目标主机进行
基于字典的目录与文件枚举，发现存活端点、敏感文件与信息泄露。

设计参考：https://github.com/maurosoria/dirsearch

核心能力：
- 内置精简字典（管理后台 / 配置 / 备份 / 调试 / Swagger / Actuator 等）
- 并发请求 + 信号量限流
- 通配符 / 软 404 假阳性过滤（随机路径基线对比，dirsearch 同款思路）
- 状态码白名单过滤
- 主机可达性预检（连接级失败立即中止，避免对死主机打满字典）
- WAF / 超时熔断（连续拦截或超时即降速或中止）
- 可选递归（深度受限 + 候选目录白名单，请求量可控）
- 可选扩展名追加（备份文件发现）
- 发现结果回写 sitemap（add_page / add_api）并产出 info_disclosure 发现

★ 本包由原 core/dir_scanner.py（1343 行）拆分而来，所有公开/私有名保持兼容。
  子模块：
    _constants  — 内置字典 / 敏感路径 / 技术栈感知路径等常量
    _wordlist   — 技术栈感知字典构建 build_tech_aware_wordlist / _is_api_priority
    _models     — 数据模型 DirEntry / DirFinding / DirScanResult
    _scanner    — DirectoryScanner 主扫描器 + scan_directories 便捷入口
"""

from __future__ import annotations

# 测试以 ``dir_scanner.httpx.AsyncClient`` 方式 patch httpx，必须保留模块级 httpx 属性。
import httpx

# ============================================================
# 常量
# ============================================================
from ._constants import (
    DEFAULT_WORDLIST,
    RECURSE_CANDIDATES,
    DEFAULT_INCLUDE_STATUS,
    SENSITIVE_PATTERNS,
    DEFAULT_EXTENSIONS,
    CRITICAL_PATHS,
    DEFAULT_USER_AGENT,
    UNIVERSAL_PATHS,
    JAVA_PATHS,
    PHP_PATHS,
    DOTNET_PATHS,
    NODE_PATHS,
    PYTHON_PATHS,
    STATIC_RESOURCE_PATHS,
    API_PRIORITY_KEYWORDS,
    _SPA_SHELL_PATTERN,
    _TECH_PATH_MAP,
)

# ============================================================
# 技术栈感知字典构建
# ============================================================
from ._wordlist import (
    build_tech_aware_wordlist,
    _is_api_priority,
)

# ============================================================
# 数据模型
# ============================================================
from ._models import (
    DirEntry,
    DirFinding,
    DirScanResult,
)

# ============================================================
# 主扫描器 + 便捷入口
# ============================================================
from ._scanner import (
    DirectoryScanner,
    scan_directories,
    log,
)

# ============================================================
# __all__ — 公开 API
# ============================================================
__all__ = [
    # 常量
    "DEFAULT_WORDLIST",
    "RECURSE_CANDIDATES",
    "DEFAULT_INCLUDE_STATUS",
    "SENSITIVE_PATTERNS",
    "DEFAULT_EXTENSIONS",
    "CRITICAL_PATHS",
    "DEFAULT_USER_AGENT",
    "UNIVERSAL_PATHS",
    "JAVA_PATHS",
    "PHP_PATHS",
    "DOTNET_PATHS",
    "NODE_PATHS",
    "PYTHON_PATHS",
    "STATIC_RESOURCE_PATHS",
    "API_PRIORITY_KEYWORDS",
    # 字典构建
    "build_tech_aware_wordlist",
    # 数据模型
    "DirEntry",
    "DirFinding",
    "DirScanResult",
    # 主入口
    "DirectoryScanner",
    "scan_directories",
]
