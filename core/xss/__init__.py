"""
XSS 专项扫描模块 — 完整流水线版本（13 阶段）。

支持的扫描类型：
- 反射型 XSS（HTTP 引擎）
- 存储型 XSS（跨页面追踪）
- DOM XSS（静态分析）
- Mutation XSS（富文本）
- postMessage / DOM Clobbering
- 文件上传 XSS
- 模板注入（CSTI/SSTI）
- 盲打 XSS（OOB 回调）
- WAF/Filter 动态绕过（LLM 驱动）
- Header/Cookie/Referer/UA 反射
- CSP 分析（辅助研判）

对外暴露的入口：
    from core.xss import XssScanner

    scanner = XssScanner(sitemap=sm, llm=llm, ...)
    async for event in scanner.run():
        ...
"""

from core.xss.scanner import XssScanner
from core.xss.models import (
    ContextType,
    InjectionPoint,
    InjectionTarget,
    Severity,
    XssCandidate,
    XssFinding,
    XssType,
    FindingStatus,
)

# 可选：导出 OOB receiver 供 WebUI 注册 webhook
try:
    from core.xss.oob import (
        LocalOobReceiver,
        get_global_oob_receiver,
        BlindXssScanner,
    )
except Exception:
    LocalOobReceiver = None  # type: ignore
    get_global_oob_receiver = None  # type: ignore
    BlindXssScanner = None  # type: ignore

__all__ = [
    "XssScanner",
    "ContextType",
    "InjectionPoint",
    "InjectionTarget",
    "Severity",
    "XssCandidate",
    "XssFinding",
    "XssType",
    "FindingStatus",
    "LocalOobReceiver",
    "get_global_oob_receiver",
    "BlindXssScanner",
]
