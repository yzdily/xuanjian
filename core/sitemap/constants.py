"""Sitemap 模块级常量 — 消除方法内重复定义，统一维护。"""

from __future__ import annotations

from core.sitemap.models import CheckResult, TestStatus

# 纯 CRUD / 通用操作名（不是真正的业务功能点）
GENERIC_NAMES: frozenset[str] = frozenset({
    "list", "detail", "info", "create", "add", "save", "update", "edit",
    "modify", "delete", "remove", "export", "import", "batch", "upload",
    "download", "search", "query", "get", "post", "put", "patch",
    "js/list", "js/detail", "js/info", "js/create", "js/add", "js/save",
    "js/update", "js/edit", "js/modify", "js/delete", "js/remove",
    "js/export", "js/import", "js/batch", "js/upload", "js/download",
})

# 静态资源后缀（不是业务 API）
STATIC_EXTS: tuple[str, ...] = (
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.mp4',
    '.mp3', '.pdf', '.zip', '.gz',
)

# 静态资源目录路径片段
STATIC_PATH_SEGS: tuple[str, ...] = ('/assets/', '/static/', '/dist/', '/node_modules/')

# 漏洞严重等级 → 标签（并集：普通漏洞 + XSS 专项均可用）
SEVERITY_LABEL: dict[str, str] = {
    "critical": "🔴 严重",
    "high": "🟠 高危",
    "medium": "🟡 中危",
    "low": "🔵 低危",
    "info": "⚪ 信息",
}

# CheckResult → 纯 emoji（用于覆盖矩阵等空间有限的表格）
CHECK_RESULT_ICON: dict[CheckResult, str] = {
    CheckResult.PENDING: "⬜",
    CheckResult.VULNERABLE: "🔴",
    CheckResult.NOT_VULN: "✅",
    CheckResult.SKIPPED: "➖",
    CheckResult.NEEDS_REVIEW: "🟡",
}

# CheckResult → emoji + 文字（用于详情报告等可读性优先的场景）
CHECK_RESULT_ICON_WITH_TEXT: dict[CheckResult, str] = {
    CheckResult.PENDING: "⬜ 待测",
    CheckResult.VULNERABLE: "🔴 存在",
    CheckResult.NOT_VULN: "✅ 不存在",
    CheckResult.SKIPPED: "➖ 跳过",
    CheckResult.NEEDS_REVIEW: "🟡 待确认",
}

# TestStatus → emoji + 文字（用于功能点详情渲染）
TEST_STATUS_ICON_WITH_TEXT: dict[TestStatus, str] = {
    TestStatus.NOT_TESTED: "⬜ 未测试",
    TestStatus.IN_PROGRESS: "🔄 测试中",
    TestStatus.TESTED: "✅ 已完成",
    TestStatus.VULN_FOUND: "🔴 发现漏洞",
    TestStatus.SKIPPED: "⏭️ 跳过",
}
