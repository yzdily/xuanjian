"""
Sitemap 数据模型 — 纯 dataclass / Enum，无副作用、无业务逻辑。

从 core/sitemap.py 抽取，便于其他模块单独 import 数据结构而不必依赖庞大的
Sitemap 主类。原 `from core.sitemap import X` 仍然可用（sitemap.py 透明再导出）。

重要：本文件不应导入 sitemap.py，避免循环依赖。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class TestStatus(str, Enum):
    NOT_TESTED = "not_tested"    # 未测试
    IN_PROGRESS = "in_progress"  # 测试中
    TESTED = "tested"            # 已测试，无发现
    VULN_FOUND = "vuln_found"    # 已测试，发现漏洞
    SKIPPED = "skipped"          # 跳过（不适用/不在 scope）


class CheckResult(str, Enum):
    PENDING = "pending"            # 待测试
    VULNERABLE = "vulnerable"      # 确认存在漏洞
    NOT_VULN = "not_vuln"          # 确认不存在
    SKIPPED = "skipped"            # 不适用，跳过
    NEEDS_REVIEW = "needs_review"  # 存疑，需人工确认


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PageInfo:
    """一个页面。"""
    url: str
    title: str = ""
    description: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    buttons: list[str] = field(default_factory=list)
    visited: bool = False


@dataclass
class APIEndpoint:
    """一个 API 端点。"""
    method: str
    url: str
    params: list[str] = field(default_factory=list)
    headers_of_interest: list[str] = field(default_factory=list)
    request_body_sample: str = ""
    response_sample: str = ""
    auth_required: bool = True
    content_type: str = ""
    discovered_by: str = ""  # 来源标识：crawler/mitmproxy/browse_worker 等
    source_type: str = "unknown"  # real_flow/crawler_flow/js_static/api_doc/inferred/menu_api/unknown
    confidence: float = 0.4        # API 真实性/可测试性置信度，0~1
    test_strategy: str = "verify_first"  # direct/verify_first/low_frequency


@dataclass
class CheckItem:
    """一个测试检查项 = 功能点 × 漏洞类型。"""
    vuln_type: str              # 漏洞类型，如 "IDOR", "SQLi", "XSS"
    result: CheckResult = CheckResult.PENDING
    detail: str = ""            # 测试结论说明
    severity: str = ""          # 漏洞等级: critical/high/medium/low
    reproduce_steps: str = ""   # 复现步骤（分步描述）
    fix_suggestion: str = ""    # 修复建议
    evidence_flow_id: str = ""  # 证据 flow_id（如果有漏洞）
    evidence_request: str = ""  # 证据请求数据包（完整 HTTP 请求）
    evidence_response: str = "" # 证据响应数据包（关键响应内容）
    skill_used: str = ""        # 用了哪个 SKILL
    tested_at: float = 0
    needs_browser: bool = False # 是否需要浏览器才能测试（XSS验证/CSRF/验证码等）


@dataclass
class FeaturePoint:
    """一个功能点 — 测试的最小单元。"""
    id: str
    name: str                          # 如 "用户登录"、"下单支付"
    description: str = ""
    page_url: str = ""
    related_apis: list[str] = field(default_factory=list)  # "METHOD url" 列表
    priority: Priority = Priority.MEDIUM
    test_status: TestStatus = TestStatus.NOT_TESTED
    checklist: list[CheckItem] = field(default_factory=list)  # 核心：测试 checklist
    findings: list[str] = field(default_factory=list)
    test_started_at: float = 0
    test_finished_at: float = 0
    requires_auth: bool = False        # 是否需要登录后才能测试
    deferred: bool = False             # 延迟状态：暂不生成 checklist，等突破后激活
    module: str = ""                   # 所属模块（一级分类），如 "权限管理"、"数据看板"

    def get_pending_checks(self) -> list[CheckItem]:
        return [c for c in self.checklist if c.result == CheckResult.PENDING]

    def get_http_pending(self) -> list[CheckItem]:
        """获取可以用纯 HTTP 测试的待测项（子 Agent 队列）。"""
        return [c for c in self.checklist if c.result == CheckResult.PENDING and not c.needs_browser]

    def get_browser_pending(self) -> list[CheckItem]:
        """获取需要浏览器的待测项（主 Agent 队列）。"""
        return [c for c in self.checklist if c.result == CheckResult.PENDING and c.needs_browser]

    def get_completed_checks(self) -> list[CheckItem]:
        return [c for c in self.checklist if c.result != CheckResult.PENDING]

    def mark_check(self, vuln_type: str, result: CheckResult, detail: str = "",
                   evidence_flow_id: str = "", skill_used: str = "",
                   evidence_request: str = "", evidence_response: str = "",
                   severity: str = "", reproduce_steps: str = "",
                   fix_suggestion: str = "") -> CheckItem | None:
        for c in self.checklist:
            if c.vuln_type == vuln_type:
                c.result = result
                c.detail = detail
                c.severity = severity
                c.reproduce_steps = reproduce_steps
                c.fix_suggestion = fix_suggestion
                c.evidence_flow_id = evidence_flow_id
                c.evidence_request = evidence_request
                c.evidence_response = evidence_response
                c.skill_used = skill_used
                c.tested_at = time.time()
                return c
        return None

    def checklist_summary(self) -> str:
        if not self.checklist:
            return "无测试项"
        lines = []
        icons = {
            CheckResult.PENDING: "⬜",
            CheckResult.VULNERABLE: "🔴",
            CheckResult.NOT_VULN: "✅",
            CheckResult.SKIPPED: "⏭️",
            CheckResult.NEEDS_REVIEW: "🟡",
        }
        for c in self.checklist:
            icon = icons.get(c.result, "⬜")
            detail = f" — {c.detail}" if c.detail else ""
            lines.append(f"{icon} {c.vuln_type}{detail}")
        return "\n".join(lines)


__all__ = [
    "TestStatus",
    "CheckResult",
    "Priority",
    "PageInfo",
    "APIEndpoint",
    "CheckItem",
    "FeaturePoint",
]
