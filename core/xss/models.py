"""
XSS 模块的数据模型。

设计原则：
- 所有数据流转用 dataclass，不依赖 sitemap 主类，便于独立测试
- ContextType 枚举覆盖所有回显上下文，每种 context 决定使用什么 payload
- XssFinding 是最终输出，含完整证据链
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class ContextType(str, Enum):
    """回显上下文类型 — 决定使用什么类型的 payload。"""
    HTML_TEXT = "html_text"           # <div>HERE</div>
    HTML_COMMENT = "html_comment"     # <!-- HERE -->
    HTML_ATTR = "html_attr"           # <input value="HERE">
    HTML_ATTR_NOQUOTE = "html_attr_noquote"  # <input value=HERE>
    HTML_ATTR_EVENT = "html_attr_event"  # <a href="HERE"> (javascript: 可能可用)
    JS_STRING = "js_string"           # var x = "HERE";
    JS_TEMPLATE = "js_template"       # `${HERE}`
    JS_CODE = "js_code"               # HERE 直接拼接到 JS 代码
    CSS = "css"                       # <style>...HERE...</style>
    URL_PATH = "url_path"             # 反射到 URL
    UNKNOWN = "unknown"


class InjectionPoint(str, Enum):
    """注入点类型。"""
    URL_PARAM = "url_param"      # ?key=HERE
    URL_PATH = "url_path_seg"    # /path/HERE
    URL_FRAGMENT = "url_fragment"  # #HERE
    HEADER = "header"            # 请求头
    COOKIE = "cookie"
    BODY_FORM = "body_form"      # form-urlencoded
    BODY_JSON = "body_json"      # JSON 字段
    BODY_XML = "body_xml"
    BODY_MULTIPART = "body_multipart"


class XssType(str, Enum):
    """XSS 类型。"""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"
    MUTATION = "mutation"
    BLIND = "blind"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """漏洞状态（LLM 研判前后）。"""
    CANDIDATE = "candidate"       # 扫描器初步标记
    CONFIRMED = "confirmed"       # LLM 研判确认
    FALSE_POSITIVE = "false_positive"  # LLM 研判排除
    NEEDS_REVIEW = "needs_review"  # 模糊，需要人工
    PENDING_JUDGE = "pending_judge"  # 等待 LLM 研判中


@dataclass
class InjectionTarget:
    """一个可注入的位置（URL/参数/Body 字段等）。"""
    url: str                              # 目标 URL（不含 payload）
    method: str = "GET"
    injection_point: InjectionPoint = InjectionPoint.URL_PARAM
    param_name: str = ""                  # 参数名（form/json/url）
    param_path: str = ""                  # JSON 嵌套路径（如 "user.profile.bio"）
    original_value: str = ""              # 原始值（用于推断类型/不破坏业务）
    headers: dict = field(default_factory=dict)  # 请求时要带的 header（如 Cookie）
    cookies: dict = field(default_factory=dict)
    body_template: str = ""               # 完整 body 模板（含其他字段）
    content_type: str = ""                # POST 时的 content-type
    auth_required: bool = False
    # 关联信息
    feature_id: str = ""                  # 来自 sitemap 的哪个功能点
    source_flow_id: str = ""              # 来自哪条 mitm 流量


@dataclass
class EchoMatch:
    """payload 在响应中的一次回显。"""
    snippet: str                          # 命中处的上下文片段（前后 50 字符）
    offset: int = 0                       # 在响应体的字节偏移
    context: ContextType = ContextType.UNKNOWN
    encoded: bool = False                 # 是否被 HTML/JS 编码
    sanitized_chars: list[str] = field(default_factory=list)  # 被过滤的字符
    in_response_field: str = "body"       # body / header / cookie


@dataclass
class XssCandidate:
    """扫描器产出的 XSS 候选 — 待 LLM 研判。"""
    target: InjectionTarget
    payload: str                          # 实际使用的 payload
    marker: str = ""                      # 唯一标记字符串
    echo_matches: list[EchoMatch] = field(default_factory=list)  # 回显位置
    confidence: float = 0.5               # 扫描器自评置信度 0-1
    xss_type: XssType = XssType.REFLECTED
    # 证据
    request_packet: str = ""              # 完整 HTTP 请求
    response_packet: str = ""             # 完整 HTTP 响应（截断 50KB）
    response_status: int = 0
    response_content_type: str = ""
    # 浏览器层验证
    browser_triggered: bool = False        # 浏览器是否真的触发了 JS 执行
    browser_evidence: str = ""             # alert/console 内容
    # 元信息
    scanner: str = "xss_http"              # 来自哪个扫描器
    scanned_at: float = field(default_factory=time.time)


@dataclass
class XssFinding:
    """XSS 漏洞最终结果 — LLM 研判后。"""
    id: str
    candidate: XssCandidate
    status: FindingStatus = FindingStatus.PENDING_JUDGE
    severity: Severity = Severity.MEDIUM
    title: str = ""                       # "反射型 XSS - /search 参数 q"
    description: str = ""                 # LLM 生成的说明
    reproduce_steps: str = ""             # 复现步骤
    fix_suggestion: str = ""              # 修复建议
    # 研判记录
    judge_reasoning: str = ""             # LLM 的研判理由
    judge_confidence: float = 0.0
    # 关联
    feature_id: str = ""
    judged_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "xss_type": self.candidate.xss_type.value,
            "url": self.candidate.target.url,
            "method": self.candidate.target.method,
            "param": self.candidate.target.param_name,
            "injection_point": self.candidate.target.injection_point.value,
            "payload": self.candidate.payload,
            "echo_count": len(self.candidate.echo_matches),
            "echo_contexts": [m.context.value for m in self.candidate.echo_matches],
            "browser_triggered": self.candidate.browser_triggered,
            "browser_evidence": self.candidate.browser_evidence,
            "reproduce_steps": self.reproduce_steps,
            "fix_suggestion": self.fix_suggestion,
            "judge_reasoning": self.judge_reasoning,
            "judge_confidence": self.judge_confidence,
            "feature_id": self.feature_id,
            "scanned_at": self.candidate.scanned_at,
            "judged_at": self.judged_at,
        }


@dataclass
class ScanStats:
    """扫描统计。"""
    targets_discovered: int = 0
    targets_scanned: int = 0
    candidates_found: int = 0
    findings_confirmed: int = 0
    findings_false_positive: int = 0
    findings_needs_review: int = 0
    started_at: float = 0
    finished_at: float = 0
    errors: list[str] = field(default_factory=list)

    @property
    def elapsed(self) -> float:
        if self.finished_at and self.started_at:
            return self.finished_at - self.started_at
        return 0
