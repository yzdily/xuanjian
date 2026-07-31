"""数据模型 — 爬虫的纯数据类（CrawledElement / CrawledForm / CrawledPage / CrawlRoundResult）。

这些类被 AutoCrawler 主类、各 Mixin 和外部调用者共同使用，单独抽出来避免循环依赖。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CrawledElement:
    page_url: str
    tag: str
    text: str
    selector: str
    href: str = ""
    triggered_requests: list[dict] = field(default_factory=list)


@dataclass
class CrawledForm:
    page_url: str
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)
    selector: str = ""
    submitted: bool = False
    submit_requests: list[dict] = field(default_factory=list)


@dataclass
class CrawledPage:
    url: str
    title: str = ""
    elements: list[CrawledElement] = field(default_factory=list)
    forms: list[CrawledForm] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    requests_during_load: list[dict] = field(default_factory=list)


@dataclass
class CrawlRoundResult:
    """一轮爬取的结果（对应一个角色）。"""
    role: str  # "anonymous" / "user_a" / "admin"
    pages: dict[str, CrawledPage] = field(default_factory=dict)
    api_endpoints: dict[str, dict] = field(default_factory=dict)  # "METHOD url" → request info
    realtime_channels: list[dict] = field(default_factory=list)  # GraphQL / WebSocket / SSE 证据
    js_endpoints: list[str] = field(default_factory=list)
    js_analysis: Any = None  # JSAnalysisResult，JS 深度分析结果
    login_success: bool = False  # 该轮是否登录成功


# 表单字段的智能填写规则
FORM_FILL_RULES = {
    # name/type 关键词 → 填写值
    "username": "testuser001",
    "user": "testuser001",
    "login": "testuser001",
    "account": "testuser001",
    "email": "test@pentest-agent.local",
    "mail": "test@pentest-agent.local",
    "phone": "13800138000",
    "mobile": "13800138000",
    "tel": "13800138000",
    "password": "TestPass123!",
    "passwd": "TestPass123!",
    "pwd": "TestPass123!",
    "confirm": "TestPass123!",
    "name": "TestUser",
    "realname": "测试用户",
    "nickname": "tester",
    "address": "测试地址",
    "city": "北京",
    "search": "test",
    "query": "test",
    "keyword": "test",
    "q": "test",
    "title": "Test Title",
    "content": "This is a test content.",
    "message": "Test message",
    "comment": "Test comment",
    "code": "123456",
    "captcha": "1234",
    "amount": "100",
    "price": "9900",
    "quantity": "1",
    "number": "1",
    "url": "https://example.com",
    "link": "https://example.com",
}
