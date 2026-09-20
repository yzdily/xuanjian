"""
AutoCrawler — 系统性页面爬取（三遍爬取法）

★ 2026-05-22 v4：本文件已拆分为 core/crawler/ 子包。
本文件保留作为 shim 兼容旧代码：
    from core.auto_crawler import AutoCrawler   # ← 仍然可用

实际实现位于：
    core/crawler/__init__.py     - 子包入口
    core/crawler/models.py       - 数据类
    core/crawler/timeouts.py     - 噪音探测 + 自适应超时
    core/crawler/scope_mixin.py  - 域名作用域 / 关联域推断
    core/crawler/url_filter_mixin.py - URL 队列治理
    core/crawler/login_mixin.py  - 登录 / 验证码 / 代理检查
    core/crawler/menu_ranker.py  - 菜单优先级排序（阶段 B）
    core/crawler/crawler_core.py - 主类编排
"""

from core.crawler import (
    AutoCrawler,
    CrawledElement,
    CrawledForm,
    CrawledPage,
    CrawlRoundResult,
    FORM_FILL_RULES,
)

__all__ = [
    "AutoCrawler",
    "CrawledElement",
    "CrawledForm",
    "CrawledPage",
    "CrawlRoundResult",
    "FORM_FILL_RULES",
]
