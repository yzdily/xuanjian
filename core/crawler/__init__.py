"""core/crawler 子包：爬虫的拆分实现。

外部导入只需：
    from core.crawler import AutoCrawler

向后兼容：旧代码 from core.auto_crawler import AutoCrawler 仍然可用
（auto_crawler.py 已改成 shim，re-export 本子包的 AutoCrawler）。
"""

from .crawler_core import AutoCrawler

# 也把数据类暴露出去，方便外部（如 session.py）引用
from .models import (
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
