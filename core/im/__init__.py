"""core.im — 多 IM 入口（飞书 / 企微 / 钉钉 / Slack + dispatcher）。

按 XUANJIAN_ROADMAP_MID_TERM §4.3 落地（中期 M3）。
零外部依赖（urllib.request 走 stdlib）。
"""
from __future__ import annotations

from core.im.base import IMConnector, _parse_slash_cmd
from core.im.dingtalk import DingtalkConnector
from core.im.dispatcher import IMDispatcher
from core.im.feishu import FeishuConnector
from core.im.slack import SlackConnector
from core.im.wecom import WecomConnector

__all__ = [
    "IMConnector",
    "IMDispatcher",
    "FeishuConnector",
    "WecomConnector",
    "DingtalkConnector",
    "SlackConnector",
    "_parse_slash_cmd",
]
