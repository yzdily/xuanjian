"""core.im.feishu — 飞书群机器人 connector（中期 M3）。

按 XUANJIAN_ROADMAP_MID_TERM §4.3 Step 2 落地（精简版）。
- send: 用 webhook POST（urllib.request，零依赖）
- receive: 走 webhook（不轮询，返回 []）
- parse_command: 共享 _parse_slash_cmd

配置：XUANJIAN_FEISHU_WEBHOOK
回滚：XUANJIAN_IM_DISABLED=1 整体关 IM
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from core.im.base import IMConnector, _parse_slash_cmd


class FeishuConnector(IMConnector):
    name = "feishu"

    def __init__(self, webhook_url: str | None = None):
        self.webhook = webhook_url or os.environ.get("XUANJIAN_FEISHU_WEBHOOK", "")

    def send(self, target: str, content: str, *, card: dict | None = None) -> dict:
        if not self.webhook:
            return {"status": "skipped", "error": "XUANJIAN_FEISHU_WEBHOOK 未设置"}
        body = (
            {"msg_type": "interactive", "card": card}
            if card
            else {"msg_type": "text", "content": {"text": content}}
        )
        try:
            req = urllib.request.Request(
                self.webhook,
                data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return {"status": r.status, "body": r.read().decode("utf-8", errors="ignore")[:200]}
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return {"status": "error", "error": str(e)[:200]}

    def receive(self) -> list[dict]:
        return []  # 飞书走 webhook，不轮询

    def parse_command(self, raw_msg: dict) -> dict | None:
        text = (raw_msg or {}).get("content", {}).get("text") or (raw_msg or {}).get("text") or ""
        return _parse_slash_cmd(text)


__all__ = ["FeishuConnector"]
