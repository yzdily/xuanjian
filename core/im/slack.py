"""core.im.slack — Slack Incoming Webhook connector（中期 M3）。"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from core.im.base import IMConnector, _parse_slash_cmd


class SlackConnector(IMConnector):
    name = "slack"

    def __init__(self, webhook_url: str | None = None):
        self.webhook = webhook_url or os.environ.get("XUANJIAN_SLACK_WEBHOOK", "")

    def send(self, target: str, content: str, *, card: dict | None = None) -> dict:
        if not self.webhook:
            return {"status": "skipped", "error": "XUANJIAN_SLACK_WEBHOOK 未设置"}
        body = {"text": content}
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
        return []

    def parse_command(self, raw_msg: dict) -> dict | None:
        text = (raw_msg or {}).get("text") or (raw_msg or {}).get("content") or ""
        return _parse_slash_cmd(text)


__all__ = ["SlackConnector"]
