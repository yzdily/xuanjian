"""core.im.base — IMConnector 抽象基类（中期 M3）。

按 XUANJIAN_ROADMAP_MID_TERM §4.3 Step 1 落地。

零外部依赖（仅 abc + re）。
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod


def _parse_slash_cmd(text: str) -> dict | None:
    """解析 /scan 指令 → {cmd, args}；非指令返回 None。

    格式：`/scan url=... mode=fast|standard|deep tenant=...`
    """
    if not text:
        return None
    s = text.strip()
    m = re.match(r"^/scan\b", s)
    if not m:
        return None
    args: dict[str, str] = {}
    for tok in s.split()[1:]:
        if "=" in tok:
            k, _, v = tok.partition("=")
            args[k.strip()] = v.strip()
    if not args:
        return None
    return {"cmd": "scan", "args": args}


class IMConnector(ABC):
    """IM 平台连接器抽象。"""

    name: str = "unknown"

    @abstractmethod
    def send(self, target: str, content: str, *, card: dict | None = None) -> dict:
        """发消息到 target（群 chat_id / user_id）。

        Returns:
            {"message_id"?, "status"?, "body"?}
        """

    @abstractmethod
    def receive(self) -> list[dict]:
        """轮询收消息（每 adapter 自带频率）。走 webhook 的 adapter 返回空 list。"""

    @abstractmethod
    def parse_command(self, raw_msg: dict) -> dict | None:
        """解析 /scan 指令 → {cmd, args}；非指令返回 None。"""


__all__ = ["IMConnector", "_parse_slash_cmd"]
