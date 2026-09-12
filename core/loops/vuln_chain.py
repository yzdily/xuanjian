"""F8 — 漏洞链持久化 + depth_chain 审计（防"发现即停"）。

每个 finding 的 depth_chain 记录在内存中，供 GATE-2.5 审计：
框架级漏洞 depth_chain 长度必须 ≥ 1。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ChainStep:
    step: str
    chain_id: str
    ts: float
    finding_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class VulnChainMemory:
    """漏洞链持久化（内存版，复用 scan_store 做落盘）。"""

    def __init__(self) -> None:
        self.chains: dict[str, list[ChainStep]] = {}

    def append(
        self, trigger: str, step: str, finding: dict[str, Any] | None = None,
    ) -> None:
        chain_id = f"{trigger}:{step}"
        chain_step = ChainStep(
            step=step,
            chain_id=chain_id,
            ts=time.time(),
            finding_id=(finding or {}).get("finding_id") or (finding or {}).get("id"),
            detail=finding or {},
        )
        self.chains.setdefault(trigger, []).append(chain_step)

    def get_depth(self, trigger: str) -> int:
        return len(self.chains.get(trigger, []))

    def get_chain(self, trigger: str) -> list[ChainStep]:
        return list(self.chains.get(trigger, []))

    def has_trigger(self, trigger: str) -> bool:
        return trigger in self.chains

    def all_triggers(self) -> list[str]:
        return list(self.chains.keys())


__all__ = ["VulnChainMemory", "ChainStep"]
