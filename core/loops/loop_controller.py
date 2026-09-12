"""F4.3 — LOOP 引擎：触发 depth_chain 自动执行。

每个 trigger 被命中后，LoopController 按 loop_matrix.yaml 的 depth_chain
逐步执行，将上一步产出作为下一步输入，直到终止条件命中或链走完。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from core.loops.vuln_chain import VulnChainMemory

_LOOP_MATRIX_PATH = Path(__file__).parent / "loop_matrix.yaml"
_MAX_DEPTH = 3


@dataclass
class Finding:
    id: str
    vuln_type: str
    severity: str = "Medium"
    url: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    extracted_artifacts: dict[str, Any] = field(default_factory=dict)


class LoopController:
    """LOOP 引擎：加载矩阵 → 按 trigger 执行 depth_chain。"""

    def __init__(
        self,
        matrix_path: Path | None = None,
        vuln_chain: VulnChainMemory | None = None,
    ):
        path = matrix_path or _LOOP_MATRIX_PATH
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        self.matrix: dict[str, dict] = {}
        for entry in raw.get("loops", []):
            self.matrix[entry["trigger"]] = entry
        self.chain = vuln_chain or VulnChainMemory()

    def get_trigger(self, trigger: str) -> dict | None:
        return self.matrix.get(trigger)

    def has_trigger(self, trigger: str) -> bool:
        return trigger in self.matrix

    async def execute(
        self,
        trigger: str,
        context: dict[str, Any],
        step_handler: Callable[[dict, dict], Any] | None = None,
    ) -> list[Finding]:
        """触发 LOOP：执行 depth_chain 每一步，返回所有子发现。

        step_handler: 可选的回调，签名为 (step_def, context) -> Finding|None。
        若不提供则仅记录链路径。
        """
        trigger_def = self.matrix.get(trigger)
        if not trigger_def:
            return []

        depth_chain = trigger_def.get("depth_chain", [])
        findings: list[Finding] = []
        max_depth = min(len(depth_chain), _MAX_DEPTH)

        for i in range(max_depth):
            step = depth_chain[i]

            if self._is_terminated(trigger, context):
                break

            if step_handler is None:
                self.chain.append(trigger, step.get("step", f"step_{i}"), context)
                continue

            step_name = step.get("step", f"step_{i}")
            try:
                step_finding = await step_handler(step, context) if _is_coro(step_handler) else step_handler(step, context)
            except Exception:
                step_finding = None

            if step_finding:
                findings.append(step_finding)
                context.update(step_finding.extracted_artifacts)
                self.chain.append(
                    trigger, step_name,
                    {"finding_id": step_finding.id, **step_finding.detail},
                )
            else:
                self.chain.append(trigger, step_name, {"status": "no_finding"})

        return findings

    def _is_terminated(self, trigger: str, context: dict[str, Any]) -> bool:
        terms = self.matrix.get(trigger, {}).get("termination", [])
        for t in terms:
            if context.get(t):
                return True
        return False


def _is_coro(fn: Callable) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(fn)


__all__ = ["LoopController", "Finding"]
