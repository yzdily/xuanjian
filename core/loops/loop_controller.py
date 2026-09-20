"""F4.3 — LOOP 引擎：触发 depth_chain 自动执行。

每个 trigger 被命中后，LoopController 按 loop_matrix.yaml 的 depth_chain
逐步执行，将上一步产出作为下一步输入，直到终止条件命中或链走完。

C 类（利用）步骤安全约束（E3-2）
--------------------------------
矩阵里被标了 `auto: false` 的 step **不会被执行**，而是产出 `awaiting_manual`
状态的人工确认节点（写入 chain 与 `ctx["_loop_awaiting_manual"]`），节点必须回答三问：
为什么停（why）/ 已具备什么条件（ready）/ 我能做什么（actions）。

两道闸门（缺一不可，防止"矩阵误标就自动打"）：
1. 矩阵闸：`step.get("auto") is False` → 引擎直接停下，**不调用 handler**；
2. 硬开关闸：环境变量 `XJ_LOOP_AUTO_EXPLOIT`（默认 `false`）——利用类 handler
   自身也必须先过这一关，否则即使矩阵漏标也不会自动发起利用。
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from core.log import get_logger
from core.loops.vuln_chain import VulnChainMemory

log = get_logger("core.loops.controller")

_LOOP_MATRIX_PATH = Path(__file__).parent / "loop_matrix.yaml"
# 安全上限（兜底防跑飞）；实际步数由矩阵的 max_steps 决定 —— 详见 E3-1 修复说明
_SAFETY_MAX_DEPTH = 12

AWAITING_MANUAL = "awaiting_manual"
# 人工确认节点的 ctx 收集桶（deep_dive 会原样透出到结构化事件/落盘）
AWAITING_MANUAL_KEY = "_loop_awaiting_manual"


def auto_exploit_enabled() -> bool:
    """硬开关：是否允许引擎自动执行利用类（C 类）步骤。**默认关闭**。"""
    return os.getenv("XJ_LOOP_AUTO_EXPLOIT", "0").strip().lower() in ("1", "true", "yes", "on")


def is_manual_step(step: dict) -> bool:
    """矩阵驱动：该 step 是否被声明为「需人工确认」（`auto: false`）。"""
    return step.get("auto") is False


def build_manual_confirmation(step: dict, ctx: dict, unlocked: bool = False) -> dict:
    """构造人工确认节点的**三问**结构（缺一即为不合格）。

    - `why`    为什么停：矩阵 `manual.why` + 当前开关状态；
    - `ready`  已具备什么条件：矩阵 `manual.ready` 标签按 `manual.ready_keys` 逐项核对 ctx；
    - `actions` 我能做什么：矩阵 `manual.actions`（引擎不臆造操作，由矩阵定义）。
    """
    manual = step.get("manual") or {}
    why = manual.get("why") or "该步骤标记为需人工确认（auto: false），默认不自动执行"
    why += (
        "（已由 XJ_LOOP_AUTO_EXPLOIT=1 解锁，但本阶段仍未实现自动利用，需人工执行）"
        if unlocked
        else "（XJ_LOOP_AUTO_EXPLOIT=false）"
    )

    labels = list(manual.get("ready") or [])
    keys = list(manual.get("ready_keys") or [])
    if not labels:
        labels = ["（矩阵未声明前置条件，请自行确认）"]
    ready: list[str] = []
    for i, label in enumerate(labels):
        key = keys[i] if i < len(keys) else None
        if key and not ctx.get(key):
            ready.append(f"{label}（未满足）")
        else:
            ready.append(str(label))

    actions = [str(a) for a in (manual.get("actions") or ["在终端手动执行", "标记不适用"])]
    return {
        "step": step.get("step") or "",
        "why": why,
        "ready": ready,
        "actions": actions or ["在终端手动执行"],
    }


def record_awaiting_manual(ctx: dict, step: dict, unlocked: bool = False) -> dict:
    """把人工确认节点写入 ctx（按 step 幂等：同一步只记一次）。"""
    entry = build_manual_confirmation(step, ctx, unlocked=unlocked)
    bucket = ctx.setdefault(AWAITING_MANUAL_KEY, [])
    for existed in bucket:
        if existed.get("step") == entry["step"]:
            return existed
    bucket.append(entry)
    return entry


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
        # ★ E3-1 修复：原实现硬编码 _MAX_DEPTH=3，会把 4 步链（如 shiro_remmeberme_active）
        #   的第 4 步静默截断，导致矩阵声明的 rce_confirmed 终止条件永远不可能触发。
        #   现改为：矩阵 max_steps 优先，仅用 _SAFETY_MAX_DEPTH 兜底防跑飞。
        max_steps = int(trigger_def.get("max_steps", _SAFETY_MAX_DEPTH))
        max_depth = min(len(depth_chain), max(max_steps, 1))

        for i in range(max_depth):
            step = depth_chain[i]
            step_name = step.get("step", f"step_{i}")

            if self._is_terminated(trigger, context):
                break

            # ★ E3-2：C 类利用步骤（矩阵 auto: false）**绝不自动执行** ——
            #   不是"跳过"（continue 到下一步），而是**停下**并产出一个人工确认节点（含三问）。
            #   后续步骤都依赖本步产出的载荷，未确认前继续列出来只会自相矛盾。
            manual = is_manual_step(step)
            manual_entry: dict = {}
            if manual:
                unlocked = auto_exploit_enabled()
                manual_entry = record_awaiting_manual(context, step, unlocked=unlocked)
                if not unlocked or step_handler is None:
                    # 闸门 1：矩阵标记 + 开关未开 → 连 handler 都不调用（零网络）；
                    # 无 handler 时同样只记人工确认节点，不去 append 整个 ctx。
                    self.chain.append(
                        trigger, step_name,
                        {"status": AWAITING_MANUAL, **manual_entry},
                    )
                    break

            if step_handler is None:
                self.chain.append(trigger, step_name, context)
                continue

            try:
                step_finding = await step_handler(step, context) if _is_coro(step_handler) else step_handler(step, context)
            except Exception as exc:
                # ★ E3-1：不再静默吞异常 —— handler 报错必须留痕（否则链条只表现为"没发现"）
                step_finding = None
                self.chain.append(
                    trigger, step_name,
                    {"status": "handler_error", "error": f"{type(exc).__name__}: {exc}"[:200]},
                )
                log.warning("[loop] step 失败 trigger=%s step=%s: %s", trigger, step_name, exc)
                continue

            if manual:
                # 开关已解锁才可能走到这里；handler 仍拒绝自动利用（见 step_handlers），
                # 链条状态统一记为 awaiting_manual，前端照常渲染人工确认节点。
                self.chain.append(
                    trigger, step_name,
                    {"status": AWAITING_MANUAL, **manual_entry},
                )
            elif step_finding:
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


__all__ = [
    "LoopController",
    "Finding",
    "AWAITING_MANUAL",
    "AWAITING_MANUAL_KEY",
    "auto_exploit_enabled",
    "is_manual_step",
    "build_manual_confirmation",
    "record_awaiting_manual",
]
