"""
core/replay — 漏洞复盘剧场 + Lesson Miner

## 价值
1. 把每次扫描的"决策链"录成可回放的剧本（为什么选这个 SKILL、payload、结论）
2. 客户/审计可以看剧本理解 AI 决策，可解释性炸裂
3. 剧本结束自动反推 lessons，回写 memory，跑得越多越聪明

## 模块结构
- frame.py    — ReplayFrame / Script 数据模型
- store.py    — 录制存盘 + 加载 (data/replays/<run_id>/script.jsonl)
- recorder.py — 监听 events 自动录制
- miner.py    — 从剧本反推 lesson，回写 memory.record
- register.py — 把 recorder 挂到事件总线（attach 一次即可）

## 零侵入接入
通过 core.events 订阅以下事件：
- worker.decision    — 选 SKILL/payload 时
- harm.validated     — 危害验证产出结论时
- crawl.snapshot.done — 一次 run 结束的暗号（可选）

旧代码完全不知道 replay 的存在。
"""

from core.replay.frame import FrameKind, ReplayFrame, ScriptMeta
from core.replay.store import (
    save_frame,
    load_script,
    list_runs,
    delete_run,
)
from core.replay.miner import mine_lessons_from_script, MinedLesson
from core.replay.emit_helper import emit_decision, emit_harm

__all__ = [
    "FrameKind",
    "ReplayFrame",
    "ScriptMeta",
    "save_frame",
    "load_script",
    "list_runs",
    "delete_run",
    "mine_lessons_from_script",
    "MinedLesson",
    "emit_decision",
    "emit_harm",
]
