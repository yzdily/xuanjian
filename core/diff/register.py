"""
core/diff/register.py — 把 diff 模块挂到事件总线上

## 用法
在 start.py 或 web/server.py 启动时调用一次：
    from core.diff.register import attach
    attach()

之后只要旧代码 emit `crawl.snapshot.done`，本模块就会自动拍快照，
零侵入旧代码。
"""

from __future__ import annotations

from typing import Any

from core.events import Events, bus
from core.log import get_logger
from core.diff.snapshot import take_snapshot

log = get_logger("diff.register")

_attached = False


def _on_crawl_snapshot_done(payload: dict[str, Any]) -> None:
    """payload 期望字段：
        - task_id: 任务 ID（必需）
        - tag: 快照标签（可选，没有就用时间戳）
        - note: 备注（可选）
    """
    task_id = payload.get("task_id")
    if not task_id:
        log.debug("crawl.snapshot.done 缺少 task_id，跳过")
        return
    take_snapshot(
        task_id=task_id,
        tag=payload.get("tag", ""),
        note=payload.get("note", ""),
    )


def attach() -> None:
    """注册事件订阅。重复调用是幂等的。"""
    global _attached
    if _attached:
        return
    bus.on(Events.CRAWL_SNAPSHOT_DONE, _on_crawl_snapshot_done)
    _attached = True
    log.debug("diff 模块已挂载到事件总线")


__all__ = ["attach"]
