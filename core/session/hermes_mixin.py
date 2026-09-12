"""
HermesMixin — 反馈学习 + 历史经验注入。

方法：
- _inject_memories: 把相关的历史经验教训注入到 context 末尾
"""

from __future__ import annotations

from core.log import get_logger

log = get_logger("session.hermes")


class HermesMixin:
    """Hermes 风格反馈学习：历史经验注入。"""

    def _inject_memories(self, ctx, vuln_type: str = "") -> int:
        """把相关的历史经验教训注入到给定 context 末尾。返回注入条数。

        每次 phase 切换或重建 context 时调用一次。
        """
        try:
            from core import memory
            target = getattr(self, "target_url", "") or ""
            lessons = memory.recall(
                target_url=target,
                vuln_type=vuln_type,
                query=getattr(self, "phase", "") or "",
                limit=12,
            )
            if not lessons:
                return 0
            block = memory.format_for_prompt(lessons)
            if not block:
                return 0
            ctx.add_system(block)
            log.info("phase=%s 注入 %d 条历史经验", getattr(self, "phase", "?"), len(lessons))
            return len(lessons)
        except Exception as e:
            log.warning("注入历史经验失败: %s", e)
            return 0
