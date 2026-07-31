"""
Session 包 — AgentSession 通过 Mixin 组合构建。

拆分原则：每个 Mixin 文件 100-400 行，按 Phase/功能边界划分。
对外接口不变：from core.session import AgentSession 仍然可用。
"""

from core.session.base import AgentSessionBase
from core.session.hermes_mixin import HermesMixin
from core.session.idle_mixin import IdlePhaseMixin
from core.session.focused_test_mixin import FocusedTestMixin
from core.session.explore_mixin import ExplorePhaseMixin
from core.session.analyze_mixin import AnalyzePhaseMixin
from core.session.advance_mixin import AdvancePhaseMixin
from core.session.report_mixin import ReportMixin
from core.session.utils_mixin import UtilsMixin
from core.session.chat_loop import ChatLoopMixin


class AgentSession(
    ChatLoopMixin,
    HermesMixin,
    IdlePhaseMixin,
    FocusedTestMixin,
    ExplorePhaseMixin,
    AnalyzePhaseMixin,
    AdvancePhaseMixin,
    ReportMixin,
    UtilsMixin,
    AgentSessionBase,
):
    """分阶段渗透 Agent 会话 — 由多个 Mixin 组合而成。"""
    pass


__all__ = ["AgentSession"]
