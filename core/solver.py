"""
Solver — 旧的渗透执行体（已废弃）

工具定义已迁移到 core/tools.py。
此文件保留 SOLVER_TOOLS 别名以保证向后兼容，以及旧 Solver 类供参考。
"""

from __future__ import annotations

# 向后兼容：其他模块如果还 from core.solver import SOLVER_TOOLS 不会报错
from core.tools import ALL_MAIN_TOOLS as SOLVER_TOOLS  # noqa: F401
