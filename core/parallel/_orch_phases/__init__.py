"""core.parallel._orch_phases — Phase 2 调度函数的拆分承载包。

原 orchestrator.py 的模块级巨型函数在此按职责拆分（D6/A5），每个子模块
≤800 行。本包统一再导出这些名字，使 ``core.parallel.orchestrator`` 与
``core.parallel`` 的调用方 import 路径零改动。
"""

from ._browser_test import start_browser_feature_test
from ._report_phase import _enter_report_phase, _execute_gap_tasks
from ._run_parallel_test import run_parallel_test
from ._supplement import _run_supplementary_test

__all__ = [
    "run_parallel_test",
    "_run_supplementary_test",
    "start_browser_feature_test",
    "_enter_report_phase",
    "_execute_gap_tasks",
]
