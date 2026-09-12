"""
orchestrator — Phase 2 顶层调度

- run_parallel_test: Phase 2 核心，并行调度子 Agent + 主 Agent
- _run_fast_scanner_core: FastScanner 纯异步执行（无 yield，可 create_task）
- _write_fast_scanner_results: FastScanner 结果回写 sitemap
- _run_llm_preparation: LLM 准备阶段（初筛/元分析/智能分组）
- _run_supplementary_test: 覆盖检查新增功能点补测
- start_browser_feature_test: 主 Agent 串行测试浏览器项
- _enter_report_phase: 进入 Phase 3 汇总报告

D6/A5 拆分：上述巨型函数已原样搬迁到 ``core/parallel/_orch_phases/``
（每个子模块 ≤800 行），本模块仅作**薄再导出壳**，保证
``core.parallel.orchestrator`` 与 ``core.parallel`` 的调用点零改动。
"""

# 薄壳：再导出 Phase 2 主函数（逻辑在 _orch_phases 子模块，行为零改动）。
from ._orch_phases import (
    _enter_report_phase,
    _execute_gap_tasks,
    _run_supplementary_test,
    run_parallel_test,
    start_browser_feature_test,
)

# 代理健康相关 helper 仍由 _orchestrator_helpers 提供（被 chat_loop 直接 import）。
from ._orchestrator_helpers import (
    _check_mitmproxy_health,
    _try_restart_mitmproxy,
)

__all__ = [
    "run_parallel_test",
    "_run_supplementary_test",
    "start_browser_feature_test",
    "_enter_report_phase",
    "_execute_gap_tasks",
    "_check_mitmproxy_health",
    "_try_restart_mitmproxy",
]
