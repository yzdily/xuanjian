"""
parallel — Phase 2 并行调度逻辑

从原 parallel.py 拆分为四个子模块：
- session_info: 浏览器 Session 信息获取
- grouping: 功能点分组逻辑
- batch_test: 脚本化批量检测
- orchestrator: 顶层调度（Phase 2 → Phase 3）

所有公开名字在此 re-export，保证 ``from core.parallel import X`` 零改动。
"""

# ---- session_info ----
from core.parallel.session_info import get_session_info

# ---- grouping ----
from core.parallel.grouping import (
    _group_features_by_api_prefix,
    _smart_group_features,
    _record_unsupported_method,
)

# ---- batch_test ----
from core.parallel.batch_test import (
    META_ANALYSIS_PROMPT,
    _meta_analyze_checklist,
    _execute_script_batch,
    _batch_test_unauth,
    _batch_prelim_test,
)

# ---- orchestrator ----
from core.parallel.orchestrator import (
    run_parallel_test,
    _run_supplementary_test,
    start_browser_feature_test,
    _enter_report_phase,
)

__all__ = [
    # session_info
    "get_session_info",
    # grouping
    "_group_features_by_api_prefix",
    "_smart_group_features",
    "_record_unsupported_method",
    # batch_test
    "META_ANALYSIS_PROMPT",
    "_meta_analyze_checklist",
    "_execute_script_batch",
    "_batch_test_unauth",
    "_batch_prelim_test",
    # orchestrator
    "run_parallel_test",
    "_run_supplementary_test",
    "start_browser_feature_test",
    "_enter_report_phase",
]
