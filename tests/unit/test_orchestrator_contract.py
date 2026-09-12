"""A5 / D6 契约冻结测试：core.parallel.orchestrator 公开面。

依据 D6_split_contract_draft.md §1.3 + §3.3 + §4 R4：拆分 orchestrator（巨型函数
拆到 core/parallel/_orch_phases/、重组 _orchestrator_helpers）时，以下名字必须保持
原样，且 core/parallel/__init__.py 与 core/session/chat_loop.py 调用点零改动。

冻结公开面（均从 core.parallel.orchestrator 导入）：
- run_parallel_test / _run_supplementary_test / start_browser_feature_test /
  _enter_report_phase（core/parallel/__init__.py 导入）
- _check_mitmproxy_health / _try_restart_mitmproxy（chat_loop.py:962-963 直接导入）

零网络、零 LLM；在完整 venv（含 httpx）下运行。
"""
from __future__ import annotations

import inspect


def test_orchestrator_frozen_names_importable():
    """6 个冻结名必须仍可从 core.parallel.orchestrator 导入。"""
    from core.parallel.orchestrator import (
        _check_mitmproxy_health,
        _enter_report_phase,
        _run_supplementary_test,
        _try_restart_mitmproxy,
        run_parallel_test,
        start_browser_feature_test,
    )

    for name in (
        run_parallel_test,
        _run_supplementary_test,
        start_browser_feature_test,
        _enter_report_phase,
        _check_mitmproxy_health,
        _try_restart_mitmproxy,
    ):
        assert callable(name), f"冻结名 {name!r} 必须可调用"


def test_orchestrator_re_export_identity_with_package():
    """core.parallel 包导入的 4 个名必须与 orchestrator 模块同一对象（re-export 不变）。"""
    from core.parallel import (
        _enter_report_phase,
        _run_supplementary_test,
        run_parallel_test,
        start_browser_feature_test,
    )
    from core.parallel.orchestrator import (
        _enter_report_phase as _erp,
        _run_supplementary_test as _rst,
        run_parallel_test as _rpt,
        start_browser_feature_test as _sbft,
    )

    assert run_parallel_test is _rpt
    assert _run_supplementary_test is _rst
    assert start_browser_feature_test is _sbft
    assert _enter_report_phase is _erp


def test_run_parallel_test_signature_frozen():
    """run_parallel_test 主入口签名冻结（首参 session）。"""
    from core.parallel.orchestrator import run_parallel_test

    params = list(inspect.signature(run_parallel_test).parameters)
    assert params and params[0] == "session", f"run_parallel_test 首参必须是 session：{params}"
