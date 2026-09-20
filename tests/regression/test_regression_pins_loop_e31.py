"""回归钉（E3-1）—— 固化 LOOP 深挖接线与本次修复的三个坑，防止回退。

每枚钉子对应一个**真实踩过的坑**（不是假想风险）：

1. `_MAX_DEPTH = 3` 硬编码截断 4 步链（`shiro_remmeberme_active` 的第 4 步 `validate_rce`
   永远跑不到 → 矩阵声明的 `rce_confirmed` 终止条件永不触发）。
2. `loop_controller` 静默吞掉 handler 异常 —— 链条出问题只表现为"没发现"，无从排查。
3. `validate_task_id()` **返回 bool 而非抛异常** —— 写成 `try: validate_task_id(x) except`
   等于没校验（我在 loops_api 里真的这么写了一次）。
4. `match_trigger` 用朴素双向子串包含 → `SQLi`（已确认）会误命中 `sqli_possible`（仅可疑），
   语义完全不同。

以及一条**接线契约**：Phase 2.7 必须挂在 `_enter_report_phase` 里、且位于
`session.phase = "report"` 之前 —— 否则深挖产出赶不上 `upsert_vuln` 与报告渲染。
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.loops import step_handlers as sh  # noqa: E402
from core.loops.loop_controller import LoopController  # noqa: E402
from core.parallel._orch_phases import _report_phase  # noqa: E402
from web.api import loops_api  # noqa: E402


def test_phase27_is_wired_before_report_phase():
    """接线契约：Phase 2.7 必须在 `session.phase = "report"` 之前被 await。"""
    src = inspect.getsource(_report_phase._enter_report_phase)
    assert "run_deep_dive" in src, "Phase 2.7 接线被移除 —— 深挖将不再在真实扫描中执行"
    i_loop = src.index("run_deep_dive")
    i_report = src.index('session.phase = "report"')
    assert i_loop < i_report, "深挖必须在报告阶段之前，否则产出进不了报告"


def test_deep_dive_runs_only_if_sitemap_exists():
    """接线必须带 sitemap 守卫（无 sitemap 的裸 chat 会话不该触发深挖）。"""
    src = inspect.getsource(_report_phase._enter_report_phase)
    seg = src[max(0, src.index("run_deep_dive") - 400):src.index("run_deep_dive")]
    assert "if session.sitemap" in seg


def test_actuator_chain_handlers_are_registered():
    for step in ("scan_all_actuator_endpoints", "extract_creds_from_env", "heapdump_download_extract"):
        assert sh.get_handler(step) is not None, f"{step} 未注册 —— actuator 单链会断"


def test_no_hardcoded_max_depth_3():
    """坑 1：不得回退成把链截断到 3 步。"""
    import core.loops.loop_controller as lc
    assert not hasattr(lc, "_MAX_DEPTH"), "_MAX_DEPTH 又回来了（会截断 4 步链）"
    assert lc._SAFETY_MAX_DEPTH >= 4


def test_handler_exception_is_recorded_not_swallowed():
    """坑 2：handler 抛异常必须落进 chain，而不是静默 continue。"""
    import asyncio

    async def boom(step, ctx):
        raise RuntimeError("boom")

    ctrl = LoopController()
    asyncio.run(ctrl.execute("actuator_exposure", {"base_url": "http://h:8080"}, step_handler=boom))
    steps = ctrl.chain.get_chain("actuator_exposure")
    assert steps, "异常未落链"
    assert steps[0].detail.get("status") == "handler_error"


def test_task_id_validation_returns_bool():
    """坑 3：`validate_task_id` 是 bool 语义；loops_api 必须用它做 if 判断。

    若有人改回 `try/except` 写法，路径穿越就无门槛了 —— 这里同时钉住两侧行为。
    """
    from web._security import validate_task_id
    assert validate_task_id("task_abc-123") is True
    for bad in ("../secret", "..", "a/b", "*", ""):
        assert validate_task_id(bad) is False

    src = inspect.getsource(loops_api.get_task_loops)
    assert "if not validate_task_id(" in src, "loops_api 的 task_id 校验被改坏（会被静默绕过）"


def test_match_trigger_does_not_confuse_confirmed_with_possible():
    """坑 4：已确认 SQLi 不能触发「可能存在 SQLi」的链。"""
    from core.loops.deep_dive import match_trigger
    ctrl = LoopController()
    assert match_trigger(ctrl, "SQLi") is None
    assert match_trigger(ctrl, "actuator_exposure") == "actuator_exposure"
    # token 全包含仍要生效（允许更精确的长名）
    assert match_trigger(ctrl, "spring_boot_actuator_exposure") == "actuator_exposure"


def _all_paths(routes) -> set[str]:
    """递归收集全部路由路径。

    ⚠️ FastAPI 0.141 起 `include_router()` 的结果是 `_IncludedRouter` 包装对象，
    其 `path` 为 None、真实路由挂在 `.original_router.routes` 内（旧版是 `.router`）——
    直接扫 `app.routes` 会把这些路由全部漏掉。
    """
    out: set[str] = set()
    for r in routes:
        p = getattr(r, "path", None)
        if isinstance(p, str) and p:
            out.add(p)
        for attr in ("router", "original_router"):
            sub = getattr(r, attr, None)
            if sub is not None and hasattr(sub, "routes"):
                out |= _all_paths(sub.routes)
    return out


def test_loops_api_routes_registered_in_server():
    """新端点必须挂在 server 上（否则前端拿不到链数据）。"""
    import web.server as srv  # noqa: F401  （import 本身即验证路由挂载未炸）
    paths = _all_paths(srv.app.routes)
    assert "/api/loops/{task_id}" in paths
    assert "/api/loops/matrix" in paths
    # 端点不得进白名单（必须走鉴权中间件）
    from web.server import _AUTH_WHITELIST
    assert not any("loops" in str(p) for p in _AUTH_WHITELIST)
