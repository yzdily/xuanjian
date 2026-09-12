"""
core.di 单元测试 — 单例重置注册表 + 上下文注入基础。

验证点：
- register_resetter / reset_singletons / registered_singletons 注册与重置语义
- 已收敛的生产单例（fuzz_router / skill_registry / exploit_skill_map）已注册
- set_context / reset_context 的 ContextVar 注入/还原（set_current_task 模式）

设计原则：零网络、零真实 LLM；不破坏其它单例（用独立名字注册桩）。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core import di  # noqa: E402
from core.di import (  # noqa: E402
    register_resetter,
    reset_singletons,
    registered_singletons,
    set_context,
    reset_context,
)

# 显式导入含 register_resetter 副作用的模块，触发其注册（注册在模块导入时完成）。
import core.fuzz.registry  # noqa: E402,F401
import core.skill_registry  # noqa: E402,F401


# ============================================================
# 1. 注册表基础语义
# ============================================================
class TestResetterRegistry:
    def test_register_and_reset_runs_fn(self):
        calls: list[str] = []

        def _fn():
            calls.append("reset")

        register_resetter("xj_test_dummy", _fn)
        try:
            assert "xj_test_dummy" in registered_singletons()
            done = reset_singletons(["xj_test_dummy"])
            assert done == ["xj_test_dummy"]
            assert calls == ["reset"]
        finally:
            # 清理：用空操作覆盖，避免残留影响其它用例
            register_resetter("xj_test_dummy", lambda: None)

    def test_reset_all_runs_all_registered(self):
        a: list[int] = []
        b: list[int] = []
        register_resetter("xj_test_a", lambda: a.append(1))
        register_resetter("xj_test_b", lambda: b.append(1))
        try:
            reset_singletons()  # 全部
            assert a == [1]
            assert b == [1]
        finally:
            register_resetter("xj_test_a", lambda: None)
            register_resetter("xj_test_b", lambda: None)

    def test_reset_unknown_name_ignored(self):
        # 未注册的名字不应抛错，且返回空
        done = reset_singletons(["xj_test_nonexistent_zzz"])
        assert done == []

    def test_register_overwrites(self):
        calls: list[str] = []
        register_resetter("xj_test_ow", lambda: calls.append("first"))
        register_resetter("xj_test_ow", lambda: calls.append("second"))
        reset_singletons(["xj_test_ow"])
        assert calls == ["second"]
        register_resetter("xj_test_ow", lambda: None)  # cleanup

    def test_registered_singletons_sorted(self):
        names = registered_singletons()
        assert names == sorted(names)


# ============================================================
# 2. 已收敛的生产单例已注册
# ============================================================
class TestProductionSingletonsRegistered:
    def test_fuzz_router_registered(self):
        assert "fuzz_router" in registered_singletons()

    def test_skill_registry_registered(self):
        assert "skill_registry" in registered_singletons()

    def test_exploit_skill_map_registered(self):
        assert "exploit_skill_map" in registered_singletons()

    def test_reset_skill_registry_clears_singleton(self):
        import contextlib

        import core.skill_registry as sr

        sr.get_registry()  # 确保已初始化
        assert sr._state.registry is not None
        try:
            reset_singletons(["skill_registry"])
            assert sr._state.registry is None
            assert sr._state.exploit_skill_map is None
        finally:
            # 还原：置空后下次 get_registry 会懒加载重建，无需手动恢复
            with contextlib.suppress(Exception):
                sr.get_registry()

    def test_reset_fuzz_router_clears_singleton(self):
        import core.fuzz.registry as fr

        fr._state.router = object()  # 桩一个非 None 值
        reset_singletons(["fuzz_router"])
        assert fr._state.router is None


# ============================================================
# 3. ContextVar 上下文注入（set_current_task 模式）
# ============================================================
class TestContextInjection:
    def test_set_and_reset_context(self):
        import contextvars

        var: contextvars.ContextVar[str] = contextvars.ContextVar("xj_test_var", default="default")

        assert var.get() == "default"
        tok = set_context(var, "injected")
        assert var.get() == "injected"
        reset_context(var, tok)
        assert var.get() == "default"

    def test_nested_context_overrides(self):
        import contextvars

        var: contextvars.ContextVar[int] = contextvars.ContextVar("xj_test_int", default=0)
        t1 = set_context(var, 1)
        assert var.get() == 1
        t2 = set_context(var, 2)
        assert var.get() == 2
        reset_context(var, t2)
        assert var.get() == 1
        reset_context(var, t1)
        assert var.get() == 0

    def test_llm_current_task_uses_same_pattern(self):
        # 回归：core.llm 的 set_current_task/reset_current_task 与本模块同构
        from core.llm._context import (
            _current_task_id,
            set_current_task,
            reset_current_task,
            get_current_task,
        )

        assert get_current_task() == ""
        tok = set_current_task("task-xyz")
        try:
            assert get_current_task() == "task-xyz"
        finally:
            reset_current_task(tok)
        assert get_current_task() == ""


# ============================================================
# 4. di 模块自身仅依赖标准库（无 core 循环）
# ============================================================
class TestDiNoCoreImports:
    def test_di_imports_stdlib_only(self):
        import ast

        src = Path(di.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name in ("threading", "typing") or n.name == "contextvars", n.name
            elif isinstance(node, ast.ImportFrom):
                # 仅允许 __future__ / typing / contextvars（标准库）
                assert node.module in ("__future__", "typing", "contextvars"), node.module
