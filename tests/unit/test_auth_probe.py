"""F2 认证探活单元测试。"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core.auth_probe import verify_auth_validity, is_auth_blocked, AuthInvalidError


class TestIsAuthBlocked:
    def test_token_expired(self):
        assert is_auth_blocked("token失效")

    def test_state_false(self):
        assert is_auth_blocked('{"state":false}')

    def test_unauthorized(self):
        assert is_auth_blocked("Unauthorized")

    def test_normal_response(self):
        assert not is_auth_blocked('{"data":"hello world"}')

    def test_empty_body(self):
        assert not is_auth_blocked("")

    def test_chinese_markers(self):
        assert is_auth_blocked("请先登录")
        assert is_auth_blocked("未登录")


class TestVerifyAuthValidity:
    def test_401_raises(self):
        class MockResp:
            status = 401
            body = ""
        with pytest.raises(AuthInvalidError, match="HTTP 401"):
            verify_auth_validity({"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp())

    def test_403_raises(self):
        class MockResp:
            status = 403
            body = ""
        with pytest.raises(AuthInvalidError, match="HTTP 403"):
            verify_auth_validity({"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp())

    def test_blocked_body_raises(self):
        class MockResp:
            status = 200
            body = '{"state":false,"msg":"token失效"}'
        with pytest.raises(AuthInvalidError, match="认证拦截"):
            verify_auth_validity({"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp())

    def test_empty_body_raises(self):
        class MockResp:
            status = 200
            body = ""
        with pytest.raises(AuthInvalidError, match="响应体为空"):
            verify_auth_validity({"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp())

    def test_normal_passes(self):
        class MockResp:
            status = 200
            body = '{"data":"hello world response"}'
        assert verify_auth_validity(
            {"url": "http://t/api"}, {}, request_fn=lambda *a, **k: MockResp(),
        ) is True

    def test_no_request_fn_passes(self):
        assert verify_auth_validity({"url": "http://t/api"}, {}) is True


# ========== 防回退：编排侧 auth 探活 import 接线（2026-09-23 真实任务崩溃根因）==========

_ORCH_PATH = (
    Path(__file__).resolve().parents[2]
    / "core" / "parallel" / "_orch_phases" / "_run_parallel_test.py"
)


class TestAuthProbeWiringInOrchestrator:
    """回归钉：编排侧 auth 探活 import 必须「模块级 + 路径正确」。

    背景（2026-09-23 真实任务崩溃）：`_run_parallel_test.py` 曾在函数内写
    ``from core.auth.probe import verify_auth_validity, AuthInvalidError``——
    路径误写（``core/auth`` 不是包，正确为单文件 ``core.auth_probe``），
    import 失败使 ``AuthInvalidError`` 成为**未绑定的函数局部变量**，
    随后 ``except AuthInvalidError`` 解析异常类型名时抛 ``UnboundLocalError``，
    吞掉原始 ImportError → 后台任务 ``uncaught_exception``，测试阶段 100% 中断。
    """

    def test_core_auth_probe_module_importable(self):
        # 正确模块存在且可导入（路径误写时该 import 也会失败）
        from core.auth_probe import AuthInvalidError, verify_auth_validity  # noqa: F401

    def test_orchestrator_has_no_bad_import_path(self):
        """AST 层校验：不存在 `import core.auth.probe`（注释里提及不算）。"""
        tree = ast.parse(_ORCH_PATH.read_text(encoding="utf-8"))
        bad_lines = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "core.auth.probe":
                bad_lines.append(node.lineno)
            elif isinstance(node, ast.Import):
                if any(a.name == "core.auth.probe" for a in node.names):
                    bad_lines.append(node.lineno)
        assert not bad_lines, (
            f"存在误写路径 core.auth.probe 的 import（行 {bad_lines}）："
            "core/auth 不是包，auth 探活模块是单文件 core.auth_probe"
        )

    def test_orchestrator_imports_auth_probe_at_module_level(self):
        """AST 层校验：`from core.auth_probe import AuthInvalidError` 必须在模块顶层。

        若被放回函数内 try，即触发 2026-09-23 的 UnboundLocalError 陷阱。
        """
        tree = ast.parse(_ORCH_PATH.read_text(encoding="utf-8"))
        top_level = [
            n for n in tree.body
            if isinstance(n, ast.ImportFrom)
            and n.module == "core.auth_probe"
            and any(a.name in ("AuthInvalidError", "verify_auth_validity") for a in n.names)
        ]
        assert top_level, (
            "auth 探活的 import 必须在模块顶层：放进函数内 try 会在 import 失败时"
            "抛 UnboundLocalError 并吞掉原始异常"
        )
