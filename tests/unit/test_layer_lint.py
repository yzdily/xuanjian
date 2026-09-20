"""A1 分层 lint 回归测试（XUANJIAN_MASTER_PLAN.md · A1）。

通过 subprocess 运行 ``scripts/layer_lint.py --quiet``，断言：
- 退出码为 0（即**无硬违反**：底座模块未反向依赖上层编排
  session/orchestrator/chat_loop/web）。

软告警（底座->中间层）不影响 CI，但会在 stdout 中打印供架构师复核。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LINT_SCRIPT = PROJECT_ROOT / "scripts" / "layer_lint.py"


def test_layer_lint_no_hard_violations():
    """底座模块不得反向依赖上层编排模块（A1 显式契约）。"""
    assert LINT_SCRIPT.exists(), f"layer_lint 脚本缺失：{LINT_SCRIPT}"
    result = subprocess.run(
        [sys.executable, str(LINT_SCRIPT), "--quiet"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"layer-lint 发现硬违反（底座->上层编排）：\n{result.stdout}\n{result.stderr}"
    )
