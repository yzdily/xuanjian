"""tests/integration/test_launcher.py — 短期 S3 验收。

按 XUANJIAN_ROADMAP_SHORT_TERM §4.3 3 断言：
1. xuanjian --help 退出码 0 + 包含 "玄鉴"
2. xuanjian doctor --help 退出码 0
3. xuanjian run --help 包含 --vuln-class 与 --tenant
"""
from __future__ import annotations

import os
import subprocess
import sys

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _run(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "cli.main", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(ROOT),
    )


def test_entry_point_help():
    """`xuanjian --help` 退出码 0，文案含 '玄鉴'。"""
    r = _run(["--help"])
    assert r.returncode == 0, f"exit={r.returncode}; stderr={r.stderr[:200]}"
    assert "玄鉴" in r.stdout or "xuanjian" in r.stdout


def test_subcommand_doctor_help():
    """`xuanjian doctor --help` 退出码 0。"""
    r = _run(["doctor", "--help"])
    assert r.returncode == 0


def test_subcommand_run_has_vuln_class_and_tenant():
    """`xuanjian run --help` 暴露 --vuln-class 与 --tenant。"""
    r = _run(["run", "--help"])
    assert r.returncode == 0
    assert "--vuln-class" in r.stdout
    assert "--tenant" in r.stdout


def test_launcher_sh_exists():
    """Linux/macOS 启动脚本存在且首行 shebang。"""
    p = ROOT / "scripts" / "launcher" / "xuanjian.sh"
    assert p.exists()
    head = p.read_text(encoding="utf-8").splitlines()[:1]
    assert head and head[0].startswith("#!"), "缺 shebang"


def test_launcher_ps1_exists():
    """Windows PowerShell 启动脚本存在。"""
    p = ROOT / "scripts" / "launcher" / "xuanjian.ps1"
    assert p.exists()
    assert "cli.main" in p.read_text(encoding="utf-8")


def test_launcher_bat_exists():
    """Windows cmd 备选启动脚本存在。"""
    p = ROOT / "scripts" / "launcher" / "xuanjian.bat"
    assert p.exists()
    assert "cli.main" in p.read_text(encoding="utf-8")
