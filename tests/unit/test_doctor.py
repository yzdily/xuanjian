"""tests/unit/test_doctor.py — 短期 S4 验收。

按 XUANJIAN_ROADMAP_SHORT_TERM §5.3 5 断言：
1. check 项数 ≥ 8
2. Python 版本断言（CI 用 3.13 跑）
3. port 检查返回 (bool, str)
4. 总闸告警
5. 端到端退出码
"""
from __future__ import annotations

import subprocess
import sys

from cli.doctor import (
    CHECKS,
    auth_total_switch,
    mitmproxy_port,
    python_version,
    run_doctor,
)


def test_checks_count_at_least_8():
    """8 项 check 必须全在。"""
    assert len(CHECKS) >= 8, f"check 项数 {len(CHECKS)} < 8"


def test_python_version_passes_on_313():
    """CI 跑 3.13.x，必须 ≥ 3.11。"""
    ok, msg = python_version()
    assert ok is True
    assert "Python" in msg


def test_mitmproxy_port_returns_tuple():
    """port check 返回 (bool, str)。"""
    ok, msg = mitmproxy_port()
    assert isinstance(ok, bool) and isinstance(msg, str)


def test_total_switch_warns_when_on(monkeypatch):
    """XUANJIAN_AUTH_DISABLED=1 时告警文案含 ⚠️。"""
    monkeypatch.setenv("XUANJIAN_AUTH_DISABLED", "1")
    ok, msg = auth_total_switch()
    assert ok is True and "⚠️" in msg


def test_doctor_subcommand_exit_code():
    """`python -m cli.main doctor` 退出码在 {0, 1}。"""
    # 走 cli.main（短期 S3 落地后），但 doctor 自身也独立可跑
    r = subprocess.run(
        [sys.executable, "-m", "cli.doctor"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert r.returncode in (0, 1), f"unexpected exit {r.returncode}; stderr={r.stderr[:300]}"


def test_run_doctor_returns_int():
    """run_doctor 返回 int。"""
    rc = run_doctor()
    assert isinstance(rc, int)
    assert rc in (0, 1)
