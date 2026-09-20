"""0918 §2.1 — `xuanjian report` 退出码契约测试。

render_report(task_id) 语义（core/cli_report.py:51）：
- 无扫描产物 / 任务目录不存在 → 2
- 有 coverage_report.md 但无 ci_gate_result.json → 0
- ci_gate_result.json 中 passed=true  → 0
- ci_gate_result.json 中 passed=false → 1
"""
from __future__ import annotations

import json

import pytest

from core import cli_report


@pytest.fixture
def art_dir(tmp_path, monkeypatch):
    """把 cli_report.ART 重定向到临时目录，避免污染真实 data/scan_artifacts。"""
    monkeypatch.setattr(cli_report, "ART", tmp_path)
    return tmp_path


def _seed(art_dir, task_id: str, *, ci: dict | None = None) -> None:
    d = art_dir / task_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "coverage_report.md").write_text("# report", encoding="utf-8")
    if ci is not None:
        (d / "ci_gate_result.json").write_text(
            json.dumps(ci), encoding="utf-8"
        )


def test_passed_false_returns_1(art_dir):
    _seed(art_dir, "demo", ci={"passed": False})
    assert cli_report.render_report("demo") == 1


def test_passed_true_returns_0(art_dir):
    _seed(art_dir, "demo", ci={"passed": True})
    assert cli_report.render_report("demo") == 0


def test_no_ci_gate_file_returns_0(art_dir):
    _seed(art_dir, "demo", ci=None)
    assert cli_report.render_report("demo") == 0


def test_no_artifact_returns_2(art_dir):
    assert cli_report.render_report("does_not_exist_task") == 2
