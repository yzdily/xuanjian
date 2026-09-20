"""
core/cli_report.py — `xuanjian report` 的 CLI 渲染层（修复 1.1）。

## 背景
`cli/main.py` 原先 `from core.session.report_mixin import render_report`，
但 `report_mixin` 只有 `ReportMixin` 类，**没有模块级 `render_report` 函数** →
ImportError → 退出码 2，CI 门禁断裂。

## 设计
**不重建 session**（规避循环依赖与 R1 风险），改为只读
`data/scan_artifacts/<task_id>/` 下已由 `export_scan_artifacts` 落盘的产物：
- `coverage_report.md`   → 终端渲染
- `report.sarif`         → 打印路径
- `ci_gate_result.json`  → 决定退出码（passed=false → 1）

## 退出码
- 0：渲染成功且门禁通过（或无门禁文件）
- 1：门禁未通过（ci_gate_result.json.passed == false）
- 2：无扫描产物 / task 不存在
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ART = Path("data/scan_artifacts")


def _latest_artifact_task() -> str | None:
    """取最近修改的扫描产物目录名（即 task_id）。无产物返回 None。"""
    if not ART.exists():
        return None
    try:
        dirs = [p for p in ART.iterdir() if p.is_dir()]
    except OSError:
        return None
    if not dirs:
        return None
    newest = max(dirs, key=lambda p: p.stat().st_mtime)
    return newest.name


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def render_report(task_id: str | None = None, *, stream=None) -> int:
    """渲染指定/最新任务的扫描报告，返回进程退出码。

    Args:
        task_id: 任务 ID；为 None 时自动取最新。
        stream:  输出流，默认 stdout（测试可注入 StringIO）。
    """
    out = stream if stream is not None else None
    task_id = task_id or _latest_artifact_task()
    if not task_id:
        print("[ERR] 无扫描产物，请先运行 xuanjian run", file=__import__("sys").stderr)
        return 2

    d = ART / task_id
    if not d.exists():
        print(f"[ERR] 任务不存在: {task_id}", file=__import__("sys").stderr)
        return 2

    md = d / "coverage_report.md"
    sarif = d / "report.sarif"
    ci = d / "ci_gate_result.json"

    if md.exists():
        try:
            text = md.read_text(encoding="utf-8")
        except OSError:
            text = ""
        if out is not None:
            out.write(text)
        else:
            print(text)

    if sarif.exists():
        line = f"\n[SARIF] {sarif}"
        if out is not None:
            out.write(line)
        else:
            print(line)

    if ci.exists():
        data = _read_json(ci) or {}
        passed = bool(data.get("passed"))
        line = f"\n[CI-GATE] {'PASS' if passed else 'FAIL'}"
        if out is not None:
            out.write(line)
        else:
            print(line)
        return 0 if passed else 1

    return 0


__all__ = ["render_report", "ART"]
