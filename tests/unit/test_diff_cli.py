"""0918 §2.2 — `xuanjian diff` 增量回归 CLI 链路测试。

验证 _run_diff 的纯翻译链路（不依赖浏览器/mitmproxy）：
list_snapshots → load_snapshot → diff_snapshots → build_regression_plan
→ save_regression_plan（落盘）→ run_regression_plan（翻译为补测任务）。
"""
from __future__ import annotations

import types

import pytest

import cli.main as cli_main
from core import diff as core_diff


@pytest.fixture
def diff_env(tmp_path, monkeypatch):
    snap_a = {"host": "https://x.test", "tag": "v1", "created_at": 100}
    snap_b = {"host": "https://x.test", "tag": "v2", "created_at": 200}

    # list_snapshots / load_snapshot：core.diff 的 re-export 名（_run_diff 内 from core.diff import）
    monkeypatch.setattr(
        core_diff, "list_snapshots", lambda host="": [snap_a, snap_b]
    )
    monkeypatch.setattr(
        core_diff, "load_snapshot", lambda host, tag: {"tag": tag}
    )

    from core.diff.models import ChangeKind

    fake_diff = types.SimpleNamespace(
        target="https://x.test",
        snapshot_a="v1",
        snapshot_b="v2",
        endpoints=[],
        pages=[],
        features=[
            types.SimpleNamespace(
                feature_id="f1",
                name="login",
                kind=ChangeKind.ADDED,
                added_apis=[],
                removed_apis=[],
                diff_fields=[],
            )
        ],
    )
    monkeypatch.setattr(core_diff, "diff_snapshots", lambda a, b, ta, tb: fake_diff)

    # save_regression_plan：重定向落盘到临时目录，避免污染 data/regression_plans
    captured = {"saved_path": None}

    def _fake_save(plan):
        p = tmp_path / "regression_plan.json"
        p.write_text("{}", encoding="utf-8")
        captured["saved_path"] = p
        return p

    monkeypatch.setattr(
        "core.diff.regression.save_regression_plan", _fake_save
    )

    # run_regression_plan：确认翻译层被调用且产出与 items 数一致的补测任务
    translated = {}

    def _fake_translate(target, plan):
        translated["n"] = len(plan.items)
        return [{"surface_key": f"{target}-{i}"} for i in range(len(plan.items))]

    monkeypatch.setattr(
        "core.diff.runner.run_regression_plan", _fake_translate
    )

    return captured, translated


def test_run_diff_end_to_end(diff_env, capsys):
    captured, translated = diff_env
    args = types.SimpleNamespace(
        target="https://x.test", baseline=None, current=None
    )
    rc = cli_main._run_diff(args)

    assert rc == 0
    # 一个 ADDED feature → 一条回归项 → 一条补测任务
    assert translated["n"] == 1
    assert captured["saved_path"] is not None
    out = capsys.readouterr().out
    assert "补测任务 : 1" in out
    assert "方案已存" in out


def test_run_diff_needs_two_snapshots(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(core_diff, "list_snapshots", lambda host="": [])
    args = types.SimpleNamespace(
        target="https://x.test", baseline=None, current=None
    )
    rc = cli_main._run_diff(args)
    assert rc == 2
    assert "无历史快照" in capsys.readouterr().err
