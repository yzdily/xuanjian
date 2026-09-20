"""回归钉（F13 ↔ E3-1 去重）—— 防止两条深挖路径重复处理同一漏洞。

背景：`_report_phase` 里 F13 钩子（`run_spawner`，产出下游补测建议）与 E3-1
Phase 2.7（`run_deep_dive`，直接执行矩阵 depth_chain）都在做"已确认漏洞 → 下游深挖"。
不做去重时，同一个漏洞会被两条路径各处理一次。

分工约定（本文件钉住它）：
- **矩阵已覆盖**的漏洞 → 交给 E3-1 确定性链（F13 跳过）
- **矩阵未覆盖**的漏洞 → 交给 F13 spawner 出建议
- **深挖总开关关闭** → 全部归 F13（此时确定性链不存在，不能白跳过）

判定单源在 `core.loops.deep_dive.covered_triggers / filter_covered_by_loops`。
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.loops.deep_dive import (  # noqa: E402
    covered_triggers,
    filter_covered_by_loops,
    match_trigger,
)
from core.loops.loop_controller import LoopController  # noqa: E402
from core.parallel._orch_phases import _report_phase  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """每个用例从默认开关状态出发。"""
    monkeypatch.delenv("XJ_LOOP_ENABLED", raising=False)
    monkeypatch.delenv("XJ_LOOP_TRIGGERS", raising=False)


def _vuln(vuln_type: str) -> dict:
    return {"vuln_type": vuln_type, "severity": "critical", "url": "http://h:8080"}


# ---------------------------------------------------------------- 覆盖集

def test_default_covers_only_actuator():
    assert covered_triggers() == {"actuator_exposure"}


def test_disabled_means_nothing_covered(monkeypatch):
    monkeypatch.setenv("XJ_LOOP_ENABLED", "0")
    assert covered_triggers() == set()


def test_all_triggers_expands_to_whole_matrix(monkeypatch):
    monkeypatch.setenv("XJ_LOOP_TRIGGERS", "all")
    assert covered_triggers() == set(LoopController().matrix)


def test_unknown_trigger_in_env_is_ignored(monkeypatch):
    """环境里写了矩阵中不存在的 trigger 时，不能假装覆盖（否则 F13 会白跳过）。"""
    monkeypatch.setenv("XJ_LOOP_TRIGGERS", "actuator_exposure,not_a_real_trigger")
    assert covered_triggers() == {"actuator_exposure"}


# ---------------------------------------------------------------- 分流

def test_covered_and_uncovered_split():
    covered, rest = filter_covered_by_loops([_vuln("actuator_exposure"), _vuln("IDOR")])
    assert [v["vuln_type"] for v in covered] == ["actuator_exposure"]
    assert [v["vuln_type"] for v in rest] == ["IDOR"]


def test_shiro_not_covered_by_default_but_covered_when_enabled(monkeypatch):
    """shiro 链默认未启用 —— 此时必须归 F13，不能悄悄跳过。"""
    _, rest = filter_covered_by_loops([_vuln("shiro_remmeberme_active")])
    assert len(rest) == 1

    monkeypatch.setenv("XJ_LOOP_TRIGGERS", "shiro_remmeberme_active")
    covered, rest = filter_covered_by_loops([_vuln("shiro_remmeberme_active")])
    assert len(covered) == 1 and rest == []


def test_disabled_sends_everything_to_f13(monkeypatch):
    monkeypatch.setenv("XJ_LOOP_ENABLED", "0")
    covered, rest = filter_covered_by_loops([_vuln("actuator_exposure"), _vuln("XSS")])
    assert covered == [] and len(rest) == 2


def test_confirmed_possible_is_not_confused(monkeypatch):
    """`SQLi`（已确认）不该被判成"会被 sqli_possible 链覆盖"（语义相反）。"""
    monkeypatch.setenv("XJ_LOOP_TRIGGERS", "all")
    assert match_trigger(LoopController(), "SQLi") is None
    _, rest = filter_covered_by_loops([_vuln("SQLi")])
    assert len(rest) == 1


def test_robust_to_malformed_items():
    """非 dict 项丢弃；缺 vuln_type 的归 F13（保守：宁可让 spawner 看一眼）。"""
    covered, rest = filter_covered_by_loops([{}, None, {"vuln_type": ""}, _vuln("actuator_exposure")])
    assert [v["vuln_type"] for v in covered] == ["actuator_exposure"]
    assert len(rest) == 2                      # {} 与 {"vuln_type": ""} 都进 rest，None 被丢


# ---------------------------------------------------------------- 接线契约

def test_report_phase_filters_before_spawner():
    """F13 必须先过滤再调 spawner（顺序反了就失去意义）。

    注意：比较的是**调用点** `await run_spawner(` 而不是裸 `run_spawner` ——
    后者会先命中文件顶部的 import 行，得出错误结论（这个坑自己踩过一次）。
    """
    src = inspect.getsource(_report_phase._enter_report_phase)
    assert "filter_covered_by_loops" in src, "F13 未做 E3-1 去重 —— 同一漏洞会被处理两次"
    assert src.index("filter_covered_by_loops") < src.index("await run_spawner("), \
        "去重必须在真正调用 spawner 之前（不是 import 之前）"


def test_report_phase_does_not_duplicate_coverage_logic():
    """判定必须单源：report_phase 不得自己重算 trigger/矩阵。"""
    src = inspect.getsource(_report_phase._enter_report_phase)
    assert "LoopController()" not in src, "report_phase 自行构造矩阵 → 覆盖判定逻辑重复实现"
    assert "_enabled_triggers" not in src
