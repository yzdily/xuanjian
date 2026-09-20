"""回归钉（E3-2）—— 固化 shiro 链接线与「C 类步骤永不自动执行」这条安全红线。

每枚钉子对应一个**真实风险**（不是假想）：

1. 矩阵如果把利用步骤的 `auto: false` 丢了，引擎就会自动打 —— 钉住矩阵标记；
2. 硬开关 `XJ_LOOP_AUTO_EXPLOIT` 默认必须是 false —— 钉住默认值与解析语义；
3. 默认状态下 C 类步骤**连 handler 都不该进**（更别说发请求）—— 用计数器钉住"零网络"；
4. 人工确认节点必须回答三问（why/ready/actions）—— 缺一即为不合格；
5. `awaiting_manual` 必须透出到结构化事件（不能被折叠成 no_finding，否则前端看不到）；
6. 即使矩阵漏标、handler 被直接调用，利用 handler 自己也要过硬开关。
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.loops import step_handlers as sh  # noqa: E402
from core.loops import deep_dive  # noqa: E402
from core.loops.loop_controller import (  # noqa: E402
    AWAITING_MANUAL,
    LoopController,
    auto_exploit_enabled,
)

MATRIX_PATH = Path(__file__).resolve().parents[2] / "core" / "loops" / "loop_matrix.yaml"
TRIGGER = "shiro_remmeberme_active"
EXPLOIT_STEPS = ("construct_deserialization_payload", "validate_rce")
BASE = "http://shop.example.com:8080"


def _matrix() -> dict:
    with open(MATRIX_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _shiro_chain() -> list[dict]:
    entry = next(e for e in _matrix()["loops"] if e["trigger"] == TRIGGER)
    return entry["depth_chain"]


# ---------------------------------------------------------------- 矩阵标记

def test_exploit_steps_are_marked_auto_false_in_matrix():
    """红线：第 3/4 步必须由**矩阵**声明 auto: false（引擎不硬编码步骤名单）。"""
    chain = {s["step"]: s for s in _shiro_chain()}
    for name in EXPLOIT_STEPS:
        assert chain[name].get("auto") is False, f"{name} 的 auto: false 被移除了"


def test_manual_blocks_declare_three_questions():
    """每个 auto:false 步骤都要在矩阵里回答三问，否则人工确认节点会缺项。"""
    for step in _shiro_chain():
        if step.get("auto") is not False:
            continue
        manual = step.get("manual") or {}
        assert str(manual.get("why") or "").strip(), step["step"]
        assert manual.get("ready"), step["step"]
        assert manual.get("actions"), step["step"]


def test_no_hardcoded_exploit_step_names_in_engine():
    """引擎只认矩阵的 `auto` 字段，不得把步骤名单写死在 loop_controller 里。"""
    import core.loops.loop_controller as lc
    src = Path(lc.__file__).read_text(encoding="utf-8")
    for name in EXPLOIT_STEPS:
        assert name not in src, f"loop_controller 硬编码了 C 类步骤名 {name}"


# ---------------------------------------------------------------- 硬开关

def test_auto_exploit_switch_defaults_off(monkeypatch):
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    assert auto_exploit_enabled() is False
    for off in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("XJ_LOOP_AUTO_EXPLOIT", off)
        assert auto_exploit_enabled() is False, off
    for on in ("1", "true", "YES", "On"):
        monkeypatch.setenv("XJ_LOOP_AUTO_EXPLOIT", on)
        assert auto_exploit_enabled() is True, on


# ---------------------------------------------------------------- C 类零网络

def _install_net_counters(monkeypatch) -> dict:
    calls = {"n": 0}

    def fake_srequest(method, url, timeout=sh.DEFAULT_TIMEOUT, **kw):
        calls["n"] += 1
        return sh.Resp(200, {"Set-Cookie": "rememberMe=deleteMe"}, "")

    async def fake_arequest(method, url, timeout=sh.DEFAULT_TIMEOUT, **kw):
        calls["n"] += 1
        return sh.Resp(200, {}, "")

    monkeypatch.setattr(sh, "srequest", fake_srequest)
    monkeypatch.setattr(sh, "arequest", fake_arequest)
    return calls


def test_exploit_steps_make_zero_network_calls_by_default(monkeypatch):
    """默认（XJ_LOOP_AUTO_EXPLOIT 未设）：C 类步骤不得产生任何网络调用。"""
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    calls = _install_net_counters(monkeypatch)
    reached: list[str] = []
    real_dispatch = sh.dispatch

    async def spy_dispatch(step, ctx):
        reached.append(step.get("step", ""))
        return await real_dispatch(step, ctx)

    lc = LoopController()
    asyncio.run(lc.execute(TRIGGER, {"base_url": BASE}, step_handler=spy_dispatch))

    assert not any(s in reached for s in EXPLOIT_STEPS), reached
    assert calls["n"] == 1, f"除第 1 步检测外不应有网络调用，实际 {calls['n']}"


def test_exploit_handlers_self_guard_against_mislabeled_matrix(monkeypatch):
    """矩阵漏标时的兜底：直接调用利用 handler 也必须被硬开关拒绝。"""
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    calls = _install_net_counters(monkeypatch)
    for name in EXPLOIT_STEPS:
        ctx: dict = {"base_url": BASE, "shiro_key": "kPH+bIxk5D2deZiIxcaaaA=="}
        step = {"step": name, "manual": {"why": "x", "ready": ["y"], "actions": ["z"]}}
        assert asyncio.run(sh.STEP_HANDLERS[name](step, ctx)) is None
        assert ctx.get("_loop_auto_exploit_unlocked") is None
    assert calls["n"] == 0


# ---------------------------------------------------------------- 三问与事件透出

def test_finding_detail_must_not_override_chain_status(monkeypatch):
    """真实网络才暴露的坑：Finding.detail 里若有 `status` 键，会把链状态顶替成
    "active_no_key"（controller 把 detail 合并进 chain 步骤），前端状态就错乱了。"""
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    _install_net_counters(monkeypatch)
    lc = LoopController()
    asyncio.run(lc.execute(TRIGGER, {"base_url": BASE}, step_handler=sh.dispatch))

    steps = {s.step: s.detail for s in lc.chain.get_chain(TRIGGER)}
    detect = steps["detect_rememberme_active"]
    assert detect.get("finding_id")
    assert "status" not in detect, detect
    by_name = {s["step"]: s for s in deep_dive._chain_steps(lc, TRIGGER)}
    assert by_name["detect_rememberme_active"]["status"] == "finding"


def test_awaiting_manual_entries_answer_three_questions(monkeypatch):
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    _install_net_counters(monkeypatch)
    lc = LoopController()
    ctx: dict = {"base_url": BASE}
    asyncio.run(lc.execute(TRIGGER, ctx, step_handler=sh.dispatch))

    entries = ctx["_loop_awaiting_manual"]
    # 引擎在第一个 C 类步骤停下（第 4 步依赖第 3 步的载荷，未确认前不列出）
    assert [e["step"] for e in entries] == ["construct_deserialization_payload"]
    for e in entries:
        assert e["why"].strip()
        assert e["ready"] and all(str(x).strip() for x in e["ready"])
        assert e["actions"] and all(str(x).strip() for x in e["actions"])
    # 链里必须留痕（不是"跳过"）
    statuses = {s.step: s.detail.get("status")
                for s in lc.chain.get_chain(TRIGGER)}
    assert statuses["construct_deserialization_payload"] == AWAITING_MANUAL
    assert "validate_rce" not in statuses, "C 类步骤未确认前不得继续往下执行"


def test_chain_steps_surfaces_awaiting_manual_not_collapsed(monkeypatch):
    """`_chain_steps` 不得把 awaiting_manual 折叠成 ok/no_finding（前端要看得到）。"""
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    _install_net_counters(monkeypatch)
    lc = LoopController()
    asyncio.run(lc.execute(TRIGGER, {"base_url": BASE}, step_handler=sh.dispatch))

    steps = {s["step"]: s for s in deep_dive._chain_steps(lc, TRIGGER)}
    node = steps["construct_deserialization_payload"]
    assert node["status"] == AWAITING_MANUAL
    assert node["awaiting_manual"] is True
    assert node["detail"]["why"].strip()


def test_deep_dive_event_carries_awaiting_manual(monkeypatch, tmp_path):
    """结构化 `loop` 事件必须带上 awaiting_manual 列表（ChainTimeline 的数据源）。"""
    from core.sitemap.models import CheckItem, CheckResult, FeaturePoint
    from core.sitemap.sitemap import Sitemap

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "1")
    monkeypatch.setenv("XJ_LOOP_TRIGGERS", TRIGGER)
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    _install_net_counters(monkeypatch)

    sm = Sitemap(target=BASE, task_id="task_pin_shiro")
    fp = FeaturePoint(id="fp1", name="首页", related_apis=[f"GET {BASE}/"])
    fp.checklist.append(CheckItem(
        vuln_type=TRIGGER, result=CheckResult.VULNERABLE, severity="high"))
    sm.features[fp.id] = fp

    events: list[tuple[str, object]] = []

    class _Session:
        sitemap = sm
        task_id = sm.task_id

        def _event(self, event_type, data, full=""):
            events.append((event_type, data))
            return ""

    async def _run():
        async for _ in deep_dive.run_deep_dive(_Session()):
            pass

    asyncio.run(_run())

    loops = [d for t, d in events if t == "loop" and isinstance(d, dict)]
    assert loops, "未产出 loop 结构化事件"
    manual = loops[0]["awaiting_manual"]
    assert [e["step"] for e in manual] == ["construct_deserialization_payload"]
    assert all(e["why"] and e["ready"] and e["actions"] for e in manual)
    assert any("需人工确认" in m for t, m in events if t == "system" and isinstance(m, str))
