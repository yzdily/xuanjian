"""E3-1 阶段 1 收尾：LOOP 深挖在真实扫描流程中的编排验证。

本测试不动网络、不动真实扫描，只验证 `core/loops/deep_dive.py` 这层"钩子线"的行为：
  1. 已确认漏洞 × 矩阵 trigger 能被匹配并执行 depth_chain；
  2. 深挖产出**写回原功能点**（供 upsert_vuln / 报告自动带上）；
  3. 链数据落盘 `data/tasks/{task_id}-loops.json`；
  4. 结构化事件 `loop` + 人类可读 system 事件都产出；
  5. `XJ_LOOP_ENABLED=0` / 非启用 trigger / 不匹配的 vuln_type → 完全静默（不打扰、不写盘）；
  6. 同一 `trigger@origin` 去重，补测轮次不会重复打链；
  7. 目标未暴露 actuator → 链条正确终止、不产出 finding（不是报错）。
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from core.loops import step_handlers as sh
from core.loops.deep_dive import match_trigger, run_deep_dive
from core.loops.loop_controller import LoopController
from core.sitemap.models import CheckItem, CheckResult, FeaturePoint
from core.sitemap.sitemap import Sitemap

BASE = "http://shop.example.com:8080"

ENV_JSON = """
{
  "activeProfiles": ["prod"],
  "propertySources": [
    {"name": "applicationConfig",
     "properties": {"spring.datasource.password": {"value": "admin123"}}}
  ]
}
"""
HEAPDUMP_BODY = 'cipherKey="kPH+bIxk5D2deZiIxcaaaA=="\npassword="admin123456"'


class FakeResponse:
    def __init__(self, status: int, text: str = "", headers: dict | None = None):
        self.status, self.text, self.headers = status, text, headers or {}


class FakeSession:
    """最小 session 桩：deep_dive 只需要 sitemap / task_id / _event。"""

    def __init__(self, sitemap: Sitemap):
        self.sitemap = sitemap
        self.task_id = sitemap.task_id
        self.events: list[tuple[str, object]] = []

    def _event(self, event_type: str, data, full: str = "") -> str:
        self.events.append((event_type, data))
        return f"data: {event_type}\n\n"

    def msgs(self) -> list[str]:
        return [d for t, d in self.events if t == "system" and isinstance(d, str)]

    def loop_events(self) -> list[dict]:
        return [d for t, d in self.events if t == "loop" and isinstance(d, dict)]


def install_fakes(monkeypatch, *, exposed: bool = True):
    async def fake_arequest(method, url, timeout=sh.DEFAULT_TIMEOUT, **kw):
        if "actuator" not in url:
            return FakeResponse(404)
        suffix = url.split("/actuator", 1)[-1] or "/"
        if not exposed:
            return FakeResponse(404)
        if suffix in ("", "/"):
            return FakeResponse(200, '{"_links":{}}')
        if suffix == "/env":
            return FakeResponse(200, ENV_JSON)
        if suffix in ("/beans", "/mappings", "/heapdump", "/configprops"):
            return FakeResponse(200, "{}")
        return FakeResponse(404)

    def fake_srequest(method, url, timeout=sh.DEFAULT_TIMEOUT, **kw):
        if url.endswith("/heapdump"):
            return FakeResponse(200, HEAPDUMP_BODY)
        return FakeResponse(404)

    monkeypatch.setattr(sh, "arequest", fake_arequest)
    monkeypatch.setattr(sh, "srequest", fake_srequest)


def make_session(task_id: str = "task_test_deepdive", vuln_type: str = "actuator_exposure") -> FakeSession:
    sm = Sitemap(target=BASE, task_id=task_id)
    fp = FeaturePoint(id="fp1", name="首页", related_apis=[f"GET {BASE}/"])
    fp.checklist.append(CheckItem(
        vuln_type=vuln_type, result=CheckResult.VULNERABLE,
        detail="actuator 端点暴露", severity="critical",
    ))
    sm.features[fp.id] = fp
    return FakeSession(sm)


def drain(session: FakeSession) -> None:
    async def _run():
        async for _ in run_deep_dive(session):
            pass
    asyncio.run(_run())


# ---------------------------------------------------------------- trigger 匹配

def test_match_trigger_exact_and_partial():
    lc = LoopController()
    assert match_trigger(lc, "actuator_exposure") == "actuator_exposure"
    # 双向包含
    assert match_trigger(lc, "spring_boot_actuator_exposure") == "actuator_exposure"
    # 不相关类型不应误命中
    assert match_trigger(lc, "SQLi") is None
    assert match_trigger(lc, "") is None


# ---------------------------------------------------------------- 主流程

def test_deep_dive_runs_chain_and_writes_back(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "1")
    monkeypatch.setenv("XJ_LOOP_TRIGGERS", "actuator_exposure")
    install_fakes(monkeypatch)

    session = make_session()
    before = len(session.sitemap.features["fp1"].checklist)
    drain(session)

    # ① 写回：env_leak + heapdump_leak 追加到原功能点
    checks = session.sitemap.features["fp1"].checklist
    assert len(checks) == before + 2, [c.vuln_type for c in checks]
    added = [c for c in checks if c.source == "loop_deep_dive"]
    assert {c.vuln_type for c in added} == {"actuator_env_leak", "heapdump_leak"}
    assert all(c.result == CheckResult.VULNERABLE for c in added)
    # ② 报告要明文（默认不脱敏）
    env_check = next(c for c in added if c.vuln_type == "actuator_env_leak")
    assert "admin123" in env_check.detail

    # ③ 事件：人类可读 + 结构化
    assert any("LOOP 深挖命中" in m for m in session.msgs())
    loops = session.loop_events()
    assert len(loops) == 1
    ev = loops[0]
    assert ev["trigger"] == "actuator_exposure" and ev["status"] == "completed"
    assert ev["version"] == 1 and ev["origin"] == BASE
    assert [s["step"] for s in ev["steps"]][:3] == [
        "scan_all_actuator_endpoints", "extract_creds_from_env", "heapdump_download_extract"]
    assert len(ev["findings"]) == 3

    # ④ 落盘
    path = Path("data/tasks") / f"{session.task_id}-loops.json"
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["task_id"] == session.task_id
    assert payload["chains"][0]["trigger"] == "actuator_exposure"
    assert payload["chains"][0]["written_back"] == 2


def test_deep_dive_dedupes_same_trigger_origin(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "1")
    install_fakes(monkeypatch)

    session = make_session()
    drain(session)
    first_loops = len(session.loop_events())
    first_checks = len(session.sitemap.features["fp1"].checklist)

    drain(session)                                   # 第二轮（模拟补测/重入）
    assert len(session.loop_events()) == first_loops
    assert len(session.sitemap.features["fp1"].checklist) == first_checks


def test_deep_dive_skips_when_disabled(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "0")
    install_fakes(monkeypatch)

    session = make_session()
    drain(session)

    assert session.events == []                                        # 完全静默
    assert not (Path("data/tasks") / f"{session.task_id}-loops.json").exists()
    assert len(session.sitemap.features["fp1"].checklist) == 1


def test_deep_dive_skips_unlisted_trigger(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "1")
    monkeypatch.setenv("XJ_LOOP_TRIGGERS", "shiro_remmeberme_active")   # E3-1 未启用
    install_fakes(monkeypatch)

    session = make_session()
    drain(session)
    assert session.events == []


def test_deep_dive_skips_unmatched_vuln_type(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "1")
    install_fakes(monkeypatch)

    session = make_session(vuln_type="SQLi")            # 矩阵无对应 trigger
    drain(session)
    assert session.events == []


def test_deep_dive_terminates_when_not_exposed(monkeypatch, tmp_path):
    """目标没暴露 actuator → 链条在第 1 步终止，不产出 finding，但要有"未命中"事件。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "1")
    install_fakes(monkeypatch, exposed=False)

    session = make_session()
    drain(session)

    assert len(session.sitemap.features["fp1"].checklist) == 1          # 无写回
    assert any("未命中" in m for m in session.msgs())
    ev = session.loop_events()[0]
    assert ev["findings"] == []
    assert ev["steps"][0]["status"] in ("no_finding", "ok")


def test_deep_dive_records_missing_handlers(monkeypatch, tmp_path):
    """矩阵里有、适配层没实现的 step 必须留痕（不静默）。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XJ_LOOP_ENABLED", "1")
    monkeypatch.setenv("XJ_LOOP_TRIGGERS", "all")     # 放开全部 trigger（含未实现链）
    install_fakes(monkeypatch)

    session = make_session()
    # 造一个命中 heapdump_leak 链的已确认漏洞（该链 3 个 step 均未实现）
    sm = session.sitemap
    fp2 = FeaturePoint(id="fp2", name="dump", related_apis=[f"GET {BASE}/actuator/heapdump"])
    fp2.checklist.append(CheckItem(vuln_type="heapdump_leak", result=CheckResult.VULNERABLE))
    sm.features[fp2.id] = fp2

    drain(session)
    reported = [m for m in session.msgs() if "未实现的 step" in m]
    assert reported, session.msgs()
    assert any("download_heapdump" in m for m in reported)
