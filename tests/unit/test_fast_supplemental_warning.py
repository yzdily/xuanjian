"""Phase 2.55 本地补测：代理未抓流量时应可见告警，而非误导性的 ✅ 0 个。

回归测试目标：
- fast 模式 Phase 2.55 依赖代理抓包 flows.jsonl 补充新 API。
- 若代理未生效（flows 为空 / 0 条流量），之前会静默打印
  ``✅ Phase 2.55 本地补测完成 (耗时 0.0s): ... 0 个``，看似正常实为空心扫描。
- 修复后：summary["warning"] = "no_phase2_flows"，orchestrator 据此渲染 ⚠️。
"""

import asyncio

import pytest

from core.supplemental_test_agent import run_supplemental_test_local


def _fake_session(target_url="https://example.com"):
    sitemap = type("Sitemap", (), {"apis": {}, "extra_scope": None})()
    return type(
        "Session",
        (),
        {
            "sitemap": sitemap,
            "target_url": target_url,
            "_phase2_started_at": 0.0,
            "task_id": "task_warn_test",
        },
    )()


async def _run(session):
    done = None
    events = []
    async for ev in run_supplemental_test_local(session):
        events.append(ev)
        if ev.get("type") == "done":
            done = ev
    return done, events


def test_empty_flows_yields_no_phase2_flows_warning(monkeypatch, tmp_path):
    """空 flows.jsonl（模拟代理未抓流量）→ summary.warning == 'no_phase2_flows'。"""
    empty_flow = tmp_path / "empty_flows.jsonl"
    empty_flow.write_text("")  # 0 字节
    monkeypatch.setenv("PROXY_FLOW_FILE", str(empty_flow))

    done, events = asyncio.run(_run(_fake_session()))
    summary = done["summary"]

    assert summary["discovered"] == 0
    assert summary.get("error") is None
    assert summary.get("warning") == "no_phase2_flows"

    # orchestrator 判定：error 或 warning 都渲染 ⚠️
    alert = summary.get("error") or summary.get("warning")
    assert alert == "no_phase2_flows"

    # 应有明确的“检查代理”提示事件
    msgs = " ".join(str(e.get("msg", "")) for e in events)
    assert "浏览器代理" in msgs or "mitmproxy" in msgs or "可分析的新流量" in msgs


def test_missing_flows_yields_flow_file_missing_error(monkeypatch, tmp_path):
    """flows.jsonl 不存在 → summary.error 标记 flow_file_missing。"""
    missing = tmp_path / "does_not_exist.jsonl"
    monkeypatch.setenv("PROXY_FLOW_FILE", str(missing))

    done, _ = asyncio.run(_run(_fake_session()))
    summary = done["summary"]

    assert summary["discovered"] == 0
    assert "flow_file_missing" in (summary.get("error") or "")
