"""T14 事件镜像落盘测试（离线，可 CI）。

★ 背景（0923 实测）：
终端里"看得见"的发现（如「主动目录爆破发现 5 个敏感信息泄露」）只推 SSE，
`data/logs/agent.log` 里出现 **0 次** —— 事后无法审计"到底给用户看过什么"。
0923 那次"报告丢数据"若不是用户主动截图，根本无从发现（那是运气，不是设计）。

本测试锁定三件事：
1. **结论类**事件（system / 终态五态 / vuln）必须落盘；
2. **高频流式**事件（message / thinking / tool_call）不得落盘（否则文件爆炸）；
3. 单行超长时必须**仍是合法 JSON**（原实现直接切字符串 → 整行报废，
   与 P16「不丢数据、可事后复核」冲突）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.session.base import (
    AgentSessionBase,
    _MIRROR_EVENT_TYPES,
    mirror_serialize,
)


def _bare_session(task_id: str = "task_test_mirror", phase: str = "test"):
    """绕过 __init__ 造一个最小会话（避免拉起 LLM / ToolExecutor / 恢复逻辑）。

    ``_mirror_event`` / ``_event`` 只依赖 ``task_id`` / ``phase``，
    因此用 ``__new__`` + 手工赋值即可，测试更快也更隔离。
    """
    s = AgentSessionBase.__new__(AgentSessionBase)
    s.task_id = task_id
    s.phase = phase
    return s


def _mirror_path() -> Path:
    return Path("data") / "logs" / "events.jsonl"


def _read_mirror() -> list[dict]:
    p = _mirror_path()
    if not p.exists():
        return []
    return [json.loads(line) for line in
            p.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture()
def isolated_cwd(tmp_path, monkeypatch):
    """把 cwd 指到临时目录 —— 镜像路径是相对路径，避免污染真实 data/logs。"""
    monkeypatch.chdir(tmp_path)
    yield tmp_path


# ==================== 1. 白名单：结论类必须落 ====================

def test_system_event_is_mirrored(isolated_cwd):
    s = _bare_session()
    s._mirror_event({"type": "system", "data": "主动目录爆破发现 5 个敏感信息泄露"})

    rows = _read_mirror()
    assert len(rows) == 1
    assert rows[0]["type"] == "system"
    assert rows[0]["task_id"] == "task_test_mirror"
    assert rows[0]["phase"] == "test"
    assert "5 个敏感信息泄露" in rows[0]["data"]
    assert isinstance(rows[0]["ts"], (int, float))


@pytest.mark.parametrize("etype", [
    "done", "task_partial", "task_unreachable", "task_failed", "task_aborted",
])
def test_terminal_states_are_mirrored(isolated_cwd, etype):
    """五态终态一个都不能漏 —— 它们是事后审计"任务到底怎么结束"的唯一凭据。"""
    s = _bare_session()
    s._mirror_event({"type": etype, "data": "x"})
    assert [r["type"] for r in _read_mirror()] == [etype]


def test_vuln_and_error_are_mirrored(isolated_cwd):
    s = _bare_session()
    s._mirror_event({"type": "vuln", "data": "[HIGH] 源码泄露(.git): /.git/config"})
    s._mirror_event({"type": "error", "data": "boom"})
    assert [r["type"] for r in _read_mirror()] == ["vuln", "error"]


# ==================== 2. 高频流式事件必须被挡掉 ====================

@pytest.mark.parametrize("etype", ["message", "thinking", "tool_call", "reasoning", "assistant"])
def test_high_frequency_events_not_mirrored(isolated_cwd, etype):
    s = _bare_session()
    s._mirror_event({"type": etype, "data": "chatter " * 100})
    assert _read_mirror() == [], f"{etype} 属高频流式事件，不应进 events.jsonl"


def test_whitelist_excludes_chatter():
    """白名单本身不得包含 message / thinking / tool_call（防止有人顺手加回去）。"""
    for bad in ("message", "thinking", "tool_call", "reasoning"):
        assert bad not in _MIRROR_EVENT_TYPES


# ==================== 3. 超长行仍须是合法 JSON ====================

def test_mirror_serialize_short_record_unchanged():
    rec = {"ts": 1.0, "task_id": "t", "phase": "p", "type": "system", "data": "hi"}
    line = mirror_serialize(rec)
    assert json.loads(line)["data"] == "hi"
    assert "truncated" not in json.loads(line)


def test_mirror_serialize_truncates_but_stays_valid_json():
    """★ 回归钉：原实现是 `json.dumps(...)[:4000]` —— 直接切片会让整行不是合法 JSON，
    审计时 `json.loads` 直接抛错，等于把这条记录写废。"""
    big = "A" * 20000
    line = mirror_serialize(
        {"ts": 1.0, "task_id": "t", "phase": "p", "type": "system", "data": big}
    )
    assert len(line) <= 4000
    parsed = json.loads(line)          # 必须可解析（不抛）
    assert parsed["truncated"] is True
    assert parsed["data"].endswith("…[truncated]")


def test_mirror_serialize_non_string_data_stays_valid():
    line = mirror_serialize(
        {"ts": 1.0, "task_id": "t", "phase": "p", "type": "system",
         "data": {"junk": "B" * 20000}}
    )
    assert len(line) <= 4000
    parsed = json.loads(line)
    assert parsed["truncated"] is True


def test_long_event_written_as_valid_jsonl(isolated_cwd):
    """端到端：超长事件经 _mirror_event 落盘后，整行仍可被 json.loads 解析。"""
    s = _bare_session()
    s._mirror_event({"type": "system", "data": "C" * 30000})
    rows = _read_mirror()              # 内部就是 json.loads，不合法会直接失败
    assert len(rows) == 1
    assert rows[0]["truncated"] is True


# ==================== 4. 镜像失败绝不影响主流程 ====================

def test_mirror_failure_does_not_raise(tmp_path, monkeypatch):
    """把 data/logs 造成文件（mkdir 必失败）→ 不得抛异常。"""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "logs").write_text("i am a file, not a dir", encoding="utf-8")

    s = _bare_session()
    s._mirror_event({"type": "system", "data": "should not raise"})  # 不抛即通过


def test_mirror_appends_instead_of_overwriting(isolated_cwd):
    """append-only：第二次写入不得覆盖第一条（审计流的基本要求）。"""
    s = _bare_session()
    s._mirror_event({"type": "system", "data": "first"})
    s._mirror_event({"type": "system", "data": "second"})
    assert [r["data"] for r in _read_mirror()] == ["first", "second"]
