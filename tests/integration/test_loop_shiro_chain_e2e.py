"""E3-2 端到端：shiro_remmeberme_active 深度链打通验证（假 HTTP 层）。

与 `test_loop_actuator_to_shiro.py`（预置 Finding 假装）不同，本测试**走真实 handler +
真实 LoopController**，只把 HTTP 层换成假响应。覆盖四条契约：

  ① 链走到第 2 步能拿到 cipherKey（source 顺序由矩阵 sources 驱动）；
  ② 第 3/4 步（C 类）**不执行**，产出 awaiting_manual 人工确认节点（三问齐全）；
  ③ `XJ_LOOP_AUTO_EXPLOIT` 开关语义：默认不调用 handler；=1 才调用，但仍旧零网络；
  ④ 拿不到 key（rememberMe 不活跃）→ `key_unobtainable` 正确终止。

⚠️ 目标域名刻意用中性 `shop.example.com`：假 host 名含模块关键词会让 URL split 误切
（E3-1 排错手册第 9 条）。
"""
from __future__ import annotations

import asyncio

import pytest

from core.loops import step_handlers as sh
from core.loops.loop_controller import LoopController

BASE = "http://shop.example.com:8080"
DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA=="
MANUAL_STEPS = ("construct_deserialization_payload", "validate_rce")


# ---------------------------------------------------------------- 假 HTTP 层

def install_shiro_fakes(monkeypatch, *, active: bool = True) -> dict[str, int]:
    """替换 shiro 链的唯二网络出口，并统计调用次数（用于断言"零网络"）。"""
    calls = {"srequest": 0, "arequest": 0}

    def fake_srequest(method, url, timeout=sh.DEFAULT_TIMEOUT, **kw):
        calls["srequest"] += 1
        headers = {"Set-Cookie": "rememberMe=deleteMe; Path=/"} if active else {}
        return sh.Resp(200, headers, "<html>ok</html>")

    async def fake_arequest(method, url, timeout=sh.DEFAULT_TIMEOUT, **kw):
        calls["arequest"] += 1
        return sh.Resp(200, {}, "")

    monkeypatch.setattr(sh, "srequest", fake_srequest)
    monkeypatch.setattr(sh, "arequest", fake_arequest)
    return calls


def run_shiro_chain(monkeypatch, *, active: bool = True):
    calls = install_shiro_fakes(monkeypatch, active=active)
    lc = LoopController()
    ctx: dict = {"base_url": BASE}
    findings = asyncio.run(
        lc.execute("shiro_remmeberme_active", ctx, step_handler=sh.dispatch)
    )
    return lc, ctx, findings, calls


def _steps(lc) -> dict:
    return {s.step: s.detail for s in lc.chain.get_chain("shiro_remmeberme_active")}


def _chain_status(lc) -> dict:
    """链步骤的「状态」字段（deep_dive 层整理后的结构，前端消费的就是这个）。"""
    from core.loops.deep_dive import _chain_steps
    return {s["step"]: s["status"] for s in _chain_steps(lc, "shiro_remmeberme_active")}


# ---------------------------------------------------------------- ① 走到第 2 步

def test_chain_reaches_step2_and_obtains_cipher_key(monkeypatch):
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    lc, ctx, findings, calls = run_shiro_chain(monkeypatch)

    assert [f.vuln_type for f in findings] == [
        "shiro_remmeberme_active", "shiro_cipherKey_leak"]
    # 第 1 步：rememberMe 活跃被确认
    assert ctx["rememberme_active"] is True
    assert ctx["shiro_detect_status"] == "active_no_key"
    # 第 2 步：按矩阵 sources 顺序取得 cipherKey
    assert ctx["shiro_key"] == DEFAULT_KEY
    assert ctx["shiro_key_source"] == "default"

    key_finding = next(f for f in findings if f.vuln_type == "shiro_cipherKey_leak")
    # 报告默认明文（XJ_EVIDENCE_REDACT 未开）
    assert key_finding.detail["cipherKey"] == DEFAULT_KEY
    # 诚实标注：默认 key 只是候选，未经解密验证（shiro_detect 的 _try_decrypt_with_key 是占位）
    assert key_finding.detail["verified"] is False
    # 第 1 步必须被链标记为「有产出」，不能被 detail 里的检测状态顶替
    assert _chain_status(lc)["detect_rememberme_active"] == "finding"
    # 检测阶段只发 1 次请求（rememberMe 是全局 Cookie，打站点根）
    assert calls == {"srequest": 1, "arequest": 0}


def test_sources_order_is_matrix_driven(monkeypatch):
    """`sources` 顺序即尝试顺序；用自定义 step 验证 heapdump / env 两条来源。"""
    assert sh._resolve_cipher_key({"sources": ["heapdump", "env"]}, {}) == ("", "")
    assert sh._resolve_cipher_key(
        {"sources": ["heapdump", "env"]}, {"shiro_key": "from-heapdump"}
    ) == ("from-heapdump", "heapdump")
    assert sh._resolve_cipher_key(
        {"sources": ["env"]}, {"spring.cipherKey": "from-env"}
    ) == ("from-env", "env")
    # default 在前时优先命中 default（与矩阵声明一致）
    assert sh._resolve_cipher_key(
        {"sources": ["default", "heapdump"]}, {"shiro_key": "from-heapdump"}
    ) == (DEFAULT_KEY, "default")


def test_default_key_case_typo_is_normalized():
    """矩阵里写的是 `default_kph+...`（小写 k），必须归一到规范 key，否则来源永远匹配不上。"""
    assert sh._canonical_default_key("kph+bIxk5D2deZiIxcaaaA==") == DEFAULT_KEY
    lc = LoopController()
    step = lc.matrix["shiro_remmeberme_active"]["depth_chain"][1]
    assert "default_kph+".lower() in " ".join(step["sources"]).lower()


# ---------------------------------------------------------------- ② C 类不执行

def test_step3_stops_chain_with_awaiting_manual(monkeypatch):
    """第 3 步是 C 类 → 引擎**停下**等人工确认；第 4 步依赖其载荷，故不再往下走。"""
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    lc, ctx, _findings, calls = run_shiro_chain(monkeypatch)

    detail = _steps(lc)
    assert detail["detect_rememberme_active"].get("finding_id")
    assert detail["construct_deserialization_payload"]["status"] == "awaiting_manual"
    # 停下 ≠ 跳过：链在第 3 步留痕后收尾（4 步链没有被截断，而是主动停在 C 类）
    assert lc.chain.get_depth("shiro_remmeberme_active") == 3
    assert "validate_rce" not in detail

    manual = ctx["_loop_awaiting_manual"]
    assert [e["step"] for e in manual] == ["construct_deserialization_payload"]
    for entry in manual:
        # 三问缺一即为不合格
        assert entry["why"].strip(), entry
        assert entry["ready"] and all(str(r).strip() for r in entry["ready"]), entry
        assert entry["actions"] and all(str(a).strip() for a in entry["actions"]), entry
    # why 必须说明"为什么停"（点名硬开关）
    assert "XJ_LOOP_AUTO_EXPLOIT" in manual[0]["why"]
    # ready 必须反映真实 ctx 状态（此时 key / rememberMe / url 都具备）
    assert any("rememberMe 活跃" == r for r in manual[0]["ready"])
    assert not any("未满足" in r for r in manual[0]["ready"])
    # C 类步骤零网络：只有第 1 步那 1 次检测请求
    assert calls == {"srequest": 1, "arequest": 0}


def test_awaiting_manual_ready_reflects_missing_conditions(monkeypatch):
    """`ready` 不是装饰：缺条件时必须显式标"未满足"。"""
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    lc = LoopController()
    ctx: dict = {"base_url": BASE}
    asyncio.run(lc.execute("shiro_remmeberme_active", ctx, step_handler=None))

    manual = ctx["_loop_awaiting_manual"]
    assert manual, "无 handler 时也必须产出人工确认节点"
    construct = next(e for e in manual if e["step"] == "construct_deserialization_payload")
    assert any("未满足" in r for r in construct["ready"]), construct["ready"]


# ---------------------------------------------------------------- ③ 硬开关语义

def test_auto_exploit_switch_semantics(monkeypatch):
    """默认：C 类步骤连 handler 都不进；=1：进入 handler 但仍零网络。"""
    reached: list[str] = []
    real_dispatch = sh.dispatch

    async def spy_dispatch(step, ctx):
        reached.append(step.get("step", ""))
        return await real_dispatch(step, ctx)

    # --- 默认（开关未设）---
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    calls = install_shiro_fakes(monkeypatch)
    lc = LoopController()
    asyncio.run(lc.execute("shiro_remmeberme_active", {"base_url": BASE},
                           step_handler=spy_dispatch))
    assert reached == ["detect_rememberme_active", "extract_cipher_key"], reached
    assert not any(s in reached for s in MANUAL_STEPS)
    assert calls == {"srequest": 1, "arequest": 0}

    # --- 打开开关 ---
    reached.clear()
    monkeypatch.setenv("XJ_LOOP_AUTO_EXPLOIT", "1")
    calls = install_shiro_fakes(monkeypatch)
    lc2 = LoopController()
    ctx2: dict = {"base_url": BASE}
    asyncio.run(lc2.execute("shiro_remmeberme_active", ctx2, step_handler=spy_dispatch))
    assert all(s in reached for s in MANUAL_STEPS), reached
    # 解锁不等于实现利用：本阶段仍不发任何利用请求，状态仍是 awaiting_manual
    assert calls == {"srequest": 1, "arequest": 0}
    detail = _steps(lc2)
    assert detail["construct_deserialization_payload"]["status"] == "awaiting_manual"
    assert ctx2["_loop_auto_exploit_unlocked"] is True
    assert "已由 XJ_LOOP_AUTO_EXPLOIT=1 解锁" in ctx2["_loop_awaiting_manual"][0]["why"]


def test_exploit_handlers_refuse_even_when_called_directly(monkeypatch):
    """矩阵闸门被绕过（直接调 handler）时，硬开关仍必须拦住。"""
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    calls = install_shiro_fakes(monkeypatch)
    lc = LoopController()

    for step in lc.matrix["shiro_remmeberme_active"]["depth_chain"]:
        if step["step"] not in MANUAL_STEPS:
            continue
        ctx: dict = {"base_url": BASE, "shiro_key": DEFAULT_KEY}
        result = asyncio.run(sh.STEP_HANDLERS[step["step"]](step, ctx))
        assert result is None, "C 类步骤不得产出 finding（更不得执行利用）"
        assert ctx.get("_loop_auto_exploit_unlocked") is None
    assert calls == {"srequest": 0, "arequest": 0}, "C 类步骤发生了网络调用"


# ---------------------------------------------------------------- ④ 终止条件

def test_key_unobtainable_terminates_chain(monkeypatch):
    """rememberMe 不活跃 → 第 2 步写 key_unobtainable → 链条终止，不产出 finding。"""
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    lc, ctx, findings, calls = run_shiro_chain(monkeypatch, active=False)

    assert findings == []
    assert ctx["key_unobtainable"] is True
    assert ctx.get("rememberme_active") is None
    # 第 3/4 步不会被"人工确认"（链条已终止）
    assert "_loop_awaiting_manual" not in ctx
    assert lc.chain.get_depth("shiro_remmeberme_active") == 2
    assert calls == {"srequest": 1, "arequest": 0}


def test_no_key_source_also_terminates(monkeypatch):
    """rememberMe 活跃但矩阵没给可用来源 → 同样 key_unobtainable（不是静默空跑）。"""
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    calls = install_shiro_fakes(monkeypatch)
    lc = LoopController()
    ctx: dict = {"base_url": BASE}
    step = {"step": "extract_cipher_key", "sources": ["heapdump", "env"]}

    ctx["rememberme_active"] = True
    result = asyncio.run(sh.extract_cipher_key(step, ctx))
    assert result is None
    assert ctx["key_unobtainable"] is True
    assert calls == {"srequest": 0, "arequest": 0}


def test_missing_target_terminates_early(monkeypatch):
    monkeypatch.delenv("XJ_LOOP_AUTO_EXPLOIT", raising=False)
    lc = LoopController()
    ctx: dict = {}
    asyncio.run(lc.execute("shiro_remmeberme_active", ctx, step_handler=sh.dispatch))
    assert ctx["key_unobtainable"] is True
    assert lc.chain.get_depth("shiro_remmeberme_active") == 1
