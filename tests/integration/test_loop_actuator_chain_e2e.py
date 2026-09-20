"""E3-1 端到端：actuator_exposure 深度链打通验证。

与既有 `test_loop_actuator_to_shiro.py`（用预置 Finding 假装）不同，本测试**走真实 handler**，
只把 HTTP 层替换为假响应 —— 以此验证：
  1. 矩阵里的 step 名能真正被 dispatch 到实现；
  2. 产物（actuator_url / 凭据 / shiro_key）通过 extracted_artifacts 逐级传递；
  3. termination 键被 handler 写入后，链条正确提前终止；
  4. 未注册的 step 被显式记录，不静默；
  5. 报告/detail 默认明文（仅 XJ_EVIDENCE_REDACT=1 时脱敏）；
  6. `_MAX_DEPTH` 截断修复后，4 步链不会被砍成 3 步。
"""
from __future__ import annotations

import asyncio

import pytest

from core.loops import step_handlers as sh
from core.loops.loop_controller import LoopController

BASE = "http://shop.example.com:8080"

# 让 _scan_secrets 能命中（沿用既有测试的载荷形态）
HEAPDUMP_BODY = b'cipherKey="kPH+bIxk5D2deZiIxcaaaA=="\npassword="admin123456"'

# actuator/env 的真实结构（JSON 优先路径要能解析出来）
ENV_JSON = """
{
  "activeProfiles": ["prod"],
  "propertySources": [
    {"name": "applicationConfig",
     "properties": {
        "spring.datasource.url": {"value": "jdbc:mysql://db.internal:3306/app"},
        "spring.datasource.password": {"value": "admin123"},
        "server.port": {"value": "8080"}
     }}
  ]
}
"""


class FakeResponse:
    def __init__(self, status: int, text: str = "", headers: dict | None = None):
        self.status = status
        self.text = text
        self.headers = headers or {}


def install_fakes(monkeypatch, *, exposed: bool = True):
    """把 HTTP 层换成假响应；exposed=False 时所有 actuator 端点都返回 404。"""

    async def fake_arequest(method, url, timeout=sh.DEFAULT_TIMEOUT, **kw):
        if "actuator" not in url:
            return FakeResponse(404)
        suffix = url.split("/actuator", 1)[-1] or "/"
        if not exposed:
            return FakeResponse(404)
        if suffix in ("", "/"):
            return FakeResponse(200, '{"_links":{}}')
        if suffix in ("/env", "/beans", "/mappings", "/heapdump", "/configprops"):
            if suffix == "/env":
                return FakeResponse(200, ENV_JSON)
            return FakeResponse(200, "{}")
        return FakeResponse(404)

    def fake_srequest(method, url, timeout=sh.DEFAULT_TIMEOUT, **kw):
        if url.endswith("/heapdump"):
            return FakeResponse(200, HEAPDUMP_BODY.decode())
        return FakeResponse(404)

    monkeypatch.setattr(sh, "arequest", fake_arequest)
    monkeypatch.setattr(sh, "srequest", fake_srequest)


def run_chain(monkeypatch, *, exposed: bool = True):
    install_fakes(monkeypatch, exposed=exposed)
    lc = LoopController()
    ctx: dict = {"base_url": BASE}
    findings = asyncio.run(lc.execute("actuator_exposure", ctx, step_handler=sh.dispatch))
    return lc, ctx, findings


# ---------------------------------------------------------------- 主链路

def test_full_chain_runs_through_real_handlers(monkeypatch):
    lc, ctx, findings = run_chain(monkeypatch)

    types = [f.vuln_type for f in findings]
    assert types == ["actuator_exposure", "actuator_env_leak", "heapdump_leak"], types
    assert lc.chain.get_depth("actuator_exposure") == 3        # 三步都执行了


def test_artifacts_flow_between_steps(monkeypatch):
    _, ctx, _ = run_chain(monkeypatch)

    # step1 → step2/3：actuator_url 被写入并用于后续请求
    assert ctx["actuator_url"] == f"{BASE}/actuator"
    assert "/actuator/env" in ctx["actuator_exposed"]
    # step3 → ctx：shiro_key 提取成功
    assert ctx["shiro_key"] == "kPH+bIxk5D2deZiIxcaaaA=="


def test_env_credentials_extracted_json_first(monkeypatch):
    _, ctx, findings = run_chain(monkeypatch)
    env_finding = next(f for f in findings if f.vuln_type == "actuator_env_leak")

    assert ctx["env_leaked_keys"], "应提取到凭据键"
    assert env_finding.detail["source"] == "json", "JSON 优先路径应命中"
    assert any("password" in k for k in env_finding.detail["evidence"])


def test_evidence_is_plaintext_by_default(monkeypatch):
    """0919 决策：报告要明文（脱敏只在显式开启环境开关时）。"""
    monkeypatch.delenv("XJ_EVIDENCE_REDACT", raising=False)
    _, _ctx, findings = run_chain(monkeypatch)
    env_finding = next(f for f in findings if f.vuln_type == "actuator_env_leak")

    joined = " ".join(env_finding.detail["evidence"].values())
    assert "admin123" in joined, f"默认应为明文，实际: {joined}"


def test_evidence_redacted_when_env_switch_on(monkeypatch):
    monkeypatch.setenv("XJ_EVIDENCE_REDACT", "1")
    _, _ctx, findings = run_chain(monkeypatch)
    env_finding = next(f for f in findings if f.vuln_type == "actuator_env_leak")

    joined = " ".join(env_finding.detail["evidence"].values())
    assert "admin123" not in joined and "***" in joined, f"开关开启应脱敏，实际: {joined}"


# ---------------------------------------------------------------- 终止与降级

def test_terminates_when_no_actuator_exposed(monkeypatch):
    lc, ctx, findings = run_chain(monkeypatch, exposed=False)

    assert findings == []
    assert ctx.get("heapdump_unreachable") is True          # termination 键被 handler 写入
    assert lc.chain.get_depth("actuator_exposure") == 1     # 第 1 步后即终止


def test_missing_handler_is_recorded_not_silent(monkeypatch):
    """未注册 step 必须留下痕迹（引擎此前"什么都不做还不吭声"）。"""
    install_fakes(monkeypatch)
    lc = LoopController()
    ctx: dict = {"base_url": BASE}
    asyncio.run(
        lc.execute("heapdump_leak", ctx, step_handler=sh.dispatch)   # 该链的 step 尚未注册
    )
    assert ctx.get("_loop_missing_handlers"), "未注册步骤应被显式记录"
    assert "download_heapdump" in ctx["_loop_missing_handlers"]


# ---------------------------------------------------------------- 截断修复

def test_max_depth_fix_allows_4_step_chain(monkeypatch):
    """shiro 链是 4 步；修复前 _MAX_DEPTH=3 会截断第 4 步。

    E3-2 起第 3/4 步是 C 类（矩阵 `auto: false`），默认会被拦成 awaiting_manual、
    不会到达 step_handler。本用例只关心"链没有被截断"，故打开硬开关
    `XJ_LOOP_AUTO_EXPLOIT=1` 让 spy 能看到全部 4 步（断言不变）。
    """
    monkeypatch.setenv("XJ_LOOP_AUTO_EXPLOIT", "1")
    lc = LoopController()
    chain = lc.matrix["shiro_remmeberme_active"]["depth_chain"]
    assert len(chain) == 4

    ctx: dict = {"base_url": BASE}
    seen: list[str] = []

    async def spy(step, context):
        seen.append(step["step"])
        return None

    asyncio.run(lc.execute("shiro_remmeberme_active", ctx, step_handler=spy))
    assert len(seen) == 4, f"4 步链应全部执行，实际只跑了 {seen}"
    assert seen[-1] == "validate_rce"


def test_safety_cap_still_bounded(monkeypatch):
    """矩阵未声明 max_steps 时用安全上限兜底，防止异常矩阵跑飞。"""
    lc = LoopController()
    huge = {"trigger": "x", "depth_chain": [{"step": f"s{i}"} for i in range(50)]}
    lc.matrix["x"] = huge

    ctx: dict = {}
    seen: list[str] = []

    async def spy(step, context):
        seen.append(step["step"])
        return None

    asyncio.run(lc.execute("x", ctx, step_handler=spy))
    assert len(seen) == 12, f"应由 _SAFETY_MAX_DEPTH 兜底，实际 {len(seen)}"
