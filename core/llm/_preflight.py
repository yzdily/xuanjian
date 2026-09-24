"""LLM 健康前置检查（preflight）。

★ T12 (0923 v2)。为什么需要：

0923 当日 5 次扫描里 **3 次**死在 LLM 层，而且全是**开跑前就能知道的事**：
- ``404 not found the model``（模型名 ``kimi-k3`` 不存在）→ 爬完 95 个 JS 文件、
  493 个功能点之后才炸
- ``insufficient balance`` **39 次**（比 429 的 6 次更致命，重试完全无用）
- ``organization max RPM: 3``（组织上限极低）

共同特征：**爬到一半才暴露，且提示"可重试"** —— 用户被引导去做一个必然失败的动作。

本模块把这三类问题提前到"点开始扫描后的 5 秒内"：

- **阻断型**（模型名不存在 / 无权限 / 余额耗尽 / 账户暂停 / Key 失效）
  → 不进 Phase 0，文案指向具体修正动作，**不含"可重试"**。
- **降级型**（RPM 过低 / 窗口未知）
  → 返回建议（降并发 + 限速），由调用方询问用户后套用。

判定复用 ``core.llm._failure::classify_llm_failure`` 的分型规则，
避免"同一件事两套判定"。
"""

from __future__ import annotations

import os
from typing import Any

from core.log import get_logger
# 阻断型分型与分型规则同源（避免两处漂移）
from core.llm._failure import BLOCKING_KINDS, LLM_PROTOCOL_MESSAGE

log = get_logger("llm.preflight")


# 认为"偏低、需要降速"的 RPM 阈值
LOW_RPM_THRESHOLD = 20.0

# 连通性自检用的最小工具定义（只用它验证"模型能不能吐 tool_calls"）
_PROBE_TOOL: list[dict] = [{
    "type": "function",
    "function": {
        "name": "preflight_ping",
        "description": "连通性自检用：把 echo 参数原样回显。",
        "parameters": {
            "type": "object",
            "properties": {"echo": {"type": "string", "description": "要回显的字符串"}},
            "required": ["echo"],
        },
    },
}]


def _toolcheck_enabled() -> bool:
    """是否启用带 tools 的连通性自检（逃生门 ``XUANJIAN_LLM_PROBE_TOOLCHECK=0``）。"""
    raw = (os.environ.get("XUANJIAN_LLM_PROBE_TOOLCHECK") or "").strip().lower()
    return raw not in ("0", "false", "off", "no")


def _probe_tool_call(config: Any) -> dict:
    """发一次**带 tools** 的最小请求，验证模型能否返回可用结构。

    为什么必须带 tools：``_probe_once`` 只证明"服务在"（不带 tools、max_tokens=1）。
    924 实测的失败形态是「能连通、不报错，但流式响应降级解析后为空」——
    这种模型在 ping 阶段完全正常，一到 Agent 循环就全程空转。
    带 tools 的探测才能覆盖那条路径。

    Returns:
        ``{"ok": bool, "kind": str, "message": str, "raw": str}``
    """
    try:
        from core.llm._config import Message
        from core.llm import LLMClient, _health
    except Exception as e:  # pragma: no cover
        return {"ok": True, "kind": "unknown", "message": f"toolcheck 不可用: {e}", "raw": ""}
    try:
        _client = LLMClient(config)
        _resp = _client.chat(
            [Message(role="user", content="请调用 preflight_ping 工具，echo 参数填 ok。")],
            tools=_PROBE_TOOL,
            temperature=0.0,
            max_tokens=128,
            caller="preflight_toolcheck",
            max_retries=0,
            use_cache=False,      # 探测必须真打 API
        )
    except Exception as e:
        _name = type(e).__name__
        if _name == "LLMEmptyResponseError":
            return {"ok": False, "kind": "llm_protocol",
                    "message": LLM_PROTOCOL_MESSAGE, "raw": str(e)[:400]}
        # 其它异常（限流/网络/模型名）由 _probe_once 负责分型，这里不重复判定
        return {"ok": True, "kind": "unknown", "message": f"toolcheck 跳过: {e}", "raw": ""}

    if _health.looks_empty(_resp):
        return {"ok": False, "kind": "llm_protocol",
                "message": LLM_PROTOCOL_MESSAGE,
                "raw": f"toolcheck 返回空响应（content/tool_calls 均为空），model={getattr(config, 'model', '')}"}
    # 自检通过 → 清掉这次探测对连续计数的影响（探测不属于业务调用）
    _health.reset()
    return {"ok": True, "kind": "ok", "message": "模型可返回工具调用", "raw": ""}


def _probe_once(config: Any, timeout_note: str = "") -> dict:
    """发一次最小请求（max_tokens=1）探测模型可达性与账户状态。

    Returns:
        ``{"ok": bool, "kind": str, "message": str, "raw": str}``
    """
    try:
        from core.llm._config import Message
        # ★ 分型函数在 core.llm._failure（FOUNDATION）。不能从
        #   core.session.chat_loop 拿 —— 那是上层编排，反向依赖会被
        #   scripts/layer_lint.py 硬拦（A1 分层契约）。
        from core.llm._failure import classify_llm_failure as _classify_llm_failure
    except Exception as e:  # pragma: no cover
        return {"ok": True, "kind": "unknown", "message": f"preflight 不可用: {e}", "raw": ""}
    try:
        from core.llm import LLMClient
        _client = LLMClient(config)
        # max_retries=0：preflight 必须快速失败，不能把 6 次退避跑满
        _client.chat(
            [Message(role="user", content="ping")],
            tools=None,
            temperature=0.0,
            max_tokens=1,
            caller="preflight",
            max_retries=0,
            use_cache=False,       # 探测必须真打 API，不能用缓存
        )
        return {"ok": True, "kind": "ok", "message": "模型可达", "raw": ""}
    except Exception as e:
        _raw = str(e)
        # ★ F4: 显式捕获 LLMEmptyResponseError（按 type(e).__name__，与
        #   _probe_tool_call:88-91 同款）→ 直接判 llm_protocol（阻断型）。
        #   之前该异常的文本「模型 wuwen 连续 3 次返回空响应…」不含任何
        #   LLM_FAILURE_RULES 关键词 → 落到 llm_error 兜底 → blocking=False
        #   → ok=True 提前 return → _probe_tool_call 永不执行。
        #   现已同步在 _failure.classify_llm_failure 加了 llm_protocol 规则，
        #   此处显式判定是 belt-and-suspenders（防规则漂移）。
        if type(e).__name__ == "LLMEmptyResponseError":
            return {"ok": False, "kind": "llm_protocol",
                    "message": LLM_PROTOCOL_MESSAGE, "raw": _raw[:400]}
        _kind, _msg = _classify_llm_failure(_raw)
        return {"ok": False, "kind": _kind, "message": _msg, "raw": _raw[:400]}


def _window_note(config: Any) -> str | None:
    """检查模型上下文窗口是否已知（未知 → 按 32K 保守估算）。"""
    try:
        from core.llm._tokens import available_input_budget, get_model_context_window
        _win = get_model_context_window(getattr(config, "model", "") or "")
        # ★ 924：预算数字走单一权威实现，避免与 _client 预检文案不一致
        _budget = available_input_budget(getattr(config, "model", "") or "")
    except Exception:
        return None
    if not _win or int(_win) <= 32768:
        return (
            f"模型 `{getattr(config, 'model', '')}` 上下文窗口未知或偏小"
            f"（按 {_win or 32768} 保守估算），实际可用输入约 "
            f"{_budget} tokens。**子 Agent 的固定提示词已占约 17K，"
            f"极易在第 1 轮即超限** —— 建议改用窗口 ≥64K 的模型，"
            f"或先把 XUANJIAN_LLM_DEFAULT_CONTEXT_WINDOW 配成该模型的真实窗口"
        )
    return None


# ★ F4: 仅这两类失败可"自愈"（重试有效），preflight 据此早退。
#   其余失败分型（含 llm_protocol / llm_model / llm_account / llm_auth / llm_error）
#   一律继续走 _probe_tool_call —— ping 失败可能是熔断计数污染导致的假阴性，
#   toolcheck 才是协议兼容性的权威判定。
_SELF_HEALING_KINDS = frozenset({"llm_rate_limit", "llm_network"})


def preflight_llm(config: Any, *, rpm: float | None = None) -> dict:
    """对给定 LLM 配置做开跑前健康检查。

    Args:
        config: ``LLMConfig`` 实例（需含 model / base_url / api_key / provider）。
        rpm: 已知的组织 RPM 上限（可选）。``None`` 时读环境变量
            ``XUANJIAN_LLM_RPM``。

    Returns:
        dict，字段：
        - ``ok``: 是否可以通过（False 表示**阻断**）
        - ``blocking``: 是否属于"不进 Phase 0"的阻断型
        - ``kind``: 分型（``llm_model`` / ``llm_account`` / ``llm_auth`` /
          ``llm_protocol`` / ``llm_rate_limit`` / ``llm_network`` / ``ok``）
        - ``message``: 面向用户的文案（已按分型给出修正动作）
        - ``suggestions``: 降级建议列表（如"降低并发+限速"）
        - ``rpm``: 生效的 RPM（0 = 未设置）
        - ``toolcheck_executed``: 是否执行了带 tools 的连通性自检（F4）
    """
    import os
    if rpm is None:
        try:
            rpm = float((os.environ.get("XUANJIAN_LLM_RPM") or "0").strip() or 0)
        except ValueError:
            rpm = 0.0

    result: dict = {
        "ok": True, "blocking": False, "kind": "ok", "message": "模型健康",
        "suggestions": [], "rpm": rpm, "model": getattr(config, "model", ""),
        "toolcheck_executed": False,
    }

    if config is None:
        result.update(ok=False, blocking=True, kind="llm_auth",
                      message="未配置任何 LLM 模型，请先到「设置 → 模型」添加并启用")
        return result

    probe = _probe_once(config)
    _probe_failed = not probe["ok"]
    if _probe_failed:
        _kind = probe["kind"]
        _blocking = _kind in BLOCKING_KINDS
        # ★ F4: ok = probe["ok"]（失败即 ok=False），不再用 `not _blocking`。
        #   之前 `ok = not _blocking` 把"非阻断"当成"成功" → llm_error 时
        #   blocking=False → ok=True → 提前 return → toolcheck 被跳过。
        result.update(
            ok=probe["ok"],
            blocking=_blocking,
            kind=_kind,
            message=probe["message"],
            raw=probe["raw"],
        )
        log.warning("[preflight] 模型不可用: kind=%s blocking=%s raw=%s",
                    _kind, _blocking, probe["raw"][:200])
        # ★ F4: 仅自愈型（限流/网络）早退；其余失败继续走 toolcheck
        #   （ping 失败可能是熔断计数污染的假阴性，toolcheck 才是权威判定）。
        if _kind in _SELF_HEALING_KINDS:
            result["suggestions"].append(
                "当前问题可自愈（限流/网络），将自动降速重试")
            return result

    # ★ 924：可达 ≠ 可用。再做一次**带 tools** 的连通性自检，
    #   拦截"能连通但响应解析为空"的模型（wuwen 形态）。
    #   ★ F4：即使 _probe_once 失败也继续走到这里（除非是自愈型早退）。
    if _toolcheck_enabled():
        _tc = _probe_tool_call(config)
        result["toolcheck_executed"] = True
        if not _tc["ok"]:
            _tc_kind = _tc.get("kind") or "llm_protocol"
            result.update(
                ok=False,
                blocking=_tc_kind in BLOCKING_KINDS,
                kind=_tc_kind,
                message=_tc["message"],
                raw=_tc.get("raw", ""),
            )
            log.warning("[preflight] tool-call 连通性自检未通过: kind=%s raw=%s",
                        _tc_kind, str(_tc.get("raw", ""))[:200])
            return result
        # toolcheck 通过
        if _tc.get("kind") == "unknown":
            # toolcheck 遇到非协议异常（如模型名 404）→ 无法判定， defer to _probe_once
            if _probe_failed:
                # _probe_once 已失败 → 保留其结论（不让 toolcheck 的 unknown 覆盖）
                return result
        elif _probe_failed:
            # ping 失败但 toolcheck 真正通过 → ping 是假阴性（熔断计数污染）
            log.info("[preflight] ping 失败但 toolcheck 通过（疑被熔断计数污染），放行")
            result.update(ok=True, blocking=False, kind="ok",
                          message="模型健康", raw="")
    elif _probe_failed:
        # toolcheck 未启用且 ping 失败 → 保留失败结论
        return result

    # 可达 → 检查降级项
    if 0 < rpm < LOW_RPM_THRESHOLD:
        result["suggestions"].append(
            f"该 Key 组织上限约 {rpm:.0f} 请求/分钟，本次扫描预计需要远超此数，"
            f"建议将 LLM_SCAN_MAX_WORKERS 降为 1 并启用限速"
            f"（环境变量 XUANJIAN_LLM_RPM={rpm:.0f}）"
        )
    _wn = _window_note(config)
    if _wn:
        result["suggestions"].append(_wn)

    result["message"] = ("模型健康，可直接开跑" if not result["suggestions"]
                         else "模型可达，但有降级建议")
    return result
