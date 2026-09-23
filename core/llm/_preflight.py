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

from typing import Any

from core.log import get_logger
# 阻断型分型与分型规则同源（避免两处漂移）
from core.llm._failure import BLOCKING_KINDS

log = get_logger("llm.preflight")


# 认为"偏低、需要降速"的 RPM 阈值
LOW_RPM_THRESHOLD = 20.0


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
        _kind, _msg = _classify_llm_failure(_raw)
        return {"ok": False, "kind": _kind, "message": _msg, "raw": _raw[:400]}


def _window_note(config: Any) -> str | None:
    """检查模型上下文窗口是否已知（未知 → 按 32K 保守估算）。"""
    try:
        from core.llm import get_model_context_window
        _win = get_model_context_window(getattr(config, "model", "") or "")
    except Exception:
        return None
    if not _win or int(_win) <= 32768:
        return (
            f"模型 `{getattr(config, 'model', '')}` 上下文窗口未知或偏小"
            f"（按 {_win or 32768} 保守估算），实际可用输入约 "
            f"{int((_win or 32768) * 0.6) - 4096} tokens，"
            f"可能导致子 Agent 频繁压缩上下文"
        )
    return None


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
          ``llm_rate_limit`` / ``llm_network`` / ``ok``）
        - ``message``: 面向用户的文案（已按分型给出修正动作）
        - ``suggestions``: 降级建议列表（如"降低并发+限速"）
        - ``rpm``: 生效的 RPM（0 = 未设置）
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
    }

    if config is None:
        result.update(ok=False, blocking=True, kind="llm_auth",
                      message="未配置任何 LLM 模型，请先到「设置 → 模型」添加并启用")
        return result

    probe = _probe_once(config)
    if not probe["ok"]:
        _kind = probe["kind"]
        _blocking = _kind in BLOCKING_KINDS
        result.update(
            ok=not _blocking,
            blocking=_blocking,
            kind=_kind,
            message=probe["message"],
            raw=probe["raw"],
        )
        if not _blocking:
            result["suggestions"].append(
                "当前问题可自愈（限流/网络），将自动降速重试")
        log.warning("[preflight] 模型不可用: kind=%s blocking=%s raw=%s",
                    _kind, _blocking, probe["raw"][:200])
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
