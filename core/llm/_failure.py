"""LLM 失败分型（纯函数，FOUNDATION 层）。

★ 为什么单独成模块：分型被两处需要 ——
``core.session.chat_loop``（运行中失败文案）与 ``core.llm._preflight``
（开跑前健康检查）。若放在 ``core.session`` 里，``core.llm`` 反向依赖上层编排，
违反 A1 分层契约（``scripts/layer_lint.py`` 会硬拦）。

★ 修 B5 (0923 v2)。修正前所有 LLM 失败统一提示「发送消息可重试」，
但实测四次失败里三次是**配置性错误**（模型名 404 / 余额不足 / 组织 RPM 上限），
重试必然再次失败 —— 等于引导用户做一个注定失败的动作。
"""

from __future__ import annotations

# llm_protocol 的面向用户文案（preflight 直接引用）
# ★ 924 F4：空响应（模型协议不兼容）的面向用户文案。
#   必须在 LLM_FAILURE_RULES 之前定义，以便规则引用。
LLM_PROTOCOL_MESSAGE = (
    "模型返回格式与本系统不兼容：流式响应解析后既无正文、也无工具调用。"
    "继续扫描只会得到「跑完了但实际什么都没测」的假结论"
    "（实测该形态会同时导致 0 已证明漏洞 与 2% 真实完成率），"
    "重试与上下文压缩均无效。请到「设置 → 模型」更换标准 OpenAI 兼容模型"
    "（如 deepseek-chat / kimi）后重新扫描。"
)

# (种类, 命中关键词, 是否值得重试, 面向用户的修正指引)
# ★ 924 F4：新增 llm_protocol 规则 —— 把「连续 N 次返回空响应」文本直接分型为
#   llm_protocol（阻断型），不再落到兜底 llm_error（非阻断）。
#   之前 _probe_once 捕获 LLMEmptyResponseError 后调 classify_llm_failure，
#   其消息文本「模型 wuwen 连续 3 次返回空响应…」不含任何既有规则关键词 →
#   落到 llm_error 兜底 → blocking=False → ok=True 提前 return →
#   _probe_tool_call 永不执行（全日志 toolcheck 仅 2 次）。
LLM_FAILURE_RULES: tuple[tuple[str, tuple[str, ...], bool, str], ...] = (
    (
        "llm_protocol",
        ("空响应", "empty response", "既无 content 也无 tool_calls",
         "content 与 tool_calls 均为空", "no content and no tool_calls"),
        False,
        LLM_PROTOCOL_MESSAGE,
    ),
    (
        "llm_model",
        ("not found the model", "model_not_found", "model not found",
         "does not exist", "no such model", "invalid model",
         "unknown model", "unsupported model"),
        False,
        "模型名不存在或无权访问，请到「设置 → 模型」修正后重试（重试当前任务无效）",
    ),
    (
        "llm_account",
        ("insufficient balance", "insufficient_quota",
         "exceeded_current_quota", "account is suspended",
         "billing", "余额"),
        False,
        "账户余额不足或已被暂停，请充值或更换 API Key（重试无效）",
    ),
    (
        "llm_auth",
        ("401", "invalid api key", "incorrect api key",
         "unauthorized", "authentication"),
        False,
        "API Key 无效或已过期，请更新 Key（重试无效）",
    ),
    (
        "llm_rate_limit",
        ("429", "rate limit", "rate_limit", "too many requests"),
        True,
        "LLM 限流（组织配额已达上限），将自动降速重试；若持续失败请换 Key 或降低并发",
    ),
    (
        "llm_network",
        ("timeout", "timed out", "connection", "502", "503", "504",
         "overloaded", "server_error", "connection error"),
        True,
        "LLM 网络异常（服务端/链路问题），稍后重试即可",
    ),
)

# 阻断型：用户必须改配置才能继续，preflight 据此拒绝进入 Phase 0
# ★ 924 新增 llm_protocol：模型能连通、账户正常，但**返回格式不兼容**
#   （流式响应降级解析后既无 content 也无 tool_calls）。
#   它不是"调用失败"，所以 LLM_FAILURE_RULES 的文本规则抓不到它 ——
#   由 _preflight 的 tool-call 连通性自检直接置为该 kind。
#   实测 task_1790223312_c75b16：wuwen 全程空响应，最终得出
#   「0 已证明漏洞」的假结论。此类问题**重试与压缩都无效**，必须换模型，
#   故列为阻断型。
BLOCKING_KINDS = frozenset({"llm_model", "llm_account", "llm_auth", "llm_protocol"})


def classify_llm_failure(err_text: str) -> tuple[str, str]:
    """把 LLM 异常文本分型，返回 ``(reason_kind, user_message)``。

    判定顺序重要：模型名 404 的报错里也可能出现 ``429``（request id），
    所以 ``llm_model`` 必须排在 ``llm_rate_limit`` / ``llm_auth`` 之前。

    Args:
        err_text: 原始异常文本（大小写不敏感）。

    Returns:
        ``(kind, message)``；未命中任何规则时返回 ``("llm_error", 通用文案)``。
    """
    s = (err_text or "").lower()
    for kind, keys, _retryable, msg in LLM_FAILURE_RULES:
        if any(k in s for k in keys):
            return kind, msg
    return "llm_error", f"LLM 调用失败，发送消息可重试（原始错误：{err_text[:120]}）"


def llm_failure_retryable(err_text: str) -> bool:
    """该 LLM 失败是否值得重试（供 UI 决定是否显示"可重试"）。"""
    s = (err_text or "").lower()
    for _kind, keys, retryable, _msg in LLM_FAILURE_RULES:
        if any(k in s for k in keys):
            return retryable
    return True


def is_blocking_failure(err_text: str) -> bool:
    """该失败是否属于"阻断型"（重试无效，必须改配置）。"""
    return classify_llm_failure(err_text)[0] in BLOCKING_KINDS
