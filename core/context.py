"""
Context — 上下文管理与压缩

当对话轮数超过阈值或 token 估算超过阈值时，将历史消息压缩为摘要，
保持"高信号、低噪音"的上下文窗口。

参考 BreachWeave 的 RTK 三层压缩机制。
"""

from __future__ import annotations

import os
from core.llm import LLMClient, Message, estimate_messages_tokens
from core.prompts import load_prompt


# ---- 压缩触发阈值 ----

# 轮次触发（兜底）：assistant 消息数达到此值时触发压缩
COMPRESS_THRESHOLD = int(os.getenv("CONTEXT_COMPRESS_THRESHOLD", "30"))

# ★ Token 触发（主触发）：上下文 token 估算达到此值时触发压缩
# 默认 24000：对 32K 模型（75% 窗口）提前压缩，对 64K+ 模型更早压缩以降低成本
# 可通过环境变量 CONTEXT_TOKEN_COMPRESS_THRESHOLD 覆盖
CONTEXT_TOKEN_COMPRESS_THRESHOLD = int(os.getenv("CONTEXT_TOKEN_COMPRESS_THRESHOLD", "24000"))

# ---- 压缩时的保留/截断策略（阶段 5-E2 可配置化） ----
# 原先 keep_count 硬编码为 20、摘要只取 user/assistant 的 content[:500]，
# 导致超出部分的 tool 消息（=测试样本结论）**既不保留也不进摘要** → 丢弃即不可恢复。
# 实测 M4 基线：30 轮丢 23 条 / 45 轮 38 条 / 60 轮 53 条（_e2_m4_baseline.py）。
KEEP_RECENT_MESSAGES = int(os.getenv("CONTEXT_KEEP_RECENT", "20"))
#: 被压缩的 tool 消息带进摘要的字符数（0 = 沿用旧行为，完全不进摘要）
TOOL_SUMMARY_CHARS = int(os.getenv("CONTEXT_TOOL_SUMMARY_CHARS", "400"))
#: 被压缩的 user/assistant 消息带进摘要的字符数
SUMMARY_TEXT_CHARS = int(os.getenv("CONTEXT_SUMMARY_TEXT_CHARS", "500"))
#: 单次压缩中带进摘要的 tool 消息条数上限（防止摘要输入本身爆掉）
TOOL_SUMMARY_MAX_ITEMS = int(os.getenv("CONTEXT_TOOL_SUMMARY_MAX", "40"))

COMPRESS_PROMPT = load_prompt("compress")

# ★ 2026-05-28：BrowseWorker 专用压缩 prompt
# 针对浏览器操作场景优化，重点保留 checklist 进度和 selector 失败记录
BROWSE_COMPRESS_PROMPT = load_prompt("browse_compress")


class ContextManager:
    """管理对话上下文，支持自动压缩。

    压缩触发条件（满足任一即触发）：
    1. Token 估算超过 CONTEXT_TOKEN_COMPRESS_THRESHOLD（主触发，防止 context 爆炸）
    2. 轮次超过 COMPRESS_THRESHOLD（兜底，防止估算偏差导致不压缩）
    """

    def __init__(self, llm: "LLMClient | None" = None, compress_mode: str = "default"):
        """
        Args:
            llm: LLM 客户端实例；可为 None（fast/无 LLM 模式），仅在 compress() 时需要
            compress_mode: 压缩模式，"default" 使用通用渗透测试压缩，
                          "browse" 使用 BrowseWorker 专用压缩（保留 checklist 进度）
        """
        self.llm = llm
        self.compress_mode = compress_mode
        self.system_messages: list[Message] = []
        self.history: list[Message] = []
        self._compressed_summary: str = ""
        # ★ Token 估算缓存：避免每次 should_compress() 都重新计算
        # _token_estimate_dirty 标记 history/system 是否变化，变化后需重新估算
        self._cached_token_estimate: int = 0
        self._token_estimate_dirty: bool = True
        # ★ 阶段 5-E2：压缩累计次数 + 上一次压缩统计（供 ContextGauge 打点 / M4 观测）。
        #   不改变任何既有方法的返回值，纯增量。
        self.compress_count: int = 0
        self.last_compress_stats: dict = {
            "compressed": False,
            "dropped_messages": 0,
            "dropped_tool_samples": 0,
            "kept_messages": 0,
            "tool_samples_in_summary": 0,
            "before_tokens": 0,
            "after_tokens": 0,
        }

    def add_system(self, content: str) -> None:
        self.system_messages.append(Message(role="system", content=content))
        self._token_estimate_dirty = True

    def add_user(self, content: str) -> None:
        self.history.append(Message(role="user", content=content))
        self._token_estimate_dirty = True

    def add_assistant(self, msg: Message) -> None:
        self.history.append(msg)
        self._token_estimate_dirty = True

    def add_tool_result(self, tool_call_id: str, content: str) -> None:
        self.history.append(Message(role="tool", content=content, tool_call_id=tool_call_id))
        self._token_estimate_dirty = True

    def get_messages(self) -> list[Message]:
        """构建完整的消息列表，含系统提示 + 压缩摘要 + 近期历史。

        自动修复 tool_calls/tool 不配对问题，防止 API 400 错误。
        """
        messages = list(self.system_messages)

        if self._compressed_summary:
            messages.append(Message(role="system", content=f"## 之前的渗透过程摘要\n\n{self._compressed_summary}"))

        # 安全检查：确保 assistant(tool_calls) 后面跟着对应的 tool 消息
        safe_history = self._ensure_tool_pairing(self.history)
        messages.extend(safe_history)
        return messages

    @staticmethod
    def _ensure_tool_pairing(history: list[Message]) -> list[Message]:
        """确保 history 中 assistant(tool_calls) 和 tool(result) 正确配对。

        如果发现不配对的情况，移除孤立的消息。
        """
        result: list[Message] = []
        i = 0
        while i < len(history):
            msg = history[i]

            if msg.role == "assistant" and msg.tool_calls:
                # 收集这个 assistant 消息需要的所有 tool_call_id
                expected_ids = {tc["id"] for tc in msg.tool_calls}

                # 向后查找所有匹配的 tool 消息
                tool_msgs = []
                j = i + 1
                found_ids = set()
                while j < len(history) and history[j].role == "tool":
                    if history[j].tool_call_id in expected_ids:
                        tool_msgs.append(history[j])
                        found_ids.add(history[j].tool_call_id)
                    j += 1

                if found_ids == expected_ids:
                    # 完整配对，全部保留
                    result.append(msg)
                    result.extend(tool_msgs)
                else:
                    # 不完整 — 跳过这个 assistant 及其 tool 消息
                    pass

                i = j
            elif msg.role == "tool":
                # 孤立的 tool 消息（前面没有 assistant+tool_calls），跳过
                i += 1
            else:
                result.append(msg)
                i += 1

        return result

    @property
    def turn_count(self) -> int:
        return sum(1 for m in self.history if m.role == "assistant")

    def estimate_tokens(self) -> int:
        """估算当前完整上下文（system + summary + history）的 token 数。

        使用基于字符的启发式估算（无需 tokenizer），结果缓存到
        _cached_token_estimate，仅在 history 变化时重新计算。

        估算包含 tool_calls JSON 和 tool_call_id 的开销，但不包含
        tools 定义（工具 schema）的开销——后者由 LLMClient.chat() 的
        预检逻辑单独计算。
        """
        if self._token_estimate_dirty:
            messages = self.get_messages()
            self._cached_token_estimate = estimate_messages_tokens(messages)
            self._token_estimate_dirty = False
        return self._cached_token_estimate

    def should_compress_by_tokens(self) -> bool:
        """仅检查 token 估算是否超过阈值。"""
        return self.estimate_tokens() >= CONTEXT_TOKEN_COMPRESS_THRESHOLD

    def check_context_budget(self, context_window: int = 65536, safety: float = 0.6) -> float:
        """★ P0-2/D14: 返回当前上下文使用率（0-1），并在超阈值时硬拦截。

        - usage >= 1.0：已达安全预算上限，记录「拒绝继续注入样本」，
          调用方应停止向上下文注入更多样本（D14 硬拦截）。
        - usage >= 0.8：80% 预警，建议压缩。

        注意：生产侧真正的硬拦截由 ``LLMClient.chat()`` 经
        ``_CONTEXT_PRECHECK_SAFETY``（0.6）在发送前抛 ``ContextLimitError``
        实现；本方法供调用方在注入样本前主动预检，避免被动超限。
        """
        tokens = self.estimate_tokens()
        available = int(context_window * safety)
        usage = tokens / available if available > 0 else 1.0
        import logging
        _log = logging.getLogger("context")
        if usage >= 1.0:
            _log.warning("⭐ 上下文预算硬拦截(D14): %d/%d tokens (%.0f%%) ≥ 安全预算，"
                         "拒绝继续注入样本", tokens, available, usage * 100)
        elif usage >= 0.8:
            _log.warning("⚠️ 上下文预算 80%% 预警: %d/%d tokens (%.0f%%)，建议压缩",
                         tokens, available, usage * 100)
        return usage

    def budget_allows_injection(self, context_window: int = 65536, safety: float = 0.6) -> bool:
        """★ D14 (P0-2)：注入样本前的预算闸门。

        返回 ``True`` 表示当前上下文仍在安全预算内，可继续注入样本；
        返回 ``False`` 表示已超 60% 安全预算（``check_context_budget`` 返回
        usage >= 1.0），调用方应**拒绝继续注入样本**（D14 硬拦截）。

        与 ``LLMClient.chat()`` 发送前的 ``ContextLimitError`` 形成双层防护：
        本方法在「注入样本」阶段主动拒绝，从源头避免上下文被 API 流量样本撑爆。
        """
        return self.check_context_budget(context_window, safety) < 1.0

    def should_compress(self) -> bool:
        """判断是否需要压缩。

        双触发条件（满足任一即触发）：
        1. Token 估算超过 CONTEXT_TOKEN_COMPRESS_THRESHOLD（主触发）
        2. 轮次超过 COMPRESS_THRESHOLD（兜底，防止估算偏差）
        """
        if self.should_compress_by_tokens():
            return True
        return self.turn_count >= COMPRESS_THRESHOLD

    def compress(self) -> str:
        """将历史压缩为摘要，保留最近的完整对话轮次。

        确保 assistant(tool_calls) + tool(result) 配对不被拆散。

        ★ 阶段 5-E2：被压缩的 **tool 消息（测试样本结论）也会带进摘要**。
        原实现只取 user/assistant 的 content[:500]，tool 消息完全不进摘要 ——
        意味着样本结论一旦被切走就**无法从摘要恢复**（实测 M4：30 轮丢 23 条 / 60 轮丢 53 条）。
        现在把 tool 内容按字符数截断后纳入摘要，至少保留「测了什么、结论是什么」。

        统计写入 ``last_compress_stats``（纯增量，不改变返回值，供 ContextGauge 打点）。
        """
        self.last_compress_stats = {
            "compressed": False,
            "dropped_messages": 0,
            "dropped_tool_samples": 0,
            "kept_messages": len(self.history),
            "tool_samples_in_summary": 0,
            "before_tokens": self.estimate_tokens(),
            "after_tokens": 0,
        }
        if len(self.history) < 8:
            return self._compressed_summary

        before_tokens = self.estimate_tokens()

        # 找安全的截断点：从后往前找，保留最近 N 条，
        # 但截断点必须在 user 消息处（不能切在 tool_calls/tool 中间）
        keep_count = max(2, KEEP_RECENT_MESSAGES)
        cut_idx = len(self.history) - keep_count

        # 往前调整到安全位置：确保 cut_idx 处是 user/system，不是 tool
        while cut_idx > 0 and self.history[cut_idx].role in ("tool", "assistant"):
            cut_idx -= 1

        if cut_idx <= 0:
            return self._compressed_summary

        to_compress = self.history[:cut_idx]
        to_keep = self.history[cut_idx:]

        # 构建压缩请求：user/assistant 取文本；★ tool 消息（样本结论）也纳入
        history_parts = []
        tool_in_summary = 0
        for m in to_compress:
            if not m.content:
                continue
            if m.role == "tool":
                if TOOL_SUMMARY_CHARS > 0 and tool_in_summary < TOOL_SUMMARY_MAX_ITEMS:
                    history_parts.append(f"[tool结果]: {m.content[:TOOL_SUMMARY_CHARS]}")
                    tool_in_summary += 1
            elif m.role in ("user", "assistant"):
                history_parts.append(f"[{m.role}]: {m.content[:SUMMARY_TEXT_CHARS]}")
        history_text = "\n".join(history_parts)

        dropped_tool_samples = sum(1 for m in to_compress if m.role == "tool")

        def _record(compressed: bool) -> None:
            if compressed:
                self.compress_count += 1
            after_tokens = self.estimate_tokens()
            self.last_compress_stats = {
                "compressed": compressed,
                "dropped_messages": len(to_compress),
                "dropped_tool_samples": dropped_tool_samples,
                "kept_messages": len(self.history),
                "tool_samples_in_summary": tool_in_summary,
                "before_tokens": before_tokens,
                "after_tokens": after_tokens,
                "compress_count": self.compress_count,
            }
            # ★ 保持既有契约：压缩后 history 已变 → token 缓存必须标记失效
            #   （上面的 estimate_tokens() 顺带把 dirty 置成了 False，此处恢复）
            self._token_estimate_dirty = True

        if not history_text.strip():
            self.history = to_keep
            self._token_estimate_dirty = True
            _record(True)
            return self._compressed_summary

        # ★ 根据压缩模式选择对应的 prompt
        active_prompt = BROWSE_COMPRESS_PROMPT if self.compress_mode == "browse" else COMPRESS_PROMPT

        compress_messages = [
            Message(role="system", content=active_prompt),
            Message(role="user", content=(
                "请压缩以下对话历史。\n\n"
                "**特别注意**：`[tool结果]` 行是实际测试样本的结论，"
                "请把它们「测了什么接口、结论是什么」保留在摘要里，不要只概括过程或只保留计划。\n\n"
                f"{history_text}"
            )),
        ]

        if self._compressed_summary:
            compress_messages.insert(
                1, Message(role="system", content=f"上一轮压缩摘要（请合并）：\n{self._compressed_summary}")
            )

        # ★ llm 未配置时跳过压缩（fast/无 LLM 模式），直接保留近期历史
        if self.llm is None:
            self.history = to_keep
            self._token_estimate_dirty = True
            _record(True)
            return self._compressed_summary

        result = self.llm.chat(compress_messages, temperature=0.1, max_tokens=4096)
        self._compressed_summary = result.content

        # 替换历史，确保 to_keep 的第一条不是 tool
        self.history = to_keep

        # ★ 压缩后标记需要重新估算 token
        self._token_estimate_dirty = True
        _record(True)

        return self._compressed_summary
