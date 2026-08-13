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
        """
        if len(self.history) < 8:
            return self._compressed_summary

        # 找安全的截断点：从后往前找，保留最近 N 条，
        # 但截断点必须在 user 消息处（不能切在 tool_calls/tool 中间）
        keep_count = 20
        cut_idx = len(self.history) - keep_count

        # 往前调整到安全位置：确保 cut_idx 处是 user/system，不是 tool
        while cut_idx > 0 and self.history[cut_idx].role in ("tool", "assistant"):
            cut_idx -= 1

        if cut_idx <= 0:
            return self._compressed_summary

        to_compress = self.history[:cut_idx]
        to_keep = self.history[cut_idx:]

        # 构建压缩请求（只取 user/assistant 的文本内容，忽略 tool 细节）
        history_parts = []
        for m in to_compress:
            if m.role in ("user", "assistant") and m.content:
                history_parts.append(f"[{m.role}]: {m.content[:500]}")
        history_text = "\n".join(history_parts)

        if not history_text.strip():
            return self._compressed_summary

        # ★ 根据压缩模式选择对应的 prompt
        active_prompt = BROWSE_COMPRESS_PROMPT if self.compress_mode == "browse" else COMPRESS_PROMPT

        compress_messages = [
            Message(role="system", content=active_prompt),
            Message(role="user", content=f"请压缩以下对话历史：\n\n{history_text}"),
        ]

        if self._compressed_summary:
            compress_messages.insert(
                1, Message(role="system", content=f"上一轮压缩摘要（请合并）：\n{self._compressed_summary}")
            )

        # ★ llm 未配置时跳过压缩（fast/无 LLM 模式），直接保留近期历史
        if self.llm is None:
            self.history = to_keep
            self._token_estimate_dirty = True
            return self._compressed_summary

        result = self.llm.chat(compress_messages, temperature=0.1, max_tokens=4096)
        self._compressed_summary = result.content

        # 替换历史，确保 to_keep 的第一条不是 tool
        self.history = to_keep

        # ★ 压缩后标记需要重新估算 token
        self._token_estimate_dirty = True

        return self._compressed_summary
