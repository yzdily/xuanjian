"""Token 估算工具与上下文窗口表。

从 core.llm 拆分而来。
"""
from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.llm._config import Message

# ============================================================
# ★ Token 估算工具 — 无需 tiktoken，基于字符的启发式估算
# ============================================================
# 用于：
# 1. ContextManager.should_compress() 的 token 触发条件
# 2. LLMClient.chat() 发送前的 context 超限预检
#
# 启发式规则（与 tiktoken 误差通常 ±20%，足够用于预检和压缩触发）：
# - CJK 字符（中日韩）：每个约 1 token
# - ASCII/拉丁字符：每 4 个字符约 1 token

# 常见模型的上下文窗口大小（tokens），用于预检
_MODEL_CONTEXT_WINDOWS: dict[str, int] = {
    # DeepSeek
    "deepseek-chat": 65536,
    "deepseek-coder": 16384,
    "deepseek-reasoner": 65536,
    "deepseek-r1": 65536,
    # Moonshot / Kimi
    "moonshot-v1-8k": 8192,
    "moonshot-v1-32k": 32768,
    "moonshot-v1-128k": 131072,
    "kimi": 131072,
    "kimi-k2": 131072,
    "kimi2": 131072,
    # Qwen
    "qwen2.5-coder": 32768,
    "qwen2.5": 32768,
    "qwen-plus": 131072,
    "qwen-max": 32768,
    "qwen-turbo": 8192,
    # OpenAI
    "gpt-4o": 128000,
    "gpt-4o-mini": 128000,
    "gpt-4-turbo": 128000,
    "gpt-4": 8192,
    "gpt-3.5-turbo": 16384,
    # Anthropic
    "claude-3-5-sonnet": 200000,
    "claude-3-5-haiku": 200000,
    "claude-3-opus": 200000,
    "claude-3-sonnet": 200000,
    "claude-3-haiku": 200000,
    # Meta
    "llama3": 8192,
    "llama3.1": 131072,
    # GLM
    "glm-4": 131072,
    "glm-4-flash": 131072,
}

# 默认上下文窗口（未匹配到已知模型时使用）
_DEFAULT_CONTEXT_WINDOW = int(os.getenv("XUANJIAN_LLM_DEFAULT_CONTEXT_WINDOW", "32768"))

# 预检安全系数：估算 token * 此系数 < 上下文窗口才放行
# 留出余量应对估算偏差 + max_tokens 预留
_CONTEXT_PRECHECK_SAFETY = 0.85


def get_model_context_window(model: str) -> int:
    """根据模型名推断上下文窗口大小（tokens）。

    先精确匹配，再模糊匹配（模型名包含 key），最后回退到默认值。
    """
    if not model:
        return _DEFAULT_CONTEXT_WINDOW
    model_lower = model.lower()
    # 精确匹配
    if model_lower in _MODEL_CONTEXT_WINDOWS:
        return _MODEL_CONTEXT_WINDOWS[model_lower]
    # 模糊匹配：模型名包含已知 key
    for key, window in _MODEL_CONTEXT_WINDOWS.items():
        if key in model_lower:
            return window
    return _DEFAULT_CONTEXT_WINDOW


def estimate_text_tokens(text: str) -> int:
    """估算文本的 token 数（无需 tokenizer）。

    启发式规则：
    - CJK 字符（中日韩统一表意文字、平假名、片假名、全角符号）：每个约 1 token
    - 其他字符（ASCII/拉丁/标点/空白）：每 4 个字符约 1 token

    对于混合中英文内容，误差通常在 ±20% 以内，足够用于预检和压缩触发。
    """
    if not text:
        return 0
    cjk_count = 0
    other_count = 0
    for ch in text:
        cp = ord(ch)
        if (0x4E00 <= cp <= 0x9FFF    # CJK Unified Ideographs
            or 0x3400 <= cp <= 0x4DBF  # CJK Extension A
            or 0x3000 <= cp <= 0x30FF  # CJK Symbols + Hiragana + Katakana
            or 0xFF00 <= cp <= 0xFFEF  # Fullwidth Forms
            or 0xF900 <= cp <= 0xFAFF  # CJK Compatibility Ideographs
        ):
            cjk_count += 1
        else:
            other_count += 1
    return cjk_count + (other_count // 4)


def estimate_messages_tokens(messages: list["Message"], tools: list[dict] | None = None) -> int:
    """估算消息列表的总 token 数（含工具定义开销）。

    每条消息的 token 开销：
    - role 标记：约 4 tokens
    - content 文本：estimate_text_tokens(content)
    - tool_calls JSON：estimate_text_tokens(json.dumps(...))
    - tool_call_id：约 3 tokens
    - reasoning_content：estimate_text_tokens(reasoning_content)

    工具定义开销：每个工具约 80 tokens（函数名 + 参数 schema 的保守估算）
    """
    total = 0
    for m in messages:
        total += 4  # role 标记开销
        if m.content:
            total += estimate_text_tokens(m.content)
        if m.tool_calls:
            total += estimate_text_tokens(json.dumps(m.tool_calls, ensure_ascii=False))
            total += len(m.tool_calls) * 3  # 每个 tool_call_id 约 3 tokens
        if m.tool_call_id:
            total += 3
        if m.reasoning_content:
            total += estimate_text_tokens(m.reasoning_content)

    if tools:
        # 每个工具定义约 50-100 tokens，保守取 80
        total += len(tools) * 80

    return total


class ContextLimitError(Exception):
    """输入 token 数估算超过模型上下文窗口时抛出。

    调用方（chat_loop / worker_agent）捕获后应触发 compress() 再重试。
    """

    def __init__(self, estimated_tokens: int, context_window: int, model: str):
        self.estimated_tokens = estimated_tokens
        self.context_window = context_window
        self.model = model
        super().__init__(
            f"上下文超限: 估算 {estimated_tokens} tokens > 可用 "
            f"{context_window} (model={model})"
        )
