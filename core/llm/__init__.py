"""LLM 客户端 — 统一封装 OpenAI 兼容协议 + Anthropic 原生协议。

支持通过 .env 配置 1~3 个模型，运行时按名称切换。
兼容 DeepSeek V4 的 reasoning_content（思考模式）。

该模块已由单文件 core/llm.py 重构为 core/llm/ 包；此 __init__.py 负责装配
各子模块并保持原有公开 API 与导入副作用不变：
- 导入即注册 harm_validation 并发池（_context）
- 导入即创建 _response_cache 全局（_response_cache）
- 导入即创建 _monitor 全局（_monitor）
"""
import time  # noqa: F401  提供 core.llm.time 属性供 patch("core.llm.time.time") 使用

from dotenv import load_dotenv

from core.log import get_logger

load_dotenv()

log = get_logger("llm")  # noqa: F401  提供 core.llm.log 属性

# ============================================================
# 子模块装配（顺序保证导入副作用触发）：
# 1) _context        —— 注册 harm_validation 并发池
# 2) _response_cache —— 创建 _response_cache 全局
# 3) _monitor        —— 创建 _monitor 全局
# 之后按依赖序导入其余子模块
# ============================================================
from core.llm._context import (
    _DEFAULT_LLM_CONCURRENCY,
    _get_caller_semaphore,
    get_current_task,
    register_llm_caller_pool,
    reset_current_task,
    set_current_task,
)
from core.llm._response_cache import (
    LLMResponseCache,
    _response_cache,
)
from core.llm._monitor import (
    LLMMonitor,
    _monitor,
)
from core.llm._tokens import (
    _CONTEXT_PRECHECK_SAFETY,
    _DEFAULT_CONTEXT_WINDOW,
    _MODEL_CONTEXT_WINDOWS,
    ContextLimitError,
    estimate_messages_tokens,
    estimate_text_tokens,
    get_model_context_window,
)
from core.llm._crypto import (
    _ENC_KEY_INFO,
    _ENC_PREFIX,
    _decrypt_api_key,
    _encrypt_api_key,
    _get_encryption_key,
    _xor_stream,
)
from core.llm._parse import (
    _THINK_BLOCK_PATTERN,
    _extract_balanced,
    _fix_trailing_commas,
    _strip_code_fences,
    _strip_think_blocks,
    parse_llm_json,
    parse_tool_call_arguments,
)
from core.llm._config import (
    _DEEPSEEK_WRONG_PATTERN,
    _KIMI_DEPRECATED_PATTERN,
    _MODEL_NAME_CORRECTIONS,
    _ObjectProxy,
    _PROVIDER_ALIASES,
    _SseToolCall,
    _is_placeholder_key,
    _normalize_model_name,
    _normalize_provider,
    _parse_sse_chat_payload,
    _parse_xml_tool_calls,
    LLMConfig,
    Message,
    load_llm_configs,
    mask_api_key,
    save_llm_configs,
)
from core.llm._client import LLMClient
from core.llm._pool import LLMPool

__all__ = [
    # public
    "LLMClient", "LLMPool", "LLMConfig", "Message", "LLMMonitor",
    "LLMResponseCache", "ContextLimitError", "parse_llm_json",
    "parse_tool_call_arguments", "estimate_text_tokens",
    "estimate_messages_tokens", "get_model_context_window",
    "set_current_task", "reset_current_task", "get_current_task",
    "register_llm_caller_pool", "load_llm_configs", "save_llm_configs",
    "mask_api_key",
    # private (re-exported for back-compat with business code / tests)
    "_monitor", "_response_cache", "_parse_sse_chat_payload",
    "_MODEL_NAME_CORRECTIONS", "_parse_xml_tool_calls", "_normalize_provider",
    "_normalize_model_name", "_encrypt_api_key", "_decrypt_api_key",
    "_get_caller_semaphore", "_DEFAULT_LLM_CONCURRENCY", "_is_placeholder_key",
    "_PROVIDER_ALIASES", "_DEEPSEEK_WRONG_PATTERN", "_KIMI_DEPRECATED_PATTERN",
    "_MODEL_CONTEXT_WINDOWS", "_DEFAULT_CONTEXT_WINDOW", "_CONTEXT_PRECHECK_SAFETY",
    "_THINK_BLOCK_PATTERN", "_strip_think_blocks", "_strip_code_fences",
    "_extract_balanced", "_fix_trailing_commas", "_SseToolCall", "_ObjectProxy",
    "_ENC_PREFIX", "_ENC_KEY_INFO", "_get_encryption_key", "_xor_stream",
]
