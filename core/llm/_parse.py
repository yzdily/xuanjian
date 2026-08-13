"""统一安全的 LLM JSON 解析（思考块/代码围栏剥离、平衡括号提取、尾逗号修复）。

从 core.llm 拆分而来。
"""
from __future__ import annotations

import json
import re

from core.log import get_logger

log = get_logger("llm")

# ============================================================
# ★ #15 统一的安全 JSON 解析（LLM 输出兜底）
# ============================================================
# 项目里曾存在 6 套重复实现，质量参差不齐；最健壮的 harm_validation/parser.py
# 没被其他模块复用。这里把它的核心逻辑提取上来作为统一入口，所有 LLM JSON
# 解析都应调用本函数，避免工具调用 args 解析失败被静默吞掉等隐患。

_THINK_BLOCK_PATTERN = re.compile(r"<think>[\s\S]*?</think>", re.IGNORECASE)


def _strip_think_blocks(text: str) -> str:
    """剥离 LLM 思考块（<think>...</think>）。"""
    if not text:
        return text
    cleaned = _THINK_BLOCK_PATTERN.sub("", text).strip()
    return cleaned if cleaned else text


def _strip_code_fences(text: str) -> str:
    """剥离 markdown 代码围栏 ```json ... ``` 或 ``` ... ```。"""
    if not text:
        return text
    m = re.search(r"```(?:json)?\s*\n?([\s\S]+?)\n?```", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return text


def _extract_balanced(text: str, open_ch: str, close_ch: str) -> str | None:
    """从 text 中提取第一个平衡的 JSON 片段（字符串感知，支持嵌套）。"""
    start = text.find(open_ch)
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape_next = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _fix_trailing_commas(text: str) -> str:
    """修复 JSON 尾随逗号：`,]` → `]`、`,}` → `}`。"""
    return re.sub(r",(\s*[\]\}])", r"\1", text)


def parse_llm_json(
    text: str,
    *,
    expect: type = dict,
    strip_think: bool = True,
    repair: bool = True,
) -> dict | list | None:
    """统一安全的 LLM JSON 解析。

    解析步骤：
    1. 剥离 <think>...</think> 思考块（DeepSeek/QwQ/R1 类模型）
    2. 剥离 markdown 代码围栏 ```json ... ```
    3. 直接 json.loads
    4. 平衡括号提取（字符串感知，支持嵌套）
    5. 尾逗号修复后重试
    全部失败返回 None。

    Args:
        expect: 期望的类型（dict 或 list）。若解析结果类型不匹配返回 None。
        strip_think: 是否剥离思考块。
        repair: 是否尝试尾逗号修复。
    """
    if not text or not text.strip():
        return None
    raw = text
    cleaned = _strip_think_blocks(raw) if strip_think else raw
    cleaned = _strip_code_fences(cleaned)

    # 3. 直接 parse
    try:
        result = json.loads(cleaned)
        if isinstance(result, expect):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # 4. 平衡括号提取
    open_ch, close_ch = ("{", "}") if expect is dict else ("[", "]")
    candidate = _extract_balanced(cleaned, open_ch, close_ch)
    if candidate:
        try:
            result = json.loads(candidate)
            if isinstance(result, expect):
                return result
        except (json.JSONDecodeError, ValueError):
            pass
        # 5. 尾逗号修复
        if repair:
            fixed = _fix_trailing_commas(candidate)
            try:
                result = json.loads(fixed)
                if isinstance(result, expect):
                    return result
            except (json.JSONDecodeError, ValueError):
                pass

    # 兜底：从原文再试一次（可能 cleaned 被错误剥离）
    if cleaned != raw:
        candidate = _extract_balanced(raw, open_ch, close_ch)
        if candidate:
            try:
                result = json.loads(candidate)
                if isinstance(result, expect):
                    return result
            except (json.JSONDecodeError, ValueError):
                pass
    return None


def parse_tool_call_arguments(raw: str, *, caller: str = "") -> tuple[dict, bool]:
    """解析工具调用 arguments 字符串，失败时返回 ({}, True) 并记日志。

    Returns:
        (args_dict, failed): failed=True 表示解析失败（已尝试修复仍失败）。
        调用方应把失败信息回填给 LLM 让它重发工具调用，而不是带着空 args 继续执行。
    """
    if not raw or not raw.strip():
        return {}, False
    try:
        args = json.loads(raw)
        if isinstance(args, dict):
            return args, False
        if isinstance(args, list):
            # 极少数 LLM 会把 dict 包成 list
            return (args[0] if args and isinstance(args[0], dict) else {}), False
        return {}, True
    except (json.JSONDecodeError, ValueError) as e:
        # 尝试用 parse_llm_json 修复
        repaired = parse_llm_json(raw, expect=dict)
        if repaired is not None:
            log.warning("[%s] tool_call arguments JSON 修复成功: %s", caller or "?", str(e)[:120])
            return repaired, False
        log.warning("[%s] tool_call arguments JSON 解析失败（已尝试修复）: %s; raw=%r",
                    caller or "?", e, raw[:200])
        return {}, True
