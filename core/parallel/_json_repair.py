"""LLM JSON 修复工具 — 从 batch_test.py 抽出的纯函数模块。

为什么独立：batch_test.py 已 1033 行，此函数为纯算法、零业务依赖、
零外部调用方，独立成模块可降低原文件体积并便于单测。
"""
from __future__ import annotations

import json
import re as _re


def _repair_llm_json(json_str: str) -> str | None:
    """修复 LLM 返回的常见 JSON 格式问题。

    修复项：
    1. 尾随逗号（]}, 前的多余逗号）
    2. 单引号 → 双引号
    3. JSON 中的注释（// 行注释和 /* */ 块注释）
    4. 字符串内未转义的控制字符（换行/制表符）
    5. 缺少逗号分隔的相邻键值对
    6. 大括号不匹配（多余的 } 或缺少的 }）

    Returns:
        修复后的 JSON 字符串，或 None（无法修复）
    """
    if not json_str:
        return None

    repaired = json_str

    # 1. 移除注释（// 行注释和 /* */ 块注释，不在字符串内的）
    # 简单方法：逐行处理，移除不在引号内的 // 注释
    lines = repaired.split("\n")
    cleaned_lines = []
    for line in lines:
        # 跳过纯注释行
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue
        # 移除行内注释（简单处理：找不在引号内的 //）
        in_string = False
        quote_char = None
        result = []
        i = 0
        while i < len(line):
            ch = line[i]
            if not in_string and ch in ('"', "'"):
                in_string = True
                quote_char = ch
            elif in_string and ch == quote_char and (i == 0 or line[i-1] != '\\'):
                in_string = False
                quote_char = None
            elif not in_string and ch == '/' and i + 1 < len(line) and line[i+1] == '/':
                break  # 行内注释开始，截断
            result.append(ch)
            i += 1
        cleaned_lines.append("".join(result))
    repaired = "\n".join(cleaned_lines)

    # 2. 移除块注释残留
    repaired = _re.sub(r'/\*.*?\*/', '', repaired, flags=_re.DOTALL)

    # 3. 修复尾随逗号
    repaired = _re.sub(r',\s*([}\]])', r'\1', repaired)

    # 4. 修复单引号 → 双引号（仅在非字符串上下文中的键名和值）
    # 简单替换：JSON 中单引号作字符串引号 → 双引号
    repaired = _re.sub(r"(?<!\\)'", '"', repaired)

    # 5. 修复字符串内未转义的控制字符
    # 将字符串值中的裸换行符替换为 \\n
    # 匹配双引号字符串内容（非贪婪），替换其中的控制字符
    repaired = _re.sub(r'"[^"]*"', _escape_control_chars, repaired)

    # 6. 修复缺少逗号的相邻键值对
    # }"key": → },"key": 和 ]"key": → ],"key":
    repaired = _re.sub(r'([}\]])\s*(")', r'\1,\2', repaired)
    # value"key": → value,"key": (数字/布尔/null 后直接跟引号)
    repaired = _re.sub(r'([0-9truefalsenull])\s+(")', r'\1,\2', repaired)
    # }"key" 和 ]"key" 已在上面处理

    # 7. 修复大括号不匹配：统计 { 和 } 数量，补齐缺失的
    open_count = repaired.count('{')
    close_count = repaired.count('}')
    if open_count > close_count:
        repaired = repaired + '}' * (open_count - close_count)
    elif close_count > open_count:
        # 移除多余的 }
        diff = close_count - open_count
        idx = len(repaired)
        while diff > 0 and idx > 0:
            idx = repaired.rfind('}', 0, idx)
            if idx < 0:
                break
            repaired = repaired[:idx] + repaired[idx+1:]
            diff -= 1

    return repaired

# --- hoisted from _repair_llm_json (A-grade, no local capture) ---
def _escape_control_chars(m):
    s = m.group(0)
    return s.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
