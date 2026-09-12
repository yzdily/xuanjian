"""P2-4 对账 JSON 容错修复回归测试（T11）。

锁定 ``core/reconcile._extract_json`` 的「字符串感知」修复：
当 JSON **值**内部包含 ``{`` ``}`` 字符（如配置描述、代码段）时，
原逻辑按 depth 计数会被误导，导致提前在内部 ``}`` 处截断、解析失败。

修复后（★ P2-4）：进入字符串字面量时 ``in_string=True``，
字符串内的 ``{`` ``}`` 不再改变 depth，能完整提取到最外层的匹配 ``}``。

设计原则：纯函数级测试，零网络、零 LLM。``core/reconcile`` 模块顶层仅依赖
asyncio/json/logging/re/time/pathlib/typing（无重依赖），可在隔离环境直接导入验证。
"""

from __future__ import annotations

import pytest

from core.reconcile import _extract_json


# ============================================================
# 1. P2-4 核心修复：值内含 { } 不误导 depth 计数
# ============================================================
@pytest.mark.parametrize("raw,expected", [
    # 值内含 { } —— 修复前会在内部 } 处截断导致解析失败
    (
        '前导文字 {"desc": "配置使用 {placeholder} 与 [array] 语法", "ok": 1} 尾随',
        {"desc": "配置使用 {placeholder} 与 [array] 语法", "ok": 1},
    ),
    # 值内含嵌套 { }
    (
        '{"rule": "if (x > 0) { y = {a:1} }", "level": 2}',
        {"rule": "if (x > 0) { y = {a:1} }", "level": 2},
    ),
    # 值内含成对大括号 + 方括号混合
    (
        '{"query": "SELECT * FROM t WHERE c IN ({1,2,3})", "n": 5}',
        {"query": "SELECT * FROM t WHERE c IN ({1,2,3})", "n": 5},
    ),
])
def test_braces_inside_string_value_not_misleading(raw, expected):
    """值内的 { } 不应被当作对象边界，必须完整解析到最外层 }。"""
    assert _extract_json(raw) == expected


# ============================================================
# 2. 常规提取路径
# ============================================================
@pytest.mark.parametrize("raw,expected", [
    ('{"a": 1}', {"a": 1}),
    ('{"a": 1, "b": [1, 2]}', {"a": 1, "b": [1, 2]}),
    ('前缀文字 {"x": "y"} 后缀文字', {"x": "y"}),
    ('```json\n{"k": "v"}\n```', {"k": "v"}),
    ('无关文字 ```json\n{"m": 9}\n``` 更多文字', {"m": 9}),
])
def test_normal_extraction(raw, expected):
    assert _extract_json(raw) == expected


# ============================================================
# 3. 失败降级（不崩、返回 None）
# ============================================================
@pytest.mark.parametrize("raw", [
    "",                                   # 空
    "   \n  ",                            # 仅空白
    "完全没有 JSON 结构",                   # 无 {
    '{"a": 1',                            # 截断（缺闭括号）
    '{"a": 1, ',                         # 截断
    "随机文字 {这不是合法JSON} 随机文字",     # 内部 } 但非合法 JSON
])
def test_failure_returns_none(raw):
    assert _extract_json(raw) is None


def test_none_input_returns_none():
    assert _extract_json(None) is None  # type: ignore[arg-type]


# ============================================================
# 4. 与 _repair 链路配合：提取后再 json.loads 稳定
# ============================================================
def test_extracted_is_json_roundtrip_stable():
    """提取出的 dict 应可直接 json.dumps 再 loads 不变（证明是合法 JSON）。"""
    import json

    raw = '{"policy": "deny if ip in {10.0.0.0/8}", "enabled": true} 垃圾尾随'
    obj = _extract_json(raw)
    assert obj is not None
    assert json.loads(json.dumps(obj)) == obj
    assert obj["enabled"] is True
