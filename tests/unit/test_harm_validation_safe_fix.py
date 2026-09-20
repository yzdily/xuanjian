"""P0-3 危害验证装配崩溃修复回归测试（T10）。

锁定 ``core/harm_validation/context`` 的两个防御性转换函数：

- ``_safe_str(val, max_len=0)`` —— 把任意值安全转成 str，防止非字符串值
  （None / list / dict / int）在后续 ``val[:10]`` / ``val[:1500]`` 类 slice 时
  抛 ``TypeError: 'NoneType' object is not subscriptable``（即 P0-C 根因
  ``None[:10]`` / ``slice(None, 10, None)``）。
- ``_safe_list(val)`` —— 把任意值安全转成 list，防止非 list 值在 slice 时抛异常。

这两个函数被 ``build_context_for_llm`` / 漏洞字段装配（context.py:269-286 等）
统一应用，是 P0-C 不再崩溃的底层保障。

设计原则：纯函数级测试，零网络、零 LLM。``core.harm_validation.context`` 模块
顶层仅依赖 logging/re/typing/urllib.parse（无重依赖），可在隔离环境直接导入验证。
"""

from __future__ import annotations

import pytest

from core.harm_validation.context import _safe_list, _safe_str


# ============================================================
# 1. _safe_str：None / 非字符串兜底为可 slice 的 str
# ============================================================
@pytest.mark.parametrize("val,expected", [
    (None, ""),
    ("", ""),
    ("abc", "abc"),
    (123, "123"),
    (0, "0"),
    (["a", "b"], "['a', 'b']"),          # list 也能安全转 str
    ({"k": 1}, "{'k': 1}"),              # dict 也能安全转 str
    (True, "True"),
])
def test_safe_str_converts_any_type(val, expected):
    assert _safe_str(val) == expected


@pytest.mark.parametrize("val", [None, 123, ["x"], {"k": 1}, True])
def test_safe_str_output_is_sliceable(val):
    """关键不变量：_safe_str 的返回值永远可安全做 [:N] slice（P0-C 根因约束）。"""
    s = _safe_str(val)
    assert s[:10] == s[:10]   # 不抛 TypeError
    assert s[:0] == ""


def test_safe_str_truncates_when_max_len_given():
    assert _safe_str("abcdefghijklmn", 5) == "abcde"
    # None 截断后仍是空串
    assert _safe_str(None, 10) == ""


def test_safe_str_long_input_truncated_not_error():
    big = "x" * 5000
    assert _safe_str(big, 1500) == "x" * 1500


# ============================================================
# 2. _safe_list：非 list 兜底为空 list
# ============================================================
@pytest.mark.parametrize("val,expected", [
    ([1, 2, 3], [1, 2, 3]),
    (None, []),
    ("not a list", []),
    (123, []),
    ({}, []),
])
def test_safe_list_converts_any_type(val, expected):
    assert _safe_list(val) == expected


@pytest.mark.parametrize("val", [None, "str", 123, {}, set()])
def test_safe_list_output_is_sliceable(val):
    """关键不变量：_safe_list 返回值永远可安全做 [:N] slice。"""
    lst = _safe_list(val)
    assert lst[:3] == lst[:3]   # 不抛 TypeError


# ============================================================
# 3. P0-C 直接复现：None 字段经 _safe_str 后装配不崩
# ============================================================
def test_none_field_safe_str_prevents_none_slice_crash():
    """复现 P0-C 根因 ``None[:10]``：经 _safe_str 包裹后该操作不再抛异常。

    模拟 harm_validation/context.py:269-286 的字段装配路径：
    漏洞字段（vuln_type / detail / title）可能为 None，
    直接 ``None[:10]`` 会抛 TypeError；用 _safe_str 包裹后安全。
    """
    raw_vuln_type = None
    raw_detail = None
    raw_title = None

    # 修复前（会抛）：raw_vuln_type[:10]
    # 修复后（安全）：
    safe_vuln_type = _safe_str(raw_vuln_type, 10)
    safe_detail = _safe_str(raw_detail, 1500)
    safe_title = _safe_str(raw_title, 200)

    assert safe_vuln_type == ""
    assert safe_detail == ""
    assert safe_title == ""


def test_build_context_uses_safe_helpers_for_none_fields():
    """_safe_str / _safe_list 是 build_context_for_llm 装配链路的安全基座。

    这里直接断言两函数的契约（被 context.py:269-286 等装配点调用），
    确保 P0-C 的 None-slice 根因被永久锁死。
    """
    assert _safe_str(None) == ""
    assert _safe_list(None) == []
    # 任意字段经 _safe_str 后都可直接参与字符串拼接 / slice
    field = _safe_str(getattr(object(), "missing_attr", None))
    assert isinstance(field, str)
