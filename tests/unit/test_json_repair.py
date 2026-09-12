"""core/parallel/_json_repair._repair_llm_json 回归测试。

D6 拆分试点：该函数原为 batch_test.py 内联纯函数（1033 行文件内），
抽出为独立模块。本测试锁定其修复语义，防止后续拆分漂移。
"""
import pytest

from core.parallel._json_repair import _repair_llm_json


@pytest.mark.parametrize("raw,expected_parsed", [
    # 1. 尾随逗号
    ('{"a": 1,}', {"a": 1}),
    # 2. 单引号 -> 双引号
    ("{'a': 'b'}", {"a": "b"}),
    # 3. 行内 // 注释
    ('{"a": 1 // trailing\n}', {"a": 1}),
    # 4. 字符串内裸控制字符（\n -> \\n）
    ('{"a": "x\ny"}', {"a": "x\ny"}),
    # 5. 缺逗号相邻键值对
    ('{"a": 1 "b": 2}', {"a": 1, "b": 2}),
    # 6. 缺闭括号
    ('{"a": {', {"a": {}}),
    # 7. 多闭括号
    ('{"a": 1}}}}', {"a": 1}),
    # 8. 块注释
    ('{"a": 1 /* c */}', {"a": 1}),
    # 9. 正常 JSON 不变
    ('{"a": 1, "b": [1, 2]}', {"a": 1, "b": [1, 2]}),
])
def test_repair_produces_valid_json(raw, expected_parsed):
    """修复后必须能被 json.loads 解析且语义正确。"""
    import json
    out = _repair_llm_json(raw)
    assert out is not None
    assert json.loads(out) == expected_parsed


def test_repair_empty_returns_none():
    assert _repair_llm_json("") is None
    assert _repair_llm_json(None) is None  # type: ignore[arg-type]
