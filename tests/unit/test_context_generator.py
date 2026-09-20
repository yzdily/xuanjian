"""§3.12.1 (5)：context_generator 单元测试。"""
from __future__ import annotations

from core.loops.context_generator import (
    detect_value_type,
    generate_int_payloads,
    generate_json_payloads,
    generate_params_payloads,
    generate_path_payloads,
    generate_payloads,
    generate_string_payloads,
)


def test_detect_int():
    assert detect_value_type("123") == "int"
    assert detect_value_type("-456") == "int"


def test_detect_float():
    assert detect_value_type("3.14") == "float"
    assert detect_value_type("1e5") == "float"


def test_detect_path():
    assert detect_value_type("/var/log") == "path"
    assert detect_value_type("..\\..\\etc") == "path"


def test_detect_json():
    assert detect_value_type('{"a":1}') == "json"
    assert detect_value_type("[1,2,3]") == "json"


def test_detect_string():
    assert detect_value_type("hello") == "string"
    assert detect_value_type("") == "string"


def test_generate_int_payloads():
    vs = generate_int_payloads("1=1")
    assert len(vs) == 4
    assert all(v.context == "int" for v in vs)
    assert any("1 AND" in v.payload for v in vs)


def test_generate_string_payloads():
    vs = generate_string_payloads("1=1")
    assert any(v.payload.startswith("'") for v in vs)


def test_generate_path_payloads():
    vs = generate_path_payloads("etc/passwd")
    assert any("../" in v.payload for v in vs)


def test_generate_json_payloads():
    vs = generate_json_payloads("1=1")
    assert all(v.payload.startswith("{") for v in vs)


def test_generate_payloads_detects_type():
    cp = generate_payloads("id", "42", "1=1")
    assert cp.param_name == "id"
    assert cp.value_type == "int"
    assert len(cp.variants) == 4


def test_generate_params_payloads_multi():
    cps = generate_params_payloads({"id": "1", "name": "alice", "path": "/a/b"})
    assert len(cps) == 3
    types = {c.param_name: c.value_type for c in cps}
    assert types == {"id": "int", "name": "string", "path": "path"}
