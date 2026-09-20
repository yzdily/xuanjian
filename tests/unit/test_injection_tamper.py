"""§2.7：可组合注入绕过原语库。"""
from __future__ import annotations

from core.loops.injection_tamper import (
    CURATED_CHAINS,
    PRIMITIVES,
    generate_variants,
    primitive_count,
    tamper,
    tamper_chain,
)


def test_primitive_count_is_28():
    assert primitive_count() == 28
    assert len(PRIMITIVES["sqli"]) == 14
    assert len(PRIMITIVES["nosql"]) == 4
    assert len(PRIMITIVES["ssti"]) == 5
    assert len(PRIMITIVES["xss"]) == 5


def test_space2comment():
    assert tamper("UNION SELECT 1", "space2comment") == "UNION/**/SELECT/**/1"


def test_tamper_chain_applies_in_order():
    # payload 需含 "="，否则 equal_to_like 无作用面
    out = tamper_chain("id=1 UNION SELECT 1", ["space2comment", "equal_to_like"])
    assert "/**/" in out
    assert " LIKE " in out


def test_unknown_primitive_is_noop():
    assert tamper("abc", "not-a-primitive") == "abc"


def test_generate_variants_sqli_ge_ten():
    # 用含空格/=/逗号/引号/OR 的典型 payload，才能触发到多数原语
    payload = "1' OR 1=1 UNION SELECT user,pass FROM users WHERE id=1"
    variants = generate_variants(payload, "sqli", limit=12)
    assert len(variants) >= 10


def test_generate_variants_simple_payload_still_yields_several():
    # 简单 payload 触发面小，属正常（产出数依赖 payload）
    variants = generate_variants("UNION SELECT 1", "sqli", limit=12)
    assert 5 <= len(variants) <= 12


def test_generate_variants_dedupes_and_excludes_identical():
    variants = generate_variants("UNION SELECT 1", "sqli")
    assert len(variants) == len(set(variants))
    assert "UNION SELECT 1" not in variants


def test_generate_variants_respects_limit():
    assert len(generate_variants("<script>alert(1)</script>", "xss", limit=3)) <= 3


def test_generate_variants_unknown_class_returns_empty():
    assert generate_variants("x", "nope") == []


def test_curated_chains_cover_all_classes():
    assert set(CURATED_CHAINS) == {"sqli", "nosql", "ssti", "xss"}


def test_nosql_urlencode():
    assert tamper('{"age":{"$ne":1}}', "nosql_op_urlencode") == '{"age":{"%24ne":1}}'
