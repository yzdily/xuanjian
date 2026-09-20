"""core.k8s.mini_yaml — 50 行最小化 YAML 解析器（长期 L4 配套）。

按 XUANJIAN_ROADMAP_LONG_TERM §5.5 风险 1 落地。
覆盖 K8s manifest 用的语法（key:value / 列表 / 嵌套 map / # 注释），
不支持 YAML 完整规范（无 anchor/alias/flow style 复杂语法）；K8s manifest 99% 走 block style 够用。

零外部依赖。
"""
from __future__ import annotations

import re
from typing import Any


def _strip_comments(text: str) -> str:
    return "\n".join(re.sub(r"#.*$", "", line) for line in text.splitlines())


def _coerce(s: str) -> Any:
    s = s.strip()
    if s in ("", "~", "null", "None"):
        return None
    if s.lower() == "true":
        return True
    if s.lower() == "false":
        return False
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s.strip('"\'')


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


def _parse_block(text: str, pos: int, indent: int) -> tuple[Any, int]:
    """解析一段相同缩进的 block。返 (parsed_value, new_pos)。"""
    result: Any = None
    cur_key: str | None = None
    while pos < len(text):
        nl = text.find("\n", pos)
        if nl == -1:
            nl = len(text)
        line = text[pos:nl]
        pos = nl + 1
        if not line.strip():
            continue
        stripped = line.lstrip()
        ind = _indent_of(line)
        if ind < indent:
            break
        if ind > indent:
            # 缩进变深，应在上层处理；这里兜底
            raise ValueError(f"mini_yaml: 缩进突变在 '{line[:50]}'")
        if stripped.startswith("- "):
            if not isinstance(result, list):
                result = []
            item_text = stripped[2:]
            if ":" in item_text and not (item_text.startswith('"') or item_text.startswith("'")):
                # inline dict: "- key: value"
                k, _, v = item_text.partition(":")
                sub: dict = {k.strip(): _coerce(v)}
                # 后面可能有更深缩进的续行
                if pos < len(text):
                    next_line_end = text.find("\n", pos)
                    if next_line_end == -1:
                        next_line_end = len(text)
                    next_line = text[pos:next_line_end]
                    if next_line.strip() and _indent_of(next_line) > ind:
                        sub2, pos = _parse_block(text, pos, ind + 2)
                        if isinstance(sub2, dict):
                            sub.update(sub2)
                result.append(sub)
            else:
                result.append(_coerce(item_text))
        elif ":" in stripped:
            if not isinstance(result, dict):
                result = {}
            k, _, v = stripped.partition(":")
            k = k.strip()
            v = v.strip()
            cur_key = k
            if not v:
                # 嵌套块
                if pos < len(text):
                    next_line_end = text.find("\n", pos)
                    if next_line_end == -1:
                        next_line_end = len(text)
                    next_line = text[pos:next_line_end]
                    if next_line.strip() and _indent_of(next_line) > ind:
                        sub_val, pos = _parse_block(text, pos, ind + 2)
                        result[k] = sub_val
                    else:
                        result[k] = None
                else:
                    result[k] = None
            else:
                result[k] = _coerce(v)
    return result, pos


def mini_yaml_load(text: str) -> Any:
    """解析单文档 YAML。"""
    text = _strip_comments(text)
    if not text.strip():
        return None
    val, _ = _parse_block(text, 0, -1)
    return val


def mini_yaml_load_all(text: str) -> list[Any]:
    """解析多文档 YAML（用 --- 分隔）。"""
    text = _strip_comments(text)
    docs: list[Any] = []
    for chunk in re.split(r"^---\s*$", text, flags=re.MULTILINE):
        chunk = chunk.strip()
        if not chunk:
            continue
        docs.append(mini_yaml_load(chunk))
    return docs


__all__ = ["mini_yaml_load", "mini_yaml_load_all"]
