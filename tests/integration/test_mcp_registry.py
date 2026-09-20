"""tests/integration/test_mcp_registry.py — 短期 S1 验收。

按 XUANJIAN_ROADMAP_SHORT_TERM §2.3 3 断言：
1. REGISTRY.md 列出 ≥ 8 项 mcp__xuanjian__* 工具名
2. 所有工具名符合 ^[a-z]+(_[a-z]+)*$ 命名规范
3. sqli_mcp.py / bola_mcp.py 都能 import（含 mcp 库缺失的 degrade 路径）
"""
from __future__ import annotations

import importlib
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "mcp_servers" / "REGISTRY.md"
NAMING_RE = re.compile(r"^[a-z]+(_[a-z]+)*$")


def _all_tool_names() -> list[str]:
    text = REGISTRY.read_text(encoding="utf-8")
    return re.findall(r"mcp__xuanjian__(\w+)", text)


def test_registry_exists():
    assert REGISTRY.exists()


def test_registry_lists_at_least_8_servers():
    """REGISTRY 必须有 ≥ 8 项 MCP 工具。"""
    names = _all_tool_names()
    assert len(names) >= 8, f"仅 {len(names)} 项，少于 8"


def test_naming_convention_matches():
    """所有 mcp__xuanjian__xxx 的 xxx 段符合小写下划线规范。"""
    for name in _all_tool_names():
        assert NAMING_RE.match(name), f"命名不规范: {name}"


def test_sqli_mcp_importable():
    """sqli_mcp.py 在 mcp 库缺失时仍可 import（degrade 到 stub）。"""
    mod = importlib.import_module("mcp_servers.sqli_mcp")
    assert mod is not None
    assert hasattr(mod, "sqli_scan")
    assert hasattr(mod, "sqli_verify")


def test_bola_mcp_importable():
    """bola_mcp.py 在 mcp 库缺失时仍可 import。"""
    mod = importlib.import_module("mcp_servers.bola_mcp")
    assert mod is not None
    assert hasattr(mod, "bola_probe")
    assert hasattr(mod, "bola_sequence")


def test_stub_raises_when_called_without_mcp(monkeypatch):
    """当 mcp 库缺失时，调 stub 函数应 raise RuntimeError。"""
    monkeypatch.setenv("XUANJIAN_MCP_DISABLED", "1")
    # 重新 import 以触发 _MCP_DISABLED 路径
    import importlib

    sqli = importlib.reload(importlib.import_module("mcp_servers.sqli_mcp"))
    import asyncio

    with pytest.raises(RuntimeError):
        asyncio.run(sqli.sqli_scan("http://x/?id=1"))

    bola = importlib.reload(importlib.import_module("mcp_servers.bola_mcp"))
    with pytest.raises(RuntimeError):
        asyncio.run(bola.bola_sequence(100))


def test_registry_maps_to_existing_files():
    """REGISTRY.md 引用的 *_mcp.py 至少要存在。"""
    text = REGISTRY.read_text(encoding="utf-8")
    for m in re.finditer(r"mcp_servers/(\w+_mcp\.py)", text):
        rel = m.group(1)
        path = ROOT / "mcp_servers" / rel
        assert path.exists(), f"REGISTRY 引用 {rel} 但文件不存在"
