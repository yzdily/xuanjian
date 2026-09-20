"""tests/unit/test_report_knowledge.py — 中期 M4 验收。

按 XUANJIAN_ROADMAP_MID_TERM §5.3 3 断言：
1. lookup_owasp('A03') 包含 Injection
2. lookup_cwe('CWE-89') → A03
3. remediation_template(...) → 包含 template_python.md
+ build_knowledge 幂等
+ knowledge_summary 正确
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts" / "build_knowledge.py"


@pytest.fixture(scope="module")
def built_knowledge():
    """模块级 fixture：跑一次 build_knowledge.py 生成 data/knowledge/。"""
    if not BUILDER.exists():
        pytest.skip(f"build_knowledge.py 不存在: {BUILDER}")
    r = subprocess.run(
        [sys.executable, str(BUILDER)],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(ROOT),
    )
    assert r.returncode == 0, f"build 失败: {r.stderr[:300]}"
    return r


def test_lookup_owasp_a03(built_knowledge):
    from core.report_knowledge import lookup_owasp

    out = lookup_owasp("A03")
    assert "Injection" in out


def test_lookup_cwe_89(built_knowledge):
    from core.report_knowledge import lookup_cwe

    out = lookup_cwe("CWE-89")
    assert "A03" in out


def test_remediation_template_path(built_knowledge):
    from core.report_knowledge import remediation_template

    out = remediation_template({"owasp_id": "A03"}, lang="python")
    assert "template_python.md" in out


def test_build_knowledge_idempotent():
    """build_knowledge.py 可重跑，不报错。"""
    r1 = subprocess.run([sys.executable, str(BUILDER)], capture_output=True, text=True, timeout=30, cwd=str(ROOT))
    r2 = subprocess.run([sys.executable, str(BUILDER)], capture_output=True, text=True, timeout=30, cwd=str(ROOT))
    assert r1.returncode == 0
    assert r2.returncode == 0


def test_knowledge_summary(built_knowledge):
    from core.report_knowledge import knowledge_summary

    s = knowledge_summary()
    assert s["exists"] is True
    assert s["files"] >= 15  # 10 owasp + 1 cwe + 4 template
    assert s["size_mb"] < 1.0  # 远低于 200MB 预算


def test_lookup_owasp_missing_returns_placeholder(tmp_path, monkeypatch):
    """owasp_id 不在库 → 返回占位文案。"""
    monkeypatch.setenv("XUANJIAN_KNOWLEDGE_PATH", str(tmp_path / "empty"))
    from core import report_knowledge

    out = report_knowledge.lookup_owasp("A99")
    assert "知识库无 A99" in out or "build_knowledge" in out
