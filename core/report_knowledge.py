"""core.report_knowledge — 报告层引用本地知识库（中期 M4）。

按 XUANJIAN_ROADMAP_MID_TERM §5.3 落地。
- lookup_owasp(owasp_id) -> 读 data/knowledge/owasp/{id}.md
- lookup_cwe(cwe_id) -> 反查 OWASP（用 core.cwe_dict）
- remediation_template(finding, lang) -> 返回修复模板路径

零外部依赖。
回滚：XUANJIAN_KNOWLEDGE_PATH 改路径（默认 data/knowledge）。
"""
from __future__ import annotations

import os
import pathlib
import sys
from typing import Optional

_DEFAULT_ROOT = pathlib.Path("data/knowledge")


def _root() -> pathlib.Path:
    return pathlib.Path(os.environ.get("XUANJIAN_KNOWLEDGE_PATH", str(_DEFAULT_ROOT)))


def _ensure_root() -> pathlib.Path:
    p = _root()
    p.mkdir(parents=True, exist_ok=True)
    return p


def lookup_owasp(owasp_id: str) -> str:
    """读 data/knowledge/owasp/{owasp_id}.md，文件不存在返回占位。"""
    p = _root() / "owasp" / f"{owasp_id}.md"
    if not p.exists():
        return f"（知识库无 {owasp_id}；请先跑 scripts/build_knowledge.py）"
    return p.read_text(encoding="utf-8")


def lookup_cwe(cwe_id: str) -> str:
    """从 core.cwe_dict 反查 CWE 属于哪个 OWASP。"""
    try:
        from core.cwe_dict import CWE_TO_OWASP

        owasp = CWE_TO_OWASP.get(cwe_id)
        if owasp:
            return f"{cwe_id} ∈ {owasp}"
    except Exception:
        pass
    return f"{cwe_id} 未在 OWASP Top 10 映射中"


def remediation_template(finding: dict, lang: str = "python") -> str:
    """返回修复模板路径提示。

    Args:
        finding: 至少含 owasp_id；lang 可选 python/java/go/node
    """
    p = _root() / "remediation" / f"template_{lang}.md"
    if not p.exists():
        return f"（知识库缺 template_{lang}.md；请先跑 scripts/build_knowledge.py）"
    lines = sum(1 for _ in p.read_text(encoding="utf-8").splitlines())
    try:
        rel = p.relative_to(_root().parent)
    except ValueError:
        rel = p
    return f"参考模板: {rel}（共 {lines} 行，OWASP={finding.get('owasp_id', '?')}）"


def knowledge_summary() -> dict:
    """知识库概览：文件数 + 总体积。用于 doctor / 报告头部。"""
    root = _root()
    if not root.exists():
        return {"exists": False, "files": 0, "size_mb": 0.0}
    files = list(root.rglob("*"))
    sz = sum(f.stat().st_size for f in files if f.is_file())
    return {
        "exists": True,
        "files": len([f for f in files if f.is_file()]),
        "size_mb": round(sz / 1024 / 1024, 3),
    }


__all__ = ["lookup_owasp", "lookup_cwe", "remediation_template", "knowledge_summary"]
