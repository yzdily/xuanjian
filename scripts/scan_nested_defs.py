"""Repo-wide nested-def scanner (D6_architect_review.md §4.5).

Finds every ``def`` / ``async def`` textually nested inside another function
(method or plain function) — the "nested function" smell the architect review
flags as a low-risk, high-yield hoist target.

Reports, per hit:
- file / line / nested func name / enclosing parent func
- ``parent_is_method``: whether the parent is a method (defines ``self``) — i.e.
  the nested def lives inside a method body (highest-value D6 hoist target)
- ``nested_len``: body size in lines (bigger = likelier to be a real unit)
- ``has_self_param`` / ``is_async``: signals for hoist feasibility

Usage:
    python scripts/scan_nested_defs.py core web mcp_servers
    python scripts/scan_nested_defs.py core --json
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path


def _func_len(node: ast.AST) -> int:
    if node.end_lineno is None or node.lineno is None:
        return 0
    return node.end_lineno - node.lineno + 1


class Visitor(ast.NodeVisitor):
    def __init__(self, path: Path, hits: list[dict]) -> None:
        self.path = path
        self.hits = hits
        self.func_stack: list[tuple[str, bool]] = []  # (name, is_method)
        self.in_class = False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev = self.in_class
        self.in_class = True
        self.generic_visit(node)
        self.in_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle(node, is_async=True)

    def _handle(self, node: ast.AST, is_async: bool) -> None:
        is_method = self.in_class  # True only when directly under a ClassDef
        if self.func_stack:
            parent_name, parent_is_method = self.func_stack[-1]
            args = node.args.args  # type: ignore[attr-defined]
            self.hits.append(
                {
                    "file": str(self.path),
                    "line": node.lineno,
                    "nested": node.name,
                    "parent": parent_name,
                    "parent_is_method": parent_is_method,
                    "nested_len": _func_len(node),
                    "has_self_param": bool(args) and args[0].arg in ("self", "cls"),
                    "is_async": is_async,
                }
            )
        self.func_stack.append((node.name, is_method))
        self.generic_visit(node)
        self.func_stack.pop()


def scan_file(path: Path) -> list[dict]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        return [{"file": str(path), "line": 0, "_error": f"SyntaxError: {exc}"}]
    hits: list[dict] = []
    Visitor(path, hits).visit(tree)
    return hits


def main(argv: list[str]) -> int:
    roots = [a for a in argv[1:] if not a.startswith("--")]
    as_json = "--json" in argv
    files: list[Path] = []
    for root in roots:
        files.extend(Path(root).rglob("*.py"))
    files = sorted(set(files))

    all_hits: list[dict] = []
    skip_dirs = {"venv", ".venv", "__pycache__"}
    for f in files:
        if skip_dirs & set(f.parts):
            continue
        all_hits.extend(scan_file(f))

    if as_json:
        print(json.dumps(all_hits, ensure_ascii=False, indent=2))
        return 0

    by_file: dict[str, list[dict]] = {}
    for h in all_hits:
        by_file.setdefault(h["file"], []).append(h)

    total = sum(len(v) for v in by_file.values())
    print(f"扫描 {len(files)} 个 .py 文件，发现 {total} 个方法内嵌套 def\n")
    print(f"{'行数':>5}  {'类型':<5} {'父方法?':<6} {'self?':<5}  文件:行  嵌套函数 (父函数)")
    print("-" * 92)
    for f in sorted(by_file):
        for h in sorted(by_file[f], key=lambda x: x["line"]):
            tag = "async" if h["is_async"] else "def"
            mth = "M" if h["parent_is_method"] else "f"
            slf = "Y" if h["has_self_param"] else "-"
            print(
                f"{h['nested_len']:>5}  {tag:<5} {mth:<6} {slf:<5}  "
                f"{f}:{h['line']}  {h['nested']} (in {h['parent']})"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
