#!/usr/bin/env python3
"""CI 风险域 parity 门禁 — 复制件漂移静态扫描（v4 §8 事故回归锁）。

背景：core/testflow/attribution_rules.py 曾复制 8 域判定表，权威源
core/endpoint/risk_domain.py 后来做了 Security 修正（移除 "link"/"load"
过宽关键字等），复制件未同步 → "load" 子串误命中 "upload" 产生 ssrf 假阳。
修复方式是单点维护（转发件），本门禁保证以后任何模块都**不允许**再私定义
这两个符号——要用，只能 from core.endpoint.risk_domain import。

规则:
  G1 私定义即红 — RISK_DOMAIN_RULES 赋值 / classify_risk_domain 函数定义，
     仅允许出现在权威源 core/endpoint/risk_domain.py（含同名局部变量，
     影子复制同样拦截）。
  G2 import 源头钉死 — ``from X import RISK_DOMAIN_RULES|classify_risk_domain``
     的 X 必须能（传递地）追溯到权威源；防"复制件的复制件"链。相对导入
     （``from .risk_domain import``）按 PEP 328 归一为绝对模块名后再判定。
  豁免 — 权威源本身；违规行行内 ``# noqa: risk-domain-gate`` 标记。

解析坐标系（重要）:
  本仓库为源目录导入（``core`` / ``scripts`` 的父目录即 sys.path 根），
  故模块名以「仓库根」为基准计算；**绝不可**再为 ``core`` 等目录追加
  ``__init__.py``（会引入 src 布局歧义，令 ``from .risk_domain`` 被解析成
  幽灵模块 ``core.core.…``，属门禁自身缺陷）。
  跳过目录（如归档参考项目 ``hollowing-optimization-plan`` / ``strix-main``）
  不参与扫描，即使它们被误标为包也无效。

局限：importlib 等动态导入不在 AST 静态扫描范围内（门禁只盯静态引用）。

用法::

    python scripts/risk_domain_parity_gate.py           # 人读输出, exit 0/1
    python scripts/risk_domain_parity_gate.py --json    # 机器可读（JSON on stdout）

退出码:
    0 = 通过
    1 = 存在违规（复制件 / 野 import / 不可解析文件）
    2 = 用法/环境错误
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
AUTHORITY_MODULE = "core.endpoint.risk_domain"
AUTHORITY_REL = "core/endpoint/risk_domain.py"
GUARDED_SYMBOLS = ("RISK_DOMAIN_RULES", "classify_risk_domain")
NOQA_MARKER = "# noqa: risk-domain-gate"
# 归档的参考项目（非本项目代码）与第三方包，不纳入扫描范围
_SKIP_DIR_NAMES = {
    "__pycache__", ".git", "node_modules", "venv", "site-packages",
    "hollowing-optimization-plan", "strix-main",
}
_SKIP_DIR_PREFIXES = (".venv",)

RULE_PRIVATE_DEF = "G1-private-def"
RULE_IMPORT_ORIGIN = "G2-import-origin"
RULE_UNPARSEABLE = "G0-unparseable"


@dataclass(frozen=True)
class _Registry:
    """模块名注册表：归一为「仓库根为基准」的绝对包名。"""

    base: Path                      # 模块名基准目录（普通布局 = 仓库根）
    module_file: dict[str, Path]    # 模块名 -> 文件
    module_is_pkg: dict[str, bool]  # 模块名 -> 是否包（__init__.py）

    def has(self, name: str) -> bool:
        return name in self.module_file


def _is_skipped(path: Path, root: Path) -> bool:
    """__pycache__/.git/venv/隐藏目录/归档参考项目跳过。"""
    try:
        rel_parts = path.relative_to(root).parts[:-1]
    except ValueError:
        return True  # root 之外（不应发生）→ 保守跳过
    for seg in rel_parts:
        if seg in _SKIP_DIR_NAMES or seg.startswith(_SKIP_DIR_PREFIXES):
            return True
        if seg.startswith(".") and seg not in (".", ".."):
            return True
    return False


def _iter_py_files(root: Path) -> list[Path]:
    return [py for py in sorted(root.rglob("*.py")) if not _is_skipped(py, root)]


def _module_name_of(path: Path, base: Path) -> str:
    """文件 → 绝对包名：``__init__.py`` 取所在包，普通模块去掉 ``.py``。"""
    rel = path.relative_to(base).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _build_registry(root: Path) -> _Registry:
    """构建模块注册表。坐标系固定为「仓库根」（普通源布局）。"""
    base = _PROJECT_ROOT
    module_file: dict[str, Path] = {}
    module_is_pkg: dict[str, bool] = {}
    for py in _iter_py_files(root):
        try:
            rel = py.relative_to(base)
        except ValueError:
            continue
        mod = _module_name_of(py, base)
        if not mod:
            continue
        module_file[mod] = py
        module_is_pkg[mod] = py.name == "__init__.py"
    return _Registry(base=base, module_file=module_file, module_is_pkg=module_is_pkg)


def _line_has_noqa(source_lines: list[str], lineno: int) -> bool:
    return 1 <= lineno <= len(source_lines) and NOQA_MARKER in source_lines[lineno - 1]


def _find_private_defs(tree: ast.AST) -> list[tuple[int, str]]:
    """返回 [(行号, 符号)]：G1 命中的私定义点。"""
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "RISK_DOMAIN_RULES":
                    hits.append((node.lineno, "RISK_DOMAIN_RULES"))
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "RISK_DOMAIN_RULES":
                hits.append((node.lineno, "RISK_DOMAIN_RULES"))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "classify_risk_domain":
                hits.append((node.lineno, "classify_risk_domain"))
    return hits


def _guarded_import_edges(tree: ast.AST) -> list[tuple[int, int, str | None]]:
    """返回 [(行号, level, 源模块)]：守卫符号的 import 边（源模块）。

    同时捕获 ``from . import classify_risk_domain``（module=None，level>0）
    这类"相对本级导入"——此前实现用 ``not node.module`` 早退会漏掉。
    """
    edges: list[tuple[int, int, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if any(alias.name in GUARDED_SYMBOLS for alias in node.names):
            edges.append((node.lineno, node.level, node.module))
    return edges


def _resolve_from(mod: str, is_package: bool, level: int, module: str | None) -> str | None:
    """PEP 328 相对导入归一为绝对模块名（level>0），level=0 原样返回。

    level=1 → 当前包；level=N → 上溯 N-1 层。返回 None = 超出仓库根。
    """
    if level == 0:
        return module
    pkg_parts = mod.split(".") if is_package else mod.split(".")[:-1]
    up = level - 1
    if up > len(pkg_parts):
        return None
    base = pkg_parts[: len(pkg_parts) - up] if up else pkg_parts
    if module:
        return ".".join([*base, *module.split(".")])
    return ".".join(base) if base else None


def _authority_reachable(edges_by_importer: dict[str, set[str]]) -> set[str]:
    """从权威源反向 BFS：所有（传递）从权威源导入守卫符号的模块 = 合法转发链。"""
    source_to_importers: dict[str, set[str]] = {}
    for importer, sources in edges_by_importer.items():
        for src in sources:
            source_to_importers.setdefault(src, set()).add(importer)
    legit = {AUTHORITY_MODULE}
    frontier = [AUTHORITY_MODULE]
    while frontier:
        src = frontier.pop()
        for importer in source_to_importers.get(src, ()):
            if importer not in legit:
                legit.add(importer)
                frontier.append(importer)
    return legit


def scan_repo(root: Path | None = None) -> list[dict]:
    """扫描仓库，返回违规列表（空列表 = 通过）。供 CI 与 pytest 双用。"""
    scan_root = (root or _PROJECT_ROOT).resolve()
    reg = _build_registry(scan_root)
    violations: list[dict] = []

    parsed: dict[str, tuple[Path, ast.AST, list[str]]] = {}
    for mod, py in reg.module_file.items():
        try:
            source = py.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py))
        except SyntaxError as exc:
            violations.append({
                "rule": RULE_UNPARSEABLE,
                "file": _rel(py, scan_root), "line": exc.lineno or 0,
                "symbol": "", "detail": f"语法错误，扫描盲区（fail-closed）: {exc.msg}",
            })
            continue
        parsed[mod] = (py, tree, source.splitlines())

    # G1: 私定义即红（权威源豁免 + 行内 noqa 豁免）
    for mod, (py, tree, lines) in parsed.items():
        if mod == AUTHORITY_MODULE:
            continue
        for lineno, symbol in _find_private_defs(tree):
            if _line_has_noqa(lines, lineno):
                continue
            violations.append({
                "rule": RULE_PRIVATE_DEF,
                "file": _rel(py, scan_root), "line": lineno, "symbol": symbol,
                "detail": f"风险域符号私定义（仅 {AUTHORITY_REL} 允许定义）；"
                          f"改为 from {AUTHORITY_MODULE} import {symbol}",
            })

    # G2: import 源头必须（传递地）追溯到权威源（相对导入按 PEP 328 归一）
    edges_by_importer: dict[str, set[str]] = {}
    edge_locs: list[tuple[Path, int, str]] = []
    for mod, (py, tree, _lines) in parsed.items():
        is_package = reg.module_is_pkg.get(mod, py.name == "__init__.py")
        for lineno, level, raw_module in _guarded_import_edges(tree):
            resolved = _resolve_from(mod, is_package, level, raw_module)
            if resolved is None or not reg.has(resolved):
                shown = f"{'.' * level}{raw_module or ''}"
                violations.append({
                    "rule": RULE_IMPORT_ORIGIN,
                    "file": _rel(py, scan_root), "line": lineno,
                    "symbol": "import-origin",
                    "detail": f"import 源 `from {shown}` 无法解析到仓库内模块"
                              f"（解析为 {resolved!r}），属契约错误（fail-closed）",
                })
                continue
            edges_by_importer.setdefault(mod, set()).add(resolved)
            edge_locs.append((py, lineno, resolved))

    legit = _authority_reachable(edges_by_importer)
    for py, lineno, src in edge_locs:
        if src in legit:
            continue
        violations.append({
            "rule": RULE_IMPORT_ORIGIN,
            "file": _rel(py, scan_root), "line": lineno,
            "symbol": "import-origin",
            "detail": f"from {src} import 守卫符号的源头无法追溯到 "
                      f"{AUTHORITY_MODULE}（复制件的复制件）",
        })
    return violations


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="CI 风险域 parity 门禁 — 复制件漂移静态扫描")
    parser.add_argument("--root", type=Path, default=_PROJECT_ROOT, help="扫描根目录")
    parser.add_argument("--json", action="store_true", help="机器可读 JSON 输出")
    args = parser.parse_args()

    if not args.root.exists():
        print(f"[skip] 根目录不存在: {args.root}")
        return 2

    violations = scan_repo(args.root)
    if args.json:
        print(json.dumps({"violations": violations, "scanned_root": str(args.root)},
                         ensure_ascii=False, indent=2))
        return 1 if violations else 0

    if violations:
        print(f"[FAIL] {len(violations)} 处风险域符号违规（parity 门禁）：")
        for v in violations:
            print(f"  [{v['rule']}] {v['file']}:{v['line']} {v['symbol']}")
            print(f"          {v['detail']}")
        print(f"\n如属历史存量确需保留，在违规行加 '{NOQA_MARKER}' 豁免。")
        return 1

    print(f"[OK] 风险域符号单点维护（{AUTHORITY_REL}），无复制件/野 import")
    return 0


if __name__ == "__main__":
    sys.exit(main())
