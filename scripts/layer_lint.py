#!/usr/bin/env python3
"""模块分层依赖 lint（XUANJIAN_MASTER_PLAN.md · A1）。

目标：冻结模块分层与依赖方向，禁止「底座叶节点」反向依赖「上层编排模块」，
防止重构后出现恶性循环依赖（回归防线）。

分层模型（来自 plan A1）：
- FOUNDATION（底座叶节点，被大量引用，**禁止** import 上层）：
    core.log / core.sitemap / core.llm（含子模块）/ core.config /
    core.prompts / core.config_runtime / core.metrics
- UPPER（上层编排，可依赖底座，但底座不可反向依赖它）：
    core.session（整体，含 chat_loop）/ core.parallel.orchestrator /
    core.orchestrator / core.chat_loop / web

检查规则：
    若「导入方模块」属于 FOUNDATION 且「被导入模块」属于 UPPER -> 违反（反向依赖）。

用法：
    python scripts/layer_lint.py            # 扫描并打印违反项，有违反则 exit 1
    python scripts/layer_lint.py --quiet    # 仅退出码，无输出（CI 用）
    import scripts.layer_lint as ll; ll.check() -> list[Violation]
"""
from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 以这些前缀开头的模块视为「底座」。键为模块前缀，值为层级数字（越小越底层）。
FOUNDATION: dict[str, int] = {
    "core.log": 0,
    "core.sitemap": 0,
    "core.llm": 0,
    "core.config": 0,
    "core.prompts": 0,
    "core.config_runtime": 0,
    "core.metrics": 0,
    # 同属底座的支撑模块（仅向下依赖）
    "core.scan_store": 0,
    "core.llm._monitor": 0,
    "core.llm._config": 0,
    "core.llm._context": 0,
}
# 以这些前缀开头的模块视为「上层编排」。
UPPER: dict[str, int] = {
    "core.session": 2,
    "core.parallel.orchestrator": 2,
    "core.orchestrator": 2,
    "core.chat_loop": 2,
    "web": 2,
}
# 中间层（MID）：可依赖 FOUNDATION，可被 UPPER 依赖；本 lint 不强制其内部分层。
MID: dict[str, int] = {
    "core.crawler": 1,
    "core.browse_worker": 1,
    "core.scan_strategies": 1,
    "core.parallel": 1,
}

# 不参与扫描的目录
_SKIP_DIRS = {"__pycache__", ".git", "node_modules", "venv", ".venv", "tests"}


@dataclass
class Violation:
    file: str
    line: int
    importer: str
    imported: str
    message: str
    hard: bool  # True=硬违反（CI 失败）；False=软告警（供架构师复核）


def _module_of_path(path: Path) -> str:
    """把文件路径映射为点分模块名（相对项目根）。"""
    rel = path.resolve().relative_to(PROJECT_ROOT)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _tier_of(module: str) -> int:
    for prefix, tier in (*FOUNDATION.items(), *MID.items(), *UPPER.items()):
        if module == prefix or module.startswith(prefix + "."):
            return tier
    return 1  # 未显式列出的 core.* 默认视为中间层


def _is_project_module(module: str) -> bool:
    """仅项目内部模块（core.* / web.*）参与分层判定；stdlib 与第三方包忽略。"""
    return module.startswith("core.") or module.startswith("web.")


def _resolve_import(path: Path, node) -> list:
    """返回 (被导入模块绝对名, 行号) 列表。"""
    out: list = []
    importer_pkg = _module_of_path(path)
    if isinstance(node, ast.ImportFrom):
        level = node.level
        mod = node.module or ""
        if level > 0:
            base_parts = importer_pkg.split(".")
            if level >= len(base_parts):
                return out
            base = base_parts[: len(base_parts) - level]
            abs_mod = ".".join(base + ([mod] if mod else []))
        else:
            abs_mod = mod
        if abs_mod:
            out.append((abs_mod, node.lineno))
    else:  # ast.Import
        for alias in node.names:
            out.append((alias.name, node.lineno))
    return out


def check(root: Path | None = None) -> list:
    """扫描项目，返回所有「底座反向依赖上层」的违反项。"""
    root = root or PROJECT_ROOT
    violations: list = []
    for path in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        name = path.name
        if name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py":
            continue
        importer = _module_of_path(path)
        importer_tier = _tier_of(importer)
        if importer_tier != 0:
            continue  # 仅检查底座模块是否反向依赖上层
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for imported, lineno in _resolve_import(path, node):
                    if not _is_project_module(imported):
                        continue  # stdlib / 第三方包不参与分层
                    imported_tier = _tier_of(imported)
                    if imported_tier <= importer_tier:
                        continue  # 向下或同层依赖，允许
                    if imported_tier == 2:
                        # 显式 UPPER 契约（session/orchestrator/chat_loop/web）：硬违反
                        violations.append(
                            Violation(
                                file=str(path.relative_to(PROJECT_ROOT)),
                                line=lineno,
                                importer=importer,
                                imported=imported,
                                message=(
                                    f"底座模块 {importer!r} 反向依赖上层编排模块 "
                                    f"{imported!r}（违反 A1 分层契约，CI 应拦截）"
                                ),
                                hard=True,
                            )
                        )
                    else:
                        # 中间层（其他 core.*）：软告警，供架构师复核分层
                        violations.append(
                            Violation(
                                file=str(path.relative_to(PROJECT_ROOT)),
                                line=lineno,
                                importer=importer,
                                imported=imported,
                                message=(
                                    f"底座模块 {importer!r} 反向依赖中间层模块 "
                                    f"{imported!r}（A1 软告警，建议下沉或解耦）"
                                ),
                                hard=False,
                            )
                        )
    return violations


def main() -> int:
    ap = argparse.ArgumentParser(description="XuanJian 模块分层 lint (A1)")
    ap.add_argument("--quiet", action="store_true", help="仅返回退出码，不打印")
    ap.add_argument("--root", default=str(PROJECT_ROOT), help="项目根目录")
    args = ap.parse_args()

    violations = check(Path(args.root))
    hard = [v for v in violations if v.hard]
    soft = [v for v in violations if not v.hard]
    if not args.quiet:
        if hard:
            print(f"[layer-lint] ✗ {len(hard)} 处硬违反（底座->上层编排）：")
            for v in hard:
                print(f"  {v.file}:{v.line}  {v.message}")
        if soft:
            print(f"[layer-lint] ⚠ {len(soft)} 处软告警（底座->中间层）：")
            for v in soft:
                print(f"  {v.file}:{v.line}  {v.message}")
        if not hard and not soft:
            print("[layer-lint] OK：无分层反向依赖（A1 约束通过）")
        elif not hard:
            print(f"[layer-lint] OK：无硬违反（{len(soft)} 软告警不影响 CI）")
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
