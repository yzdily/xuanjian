#!/usr/bin/env python
"""CI 行数闸门 — D6 §1.3 防巨文件复发。

扫描 core/ 下 .py 文件，超过阈值（默认 800 行）的报红退出码 1，
除非文件首行含 ``# noqa: giant`` 显式豁免（历史存量）。

用法::

    python scripts/check_giant_files.py            # 默认 core/ 800 行
    python scripts/check_giant_files.py --max 600  # 自定义阈值
    python scripts/check_giant_files.py --dir web  # 自定义目录
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DIR = "core"
_DEFAULT_MAX = 800
_EXEMPT_MARKER = "# noqa: giant"


def _count_lines(path: Path) -> int:
    """统计文件行数（含空行）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def _is_exempt(path: Path) -> bool:
    """文件首 30 行含豁免标记则跳过（覆盖多行 docstring）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(30):
                line = f.readline()
                if not line:
                    break
                if _EXEMPT_MARKER in line:
                    return True
    except Exception:
        pass
    return False


def scan_directory(directory: Path, max_lines: int = _DEFAULT_MAX) -> list[tuple[str, int]]:
    """扫描目录，返回超阈值文件列表 [(相对路径, 行数)]。"""
    offenders: list[tuple[str, int]] = []
    for py in sorted(directory.rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        if _is_exempt(py):
            continue
        n = _count_lines(py)
        if n > max_lines:
            try:
                rel = py.relative_to(_PROJECT_ROOT).as_posix()
            except ValueError:
                rel = str(py)
            offenders.append((rel, n))
    return offenders


def main() -> int:
    parser = argparse.ArgumentParser(description="CI 行数闸门 — 防巨文件复发")
    parser.add_argument("--dir", default=_DEFAULT_DIR, help="扫描目录（默认 core）")
    parser.add_argument("--max", type=int, default=_DEFAULT_MAX, help="行数阈值（默认 800）")
    args = parser.parse_args()

    target = _PROJECT_ROOT / args.dir
    if not target.exists():
        print(f"[skip] 目录 {args.dir} 不存在")
        return 0

    offenders = scan_directory(target, args.max)
    if offenders:
        print(f"[FAIL] {len(offenders)} 个文件超过 {args.max} 行（D6 闸门）：")
        for rel, n in offenders:
            print(f"  {rel}: {n} 行")
        print(f"\n如属历史存量无法立即拆分，在文件首行加 '{_EXEMPT_MARKER}' 豁免。")
        return 1

    print(f"[OK] {args.dir}/ 下无超过 {args.max} 行的 .py 文件")
    return 0


if __name__ == "__main__":
    sys.exit(main())
