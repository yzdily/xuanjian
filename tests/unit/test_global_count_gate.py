"""D7 global 计数护栏 — 防止 holder 化后 global 回潮。

D7 完成后 core/ 内 `global` 声明应 ≤1（仅 `_PROCESS_RUN_ID`，D 类故意全局）。
任何新增 `global` 需要么改为 holder 模式，要么加 `# @intentional_global` 标注并在此豁免。
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CORE = _PROJECT_ROOT / "core"

_GLOBAL_RE = re.compile(r"^\s*global\s+", re.MULTILINE)
_INTENTIONAL_MARKER = "@intentional_global"

# D7 完成后的豁免白名单（仅 D 类故意全局）
_EXEMPT_FILES = {
    "core/replay/recorder.py",  # _PROCESS_RUN_ID — D 类进程级兜底
}


def _scan_globals() -> list[tuple[str, int, str, bool]]:
    """扫描 core/ 下所有 .py 的 global 声明。

    Returns:
        [(相对路径, 行号, 行内容, 是否豁免)]
    """
    results: list[tuple[str, int, str, bool]] = []
    for py in sorted(_CORE.rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        try:
            text = py.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = py.relative_to(_PROJECT_ROOT).as_posix()
        lines = text.splitlines()
        # 检查 global 行及其前一行是否有 @intentional_global
        for i, line in enumerate(lines):
            if _GLOBAL_RE.match(line):
                prev = lines[i - 1] if i > 0 else ""
                is_exempt = (_INTENTIONAL_MARKER in prev) or (rel in _EXEMPT_FILES)
                results.append((rel, i + 1, line.strip(), is_exempt))
    return results


def test_core_global_count_below_threshold():
    """core/ 内 global 声明 ≤1（D7 目标：54→1）。"""
    all_globals = _scan_globals()
    un_exempted = [(rel, ln, line) for rel, ln, line, exempt in all_globals if not exempt]

    assert len(un_exempted) == 0, (
        f"D7 回归：core/ 内有 {len(un_exempted)} 个未豁免的 global 声明（目标 0）：\n"
        + "\n".join(f"  {rel}:{ln}: {line}" for rel, ln, line in un_exempted)
        + "\n请改为 holder 模式（@dataclass _State + _state 属性），"
        "或加 `# @intentional_global` 标注并更新白名单。"
    )


def test_core_global_total_count():
    """core/ 内 global 总数（含豁免）应 ≤2（仅 _PROCESS_RUN_ID + 可能的未来特例）。"""
    all_globals = _scan_globals()
    assert len(all_globals) <= 2, (
        f"core/ global 总数 {len(all_globals)} > 2，即使全部豁免也过多：\n"
        + "\n".join(f"  {rel}:{ln}: {line}" for rel, ln, line, _ in all_globals)
    )


def test_exempted_globals_have_intentional_marker():
    """豁免的 global 必须有 @intentional_global 标注或在白名单中。"""
    all_globals = _scan_globals()
    for rel, ln, line, exempt in all_globals:
        if exempt:
            # 确认确实有标注或白名单
            assert rel in _EXEMPT_FILES or exempt, (
                f"{rel}:{ln} 的 global 被标记为豁免但无 @intentional_global 标注"
            )
