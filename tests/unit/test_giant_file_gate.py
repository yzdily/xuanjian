"""D6 CI 行数闸门测试 — 验证 check_giant_files.py 功能 + 存量豁免。

闸门逻辑：core/ 下 .py >800 行报红，``# noqa: giant`` 豁免历史存量。
本测试验证：(1) 闸门能正确识别超阈值文件；(2) 豁免标记生效；
(3) 列出当前超阈值存量（仅 info，不 fail — 存量豁免由 Stage 2-4 逐步消化）。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = _PROJECT_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from check_giant_files import scan_directory, _count_lines, _is_exempt  # noqa: E402


# ---- 闸门功能测试 ----

def test_count_lines_basic(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("a\nb\nc\n")
    assert _count_lines(f) == 3


def test_exempt_marker_recognized(tmp_path):
    f = tmp_path / "exempt.py"
    f.write_text("# noqa: giant\ncontent\n")
    assert _is_exempt(f) is True


def test_exempt_marker_in_docstring(tmp_path):
    f = tmp_path / "exempt2.py"
    f.write_text('"""Mod doc.\n# noqa: giant\n"""\nx=1\n')
    assert _is_exempt(f) is True


def test_exempt_marker_after_long_docstring(tmp_path):
    """docstring 超过 5 行时标记仍能被识别。"""
    f = tmp_path / "exempt3.py"
    lines = ['"""'] + [f'line {i}' for i in range(20)] + ['"""', '# noqa: giant', 'x=1']
    f.write_text("\n".join(lines) + "\n")
    assert _is_exempt(f) is True


def test_no_exempt_marker(tmp_path):
    f = tmp_path / "normal.py"
    f.write_text("x = 1\n")
    assert _is_exempt(f) is False


def test_scan_directory_finds_offenders(tmp_path):
    """超阈值文件被识别，豁免文件被跳过。"""
    (tmp_path / "small.py").write_text("x = 1\n")
    big = tmp_path / "big.py"
    big.write_text("\n" * 10 + "y = 2\n")
    exempt = tmp_path / "exempt.py"
    exempt.write_text("# noqa: giant\n" + "\n" * 20)
    offenders = scan_directory(tmp_path, max_lines=5)
    paths = [p for p, _ in offenders]
    assert "big.py" in paths[0]
    assert not any("exempt.py" in p for p in paths)
    assert not any("small.py" in p for p in paths)


# ---- 存量扫描（仅 info，不 fail）----

def test_core_giant_files_baseline():
    """列出 core/ 当前超 800 行的文件 — 仅 info，不 fail。

    存量由 D6 Stage 2-4 逐步消化；新增巨文件会被闸门拦住。
    """
    core = _PROJECT_ROOT / "core"
    offenders = scan_directory(core, 800)
    if offenders:
        # 检查是否都有豁免标记
        un_exempted = []
        for rel, n in offenders:
            f = _PROJECT_ROOT / rel
            if not _is_exempt(f):
                un_exempted.append((rel, n))
        if un_exempted:
            pytest.fail(
                f"core/ 下 {len(un_exempted)} 个超 800 行文件未加 '# noqa: giant' 豁免：\n"
                + "\n".join(f"  {rel}: {n} 行" for rel, n in un_exempted)
                + "\n请加 '# noqa: giant' 豁免（历史存量）或拆分至 ≤800 行。"
            )
        else:
            # 全部已豁免 — 仅 info
            print(f"\n[info] core/ 下 {len(offenders)} 个历史巨文件已豁免（D6 Stage 2-4 消化中）")
