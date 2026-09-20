"""§4 Phase 2 item 1：能力成熟度矩阵单元测试。

策略：
1. 用 tmp_path + 合成矩阵 + 合成测试文件，纯单元验证 load/iter/find/check/
   gate/report 的函数行为（不依赖真实 tests/ 目录）。
2. 真实矩阵 smoke：加载 ``core/capability_matrix.json``，断言 schema 合法，
   且当前已存在的测试文件被正确识别为 covered（正向 smoke）。
3. 不对真实矩阵断言 ``gate_seal() == True``——封板状态由 CI 实际跑 gate
   决定，不是本单测的职责。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.capability_matrix import (
    check_dod,
    find_tests,
    gate_seal,
    iter_items,
    load_matrix,
    render_report,
    validate_schema,
)


# ============================================================
# 合成矩阵 fixtures
# ============================================================
def _synth_matrix() -> dict:
    return {
        "version": "1.0-test",
        "tiers": [
            {
                "level": "L0",
                "name": "测试档",
                "items": [
                    {
                        "id": "T-1",
                        "name": "已覆盖项",
                        "dod": "存在合成测试文件",
                        "test_globs": ["tests/unit/test_alpha.py"],
                    },
                    {
                        "id": "T-2",
                        "name": "未覆盖项",
                        "dod": "测试文件缺失",
                        "test_globs": ["tests/unit/test_beta_missing.py"],
                    },
                ],
            },
            {
                "level": "L1",
                "name": "glob 档",
                "items": [
                    {
                        "id": "T-3",
                        "name": "glob 命中",
                        "dod": "通配符匹配",
                        "test_globs": ["tests/unit/test_gamma_*.py"],
                    },
                ],
            },
        ],
    }


@pytest.fixture
def synth_project(tmp_path: Path) -> tuple[Path, dict, Path]:
    """合成工程根：含 tests/unit/test_alpha.py + test_gamma_x.py。"""
    matrix = _synth_matrix()
    mpath = tmp_path / "capability_matrix.json"
    mpath.write_text(json.dumps(matrix, ensure_ascii=False), encoding="utf-8")

    tests_dir = tmp_path / "tests" / "unit"
    tests_dir.mkdir(parents=True)
    (tests_dir / "test_alpha.py").write_text("# alpha\n", encoding="utf-8")
    (tests_dir / "test_gamma_one.py").write_text("# gamma1\n", encoding="utf-8")
    (tests_dir / "test_gamma_two.py").write_text("# gamma2\n", encoding="utf-8")
    return tmp_path, matrix, mpath


# ============================================================
# 1. schema 校验
# ============================================================
def test_validate_schema_rejects_missing_tiers():
    bad = {"version": "x"}
    errs = validate_schema(bad)
    assert errs and "tiers" in errs[0]


def test_validate_schema_rejects_dup_id():
    bad = {
        "tiers": [
            {"level": "L0", "name": "a", "items": [
                {"id": "X", "name": "n", "dod": "d", "test_globs": ["t.py"]},
            ]},
            {"level": "L1", "name": "b", "items": [
                {"id": "X", "name": "n", "dod": "d", "test_globs": ["t.py"]},
            ]},
        ]
    }
    errs = validate_schema(bad)
    assert any("重复" in e for e in errs)


def test_validate_schema_accepts_synthetic():
    assert validate_schema(_synth_matrix()) == []


# ============================================================
# 2. iter_items 展平 + 注入 level
# ============================================================
def test_iter_items_flattens_with_level():
    items = list(iter_items(_synth_matrix()))
    ids = [i["id"] for i in items]
    assert ids == ["T-1", "T-2", "T-3"]
    assert items[0]["level"] == "L0"
    assert items[2]["level"] == "L1"
    assert items[0]["tier_name"] == "测试档"


# ============================================================
# 3. find_tests：精确路径 + glob 双形态
# ============================================================
def test_find_tests_exact_path_hit(synth_project):
    root, matrix, _ = synth_project
    item = next(i for i in iter_items(matrix) if i["id"] == "T-1")
    hits = find_tests(item, project_root=root)
    assert hits == ["tests/unit/test_alpha.py"]


def test_find_tests_exact_path_miss(synth_project):
    root, matrix, _ = synth_project
    item = next(i for i in iter_items(matrix) if i["id"] == "T-2")
    assert find_tests(item, project_root=root) == []


def test_find_tests_glob_pattern(synth_project):
    root, matrix, _ = synth_project
    item = next(i for i in iter_items(matrix) if i["id"] == "T-3")
    hits = find_tests(item, project_root=root)
    assert "tests/unit/test_gamma_one.py" in hits
    assert "tests/unit/test_gamma_two.py" in hits


# ============================================================
# 4. check_dod：覆盖标记
# ============================================================
def test_check_dod_marks_covered_and_uncovered(synth_project):
    root, matrix, _ = synth_project
    report = check_dod(matrix, project_root=root)
    assert report["T-1"]["covered"] is True
    assert report["T-2"]["covered"] is False
    assert report["T-3"]["covered"] is True
    assert report["T-1"]["level"] == "L0"
    assert report["T-3"]["level"] == "L1"


# ============================================================
# 5. gate_seal：封板闸门
# ============================================================
def test_gate_seal_false_when_any_uncovered(synth_project):
    root, matrix, _ = synth_project
    assert gate_seal(matrix, project_root=root) is False


def test_gate_seal_true_when_all_covered(tmp_path: Path):
    matrix = {
        "tiers": [
            {"level": "L0", "name": "ok", "items": [
                {"id": "OK", "name": "n", "dod": "d",
                 "test_globs": ["tests/unit/test_x.py"]},
            ]}
        ]
    }
    (tmp_path / "tests" / "unit").mkdir(parents=True)
    (tmp_path / "tests" / "unit" / "test_x.py").write_text("# x\n", encoding="utf-8")
    assert gate_seal(matrix, project_root=tmp_path) is True


def test_gate_seal_loads_default_when_matrix_none(synth_project, monkeypatch):
    """matrix=None 时应从默认路径加载（合成路径替换默认）。"""
    root, _, mpath = synth_project
    monkeypatch.setattr(
        "core.capability_matrix._DEFAULT_MATRIX_PATH", mpath
    )
    monkeypatch.chdir(root)
    assert gate_seal(project_root=root) is False


# ============================================================
# 6. render_report：markdown 渲染
# ============================================================
def test_render_report_contains_marks_and_summary(synth_project):
    root, matrix, _ = synth_project
    md = render_report(matrix, project_root=root)
    assert "能力成熟度 DoD 覆盖报告" in md
    assert "PASS" in md and "FAIL" in md
    assert "test_alpha.py" in md
    assert "尚未封板" in md  # T-2 未覆盖


def test_render_report_all_covered_says_sealable(tmp_path: Path):
    matrix = {
        "tiers": [
            {"level": "L0", "name": "ok", "items": [
                {"id": "OK", "name": "n", "dod": "d",
                 "test_globs": ["tests/unit/test_x.py"]},
            ]}
        ]
    }
    (tmp_path / "tests" / "unit").mkdir(parents=True)
    (tmp_path / "tests" / "unit" / "test_x.py").write_text("# x\n", encoding="utf-8")
    md = render_report(matrix, project_root=tmp_path)
    assert "可封板" in md
    assert "尚未封板" not in md


# ============================================================
# 7. 真实矩阵 smoke（不锁定封板状态）
# ============================================================
def test_real_matrix_schema_valid():
    m = load_matrix()
    errs = validate_schema(m)
    assert errs == [], f"真实矩阵 schema 违规: {errs}"


def test_real_matrix_has_all_four_tiers():
    m = load_matrix()
    levels = [t["level"] for t in m["tiers"]]
    assert levels == ["L0", "L1", "L2", "L3"]


def test_real_matrix_known_covered_items_smoke():
    """正向 smoke：真实工程根下，L0-1/L0-2/L0-3/L1-1 等已有测试的项应判 covered=True。

    不对 gate_seal 全量断言 True——封板状态由 CI 实际跑 gate 决定。
    显式传 project_root 避免全量回归中其他测试 chdir 导致的 cwd 漂移。
    """
    project_root = Path(__file__).resolve().parents[2]  # tests/unit → 项目根
    m = load_matrix()
    report = check_dod(m, project_root)
    # 至少这些已存在的测试应被判 covered
    must_covered = ["L0-1", "L0-2", "L0-3", "L1-1", "L1-2", "L1-3", "L1-4",
                    "L2-1", "L2-2", "L2-3", "L2-4", "L2-5", "L2-6",
                    "L3-1", "L3-2", "L3-3"]
    missing = [iid for iid in must_covered if not report[iid]["covered"]]
    assert not missing, f"应已覆盖但被判未覆盖: {missing}"
