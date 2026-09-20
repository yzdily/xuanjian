"""空心化判定谓词单测（A3 单源化回归锁）。

锁定 ``core/session/hollowing.py::is_hollowed`` 的双条件语义，
防止 report_mixin / report_mcp 日后再次漂移到各自的内联实现。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

from core.session.hollowing import is_hollowed


class TestIsHollowed:
    """双条件空心化判定（满足任一即触发，且 vulns==0、total>0）。"""

    @pytest.mark.parametrize("real,skip,pending,vulns,total,expected", [
        # 条件1：real<10 & skip>70 & vulns==0
        (8, 75, 5, 0, 100, True),
        (9, 71, 0, 0, 100, True),   # 边界：刚好 <10 / >70
        (9, 69, 0, 0, 100, False),  # skip 不够
        (10, 75, 5, 0, 100, False), # real 不够小（==10 不触发）
        # 条件2：real<5 & (skip+pending)>80 & vulns==0
        (4, 40, 45, 0, 100, True),  # pending 主导
        (4, 81, 0, 0, 100, True),   # skip 主导，real<5
        (4, 40, 40, 0, 100, False), # uncovered=80 不够（需 >80）
        # 有漏洞一律不判空心化
        (4, 40, 45, 1, 100, False),
        (8, 75, 5, 2, 100, False),
        # 无数据
        (0, 0, 0, 0, 0, False),
        # 正常扫描
        (50, 10, 5, 0, 100, False),
    ])
    def test_predicate(self, real, skip, pending, vulns, total, expected):
        assert is_hollowed(real, skip, pending, vulns, total) is expected

    def test_total_zero_returns_false(self):
        assert is_hollowed(0, 90, 90, 0, 0) is False

    def test_vulns_nonzero_returns_false_even_if_rates_bad(self):
        """有漏洞就不算空心化（有真实发现）。"""
        assert is_hollowed(1, 90, 90, 5, 100) is False
