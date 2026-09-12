"""G14 回归套件 —— G4 覆盖账本 + 未覆盖门控 gate 锁定。

运行：python -m pytest tests/unit/test_coverage_ledger.py -v -o addopts="" -p no:cacheprovider
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.loops.coverage_tracker import CoverageEntry  # noqa: E402
from core.loops.coverage_ledger import (  # noqa: E402
    HIGH_RISK_VULN_TYPES,
    build_coverage_ledger,
    domain_conclusion_table,
    gate_uncovered_high,
    uncovered_statement,
)
from core.endpoint.surface_inventory import build_surface_inventory  # noqa: E402


def _surfaces():
    return build_surface_inventory(
        [
            {"method": "POST", "url": "/api/users/avatar/upload"},
            {"method": "GET", "url": "/api/report/export"},
            {"method": "GET", "url": "/api/users/123"},
        ],
        host="example.com",
    )["surfaces"]


def _entries():
    # /upload 完整测了（reported file_upload_unrestricted）
    # /export 测了 sqli 但漏了 ssti
    # /users 完全没测
    return [
        CoverageEntry(surface="POST /api/users/avatar/upload",
                      risk_area="file_upload_unrestricted", outcome="reported"),
        CoverageEntry(surface="POST /api/users/avatar/upload",
                      risk_area="path_traversal", outcome="no_issue_found"),
        CoverageEntry(surface="GET /api/report/export",
                      risk_area="sqli", outcome="reported"),
        # ruled_out 必须有 evidence
        CoverageEntry(surface="GET /api/report/export",
                      risk_area="path_traversal", outcome="ruled_out",
                      evidence={"reason": "无路径参数"}),
    ]


class TestCoverageLedger:
    """G4：期望×实测对账 + 域级结论表 + 未覆盖门控。"""

    def test_per_surface_missing(self):
        ledger = build_coverage_ledger(_surfaces(), _entries())
        ps = {p["surface_key"]: p for p in ledger["per_surface"]}
        upload = ps["POST /api/users/avatar/upload"]
        # 已测的两项（file_upload_unrestricted / path_traversal）不在 missing
        assert "file_upload_unrestricted" not in upload["missing"]
        assert "path_traversal" not in upload["missing"]
        # 但 POST 写操作默认追加的 idor/bola 等确实 missing（未测）——账本正确识别
        assert "idor" in upload["missing"]
        # /export 漏 ssti
        assert "ssti" in ps["GET /api/report/export"]["missing"]
        # /users 完全没测
        assert ps["GET /api/users/123"]["missing"]

    def test_uncovered_high_detected(self):
        ledger = build_coverage_ledger(_surfaces(), _entries())
        # /users 期望 idor/bola（高风险）未覆盖
        uh = ledger["uncovered_high"]
        assert any(u["vuln_type"] == "idor" for u in uh)
        assert any(u["vuln_type"] == "bola" for u in uh)

    def test_gate_blocks_on_uncovered_high(self):
        ledger = build_coverage_ledger(_surfaces(), _entries())
        passed, reason = gate_uncovered_high(ledger)
        assert passed is False
        assert "阻断" in reason

    def test_gate_passes_when_all_covered(self):
        # 全部 ruled_out（带 evidence）→ 通过
        surfaces = _surfaces()
        entries = []
        for s in surfaces:
            from core.loops.coverage_derive import derive_expected_vuln_types
            for vt in derive_expected_vuln_types(s):
                entries.append(CoverageEntry(
                    surface=s["_surface_key"], risk_area=vt,
                    outcome="ruled_out", evidence={"reason": "N/A"},
                ))
        ledger = build_coverage_ledger(surfaces, entries)
        passed, reason = gate_uncovered_high(ledger)
        assert passed is True, reason

    def test_gate_blocks_on_validation_error(self):
        # ruled_out 无 evidence → 校验失败 → 阻断
        entries = [CoverageEntry(surface="GET /x", risk_area="sqli",
                                 outcome="ruled_out", evidence={})]
        ledger = build_coverage_ledger(
            [{"_surface_key": "GET /x", "_tags": {"risk_domain": ["injection"]},
              "method": "GET", "url": "/x"}],
            entries,
        )
        passed, reason = gate_uncovered_high(ledger)
        assert passed is False
        assert "校验失败" in reason

    def test_domain_conclusion_table_markdown(self):
        ledger = build_coverage_ledger(_surfaces(), _entries())
        table = domain_conclusion_table(ledger)
        assert "| 风险域 |" in table
        assert "🔴" in table or "🟡" in table  # 有缺失即标红/黄

    def test_uncovered_statement(self):
        ledger = build_coverage_ledger(_surfaces(), _entries())
        stmt = uncovered_statement(ledger)
        assert "未覆盖声明" in stmt
        assert "GET /api/users/123" in stmt  # 列出缺失端点

    def test_by_risk_domain_aggregation(self):
        ledger = build_coverage_ledger(_surfaces(), _entries())
        bd = ledger["by_risk_domain"]
        assert "authz" in bd
        assert bd["authz"]["missing"] >= 1

    def test_zero_deps(self):
        src = Path(__file__).resolve().parents[2] / "core/loops/coverage_ledger.py"
        txt = src.read_text(encoding="utf-8")
        assert "import httpx" not in txt and "import requests" not in txt
