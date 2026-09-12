"""G14 回归套件 —— G2 接口面盘点 + G3 期望漏洞类型推导 gate 锁定。

运行：python -m pytest tests/unit/test_coverage_derive.py -v -o addopts="" -p no:cacheprovider
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.endpoint.surface_inventory import (  # noqa: E402
    build_surface_inventory,
    inventory_summary,
)
from core.loops.coverage_derive import (  # noqa: E402
    derive_expected_vuln_types,
    expected_coverage_matrix,
)
from core.endpoint.risk_domain import tag_endpoints  # noqa: E402


def _eps():
    return [
        {"method": "POST", "url": "/api/users/avatar/upload"},
        {"method": "GET", "url": "/api/users/123"},
        {"method": "GET", "url": "/api/report/export"},
        {"method": "GET", "url": "/static/app.js"},
        {"method": "POST", "url": "http://evil.com/api/pay"},
        {"method": "GET", "url": "/api/users/123"},  # 重复，应去重
    ]


class TestSurfaceInventory:
    """G2：去重 + 静态资产剔除 + 跨域标注 + 风险域分布。"""

    def test_dedup(self):
        inv = build_surface_inventory(_eps(), host="example.com")
        assert inv["total"] == 6
        assert inv["unique"] == 5  # 一个重复

    def test_static_assets_excluded_from_testable(self):
        inv = build_surface_inventory(_eps(), host="example.com")
        assert inv["static_assets"] == 1  # /static/app.js
        # testable = unique - static - cross_host
        assert inv["testable"] == inv["unique"] - inv["static_assets"] - inv["cross_host"]

    def test_cross_host_marked(self):
        inv = build_surface_inventory(_eps(), host="example.com")
        assert inv["cross_host"] == 1  # http://evil.com/...

    def test_by_risk_domain(self):
        inv = build_surface_inventory(_eps(), host="example.com")
        assert "upload" in inv["by_risk_domain"]
        assert "authz" in inv["by_risk_domain"]
        # 多域端点在多域计数
        assert inv["by_risk_domain"]["authz"]["count"] >= 1

    def test_summary_string(self):
        inv = build_surface_inventory(_eps(), host="example.com")
        s = inventory_summary(inv)
        assert "接口面" in s
        assert "可测" in s

    def test_surfaces_carry_surface_key(self):
        inv = build_surface_inventory(_eps(), host="example.com")
        assert all("_surface_key" in s for s in inv["surfaces"])

    def test_zero_deps(self):
        src = Path(__file__).resolve().parents[2] / "core/endpoint/surface_inventory.py"
        txt = src.read_text(encoding="utf-8")
        assert "import httpx" not in txt and "import requests" not in txt


class TestCoverageDerive:
    """G3：域→漏洞类型 + 写操作追加 + 响应信号启发式 + 兜底不漏测。"""

    def test_domain_to_vuln_types(self):
        eps = tag_endpoints([{"method": "POST", "url": "/upload"}])
        vts = derive_expected_vuln_types(eps[0])
        assert "file_upload_unrestricted" in vts
        assert "path_traversal" in vts  # upload 域含 path_traversal

    def test_injection_domain(self):
        eps = tag_endpoints([{"method": "GET", "url": "/api/report/export"}])
        vts = derive_expected_vuln_types(eps[0])
        assert "sqli" in vts
        assert "ssti" in vts

    def test_authz_write_defaults(self):
        # 写操作无关键字命中 → authz + 写操作追加 bfla/mass_assignment
        eps = tag_endpoints([{"method": "POST", "url": "/api/xyz"}])
        vts = derive_expected_vuln_types(eps[0])
        assert "idor" in vts
        assert "bfla" in vts
        assert "mass_assignment" in vts

    def test_response_signal_sql(self):
        eps = tag_endpoints([{"method": "GET", "url": "/api/search"}])
        vts = derive_expected_vuln_types(
            eps[0],
            response_signals={"body": "SQL syntax error at line 1"},
        )
        assert "sqli" in vts

    def test_response_signal_xss(self):
        eps = tag_endpoints([{"method": "GET", "url": "/api/users/1"}])
        vts = derive_expected_vuln_types(
            eps[0],
            response_signals={"body": "<script>alert(1)</script>"},
        )
        assert "xss" in vts

    def test_fallback_no_miss(self):
        """兜底不漏测：无任何命中也至少返回 info_disclosure。"""
        eps = tag_endpoints([{"method": "GET", "url": "/aaa"}])
        vts = derive_expected_vuln_types(eps[0])
        assert vts  # 非空
        assert "info_disclosure" in vts

    def test_dedup_preserve_order(self):
        eps = tag_endpoints([{"method": "POST", "url": "/upload"}])
        vts = derive_expected_vuln_types(eps[0])
        assert len(vts) == len(set(vts))

    def test_expected_coverage_matrix(self):
        inv = build_surface_inventory(_eps(), host="example.com")
        matrix = expected_coverage_matrix(inv["surfaces"])
        assert len(matrix) == inv["unique"]
        assert all("expected_vuln_types" in row for row in matrix)
        assert all(row["expected_vuln_types"] for row in matrix)  # 都非空

    def test_zero_deps(self):
        src = Path(__file__).resolve().parents[2] / "core/loops/coverage_derive.py"
        txt = src.read_text(encoding="utf-8")
        assert "import httpx" not in txt and "import requests" not in txt
