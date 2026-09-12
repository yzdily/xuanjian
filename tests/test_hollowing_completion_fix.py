"""验证 P0-1/P1-1/P0-2 修复：补测回写完成率、空心化 pending 判定、分母解耦。"""
import pytest
from core.sitemap.models import FeaturePoint, CheckItem, CheckResult, Priority


class _FakeSitemap:
    """最小化 sitemap mock，供 ReportMixin 使用。"""
    def __init__(self, features_dict):
        self.features = features_dict
        self.apis = {}
        self._ghost_endpoint_count = 0
        self.phase_status = "completed"
        self.termination_reason = ""

    def get_coverage(self):
        return {"vulns": 0, "checks_done": 0, "checks_total": 0,
                "fast_scanner_stats": {}}


class _FakeSession:
    """最小化 session mock。"""
    def __init__(self, sitemap):
        self.sitemap = sitemap
        self._flows_no_new_api = False


from core.session.report_mixin import ReportMixin


class _ReportMixinHolder(ReportMixin, _FakeSession):
    """组合 ReportMixin 与 fake session。"""
    def __init__(self, sitemap):
        _FakeSession.__init__(self, sitemap)


def _make_feature(name, check_results, origin="validated"):
    """创建一个 feature，check_results 是 CheckResult 列表。"""
    fp = FeaturePoint(
        id=name,
        name=name,
        description=f"test feature {name}",
        priority=Priority.MEDIUM,
    )
    fp.origin = origin
    for cr in check_results:
        fp.checklist.append(CheckItem(vuln_type="generic", result=cr))
    return fp


class TestComputeRealCompletion:
    """P0-2: 验证 validated/speculative 分母解耦。"""

    def test_pending_rate_returned(self):
        """_compute_real_completion 返回 pending_rate。"""
        sitemap = _FakeSitemap({
            "f1": _make_feature("f1", [CheckResult.PENDING, CheckResult.NOT_VULN]),
        })
        holder = _ReportMixinHolder(sitemap)
        rc = holder._compute_real_completion()
        assert "pending_rate" in rc
        assert rc["pending"] == 1
        assert rc["pending_rate"] == 50.0

    def test_validated_speculative_separated(self):
        """validated 和 speculative 分别统计。"""
        sitemap = _FakeSitemap({
            "f1": _make_feature("f1", [CheckResult.NOT_VULN, CheckResult.NOT_VULN], origin="validated"),
            "f2": _make_feature("f2", [CheckResult.PENDING, CheckResult.PENDING, CheckResult.NOT_VULN], origin="speculative"),
        })
        holder = _ReportMixinHolder(sitemap)
        rc = holder._compute_real_completion()
        assert rc["validated_total"] == 2
        assert rc["validated_done"] == 2
        assert rc["validated_rate"] == 100.0
        assert rc["speculative_total"] == 3
        assert rc["speculative_done"] == 1
        assert rc["speculative_rate"] == 33.3

    def test_empty_sitemap(self):
        """空 sitemap 返回全零。"""
        sitemap = _FakeSitemap({})
        holder = _ReportMixinHolder(sitemap)
        rc = holder._compute_real_completion()
        assert rc["total"] == 0
        assert rc["pending_rate"] == 0.0
        assert rc["validated_rate"] == 0.0
        assert rc["speculative_rate"] == 0.0


class TestDetectHollowing:
    """P1-1: 验证空心化检测器纳入 pending_rate。"""

    def test_hollowing_triggers_on_high_pending(self):
        """real_rate < 5% 且 (skip_rate + pending_rate) > 80% 时触发空心化。"""
        # 模拟 task_1786603505 场景：17 done, 27 skipped, 2889 pending, total=2933
        checks = [CheckResult.NOT_VULN] * 17
        checks += [CheckResult.SKIPPED] * 27
        checks += [CheckResult.PENDING] * 2889
        sitemap = _FakeSitemap({
            "f1": _make_feature("f1", checks),
        })
        holder = _ReportMixinHolder(sitemap)
        h = holder._detect_hollowing()
        assert h is not None
        assert h["is_hollowed"] is True
        assert h["alert_level"] == "danger"
        assert h["pending"] == 2889
        assert h["pending_rate"] > 80.0

    def test_hollowing_not_triggered_when_well_covered(self):
        """正常覆盖率不触发空心化。"""
        checks = [CheckResult.NOT_VULN] * 80 + [CheckResult.PENDING] * 20
        sitemap = _FakeSitemap({
            "f1": _make_feature("f1", checks),
        })
        holder = _ReportMixinHolder(sitemap)
        h = holder._detect_hollowing()
        assert h is None

    def test_hollowing_triggers_on_high_skip(self):
        """原始条件仍然有效：skip_rate > 70%。"""
        checks = [CheckResult.NOT_VULN] * 5 + [CheckResult.SKIPPED] * 95
        sitemap = _FakeSitemap({
            "f1": _make_feature("f1", checks),
        })
        holder = _ReportMixinHolder(sitemap)
        h = holder._detect_hollowing()
        assert h is not None
        assert h["is_hollowed"] is True

    def test_hollowing_message_includes_pending(self):
        """空心化告警消息包含 pending 信息。"""
        checks = [CheckResult.NOT_VULN] * 3 + [CheckResult.PENDING] * 97
        sitemap = _FakeSitemap({
            "f1": _make_feature("f1", checks),
        })
        holder = _ReportMixinHolder(sitemap)
        h = holder._detect_hollowing()
        assert h is not None
        assert "未测" in h["message"]
        assert "pending" in h["message"].lower() or "未测" in h["message"]


class TestCheckItemSourceField:
    """验证 CheckItem.source 字段已声明（非动态属性）。"""
    def test_source_field_default(self):
        c = CheckItem(vuln_type="SQLi")
        assert c.source == ""

    def test_source_field_settable(self):
        c = CheckItem(vuln_type="SQLi")
        c.source = "fast_scanner_supplemental"
        assert c.source == "fast_scanner_supplemental"


class TestFeaturePointOriginField:
    """验证 FeaturePoint.origin 字段已声明。"""
    def test_origin_default_validated(self):
        fp = FeaturePoint(id="t1", name="test", description="desc")
        assert fp.origin == "validated"

    def test_origin_settable(self):
        fp = FeaturePoint(id="t1", name="test", description="desc")
        fp.origin = "speculative"
        assert fp.origin == "speculative"
