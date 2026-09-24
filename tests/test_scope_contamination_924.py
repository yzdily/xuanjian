# -*- coding: utf-8 -*-
"""924 跨资产污染修复回归用例（task_1790219173_3617ab 复盘）。

背景：r.aibank.com 任务返回 nginx 默认页 → 爬虫跟链 nginx.com → 302 → f5.com，
作用域自动膨胀 + feature_gen/report 零 host 校验 + 补测队列不排除幽灵端点，
导致报告 6/7 漏洞与补测队列 20 项全是 f5.com。

本文件钉死四道防线，防止回归：
  L1 scope_mixin   —— 高频非同品牌域不再自动晋升（泄漏①）
  L2 feature_gen   —— 越界 host 不建 API/功能点（泄漏②）
  L3 report        —— 补测队列排除幽灵/越界；越界漏洞只进排除清单（泄漏③⑤）
  逃生门            —— XUANJIAN_SCOPE_AUTO_PROMOTE=1 可临时恢复旧行为
"""
import os

import pytest

from core.sitemap.sitemap import Sitemap
from core.sitemap.models import (
    FeaturePoint, CheckItem, Priority, TestStatus, CheckResult,
)


@pytest.fixture()
def sm():
    return Sitemap(target="https://r.aibank.com/", task_id="test_scope_924")


class TestHostInScope:
    def test_target_and_subdomains_in_scope(self, sm):
        assert sm._host_in_scope("https://r.aibank.com/api/x") is True
        assert sm._host_in_scope("https://sub.r.aibank.com/x") is True

    def test_foreign_host_rejected(self, sm):
        assert sm._host_in_scope("https://www.f5.com/datasets/1") is False

    def test_relative_and_empty_pass(self, sm):
        assert sm._host_in_scope("/relative/path") is True
        assert sm._host_in_scope("") is True

    def test_explicit_extra_scope_pass(self, sm):
        sm.extra_scope.add("nginx.org")
        assert sm._host_in_scope("https://nginx.org/en/docs/") is True
        assert sm._host_in_scope("https://evil.com") is False


class TestAddApiGate:
    def test_in_scope_api_kept(self, sm):
        assert sm.add_api("GET", "https://r.aibank.com/api/users") is not None

    def test_out_of_scope_api_rejected(self, sm):
        assert sm.add_api("GET", "https://www.f5.com/api/headers") is None
        assert not any("f5.com" in k for k in sm.apis)


class TestFeatureGenGate:
    def test_out_of_scope_feature_rejected(self, sm):
        fp = sm._create_atomic_feature(
            "设置(查询)", "API 端点 GET https://www.f5.com/datasets/{id}/settings/embeddings",
            "https://www.f5.com/datasets/{id}/settings/embeddings",
            "GET https://www.f5.com/datasets/{id}/settings/embeddings",
            ["未授权访问", "IDOR越权"])
        assert fp is None

    def test_in_scope_feature_created(self, sm):
        fp = sm._create_atomic_feature(
            "用户管理(查询)", "API 端点 GET https://r.aibank.com/api/users",
            "https://r.aibank.com/users",
            "GET https://r.aibank.com/api/users", ["未授权访问"])
        assert fp is not None

    def test_add_feature_public_entry_gated(self, sm):
        fp = sm.add_feature("越界功能点", "API 端点 GET https://www.f5.com/x/y",
                            page_url="https://www.f5.com/x",
                            related_apis=["GET https://www.f5.com/x/y"])
        assert fp is None


class TestGhostAndOosPredicates:
    def _ghost_fp(self):
        fp = FeaturePoint(id="fp_5", name="设置(查询)", page_url="https://www.f5.com/x",
                          related_apis=["GET https://www.f5.com/x"],
                          priority=Priority.CRITICAL, checklist=[])
        fp.test_status = TestStatus.SKIPPED
        fp.description = "API 端点 GET https://www.f5.com/x [GHOST-ENDPOINT]"
        return fp

    def test_ghost_detected(self, sm):
        assert sm._fp_is_ghost(self._ghost_fp()) is True

    def test_oos_detected(self, sm):
        assert sm._fp_out_of_scope(self._ghost_fp()) is True

    def test_normal_fp_clean(self, sm):
        fp = FeaturePoint(id="fp_1", name="root", page_url="https://r.aibank.com/",
                          related_apis=["GET https://r.aibank.com/"],
                          priority=Priority.MEDIUM, checklist=[])
        assert sm._fp_is_ghost(fp) is False
        assert sm._fp_out_of_scope(fp) is False


class TestReportFilters:
    def test_ghost_fp_not_in_retest_queue(self, sm):
        """★ 泄漏⑤：幽灵端点（skipped + [GHOST-ENDPOINT]）不得出现在补测队列。"""
        fp_ok = FeaturePoint(id="fp_1", name="root", page_url="https://r.aibank.com/",
                             related_apis=["GET https://r.aibank.com/"],
                             priority=Priority.MEDIUM,
                             checklist=[CheckItem(vuln_type="SQL注入")])
        fp_ghost = self._ghost_fp_obj()
        fp_ghost.checklist = [CheckItem(vuln_type="IDOR越权"),
                              CheckItem(vuln_type="信息泄露")]
        sm.features = {"fp_1": fp_ok, "fp_5": fp_ghost}
        lines = sm._render_execution_quality_summary()
        assert not any("fp_5" in l for l in lines), "幽灵端点泄漏进补测队列"
        assert any("fp_1" in l for l in lines)

    def _ghost_fp_obj(self):
        fp = FeaturePoint(id="fp_5", name="设置(查询)", page_url="https://www.f5.com/x",
                          related_apis=["GET https://www.f5.com/x"],
                          priority=Priority.CRITICAL, checklist=[])
        fp.test_status = TestStatus.SKIPPED
        fp.description = "API 端点 GET https://www.f5.com/x [GHOST-ENDPOINT]"
        return fp

    def test_oos_vuln_only_in_exclusion_list(self, sm):
        """★ 泄漏③：越界漏洞不进 3.1 漏洞详情，只进排除清单。"""
        c_vuln = CheckItem(vuln_type="未授权访问")
        c_vuln.result = CheckResult.VULNERABLE
        c_vuln.severity = "medium"
        fp_oos = FeaturePoint(id="fp_26", name="api/headers",
                              page_url="https://www.f5.com/api/headers",
                              related_apis=["GET https://www.f5.com/api/headers"],
                              priority=Priority.HIGH, checklist=[c_vuln])
        fp_ok = FeaturePoint(id="fp_1", name="root", page_url="https://r.aibank.com/",
                             related_apis=["GET https://r.aibank.com/"],
                             priority=Priority.MEDIUM,
                             checklist=[CheckItem(vuln_type="SQL注入")])
        sm.features = {"fp_1": fp_ok, "fp_26": fp_oos}
        det = []
        sm._render_vuln_details(det)
        text = "\n".join(det)
        assert "排除清单" in text, "越界发现缺少排除清单披露"
        seg_before = text.split("排除清单")[0]
        assert "www.f5.com" not in seg_before, "越界漏洞渲染进了主章节"

    def test_feature_details_excludes_oos(self, sm):
        c = CheckItem(vuln_type="XSS")
        fp_oos = FeaturePoint(id="fp_9", name="search", page_url="https://www.f5.com/search/",
                              related_apis=["GET https://www.f5.com/search/"],
                              priority=Priority.HIGH, checklist=[c])
        sm.features = {"fp_9": fp_oos}
        lines = []
        sm._render_feature_details(lines)
        text = "\n".join(lines)
        assert "www.f5.com" not in text


# ============================================================
# P2 后续重构项：AuthorizedScope 契约统一 + scope_fingerprint 打标（924 §4.2）
# ============================================================

class TestAuthorizedScopeContract:
    """契约本体：hosts/contains 判定 + 指纹稳定性 + 模式单一来源。"""

    def test_fingerprint_stable_and_sensitive(self):
        """相同作用域状态 → 相同指纹；target/extra_scope/mode 任一变化 → 指纹变化。"""
        from core.scope_contract import AuthorizedScope, SCOPE_MODE_STRICT, SCOPE_MODE_EXTENDED

        a = AuthorizedScope.from_parts("https://r.aibank.com/", {"nginx.org"})
        b = AuthorizedScope.from_parts("https://r.aibank.com/", {"nginx.org"})
        assert a.fingerprint() == b.fingerprint()  # 跨实例稳定

        diff_scope = AuthorizedScope.from_parts(
            "https://r.aibank.com/", {"nginx.org", "nginx.com"})
        assert a.fingerprint() != diff_scope.fingerprint()  # extra_scope 变化

        diff_target = AuthorizedScope.from_parts("https://evil.com/", {"nginx.org"})
        assert a.fingerprint() != diff_target.fingerprint()  # target 变化

        ext = AuthorizedScope.from_parts(
            "https://r.aibank.com/", {"nginx.org"}, mode=SCOPE_MODE_EXTENDED)
        strict = AuthorizedScope.from_parts(
            "https://r.aibank.com/", {"nginx.org"}, mode=SCOPE_MODE_STRICT)
        assert ext.fingerprint() != strict.fingerprint()  # mode 变化

    def test_contains_matches_legacy_behavior(self):
        from core.scope_contract import AuthorizedScope
        sc = AuthorizedScope.from_parts("https://r.aibank.com/", {"nginx.org"})
        assert sc.contains("https://r.aibank.com/api/x") is True
        assert sc.contains("https://sub.r.aibank.com/x") is True
        assert sc.contains("https://nginx.org/en/docs/") is True
        assert sc.contains("https://www.f5.com/datasets/1") is False  # 本案越界资产
        assert sc.contains("/relative") is True
        assert sc.contains("") is True

    def test_sitemap_shares_extra_scope_with_contract(self):
        """sitemap.extra_scope 与契约共享同一集合：运行期 update 实时生效。"""
        assert "nginx.org" not in sm_scope_fixture().scope.hosts()
        s = sm_scope_fixture()
        s.extra_scope.add("nginx.org")
        assert "nginx.org" in s.scope.hosts()
        assert s.scope.contains("https://nginx.org/en/docs/") is True
        assert s.scope.fingerprint() != sm_scope_fixture().scope.fingerprint()

    def test_sitemap_delegates_to_contract(self):
        """Sitemap._host_in_scope 是契约的门面：两者判定必须一致。"""
        s = sm_scope_fixture()
        for url in ("https://r.aibank.com/api/x", "https://www.f5.com/api/headers",
                    "https://sub.r.aibank.com/x", "/rel"):
            assert s._host_in_scope(url) == s.scope.contains(url)

    def test_mode_single_source(self, monkeypatch):
        """模式单一来源：默认 strict；XUANJIAN_SCOPE_AUTO_PROMOTE=1 → extended。"""
        from core.scope_contract import (
            AuthorizedScope, current_mode, is_extended_mode,
            SCOPE_MODE_STRICT, SCOPE_MODE_EXTENDED,
        )
        monkeypatch.delenv("XUANJIAN_SCOPE_AUTO_PROMOTE", raising=False)
        assert current_mode() == SCOPE_MODE_STRICT
        assert is_extended_mode() is False
        assert AuthorizedScope.from_parts("https://x.com/").mode == SCOPE_MODE_STRICT

        monkeypatch.setenv("XUANJIAN_SCOPE_AUTO_PROMOTE", "1")
        assert current_mode() == SCOPE_MODE_EXTENDED
        assert is_extended_mode() is True
        assert AuthorizedScope.from_parts("https://x.com/").mode == SCOPE_MODE_EXTENDED

    def test_describe_lists_authorized_assets(self):
        s = sm_scope_fixture()
        s.extra_scope.add("nginx.org")
        text = s.scope.describe()
        assert "r.aibank.com" in text
        assert "nginx.org" in text
        assert "strict" in text
        assert "f5.com" not in text


def sm_scope_fixture():
    return Sitemap(target="https://r.aibank.com/", task_id="test_scope_924")


class TestScopeFingerprintTagging:
    """产物打标：sitemap 持久化 / realtime 报告 / CI 闸门产物各带指纹。"""

    def test_sitemap_save_load_roundtrip(self, tmp_path, monkeypatch):
        """save 落盘 extra_scope/指纹；load 恢复后授权域继续生效（防会话恢复丢授权）。"""
        import json
        monkeypatch.chdir(tmp_path)
        s = Sitemap(target="https://r.aibank.com/", task_id="fp_tag_roundtrip")
        s.extra_scope.add("nginx.org")
        fp_before = s.scope.fingerprint()
        s.save()

        raw = json.loads(s._persist_path.read_text(encoding="utf-8"))
        assert raw["scope_fingerprint"] == fp_before
        assert "nginx.org" in raw["extra_scope"]
        assert raw["scope_mode"] == "strict"
        assert "r.aibank.com" in raw["scope_authorized_hosts"]

        # 新实例恢复：extra_scope 必须回得来，越界判定继续成立
        s2 = Sitemap(target="https://r.aibank.com/", task_id="fp_tag_roundtrip")
        assert s2.load() is True
        assert "nginx.org" in s2.extra_scope
        assert s2._host_in_scope("https://nginx.org/en/docs/") is True
        assert s2._host_in_scope("https://www.f5.com/x") is False
        assert s2.scope_fingerprint() == fp_before  # 恢复后指纹一致
        assert s2.scope_fingerprint_at_save == fp_before

    def test_realtime_report_carries_scope_tag(self, tmp_path, monkeypatch):
        """§1.1 封面固定渲染授权资产清单 + 作用域指纹（§4.1/§4.2）。"""
        monkeypatch.chdir(tmp_path)
        s = Sitemap(target="https://r.aibank.com/", task_id="fp_tag_report")
        s.extra_scope.add("nginx.org")
        content = s.flush_report()
        assert "授权资产" in content
        assert "r.aibank.com" in content
        assert "nginx.org" in content
        assert "作用域指纹" in content
        assert s.scope.fingerprint() in content
        # 授权资产行不得混入本案越界资产
        auth_row = [l for l in content.splitlines() if l.startswith("| 授权资产 |")][0]
        assert "f5.com" not in auth_row

    def test_ci_gate_result_carries_scope_tag(self, tmp_path, monkeypatch):
        """ci_gate_result.json 带 scope_fingerprint/scope_mode，供 CI/审计核对。"""
        import json
        monkeypatch.chdir(tmp_path)
        s = Sitemap(target="https://r.aibank.com/", task_id="fp_tag_cigate")
        s.extra_scope.add("nginx.org")
        s.save()  # 先建目录结构（data/scan_artifacts 由 _artifacts_dir 自建）

        from types import SimpleNamespace
        from core.loops.coverage_integration import export_scan_artifacts
        session = SimpleNamespace(sitemap=s, task_id="fp_tag_cigate",
                                   target_url="https://r.aibank.com/")
        export_scan_artifacts(session)

        gate_path = tmp_path / "data" / "scan_artifacts" / "fp_tag_cigate" / "ci_gate_result.json"
        ci = json.loads(gate_path.read_text(encoding="utf-8"))
        assert ci["scope_fingerprint"] == s.scope.fingerprint()
        assert ci["scope_mode"] == "strict"


class TestScopeMixinTightening:
    def _fake_crawler(self):
        from core.crawler.scope_mixin import ScopeMixin

        class _FakeCrawler(ScopeMixin):
            def __init__(self):
                self.target_domain = "r.aibank.com"
                self.extra_scope = set()
                self._THIRD_PARTY_BLACKLIST = set()
                self._reports = []
            def _report(self, msg):
                self._reports.append(msg)
        return _FakeCrawler()

    def _captured(self, host, n=10):
        return [{"url": f"https://{host}/api/x{i}", "resource_type": "fetch"}
                for i in range(n)]

    def test_high_freq_non_brand_not_promoted(self):
        """★ 泄漏①：API≥3 次不再自动晋升非同品牌域。"""
        fc = self._fake_crawler()
        discovered = fc.infer_extra_scope(self._captured("www.f5.com"))
        assert "www.f5.com" not in discovered
        assert "www.f5.com" not in fc.extra_scope
        assert any("作用域保护" in r for r in fc._reports)

    def test_same_brand_still_promoted(self):
        fc = self._fake_crawler()
        discovered = fc.infer_extra_scope(self._captured("app.aibank.com"))
        assert "app.aibank.com" in discovered

    def test_escape_hatch_restores_old_behavior(self, monkeypatch):
        """逃生门：XUANJIAN_SCOPE_AUTO_PROMOTE=1 临时恢复旧行为。"""
        monkeypatch.setenv("XUANJIAN_SCOPE_AUTO_PROMOTE", "1")
        fc = self._fake_crawler()
        discovered = fc.infer_extra_scope(self._captured("www.f5.com"))
        assert "www.f5.com" in discovered
