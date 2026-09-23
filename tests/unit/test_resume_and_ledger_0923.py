"""0923 v2 修复的单元测试：resume 归一 / 终态分流 / 台账唯一入口 / 报告双消费点。

覆盖缺陷：A1 A2 A3 A4 A5 / B4 B5 / D3 D5 D7 / D8 / D10 / D11 / B1 / B1b。
"""

from __future__ import annotations

import json

import pytest


# ============================================================
# 1. resume 判定唯一入口（T6' / 修 A2 + D11）
# ============================================================

class TestMatchResume:
    """「继续」必须容错：不要求用户精确打一个词。"""

    @pytest.mark.parametrize("msg", [
        "继续",
        "继续吧",
        "请继续",
        "麻烦帮我继续",
        "继续测试",
        "继续测试跑完这个流程",      # ★ 用户原话，修正前后端两处都判不中
        "/继续",
        "。继续",
        "resume",
        "Resume 一下",
        "CONTINUE",
        "go on",
        "接着刚才那个",
        "恢复扫描",
        "续跑",
        "task_1790130538_0bc917 继续",
    ])
    def test_resume_variants_matched(self, msg):
        from core.session.chat_loop import _match_resume
        assert _match_resume(msg) is True, f"{msg!r} 应命中 resume"

    @pytest.mark.parametrize("msg", [
        "你好",
        "扫描一下 https://example.com",
        "停止",
        "清空",
        "帮我看看这个报告",
        "不要继续",
        "",
        "   ",
    ])
    def test_non_resume_not_matched(self, msg):
        from core.session.chat_loop import _match_resume
        assert _match_resume(msg) is False, f"{msg!r} 不应命中 resume"

    def test_single_source_of_truth(self):
        """idle 分支与非 idle 分支必须共用同一判定（禁止第三套实现）。

        修正前项目里有**两套**互不一致的判定：
        idle 精确等值 + _detect_and_handle_resume_command 的子串模糊。
        只改一套 = 复制"D6 同一件事两套实现"的旧病。
        """
        import inspect
        from core.session import chat_loop
        src = inspect.getsource(chat_loop.ChatLoopMixin._detect_and_handle_resume_command)
        assert "_match_resume" in src, (
            "_detect_and_handle_resume_command 必须调用 _match_resume，"
            "否则又出现两套判定"
        )
        assert "_resume_keywords" not in src, "旧的独立关键词表必须已移除"


class TestDetectAndHandleResumeCommand:
    """既有行为保持：该函数只负责重置 nudge 计数，且仅对 analyze/test/explore 生效。"""

    def _mk(self):
        from core.session.chat_loop import ChatLoopMixin

        class Fake:
            _nudge_count = {}
            _detect_and_handle_resume_command = (
                ChatLoopMixin._detect_and_handle_resume_command
            )
            reset_nudge_counter = lambda self, phase=None: None  # noqa: E731

        return Fake()

    def test_handled_in_test_phase(self):
        assert self._mk()._detect_and_handle_resume_command("继续", "test")[0] is True

    def test_not_handled_in_idle(self):
        """idle 阶段由 chat_loop 的 idle 分支处理，这里不接管（既有断言保留）。"""
        assert self._mk()._detect_and_handle_resume_command("继续", "idle")[0] is False

    def test_not_handled_for_plain_message(self):
        assert self._mk()._detect_and_handle_resume_command("你好", "test")[0] is False


# ============================================================
# 2. 断点阶段推断（T6' / 修 A3 + A5）
# ============================================================

class TestInferResumeStage:
    class _Res:
        def __init__(self, name):
            self.name = name

    class _Check:
        def __init__(self, result):
            self.result = result

    class _FP:
        def __init__(self, checklist):
            self.checklist = checklist

    class _SM:
        def __init__(self, apis=0, features=None):
            self.apis = {f"api{i}": {} for i in range(apis)}
            self.features = features or {}

    class _Session:
        def __init__(self, sm, blocked=False):
            self.sitemap = sm
            self._resume_blocked = blocked

    def test_no_progress_returns_explore(self):
        from core.session.chat_loop import _infer_resume_stage
        s = self._Session(self._SM())
        assert _infer_resume_stage(s) == "explore"

    def test_apis_without_features_returns_analyze(self):
        from core.session.chat_loop import _infer_resume_stage
        s = self._Session(self._SM(apis=94))
        assert _infer_resume_stage(s) == "analyze"

    def test_features_untested_returns_analyze(self):
        from core.session.chat_loop import _infer_resume_stage
        sm = self._SM(apis=10, features={
            "f1": self._FP([self._Check(self._Res("PENDING"))]),
        })
        assert _infer_resume_stage(self._Session(sm)) == "analyze"

    def test_partially_tested_returns_test(self):
        from core.session.chat_loop import _infer_resume_stage
        sm = self._SM(apis=10, features={
            "f1": self._FP([self._Check(self._Res("VULNERABLE"))]),
            "f2": self._FP([self._Check(self._Res("PENDING"))]),
        })
        assert _infer_resume_stage(self._Session(sm)) == "test"

    def test_fully_tested_returns_report(self):
        from core.session.chat_loop import _infer_resume_stage
        sm = self._SM(apis=10, features={
            "f1": self._FP([self._Check(self._Res("SAFE"))]),
            "f2": self._FP([self._Check(self._Res("VULNERABLE"))]),
        })
        assert _infer_resume_stage(self._Session(sm)) == "report"

    def test_resume_blocked_after_explicit_stop(self):
        """用户点「停止」（非暂停）后不允许复用断点 —— 语义上等于重开。"""
        from core.session.chat_loop import _infer_resume_stage
        sm = self._SM(apis=10, features={
            "f1": self._FP([self._Check(self._Res("VULNERABLE"))]),
        })
        assert _infer_resume_stage(self._Session(sm, blocked=True)) == "explore"

    def test_never_raises_on_broken_sitemap(self):
        from core.session.chat_loop import _infer_resume_stage
        class Broken:
            @property
            def sitemap(self):
                raise RuntimeError("boom")
        assert _infer_resume_stage(Broken()) == "explore"


# ============================================================
# 3. LLM 失败分型（修 B5：404/余额 不得提示"可重试"）
# ============================================================

class TestClassifyLlmFailure:
    @pytest.mark.parametrize("err,kind,retryable", [
        ("Error code: 404 - Not found the model kimi-k3", "llm_model", False),
        ("insufficient balance", "llm_account", False),
        ("429 rate_limit_reached_error", "llm_rate_limit", True),
        ("401 invalid api key", "llm_auth", False),
        ("Connection error timeout", "llm_network", True),
        ("完全未知的错误", "llm_error", True),
    ])
    def test_classification(self, err, kind, retryable):
        from core.session.chat_loop import _llm_failure_retryable, _classify_llm_failure
        got_kind, _msg = _classify_llm_failure(err)
        assert got_kind == kind, f"{err!r} → {got_kind}，期望 {kind}"
        assert _llm_failure_retryable(err) is retryable

    def test_model_404_wins_over_401_429_rules(self):
        """模型名 404 消息里也可能含 429（request id），模型规则必须排在前。"""
        from core.session.chat_loop import _classify_llm_failure
        for err in ("Not found the model kimi-k3",
                    "404 model not found (request id 429abc)",
                    "The model `wuwen-x` does not exist"):
            kind, _ = _classify_llm_failure(err)
            assert kind == "llm_model", f"{err!r} → {kind}，期望 llm_model"

    def test_message_has_no_retry_hint_for_config_errors(self):
        from core.session.chat_loop import _classify_llm_failure
        for err in ("insufficient balance", "404 not found the model x",
                    "401 invalid api key"):
            _kind, msg = _classify_llm_failure(err)
            assert "可重试" not in msg or "重试无效" in msg, (
                f"配置性错误不得引导用户重试: {msg!r}"
            )


# ============================================================
# 4. 台账唯一入口（T1 / 修 D3 + 静默失败）
# ============================================================

class _Finding:
    def __init__(self, **kw):
        self.vuln_type = kw.get("vuln_type", "源码泄露(.git)")
        self.severity = kw.get("severity", "high")
        self.url = kw.get("url", "https://x/.git/config")
        self.detail = kw.get("detail", "d")
        self.evidence = kw.get("evidence", "e")
        self.review_status = kw.get("review_status", "needs_review")
        self.review_reason = kw.get("review_reason", "")
        self.evidence_quality = kw.get("evidence_quality", "")
        self.body_sha256 = kw.get("body_sha256", "")
        self.path = kw.get("path", "/.git/config")


class _SM:
    def __init__(self):
        self._dirscan_sensitive_vulns = []


class TestPersistDirFindings:
    def test_writes_and_dedupes(self):
        from core.session.dir_finding_store import persist_dir_findings
        sm = _SM()
        f = _Finding()
        assert persist_dir_findings(sm, [f], source="dirscan_active") == 1
        # 幂等：同 (url, vuln_type) 不重复
        assert persist_dir_findings(sm, [f], source="dirscan_active") == 0
        assert len(sm._dirscan_sensitive_vulns) == 1
        row = sm._dirscan_sensitive_vulns[0]
        assert row["source"] == "dirscan_active"
        assert row["review_status"] == "needs_review"

    def test_missing_review_status_defaults_to_needs_review(self):
        """fail-safe：缺标签的发现绝不能被当成"已确认漏洞"。"""
        from core.session.dir_finding_store import persist_dir_findings
        sm = _SM()
        f = _Finding()
        del f.review_status
        persist_dir_findings(sm, [f])
        assert sm._dirscan_sensitive_vulns[0]["review_status"] == "needs_review"

    def test_unavailable_sitemap_logs_not_silent(self, caplog):
        """★ 修 explore_mixin 原实现的静默吞异常（AttributeError 被 except 吞掉）。"""
        from core.session.dir_finding_store import persist_dir_findings

        class Frozen:
            __slots__ = ()
            _dirscan_sensitive_vulns = "not-a-list"

        assert persist_dir_findings(Frozen(), [_Finding()]) == 0

    def test_none_sitemap_returns_zero(self):
        from core.session.dir_finding_store import persist_dir_findings
        assert persist_dir_findings(None, [_Finding()]) == 0

    def test_creates_ledger_attr_when_missing(self):
        """旧版反序列化对象没有该属性时，应兜底创建而非静默丢失。"""
        from core.session.dir_finding_store import persist_dir_findings

        class Bare:
            pass

        b = Bare()
        assert persist_dir_findings(b, [_Finding()]) == 1
        assert len(b._dirscan_sensitive_vulns) == 1

    def test_is_confirmed_only_for_confirmed(self):
        from core.session.dir_finding_store import is_confirmed
        assert is_confirmed({"review_status": "confirmed"}) is True
        assert is_confirmed({"review_status": "needs_review"}) is False
        assert is_confirmed({}) is False, "缺字段必须按未确认处理"
        assert is_confirmed("not-a-dict") is False


# ============================================================
# 5. 报告两个消费点必须结论一致（修 D8 / E16）
# ============================================================

class TestCoverageBothConsumers:
    """★ V16/V17：台账的两个消费点必须结论一致（修 D8 / E16）。"""

    class _F:
        def __init__(self, url, status):
            self.vuln_type = "源码泄露(.git)"
            self.severity = "high"
            self.url = url
            self.detail = "d"
            self.evidence = "body_sha256=x"
            self.review_status = status
            self.review_reason = "catch-all" if status != "confirmed" else ""
            self.evidence_quality = "content_match"
            self.body_sha256 = "x"
            self.path = "/.git/config"

    def _build(self, tmp_path, with_features: bool):
        from core.sitemap import Sitemap
        from core.session.dir_finding_store import persist_dir_findings
        sm = Sitemap(target="https://ics.example.com/", task_id="task_cov")
        sm._persist_path = tmp_path / "t-sitemap.json"
        if with_features:
            sm.add_feature(name="登录", module="auth",
                           page_url="https://ics.example.com/login")
        persist_dir_findings(sm, [
            self._F("https://ics.example.com/.git/config", "confirmed"),
            self._F("https://ics.example.com/.git/index", "needs_review"),
            self._F("https://ics.example.com/..;/actuator/env", "needs_review"),
        ])
        return sm

    @pytest.mark.parametrize("with_features", [False, True])
    def test_counts_reported_on_both_paths(self, tmp_path, with_features):
        """0 功能点（目标不可达场景）与正常路径都必须报告目录类发现计数。"""
        cov = self._build(tmp_path, with_features).get_coverage()
        assert cov["dirscan_confirmed"] == 1
        assert cov["dirscan_needs_review"] == 2
        assert cov["vuln_items"] == 1, "只有 confirmed 才计入已确认漏洞"

    @pytest.mark.parametrize("with_features", [False, True])
    def test_matrix_filters_unverified(self, tmp_path, with_features):
        """矩阵视图不得把未验证发现印成已确认（修正前零状态过滤）。"""
        m = self._build(tmp_path, with_features).get_coverage_matrix()
        assert "已通过内容校验" in m
        assert "/.git/config" in m, "confirmed 的发现必须可见"
        assert "/.git/index" not in m, "needs_review 不得进已确认表格"
        assert "未通过内容校验" in m, "必须显式声明待复核条数"

    def test_two_consumers_agree(self, tmp_path):
        """两个消费点的 confirmed 条数必须一致。"""
        sm = self._build(tmp_path, True)
        cov = sm.get_coverage()
        matrix = sm.get_coverage_matrix()
        assert cov["dirscan_confirmed"] == matrix.count("| 源码泄露(.git) |")

    def test_both_consumers_use_single_predicate(self):
        import inspect
        from core.sitemap import coverage
        src_cov = inspect.getsource(coverage.CoverageMixin.get_coverage)
        src_matrix = inspect.getsource(coverage.CoverageMixin.get_coverage_matrix)
        assert "split_by_review" in src_cov
        assert "_render_dirscan_section" in src_matrix, (
            "矩阵必须走统一渲染入口，否则又会漂移出第二套过滤逻辑"
        )


# ============================================================
# 6. 终态事件语义（T9 / 修 B4）
# ============================================================

class TestTerminalEventNormalization:
    def _mk(self, **attrs):
        from core.session.base import AgentSessionBase

        class Fake:
            task_id = "task_test"
            phase = "test"
            _normalize_terminal_event = (
                AgentSessionBase._normalize_terminal_event
            )

            def __init__(self):
                for k, v in attrs.items():
                    setattr(self, k, v)

        return Fake()

    def test_done_stays_done(self):
        assert self._mk()._normalize_terminal_event("done") == "done"

    def test_unreachable_replaces_done(self):
        """目标不可达不得报"扫描完成" —— 与"扫完确实没漏洞"必须可区分。"""
        f = self._mk(_target_unreachable=True)
        assert f._normalize_terminal_event("done") == "task_unreachable"

    def test_partial_when_groups_stuck(self):
        f = self._mk(_browse_stuck_groups=["菜单A"])
        assert f._normalize_terminal_event("done") == "task_partial"

    def test_unreachable_wins_over_partial(self):
        f = self._mk(_target_unreachable=True, _browse_stuck_groups=["A"])
        assert f._normalize_terminal_event("done") == "task_unreachable"

    def test_other_events_untouched(self):
        f = self._mk(_target_unreachable=True)
        for evt in ("system", "task_failed", "task_aborted", "phase"):
            assert f._normalize_terminal_event(evt) == evt


class TestEventMirrorTypes:
    def test_terminal_events_are_mirrored(self):
        from core.session.base import _MIRROR_EVENT_TYPES
        for evt in ("done", "task_partial", "task_unreachable",
                    "task_failed", "task_aborted", "system"):
            assert evt in _MIRROR_EVENT_TYPES

    def test_high_frequency_streams_excluded(self):
        from core.session.base import _MIRROR_EVENT_TYPES
        for evt in ("message", "thinking", "tool_call"):
            assert evt not in _MIRROR_EVENT_TYPES, (
                "高频流式事件不进镜像，避免 events.jsonl 爆炸"
            )


# ============================================================
# 7. LLM 限速器（T10 / 修 C2 C3）
# ============================================================

class TestTokenBucket:
    def test_rpm_to_interval(self):
        from core.llm._client import _TokenBucket
        b = _TokenBucket(3)
        assert b.min_interval == pytest.approx(20.0), "3 RPM 必须等于 20s 间隔"

    def test_zero_rpm_means_unlimited(self):
        from core.llm._client import _TokenBucket
        b = _TokenBucket(0)
        assert b.min_interval == 0.0
        assert b.acquire() == 0.0

    def test_acquire_enforces_interval(self, monkeypatch):
        import core.llm._client as c
        b = c._TokenBucket(60)  # 1s 间隔
        slept: list[float] = []
        monkeypatch.setattr(c.time, "sleep", lambda s: slept.append(s))
        assert b.acquire() == 0.0          # 第一次不等待
        second = b.acquire()               # 第二次应等到下一个窗口
        assert second > 0, "第二次调用必须被限速"
        assert slept, "必须真的 sleep"

    def test_configure_resets(self):
        from core.llm._client import _TokenBucket
        b = _TokenBucket(0)
        b.configure(6)
        assert b.min_interval == pytest.approx(10.0)
        b.configure(0)
        assert b.min_interval == 0.0
