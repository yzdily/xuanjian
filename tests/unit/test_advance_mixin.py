"""
AdvancePhaseMixin 单元测试

验证点：
- _handle_phase_complete：Phase 1/2 完成前的防护检查（功能点/checklist/拒绝次数保护）
- _advance_phase：阶段推进状态机（explore→analyze→test→report→done，含 fast 模式直跳）

设计说明：
- AdvancePhaseMixin 是一个 Mixin，依赖大量外部组件（Sitemap/LLM/ContextManager/parallel 模块）。
  这里构造一个 FakeSession 子类，把 _event/_phase_label/_check_operation_coverage
  等辅助方法替换为可控桩，并通过 patch 替换 core.parallel / core.business_understanding
  里的运行时导入函数，做到零网络、零真实 LLM。
- _event 在真实实现里返回 SSE 格式字符串；FakeSession._event 同时把事件 dict 记录到
  self.events，便于断言。parallel/browser 桩则产出可识别的字符串标记。
- 异步测试用 @pytest.mark.asyncio 标记（pytest-asyncio strict 模式）。
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from core.session.advance_mixin import AdvancePhaseMixin
from core.sitemap.models import (
    CheckItem,
    CheckResult,
    FeaturePoint,
    Priority,
)


# ============================================================
# 测试辅助：FakeSitemap / FakeSession
# ============================================================

class FakeSitemap:
    """轻量 Sitemap 桩，仅暴露 advance_mixin 访问的属性与方法。"""

    def __init__(self):
        self.features: dict[str, FeaturePoint] = {}
        self.apis: dict[str, object] = {}
        self.api_samples: dict[str, dict] = {}
        self.business_summary: str = ""
        self.tech_stack: str = ""
        self.business_understanding = None
        self.extra_scope: list[str] = []
        self._finish_test_calls: list[tuple] = []

    def finish_test(self, feature_id: str, reason: str = "normal") -> None:
        self._finish_test_calls.append((feature_id, reason))
        fp = self.features.get(feature_id)
        if fp is not None:
            fp.test_finished_at = time.time()
            for c in fp.checklist:
                if c.result == CheckResult.PENDING:
                    c.result = CheckResult.SKIPPED

    def flush_samples_to_files(self) -> dict:
        return {"total_files": 0, "total_size_kb": 0}

    def save(self) -> None:
        return None


class FakeSession(AdvancePhaseMixin):
    """继承 AdvancePhaseMixin 的假会话，辅助方法替换为可控桩。"""

    def __init__(self):
        self.phase: str = "explore"
        self.sitemap: FakeSitemap | None = None
        self.llm: object | None = MagicMock()
        self.current_context: MagicMock = MagicMock()
        self.current_feature_id: str | None = None
        self.user_scan_mode: str = "smart"
        self.scan_mode: str = "batch"
        self.task_id: str = "test-task-001"
        self.strategy: MagicMock = MagicMock()
        self.has_credentials: bool = False
        self._phase1_reject_count: int = 0
        self._phase2_started_at: float = 0.0
        # 事件收集（_event 产出的 dict）
        self.events: list[dict] = []
        # 可控行为桩
        self._coverage_report: dict = {"blocked": False, "warnings": [], "message": ""}
        self._escalation_result = None
        self._sync_result: dict = {
            "total_flows": 0, "new_apis": 0, "new_samples": 0, "new_features": 0,
        }
        self._new_context_calls: list[str] = []
        self._auto_infer_called: bool = False
        self._escalate_calls: list[tuple] = []

    # ---- 被覆盖的辅助方法 ----
    def _event(self, event_type: str, data, full: str = "") -> str:
        evt = {"type": event_type, "data": data}
        self.events.append(evt)
        return f"data: {json.dumps(evt, ensure_ascii=False)}\n\n"

    def _phase_label(self) -> str:
        return self.phase

    def _check_operation_coverage(self) -> dict:
        return self._coverage_report

    def _check_post_crawl_escalation(self):
        return self._escalation_result

    def _auto_infer_tech_stack(self) -> None:
        self._auto_infer_called = True
        if self.sitemap is not None:
            self.sitemap.tech_stack = "PHP"
            self.sitemap.business_summary = "auto-inferred"

    def _maybe_escalate_mode(self, reason: str, direction: str):
        self._escalate_calls.append((reason, direction))
        return None

    def _sync_all_flows_to_sitemap(self) -> dict:
        return self._sync_result

    async def _maybe_split_analyze(self):
        # 真实方法为 async generator；这里空实现，不产出事件
        if False:  # pragma: no cover
            yield

    def _new_context_for_phase(self, phase_prompt: str) -> MagicMock:
        self._new_context_calls.append(phase_prompt)
        ctx = MagicMock()
        self.current_context = ctx
        return ctx


# ---- 模块级桩函数（用于 patch 替换运行时 from X import Y 的目标）----

async def _advance_noop(self, summary: str):
    """_advance_phase 的空桩：记录调用，不产出事件。"""
    self._advance_called = True
    self._advance_summary = summary
    if False:  # pragma: no cover  # 让函数成为 async generator function
        yield


async def _parallel_test_noop(session):
    """run_parallel_test 的空桩：产出一个字符串标记。"""
    yield "PARALLEL_TEST_DONE"


async def _browser_feature_test_noop(session):
    """start_browser_feature_test 的空桩。"""
    yield "BROWSER_FEATURE_TEST_DONE"


async def _enter_report_phase_noop(session):
    """_enter_report_phase 的空桩。"""
    yield "ENTER_REPORT_DONE"


async def _fake_analyze_business_ok(**kwargs):
    """analyze_business 成功返回桩。"""
    return {
        "status": "ok",
        "understanding": {
            "domain": {"label": "电商系统"},
            "roles": [{"name": "admin"}, {"name": "user"}],
            "promises": ["订单不可篡改"],
            "attack_hypotheses": [{"hypothesis": "越权下单"}],
        },
        "summary": "这是一个电商系统",
    }


# ============================================================
# 通用收集工具
# ============================================================

async def _collect(async_gen) -> list:
    """把 async generator 的产出收集成列表（元素为 _event 字符串或桩标记字符串）。"""
    out: list = []
    async for item in async_gen:
        out.append(item)
    return out


def _event_data_contains(session_events: list[dict], keyword: str) -> bool:
    """检查 session.events 里是否有某条事件的 data 含 keyword。"""
    return any(keyword in str(e.get("data", "")) for e in session_events)


def _has_event_type(session_events: list[dict], event_type: str) -> bool:
    return any(e.get("type") == event_type for e in session_events)


def _make_feature(
    fid: str = "fp-1",
    name: str = "用户登录",
    description: str = "用户登录功能",
    deferred: bool = False,
    checklist_results: list[CheckResult] | None = None,
    related_apis: list[str] | None = None,
) -> FeaturePoint:
    fp = FeaturePoint(
        id=fid,
        name=name,
        description=description,
        deferred=deferred,
        related_apis=list(related_apis or []),
        priority=Priority.HIGH,
    )
    for idx, res in enumerate(checklist_results or []):
        fp.checklist.append(CheckItem(vuln_type=f"VULN_{idx}", result=res))
    return fp


def _tool_call(tid: str = "tc-1") -> dict:
    return {"id": tid, "name": "phase_complete", "arguments": {}}


# ============================================================
# _handle_phase_complete 测试
# ============================================================

class TestHandlePhaseComplete:
    """phase_complete 工具调用的防护检查。"""

    @pytest.mark.asyncio
    async def test_analyze_no_active_features_rejected(self):
        """Phase analyze：无活跃功能点（全部 deferred）→ 拒绝，不推进。"""
        session = FakeSession()
        session.phase = "analyze"
        sitemap = FakeSitemap()
        # 只有一个 deferred 功能点 → active_features 为空
        sitemap.features["fp-1"] = _make_feature(deferred=True, checklist_results=[CheckResult.PENDING])
        session.sitemap = sitemap
        session._advance_called = False

        with patch.object(FakeSession, "_advance_phase", _advance_noop):
            await _collect(session._handle_phase_complete(
                _tool_call(), {"summary": "分析完成"}
            ))

        # 产出拒绝事件，且 _advance_phase 未被调用
        assert _event_data_contains(session.events, "拒绝"), \
            f"应包含拒绝事件，实际: {session.events}"
        assert not getattr(session, "_advance_called", False), "无功能点时不应推进阶段"
        # add_tool_result 应被调用，记录拒绝原因
        session.current_context.add_tool_result.assert_called_once()
        tool_msg = session.current_context.add_tool_result.call_args[0][1]
        assert "功能点" in tool_msg

    @pytest.mark.asyncio
    async def test_analyze_with_features_and_good_coverage_passes(self):
        """Phase analyze：有活跃功能点、覆盖良好、已设业务类型 → 通过并推进。"""
        session = FakeSession()
        session.phase = "analyze"
        sitemap = FakeSitemap()
        sitemap.features["fp-1"] = _make_feature(
            deferred=False,
            related_apis=["POST /api/login"],
            checklist_results=[CheckResult.PENDING],
        )
        sitemap.business_summary = "电商系统"  # 已设业务类型，跳过自动推断
        session.sitemap = sitemap
        session._coverage_report = {"blocked": False, "warnings": [], "message": "good"}
        session._advance_called = False

        with patch.object(FakeSession, "_advance_phase", _advance_noop):
            await _collect(session._handle_phase_complete(
                _tool_call(), {"summary": "分析完成"}
            ))

        assert getattr(session, "_advance_called", False), "通过时应推进阶段"
        # 应产出 phase_complete 事件
        assert _has_event_type(session.events, "phase_complete"), \
            f"应包含 phase_complete 事件，实际: {session.events}"
        # 未触发自动推断
        assert not session._auto_infer_called

    @pytest.mark.asyncio
    async def test_analyze_coverage_blocked_rejected_increments_count(self):
        """Phase analyze：操作覆盖 blocked → 拒绝，reject_count 自增。"""
        session = FakeSession()
        session.phase = "analyze"
        sitemap = FakeSitemap()
        sitemap.features["fp-1"] = _make_feature(
            deferred=False, related_apis=["GET /api/x"], checklist_results=[CheckResult.PENDING]
        )
        sitemap.business_summary = "biz"
        session.sitemap = sitemap
        session._coverage_report = {
            "blocked": True, "warnings": [], "message": "⛔ 操作覆盖不达标",
        }
        session._phase1_reject_count = 0
        session._advance_called = False

        with patch.object(FakeSession, "_advance_phase", _advance_noop):
            await _collect(session._handle_phase_complete(
                _tool_call(), {"summary": "分析完成"}
            ))

        # 拒绝且计数 +1
        assert session._phase1_reject_count == 1
        assert not getattr(session, "_advance_called", False), "blocked 时不应推进"
        assert _event_data_contains(session.events, "操作覆盖不达标")
        session.current_context.add_tool_result.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_coverage_blocked_force_pass_after_3_rejects(self):
        """Phase analyze：拒绝次数已 3 次，第 4 次强制放行（带警告）并推进。"""
        session = FakeSession()
        session.phase = "analyze"
        sitemap = FakeSitemap()
        sitemap.features["fp-1"] = _make_feature(
            deferred=False, related_apis=["GET /api/x"], checklist_results=[CheckResult.PENDING]
        )
        sitemap.business_summary = "biz"
        session.sitemap = sitemap
        session._coverage_report = {
            "blocked": True, "warnings": [], "message": "⛔ 操作覆盖不达标",
        }
        # 已拒绝 3 次，本次为第 4 次 → 强制放行
        session._phase1_reject_count = 3
        session._advance_called = False

        with patch.object(FakeSession, "_advance_phase", _advance_noop):
            await _collect(session._handle_phase_complete(
                _tool_call(), {"summary": "分析完成"}
            ))

        assert session._phase1_reject_count == 4
        # 应有强制放行警告
        assert _event_data_contains(session.events, "强制放行"), \
            f"应包含强制放行警告，实际: {session.events}"
        # 强制放行后继续推进
        assert getattr(session, "_advance_called", False), "强制放行后应推进阶段"
        # 同时仍产出 phase_complete
        assert _has_event_type(session.events, "phase_complete")

    @pytest.mark.asyncio
    async def test_analyze_soft_warning_passes_with_warning_event(self):
        """Phase analyze：覆盖未 blocked 但有 warnings → 放行并产出警告事件。"""
        session = FakeSession()
        session.phase = "analyze"
        sitemap = FakeSitemap()
        sitemap.features["fp-1"] = _make_feature(
            deferred=False, related_apis=["GET /api/x"], checklist_results=[CheckResult.PENDING]
        )
        sitemap.business_summary = "biz"
        session.sitemap = sitemap
        session._coverage_report = {
            "blocked": False,
            "warnings": ["写操作占比低"],
            "message": "⚠️ 覆盖质量一般",
        }
        session._advance_called = False

        with patch.object(FakeSession, "_advance_phase", _advance_noop):
            await _collect(session._handle_phase_complete(
                _tool_call(), {"summary": "分析完成"}
            ))

        # 警告事件被产出（_check_operation_coverage 返回的 message 直接作为 system 事件）
        assert _event_data_contains(session.events, "覆盖质量一般")
        # 仍然放行推进
        assert getattr(session, "_advance_called", False)

    @pytest.mark.asyncio
    async def test_test_phase_all_pending_checklist_rejected(self):
        """Phase test：当前功能点 checklist 全 PENDING → 拒绝。"""
        session = FakeSession()
        session.phase = "test"
        sitemap = FakeSitemap()
        fp = _make_feature(
            fid="fp-current",
            checklist_results=[CheckResult.PENDING, CheckResult.PENDING],
        )
        sitemap.features["fp-current"] = fp
        session.sitemap = sitemap
        session.current_feature_id = "fp-current"
        session._advance_called = False

        with patch.object(FakeSession, "_advance_phase", _advance_noop):
            await _collect(session._handle_phase_complete(
                _tool_call(), {"summary": "测试完成"}
            ))

        assert not getattr(session, "_advance_called", False), "全 PENDING 时不应推进"
        assert _event_data_contains(session.events, "拒绝"), \
            f"应包含拒绝事件，实际: {session.events}"
        tool_msg = session.current_context.add_tool_result.call_args[0][1]
        assert "checklist" in tool_msg

    @pytest.mark.asyncio
    async def test_test_phase_with_completed_check_passes(self):
        """Phase test：checklist 有非 PENDING 项 → 通过并推进。"""
        session = FakeSession()
        session.phase = "test"
        sitemap = FakeSitemap()
        fp = _make_feature(
            fid="fp-current",
            checklist_results=[CheckResult.NOT_VULN, CheckResult.PENDING],
        )
        sitemap.features["fp-current"] = fp
        session.sitemap = sitemap
        session.current_feature_id = "fp-current"
        session._advance_called = False

        with patch.object(FakeSession, "_advance_phase", _advance_noop):
            await _collect(session._handle_phase_complete(
                _tool_call(), {"summary": "测试完成"}
            ))

        assert getattr(session, "_advance_called", False), "有打勾时应推进"
        assert _has_event_type(session.events, "phase_complete")

    @pytest.mark.asyncio
    async def test_analyze_missing_business_summary_triggers_auto_infer(self):
        """Phase analyze：未设 business_summary → 触发 _auto_infer_tech_stack 并产出警告。"""
        session = FakeSession()
        session.phase = "analyze"
        sitemap = FakeSitemap()
        sitemap.features["fp-1"] = _make_feature(
            deferred=False, related_apis=["GET /api/x"], checklist_results=[CheckResult.PENDING]
        )
        # 故意不设 business_summary
        session.sitemap = sitemap
        session._coverage_report = {"blocked": False, "warnings": [], "message": "good"}
        session._advance_called = False

        with patch.object(FakeSession, "_advance_phase", _advance_noop):
            await _collect(session._handle_phase_complete(
                _tool_call(), {"summary": "分析完成"}
            ))

        assert session._auto_infer_called, "未设业务类型应触发自动推断"
        assert _event_data_contains(session.events, "自动推断技术栈"), \
            f"应包含自动推断警告，实际: {session.events}"
        assert getattr(session, "_advance_called", False)


# ============================================================
# _advance_phase 测试
# ============================================================

class TestAdvancePhase:
    """阶段推进状态机。"""

    @pytest.mark.asyncio
    async def test_explore_smart_mode_advances_to_analyze(self):
        """explore + smart + 有 LLM → 推进到 analyze，注入 Phase 1 上下文。"""
        session = FakeSession()
        session.phase = "explore"
        session.user_scan_mode = "smart"
        session.llm = MagicMock()  # 有 LLM
        session._escalation_result = None

        with patch("core.parallel.run_parallel_test", _parallel_test_noop):
            await _collect(session._advance_phase("探索完成"))

        assert session.phase == "analyze"
        # 应创建新 context 并注入 Phase 1 prompt
        assert len(session._new_context_calls) == 1
        assert _event_data_contains(session.events, "功能分析")
        # current_context.add_user 应被调用一次（Phase 1 引导）
        session.current_context.add_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_explore_fast_mode_skips_to_test(self):
        """explore + fast 模式 → 跳过 Phase 1，直接进 Phase 2。"""
        session = FakeSession()
        session.phase = "explore"
        session.user_scan_mode = "fast"
        session.llm = MagicMock()

        with patch("core.parallel.run_parallel_test", _parallel_test_noop):
            await _collect(session._advance_phase("探索完成"))

        assert session.phase == "test"
        # 应产出 FAST 模式跳过提示
        assert _event_data_contains(session.events, "FAST 模式跳过"), \
            f"应包含 FAST 模式提示，实际: {session.events}"
        # 不应进入 Phase 1 分析（未创建 analyze 上下文）
        assert len(session._new_context_calls) == 0

    @pytest.mark.asyncio
    async def test_explore_no_llm_skips_to_test(self):
        """explore + 无 LLM → 走 fast 分支直接进 Phase 2。"""
        session = FakeSession()
        session.phase = "explore"
        session.user_scan_mode = "smart"
        session.llm = None  # 无 LLM

        with patch("core.parallel.run_parallel_test", _parallel_test_noop):
            await _collect(session._advance_phase("探索完成"))

        assert session.phase == "test"
        assert _event_data_contains(session.events, "FAST")

    @pytest.mark.asyncio
    async def test_analyze_advances_to_test_with_business_understanding(self):
        """analyze → test：执行 Phase 1.5 业务理解后进入 Phase 2（batch 模式）。"""
        session = FakeSession()
        session.phase = "analyze"
        session.user_scan_mode = "smart"
        session.llm = MagicMock()  # 有 LLM 才会跑业务理解
        sitemap = FakeSitemap()
        sitemap.features["fp-1"] = _make_feature(
            deferred=False, related_apis=["POST /api/login"], checklist_results=[CheckResult.PENDING]
        )
        sitemap.business_summary = "电商系统"
        session.sitemap = sitemap
        session.scan_mode = "batch"

        with patch("core.business_understanding.analyze_business", _fake_analyze_business_ok), \
             patch("core.parallel.run_parallel_test", _parallel_test_noop):
            await _collect(session._advance_phase("分析完成"))

        assert session.phase == "test"
        # 应记录 Phase 2 起点时间戳
        assert session._phase2_started_at > 0
        # 业务理解结果应写入 sitemap
        assert sitemap.business_understanding is not None
        assert sitemap.business_understanding.get("status") == "ok"
        # 应有 Phase 1.5 业务理解事件 + Phase 2 并行测试事件
        assert _event_data_contains(session.events, "业务理解"), \
            f"应包含业务理解事件，实际: {session.events}"
        assert _event_data_contains(session.events, "并行测试"), \
            f"应包含 Phase 2 事件，实际: {session.events}"

    @pytest.mark.asyncio
    async def test_analyze_to_test_business_understanding_degraded_on_failure(self):
        """analyze → test：业务理解失败时降级，主链路继续进入 Phase 2。"""
        async def _fake_bu_fail(**kwargs):
            return {"status": "error", "error": "LLM 不可用"}

        session = FakeSession()
        session.phase = "analyze"
        session.user_scan_mode = "smart"
        session.llm = MagicMock()
        sitemap = FakeSitemap()
        sitemap.features["fp-1"] = _make_feature(
            deferred=False, related_apis=["GET /api/x"], checklist_results=[CheckResult.PENDING]
        )
        sitemap.business_summary = "biz"
        session.sitemap = sitemap
        session.scan_mode = "batch"

        with patch("core.business_understanding.analyze_business", _fake_bu_fail), \
             patch("core.parallel.run_parallel_test", _parallel_test_noop):
            await _collect(session._advance_phase("分析完成"))

        # 业务理解失败 → 仍推进到 Phase 2（兜底）
        assert session.phase == "test"
        assert _event_data_contains(session.events, "业务理解失败"), \
            f"应包含业务理解失败事件，实际: {session.events}"
        # 失败应触发降级判定
        assert any(reason == "business_understanding_failed" for reason, _ in session._escalate_calls)

    @pytest.mark.asyncio
    async def test_test_phase_advances_to_browser_feature_test(self):
        """test → report：调用 finish_test 并启动浏览器功能测试。"""
        session = FakeSession()
        session.phase = "test"
        sitemap = FakeSitemap()
        fp = _make_feature(fid="fp-current", checklist_results=[CheckResult.NOT_VULN])
        sitemap.features["fp-current"] = fp
        session.sitemap = sitemap
        session.current_feature_id = "fp-current"

        with patch("core.parallel.start_browser_feature_test", _browser_feature_test_noop):
            yielded = await _collect(session._advance_phase("测试完成"))

        # 应调用 sitemap.finish_test
        assert sitemap._finish_test_calls, "应调用 finish_test"
        assert sitemap._finish_test_calls[0][0] == "fp-current"
        # 浏览器功能测试桩标记被透传
        assert "BROWSER_FEATURE_TEST_DONE" in yielded, \
            f"应透传浏览器测试事件，实际: {yielded}"

    @pytest.mark.asyncio
    async def test_report_phase_emits_done(self):
        """report → done：产出 done 事件。"""
        session = FakeSession()
        session.phase = "report"

        await _collect(session._advance_phase("报告完成"))

        assert _has_event_type(session.events, "done"), \
            f"report 阶段应产出 done 事件，实际: {session.events}"
        assert _event_data_contains(session.events, "报告已生成")
