"""回归钉（regression pins）—— 为此前已修复的缺陷固化防回退测试。

每个测试类对应一个曾经踩过的坑，用最小、确定性的用例锁定其正确行为：
- 零网络、零 LLM、零文件副作用（仅构造内存对象 / mock）。
- 难以实例化的真实对象用 MagicMock / 内存替身替代。

覆盖四枚回归钉：
1. ``AdvancePhaseMixin._advance_phase`` —— Phase 状态机推进（explore→analyze→test→report）
2. ``ScanStrategyConfig.crawl_timeout`` —— 适配器字段透传（曾缺失导致 AttributeError）
3. ``orchestrator._effective_max_workers`` —— 并发上限选择逻辑
4. ``form_api_bridge.register_form_apis`` —— 爬虫表单→可测 API 的完整链路

注：源码先行阅读后再写测试。实际 API 与任务描述的个别措辞（如 "summary dict"）
有出入时，一律以源码真实签名为准（见各处注释）。
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# 让 tests/regression/ 内可直接 import core / web / mcp_servers
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.form_api_bridge import register_form_apis  # noqa: E402
from core.scan_strategies import (  # noqa: E402
    ScanConfig,
    ScanMode,
    ScanStrategyConfig,
    get_scan_strategy,
)
from core.session.advance_mixin import AdvancePhaseMixin  # noqa: E402
from core.sitemap import Sitemap  # noqa: E402


# ============================================================
# 共用工具
# ============================================================
def _drain(async_gen) -> list:
    """同步驱动一个 async generator，收集所有 yield 的事件。

    _advance_phase 是 async generator；用 asyncio.run 在同步测试里消费它，
    与项目 conftest.run_async 保持同一套路。
    """
    async def _run():
        out: list = []
        async for evt in async_gen:
            out.append(evt)
        return out
    return asyncio.run(_run())


# ---- 给 _advance_phase 用的并行/浏览器桩（避免真实编排）----
async def _stub_parallel_test(session):
    yield {"type": "stub", "source": "run_parallel_test"}


async def _stub_browser_feature_test(session):
    yield {"type": "stub", "source": "start_browser_feature_test"}


async def _stub_enter_report_phase(session):
    yield {"type": "stub", "source": "_enter_report_phase"}


# ============================================================
# 钉 1：_advance_phase 状态机
# ============================================================
class _StubContext:
    """current_context 替身：记录 add_user / add_tool_result 调用。"""

    def __init__(self) -> None:
        self.users: list[str] = []
        self.tool_results: list[tuple] = []

    def add_user(self, msg: str) -> None:
        self.users.append(msg)

    def add_tool_result(self, tc_id: Any, result: str) -> None:
        self.tool_results.append((tc_id, result))


class _MockAdvanceSession(AdvancePhaseMixin):
    """最小 session 替身，仅满足 _advance_phase 读取的依赖。

    把重活（run_parallel_test / 业务理解 / sitemap 落库）全部短路，
    只让 Phase 状态机本身跑起来，从而钉死 phase 转移契约。
    """

    def __init__(
        self,
        *,
        phase: str = "explore",
        llm: Any = None,
        user_scan_mode: str = "smart",
        scan_mode: str = "batch",
        sitemap: Any = None,
        current_feature_id: Any = None,
        set_user_scan_mode: bool = True,
    ) -> None:
        self.phase = phase
        self.llm = llm
        if set_user_scan_mode:
            self.user_scan_mode = user_scan_mode
        # 不设 user_scan_mode → 验证 getattr 兜底 'smart'
        self.scan_mode = scan_mode
        self.sitemap = sitemap
        self.current_feature_id = current_feature_id
        self.current_context = _StubContext()
        self.events: list[dict] = []
        self._phase2_started_at: float | None = None
        self.strategy = MagicMock()

    # ---- _advance_phase 读取的桩 ----
    def _event(self, etype: str, message: str = "") -> dict:
        evt = {"type": etype, "message": message}
        self.events.append(evt)
        return evt

    def _new_context_for_phase(self, prompt: Any):
        self.current_context = _StubContext()
        return self.current_context

    def _check_post_crawl_escalation(self):
        return None  # 不升级


@pytest.mark.regression
class TestAdvancePhase:
    """回归钉：_advance_phase 的 phase 转移状态机。

    历史风险：fast / 无 LLM 路径下推进错误，或依赖未就绪即抛异常。
    这里用 _MockAdvanceSession 钉死各 phase 的转移契约与边界。
    """

    @patch("core.parallel.run_parallel_test", _stub_parallel_test)
    def test_explore_to_test_without_llm(self):
        """llm=None → explore 直接跳到 test（FAST 兜底路径），并触发 run_parallel_test。"""
        sess = _MockAdvanceSession(phase="explore", llm=None)
        events = _drain(sess._advance_phase("探索完成"))
        assert sess.phase == "test"
        assert any(e.get("source") == "run_parallel_test" for e in events)

    @patch("core.parallel.run_parallel_test", _stub_parallel_test)
    def test_explore_fast_mode_short_circuits_to_test(self):
        """user_scan_mode='fast'（即便有 LLM）也跳过 Phase 1 直接进 test。"""
        sess = _MockAdvanceSession(phase="explore", llm=MagicMock(), user_scan_mode="fast")
        _drain(sess._advance_phase("done"))
        assert sess.phase == "test"

    def test_explore_to_analyze_with_llm(self):
        """有 LLM + 非 fast → explore 推进到 analyze，并下发 Phase 1 上下文。"""
        sess = _MockAdvanceSession(phase="explore", llm=MagicMock(), user_scan_mode="smart")
        events = _drain(sess._advance_phase("探索完成"))
        assert sess.phase == "analyze"
        # _new_context_for_phase 被调用，且向新上下文下发了 user 消息
        assert sess.current_context.users
        # 产生了一条 phase 事件
        assert any(e.get("type") == "phase" for e in events)

    @patch("core.parallel.run_parallel_test", _stub_parallel_test)
    def test_analyze_to_test_batch_mode(self):
        """analyze → test：sitemap 为空时跳过业务理解/流量同步，进入 Phase 2 并打时间戳。"""
        sess = _MockAdvanceSession(
            phase="analyze", llm=MagicMock(), sitemap=None, scan_mode="batch"
        )
        _drain(sess._advance_phase("分析完成"))
        assert sess.phase == "test"
        assert sess._phase2_started_at is not None

    @patch("core.parallel.run_parallel_test", _stub_parallel_test)
    def test_analyze_realtime_mode_enters_report(self):
        """analyze + scan_mode='realtime' → 走 strategy.on_phase1_complete + _enter_report_phase。"""
        sess = _MockAdvanceSession(
            phase="analyze", llm=MagicMock(), sitemap=None, scan_mode="realtime"
        )

        # strategy.on_phase1_complete 是 async generator
        async def _on_phase1_complete(s, summary):
            yield {"type": "stub", "source": "on_phase1_complete"}

        sess.strategy.on_phase1_complete = _on_phase1_complete

        with patch("core.parallel._enter_report_phase", _stub_enter_report_phase):
            events = _drain(sess._advance_phase("分析完成"))
        assert sess.phase == "test"
        assert any(e.get("source") == "on_phase1_complete" for e in events)
        assert any(e.get("source") == "_enter_report_phase" for e in events)

    @patch("core.parallel.start_browser_feature_test", _stub_browser_feature_test)
    def test_test_phase_invokes_browser_feature_test(self):
        """test → start_browser_feature_test（主 Agent 浏览器项）。"""
        sess = _MockAdvanceSession(phase="test", sitemap=None, current_feature_id=None)
        events = _drain(sess._advance_phase("测试完成"))
        assert any(e.get("source") == "start_browser_feature_test" for e in events)

    def test_report_phase_emits_done(self):
        """report → 仅 yield 一条 done 事件。"""
        sess = _MockAdvanceSession(phase="report")
        events = _drain(sess._advance_phase("报告完成"))
        assert any(e.get("type") == "done" for e in events)

    def test_empty_summary_string_is_accepted(self):
        """空字符串 summary 不应崩溃（log.info 做 summary[:80]，空串合法）。"""
        sess = _MockAdvanceSession(phase="report")
        events = _drain(sess._advance_phase(""))
        assert any(e.get("type") == "done" for e in events)

    def test_none_summary_raises_typeerror(self):
        """None summary 必抛 TypeError —— 钉死 summary 必须是字符串的契约。

        _advance_phase 入口处 ``log.info(..., summary[:80])`` 会对 None 取下标，
        表征当前行为：summary 不可为 None。若将来改成容错，此测试会失败，
        提示同步更新契约文档。
        """
        sess = _MockAdvanceSession(phase="report")
        with pytest.raises(TypeError):
            _drain(sess._advance_phase(None))  # type: ignore[arg-type]

    def test_missing_user_scan_mode_defaults_to_smart(self):
        """session 未设置 user_scan_mode 时，getattr 兜底 'smart'，走 LLM 分析路径。

        对应任务“missing fields”：可选属性缺失时应被 getattr 默认值兜住，
        而非 AttributeError 崩溃。
        """
        sess = _MockAdvanceSession(
            phase="explore", llm=MagicMock(), set_user_scan_mode=False
        )
        assert not hasattr(sess, "user_scan_mode")
        _drain(sess._advance_phase("探索完成"))
        # smart ≠ fast 且有 LLM → 推进到 analyze（而非直接 test）
        assert sess.phase == "analyze"


# ============================================================
# 钉 2：ScanStrategyConfig.crawl_timeout
# ============================================================
def _make_ssc(**overrides) -> ScanStrategyConfig:
    """构造 ScanStrategyConfig 的便捷工厂（填齐所有必填字段）。"""
    defaults = dict(
        mode=ScanMode.STANDARD,
        llm_max_workers=3,
        enable_fast_scanner=True,
        skip_meta_analysis=False,
        skip_business_understanding=False,
        crawl_max_pages=60,
        crawl_fast_mode=False,
        fast_scan_workers=15,
        total_timeout=3600,
    )
    defaults.update(overrides)
    return ScanStrategyConfig(**defaults)


@pytest.mark.regression
class TestScanStrategyConfigCrawlTimeout:
    """回归钉：ScanStrategyConfig.crawl_timeout 字段透传。

    历史缺陷：crawl_timeout 此前仅存在于 ScanConfig，未透传到 orchestrator 适配器，
    导致 chat_loop 在 fast 模式读取 ``_crawl_cfg.crawl_timeout`` 时抛
    ``'ScanStrategyConfig' object has no attribute 'crawl_timeout'``。
    """

    def test_field_has_default_300(self):
        cfg = _make_ssc()
        assert hasattr(cfg, "crawl_timeout")
        assert cfg.crawl_timeout == 300

    def test_customizable_via_constructor(self):
        cfg = _make_ssc(crawl_timeout=999)
        assert cfg.crawl_timeout == 999

    def test_from_scan_config_passes_crawl_timeout(self):
        sc = ScanConfig(mode=ScanMode.DEEP)
        sc.crawl_timeout = 4242
        ssc = ScanStrategyConfig.from_scan_config(sc)
        assert ssc.crawl_timeout == 4242

    def test_fast_mode_crawl_timeout_is_180(self):
        assert get_scan_strategy("fast").crawl_timeout == 180

    def test_standard_mode_crawl_timeout_is_180(self):
        assert get_scan_strategy("standard").crawl_timeout == 180

    def test_deep_mode_crawl_timeout_is_300(self):
        assert get_scan_strategy("deep").crawl_timeout == 300

    def test_smart_mode_crawl_timeout_is_300(self):
        assert get_scan_strategy("smart").crawl_timeout == 300

    def test_no_attribute_error_on_any_mode(self):
        """直接钉死历史崩溃点：所有深度模式访问 crawl_timeout 都不再抛 AttributeError。"""
        for mode in ("fast", "standard", "deep", "smart"):
            ssc = get_scan_strategy(mode)
            assert ssc.crawl_timeout > 0  # 访问不抛异常即通过

    def test_round_trip_preserves_value(self):
        """ScanConfig → ScanStrategyConfig 透传不丢值（不同档位的真实值）。"""
        for mode, expected in (
            (ScanMode.FAST, 180),
            (ScanMode.STANDARD, 180),
            (ScanMode.DEEP, 300),
        ):
            sc = ScanConfig.from_mode(mode)
            ssc = ScanStrategyConfig.from_scan_config(sc)
            assert ssc.crawl_timeout == expected


# ============================================================
# 钉 3：_effective_max_workers
# ============================================================
def _compute_effective_max_workers(scan_cfg) -> int:
    """忠实复刻 orchestrator.run_parallel_test 内的并发上限选择表达式：

        _effective_max_workers = LLM_SCAN_MAX_WORKERS if scan_cfg.llm_max_workers > 0 else MAX_WORKERS

    说明：源码里 _effective_max_workers 是 run_parallel_test 内的局部变量（非方法/属性），
    无法直接调用；这里把同一表达式抽成纯函数，在不启动整个 async 编排的前提下钉死不变量。
    """
    from core.config import LLM_SCAN_MAX_WORKERS, MAX_WORKERS
    return LLM_SCAN_MAX_WORKERS if scan_cfg.llm_max_workers > 0 else MAX_WORKERS


@pytest.mark.regression
class TestEffectiveMaxWorkers:
    """回归钉：_effective_max_workers 并发上限选择。

    逻辑：LLM 启用（llm_max_workers>0）→ 受 LLM 并发上限约束；
         否则（fast / 0 / 负数）→ 走 MAX_WORKERS，不崩溃。
    注意：返回值是来自常量的“上限挡位”，并非直接回传 llm_max_workers 本身。
    """

    def test_constants_positive(self):
        from core.config import LLM_SCAN_MAX_WORKERS, MAX_WORKERS
        assert LLM_SCAN_MAX_WORKERS > 0
        assert MAX_WORKERS > 0

    def test_fast_mode_uses_max_workers(self):
        from core.config import MAX_WORKERS
        assert _compute_effective_max_workers(get_scan_strategy("fast")) == MAX_WORKERS

    def test_standard_mode_uses_llm_cap(self):
        from core.config import LLM_SCAN_MAX_WORKERS
        assert _compute_effective_max_workers(get_scan_strategy("standard")) == LLM_SCAN_MAX_WORKERS

    def test_deep_mode_uses_llm_cap(self):
        from core.config import LLM_SCAN_MAX_WORKERS
        assert _compute_effective_max_workers(get_scan_strategy("deep")) == LLM_SCAN_MAX_WORKERS

    def test_smart_mode_uses_llm_cap(self):
        from core.config import LLM_SCAN_MAX_WORKERS
        assert _compute_effective_max_workers(get_scan_strategy("smart")) == LLM_SCAN_MAX_WORKERS

    def test_explicit_llm_max_workers_zero_falls_back(self):
        from core.config import MAX_WORKERS
        cfg = _make_ssc(llm_max_workers=0)
        assert _compute_effective_max_workers(cfg) == MAX_WORKERS

    def test_explicit_llm_max_workers_one_uses_llm_cap(self):
        """llm_max_workers=1（>0）即启用 LLM 路径 → 取 LLM 并发上限（常量值），而非 1。"""
        from core.config import LLM_SCAN_MAX_WORKERS
        cfg = _make_ssc(llm_max_workers=1)
        assert _compute_effective_max_workers(cfg) == LLM_SCAN_MAX_WORKERS

    def test_high_llm_max_workers_respects_cap(self):
        """llm_max_workers 远超常量上限时，effective 仍受常量上限约束（不无限放大）。"""
        from core.config import LLM_SCAN_MAX_WORKERS
        cfg = _make_ssc(llm_max_workers=9999)
        eff = _compute_effective_max_workers(cfg)
        assert eff == LLM_SCAN_MAX_WORKERS
        assert eff <= LLM_SCAN_MAX_WORKERS  # 不超过 LLM 上限

    def test_negative_llm_max_workers_handled_gracefully(self):
        """负数 llm_max_workers：`> 0` 为 False → 落入 else 分支取 MAX_WORKERS，不崩溃。"""
        from core.config import MAX_WORKERS
        cfg = _make_ssc(llm_max_workers=-5)
        assert _compute_effective_max_workers(cfg) == MAX_WORKERS

    def test_effective_always_positive_and_bounded(self):
        from core.config import LLM_SCAN_MAX_WORKERS, MAX_WORKERS
        upper = max(LLM_SCAN_MAX_WORKERS, MAX_WORKERS)
        for mode in ("fast", "standard", "deep", "smart"):
            eff = _compute_effective_max_workers(get_scan_strategy(mode))
            assert 0 < eff <= upper

    def test_effective_is_one_of_the_two_caps(self):
        """effective 只能取自 {MAX_WORKERS, LLM_SCAN_MAX_WORKERS} 两个挡位。"""
        from core.config import LLM_SCAN_MAX_WORKERS, MAX_WORKERS
        allowed = {MAX_WORKERS, LLM_SCAN_MAX_WORKERS}
        for mode in ("fast", "standard", "deep", "smart"):
            assert _compute_effective_max_workers(get_scan_strategy(mode)) in allowed


# ============================================================
# 钉 4：register_form_apis 完整链路
# ============================================================
def _form(
    action: str = "",
    method: str = "POST",
    fields: list | None = None,
    page: str = "",
    submitted: bool = False,
    requests_triggered: int = 0,
) -> dict:
    return {
        "action": action,
        "method": method,
        "fields": fields if fields is not None else ["username", "password"],
        "page": page,
        "submitted": submitted,
        "requests_triggered": requests_triggered,
    }


def _crawl_result(forms: list, api_endpoints: list | None = None) -> dict:
    return {"forms": forms, "api_endpoints": api_endpoints or []}


@pytest.mark.regression
class TestFormBridgeChain:
    """回归钉：register_form_apis 端到端链路。

    链路：crawl_result.forms → register_form_apis → sitemap.apis（真实 APIEndpoint）
         → sitemap.api_samples（请求样本，post_data 由 fields 拼接）。

    用真实 Sitemap（构造零 I/O）验证集成，确保“发现但未提交”的表单 action
    真正落入可测 API 清单（sitemap.apis），而非仅停留在爬虫结果里。
    """

    TARGET = "https://example.com"

    def test_chain_login_form_registered_as_api(self):
        """POST 登录表单 → 注册为 API + 写入请求样本（discovered_by=form_inference）。"""
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result([_form(
            action="/login", method="POST", fields=["username", "password"],
            page=self.TARGET + "/login",
        )])
        added = register_form_apis(sm, cr, target_url=self.TARGET + "/")

        # 链路终点 1：返回值
        assert added == ["POST https://example.com/login"]
        # 链路终点 2：sitemap.apis 出现真实 APIEndpoint
        key = "POST https://example.com/login"
        assert key in sm.apis
        ep = sm.apis[key]
        assert ep.method == "POST"
        assert ep.url == "https://example.com/login"
        assert ep.discovered_by == "form_inference"
        # 链路终点 3：请求样本已写入（post_data 由 fields 拼接）
        assert sm.api_samples

    def test_chain_get_form_uses_get_method(self):
        """GET 表单 → 注册为 GET API。"""
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result([_form(
            action="/search", method="GET", fields=["q"],
            page=self.TARGET + "/search",
        )])
        added = register_form_apis(sm, cr, target_url=self.TARGET + "/")
        assert added == ["GET https://example.com/search"]
        assert "GET https://example.com/search" in sm.apis

    def test_chain_post_and_get_coexist(self):
        """POST 与 GET 表单并存，互不覆盖。"""
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result([
            _form(action="/login", method="POST", fields=["u"], page=self.TARGET + "/login"),
            _form(action="/search", method="GET", fields=["q"], page=self.TARGET + "/search"),
        ])
        added = register_form_apis(sm, cr, target_url=self.TARGET + "/")
        assert set(added) == {
            "POST https://example.com/login",
            "GET https://example.com/search",
        }
        assert len(sm.apis) == 2

    def test_chain_relative_action_resolved(self):
        """相对 action 经 urljoin 解析为绝对 URL 后注册。"""
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result([_form(
            action="auth/signin", method="POST", fields=["u"],
            page=self.TARGET + "/login",
        )])
        added = register_form_apis(sm, cr, target_url=self.TARGET + "/")
        assert added == ["POST https://example.com/auth/signin"]
        assert "POST https://example.com/auth/signin" in sm.apis

    def test_chain_empty_forms_no_registration(self):
        sm = Sitemap(target=self.TARGET)
        added = register_form_apis(sm, _crawl_result([]), target_url=self.TARGET + "/")
        assert added == []
        assert sm.apis == {}

    def test_chain_missing_forms_key_no_registration(self):
        """crawl_result 无 forms 键 → 空列表兜底，不崩溃。"""
        sm = Sitemap(target=self.TARGET)
        added = register_form_apis(sm, {}, target_url=self.TARGET + "/")
        assert added == []
        assert sm.apis == {}

    def test_chain_form_without_action_skipped(self):
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result([_form(action="", fields=["u"], page=self.TARGET + "/login")])
        added = register_form_apis(sm, cr, target_url=self.TARGET + "/")
        assert added == []
        assert sm.apis == {}

    def test_chain_non_business_action_skipped(self):
        """javascript: 等非业务 action 不注册。"""
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result([_form(
            action="javascript:void(0)", fields=["u"], page=self.TARGET + "/login",
        )])
        added = register_form_apis(sm, cr, target_url=self.TARGET + "/")
        assert added == []
        assert sm.apis == {}

    def test_chain_submitted_form_skipped(self):
        """已提交表单的请求已在 api_endpoints，不再推断注册。"""
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result([_form(
            action="/login", submitted=True, page=self.TARGET + "/login",
        )])
        added = register_form_apis(sm, cr, target_url=self.TARGET + "/")
        assert added == []
        assert sm.apis == {}

    def test_chain_dedup_against_existing_api_endpoints(self):
        """crawl_result.api_endpoints 已含该 (method,url) → 不重复注册。"""
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result(
            [_form(action="/login", method="POST", fields=["u"], page=self.TARGET + "/login")],
            api_endpoints=[{"method": "POST", "url": self.TARGET + "/login"}],
        )
        added = register_form_apis(sm, cr, target_url=self.TARGET + "/")
        assert added == []
        assert sm.apis == {}

    def test_chain_idempotent_no_duplicate(self):
        """同一表单二次注册：sitemap.apis 已有同名条目 → 去重，返回空。"""
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result([_form(
            action="/login", method="POST", fields=["u"], page=self.TARGET + "/login",
        )])
        first = register_form_apis(sm, cr, target_url=self.TARGET + "/")
        second = register_form_apis(sm, cr, target_url=self.TARGET + "/")
        assert first == ["POST https://example.com/login"]
        assert second == []
        assert len(sm.apis) == 1

    def test_chain_sample_post_data_built_from_fields(self):
        """请求样本 body 由 fields 拼接为 'name=&name=' 形式。"""
        sm = Sitemap(target=self.TARGET)
        cr = _crawl_result([_form(
            action="/login", method="POST", fields=["user", "pass"],
            page=self.TARGET + "/login",
        )])
        register_form_apis(sm, cr, target_url=self.TARGET + "/")
        # 真实 Sitemap：至少有一条样本，其 body 为 'user=&pass='
        bodies = [s.get("body", "") for s in sm.api_samples.values()]
        assert "user=&pass=" in bodies

    def test_chain_max_forms_limits_registration(self):
        sm = Sitemap(target=self.TARGET)
        forms = [
            _form(action=f"/api/{i}", method="POST", fields=["u"], page=self.TARGET + "/")
            for i in range(10)
        ]
        added = register_form_apis(
            sm, _crawl_result(forms), target_url=self.TARGET + "/", max_forms=3
        )
        assert len(added) == 3
        assert len(sm.apis) == 3
