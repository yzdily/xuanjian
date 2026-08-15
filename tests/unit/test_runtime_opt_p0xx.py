"""P0-1 / P0-2 / P2-2 / P2-3 运行时优化回归锁（T8 / T9 / T12 / T14）。

把已落地的运行时优化锁成防回退测试，避免「修完不写测试」再次退化：

- T8  (P0-1  FastScanner 超时熔断)：引擎新增 ``_per_rule_timeout`` /
  ``_heartbeat_interval`` / ``_deadline`` / ``_hard_timeout`` 四个超时/心跳参数，
  锁定其默认值（45s / 60s / None / 600s），防止超时熔断逻辑被意外改回「无限等待」。
- T9  (P0-2  上下文预算拦截)：``ContextManager.check_context_budget`` 在上下文
  使用率 ≥ 0.8 时记录预警并返回使用率；锁定「空上下文≈0、超载上下文≥0.8 且告警」。
- T12 (P0-2  语义分组上限)：``config.MAX_FEATURES_PER_GROUP`` 由 8 降至 4，
  防止子 Agent 单组上下文再次超限（P0-B 根因）。纯常量锁。
- T14 (P2-2 部分完成措辞 / P2-3 认证页自动升级 / SPA 空壳指引)：三项可读性
  与 FAST→STANDARD 自动升级修复，以「源码契约」方式锁定关键分支与字符串，
  防止静默回退（与 test_xj_security.py 的 XJ-02 源码契约模式一致）。
- T13 (P1-2 补测回写 NOT_VULN)：以源码契约锁定
  ``_runner.py`` 中「补测未发现漏洞 → PENDING 项标记 NOT_VULN」的补全逻辑。

注：T8/T9 涉及 core.fast_scanner / core.context 等较重模块，采用函数内惰性导入；
这些模块在完整测试环境（1245 passed 套件）可正常导入，本机隔离环境未装
pytest/fastapi 故仅做语法与契约校验。
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


# ============================================================
# T8 — P0-1 FastScanner 超时/心跳参数锁
# ============================================================
@pytest.mark.regression
class TestFastScannerTimeoutParams:
    """P0-1：引擎新增的超时熔断参数默认值锁死。

    历史根因（P0-A）：orchestrator 硬超时 cancel() 会丢结果，且单规则无熔断。
    修复后引擎自带单规则 45s 熔断 + 60s 进度心跳 + 600s 硬超时感知。
    这些常量若被改回 0/无限，P0-A 会复现。
    """

    def test_per_rule_timeout_is_45s(self):
        from core.fast_scanner._engine import FastScanner
        eng = FastScanner(max_workers=1)
        assert eng._per_rule_timeout == 45.0

    def test_heartbeat_interval_is_60s(self):
        from core.fast_scanner._engine import FastScanner
        eng = FastScanner(max_workers=1)
        assert eng._heartbeat_interval == 60.0

    def test_hard_timeout_default_600s(self):
        from core.fast_scanner._engine import FastScanner
        eng = FastScanner(max_workers=1)
        assert eng._hard_timeout == 600.0

    def test_hard_timeout_overridable(self):
        from core.fast_scanner._engine import FastScanner
        eng = FastScanner(max_workers=1, hard_timeout=120.0)
        assert eng._hard_timeout == 120.0

    def test_deadline_initially_none(self):
        from core.fast_scanner._engine import FastScanner
        eng = FastScanner(max_workers=1)
        # 扫描开始前 deadline 未设置；扫描启动时由引擎写入 time.monotonic() 基准
        assert eng._deadline is None


# ============================================================
# T9 — P0-2 上下文预算拦截行为锁
# ============================================================
@pytest.mark.regression
class TestContextBudgetGuard:
    """P0-2：上下文预算预警与返回使用率锁死。

    历史根因（P0-B）：子 Agent 上下文超限（~52K > 65K）被动等 ContextLimitError。
    修复后 ``check_context_budget`` 主动返回使用率，≥0.8 时记录告警，
    供 WorkerAgent 在每轮调用前主动压缩。
    """

    def test_empty_context_usage_is_near_zero(self):
        from core.context import ContextManager
        cm = ContextManager(llm=None)
        usage = cm.check_context_budget(context_window=65536, safety=0.85)
        assert isinstance(usage, float)
        assert usage < 0.8  # 空上下文不应触发预警

    def test_overloaded_context_triggers_warning_and_high_usage(self, caplog):
        from core.context import ContextManager
        cm = ContextManager(llm=None)
        # 注入一段远超窗口的内容（约 5 万字符 → 估算 token 远超可用上限）
        big = "x" * 50000
        cm.add_user(big)

        with caplog.at_level(logging.WARNING, logger="context"):
            usage = cm.check_context_budget(context_window=200, safety=0.85)
        assert isinstance(usage, float)
        assert usage >= 0.8
        assert any("上下文预算" in r.message for r in caplog.records)

    def test_usage_scales_with_context_window(self):
        from core.context import ContextManager
        cm = ContextManager(llm=None)
        cm.add_user("y" * 20000)
        # 窗口越小，使用率越高（同样的上下文，窗口 100 比 100000 使用率高）
        small = cm.check_context_budget(context_window=100, safety=0.85)
        large = cm.check_context_budget(context_window=100000, safety=0.85)
        assert small >= large

    def test_d14_precheck_safety_locked_to_06(self):
        """D14：生产侧硬拦截阀门 ``_CONTEXT_PRECHECK_SAFETY`` 锁定 0.6。

        历史根因：原值 0.85 导致 ``LLMClient.chat()`` 在 ~52K 才抛
        ``ContextLimitError``，子 Agent 被动超限。D14 降至 0.6，在 ~39K
        即触发压缩，从源头避免上下文超载。锁定防止被静默改回 0.85。
        """
        from core.llm._tokens import _CONTEXT_PRECHECK_SAFETY
        assert _CONTEXT_PRECHECK_SAFETY == 0.6

    def test_d14_check_context_budget_default_safety_hard_blocks(self, caplog):
        """D14：``check_context_budget`` 默认 safety=0.6，超 60% 预算即硬拦截。

        用真实 65536 窗口 + ~42K CJK tokens 验证：旧阈值 0.85（55705）下
        此用量不会触发，新阈值 0.6（39321）下应触发「拒绝继续注入样本」。
        """
        from core.context import ContextManager
        cm = ContextManager(llm=None)
        cm.add_user("中" * 42000)  # ≈42000 CJK tokens，超过 65536*0.6=39321
        with caplog.at_level(logging.WARNING, logger="context"):
            usage = cm.check_context_budget(context_window=65536)  # 默认 safety=0.6
        assert usage >= 1.0
        assert any("硬拦截" in r.message for r in caplog.records)

    def test_d14_budget_allows_injection_gate(self):
        """D14：budget_allows_injection() 在超预算时返回 False（硬拦截判定）。

        配合 worker_agent._build_group_task_message 中的预检：超 60% 预算即
        拒绝注入样本，从源头避免上下文被 API 流量样本撑爆。
        """
        from core.context import ContextManager
        cm = ContextManager(llm=None)
        cm.add_user("中" * 42000)  # ≈42000 tokens > 65536*0.6=39321
        assert cm.check_context_budget(context_window=65536) >= 1.0
        assert cm.budget_allows_injection(context_window=65536) is False
        # 未超限时应允许注入
        fresh = ContextManager(llm=None)
        assert fresh.budget_allows_injection(context_window=65536) is True


# ============================================================
# T12 — P0-2 语义分组上限常量锁
# ============================================================
@pytest.mark.regression
class TestMaxFeaturesPerGroupConstant:
    """P0-2：MAX_FEATURES_PER_GROUP 由 8 降至 4 的回归锁。

    这是 P0-B 的直接修复点：8 功能点一组（8×4K 样本 + 2 SKILL ≈ 56K tokens）
    会超过 65536 窗口。若有人把它改回 8，上下文超限会复现。
    """

    def test_max_features_per_group_is_four(self):
        from core.config import MAX_FEATURES_PER_GROUP
        assert MAX_FEATURES_PER_GROUP == 4

    def test_max_features_per_group_below_old_eight(self):
        """显式钉死：绝不允许回到触发 P0-B 的 8。"""
        from core.config import MAX_FEATURES_PER_GROUP
        assert MAX_FEATURES_PER_GROUP < 8

    def test_features_per_worker_is_three(self):
        """P0-2 另一修复点：FEATURES_PER_WORKER 由 5 降至 3（与孤儿 .py 旧值 5 区分）。"""
        from core.supplemental_test_agent._constants import FEATURES_PER_WORKER
        assert FEATURES_PER_WORKER == 3


# ============================================================
# T14 — P2-2 / P2-3 / SPA 空壳 源码契约锁
# ============================================================
@pytest.mark.regression
class TestRuntimeReadabilityAndUpgradeContracts:
    """P2-2/P2-3/SPA：以源码契约锁定关键分支与字符串，防静默回退。

    这些逻辑深埋在 orchestrator / chat_loop / worker_helpers 大类中，
    难以单测构造，故采用「源码契约」方式（与 test_xj_security.py XJ-02 同模式）：
    断言修复特征串必须存在于源码，任何回退/误删都会让测试失败。
    """

    def test_partial_completion_wording_present(self):
        """P2-2：低覆盖（real_rate<10%）时不再称「扫描完成」，改标「部分完成 / 覆盖不足」。"""
        src = (_PROJECT_ROOT / "core" / "parallel" / "orchestrator.py").read_text(encoding="utf-8")
        assert "部分完成 / 覆盖不足（真实完成率" in src
        assert "real_rate < 10.0" in src
        # 「覆盖不足」措辞必须存在（替代旧的误导式「扫描完成」）
        assert "覆盖不足" in src

    def test_auth_page_auto_upgrade_present(self):
        """P2-3：FAST 模式遇到认证页（login/register/signin 等）自动升级 STANDARD。"""
        src = (_PROJECT_ROOT / "core" / "session" / "chat_loop.py").read_text(encoding="utf-8")
        # 认证页特征元组必须完整存在
        for pat in ("passport/login", "/login", "login.html", "/signin",
                    "/register", "register.html", "/signup", "/auth"):
            assert pat in src, f"认证页特征缺失: {pat}"
        # 升级动作必须存在（FAST → STANDARD）
        assert 'self.user_scan_mode = "standard"' in src
        # 升级必须限定在 FAST 模式下（_user_mode_fast 守卫）
        assert "_user_mode_fast" in src

    def test_spa_shell_guidance_present(self):
        """SPA 短路：worker 上下文注入「前端页面 URL 永远返回 SPA 空壳 200，必须测后端 /api/*」指引。"""
        src = (_PROJECT_ROOT / "core" / "worker_agent" / "_helpers.py").read_text(encoding="utf-8")
        assert "前后端分离架构下前端页面 URL 永远返回 SPA 空壳 200，必须测后端 /api/* 才有意义" in src


# ============================================================
# T13 — P1-2 补测回写 NOT_VULN 源码契约锁
# ============================================================
@pytest.mark.regression
class TestSupplementalNotVulnWriteback:
    """P1-2：补测未发现漏洞时，已测试的 PENDING 项标记 NOT_VULN 回写 checklist。

    防止补测项永远停留在 PENDING，导致 pending_rate 虚高、误触发空心化告警。
    以源码契约锁定补全逻辑（深埋在 _runner.py 补测循环内）。
    """

    def test_pending_marked_not_vuln_on_zero_vulns(self):
        src = (_PROJECT_ROOT / "core" / "supplemental_test_agent" / "_runner.py").read_text(encoding="utf-8")
        # 零漏洞分支（由 `if result.vuln_count > 0` 的 else 触发）
        assert "result.vuln_count > 0" in src
        # PENDING → NOT_VULN 回写
        assert "c.result = CheckResult.NOT_VULN" in src
        # 仅对 PENDING 项回写（避免覆盖已有结论）
        assert "c.result == CheckResult.PENDING" in src
        # 来源标记，便于审计
        assert '"fast_scanner_supplemental"' in src
