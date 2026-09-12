"""
AdvancePhaseMixin — Phase 推进状态机。

方法：
- _handle_phase_complete: 处理 phase_complete 工具调用
- _advance_phase: 阶段推进核心逻辑（Phase 0→1→1.5→2→2.5→2.55→2.6→3）
"""

from __future__ import annotations

import json
import time
from typing import AsyncGenerator

from core.sitemap import CheckResult
from core.prompts.phases import (
    PHASE_EXPLORE_PROMPT, PHASE_ANALYZE_PROMPT,
    PHASE_TEST_PROMPT, PHASE_REPORT_PROMPT,
)
from core.log import get_logger

log = get_logger("session.advance")


class AdvancePhaseMixin:
    """Phase 推进状态机。"""

    async def _handle_phase_complete(self, tc: dict, args: dict) -> AsyncGenerator[str, None]:
        """处理 phase_complete 工具调用。"""
        summary = args.get("summary", "")

        # 防护：Phase 1 完成前必须有活跃功能点
        if self.phase == "analyze" and self.sitemap:
            active_features = [f for f in self.sitemap.features.values() if not f.deferred]
            if len(active_features) == 0:
                self.current_context.add_tool_result(tc["id"],
                    "⛔ 拒绝完成：你还没有添加任何功能点！\n"
                    "必须先用 sitemap_add_feature 添加至少 1 个功能点。")
                yield self._event("system", "⛔ Phase 1 完成被拒绝：未添加功能点")
                return

            # ★ 操作覆盖度量：检查 API 抓取质量
            coverage_report = self._check_operation_coverage()
            if coverage_report["blocked"]:
                # ★ 拒绝次数保护：超过 3 次强制放行，防止死循环
                self._phase1_reject_count = getattr(self, '_phase1_reject_count', 0) + 1
                if self._phase1_reject_count <= 3:
                    self.current_context.add_tool_result(tc["id"], coverage_report["message"])
                    yield self._event("system", coverage_report["message"])
                    return
                else:
                    # 第 4 次：强制放行，带严重警告
                    yield self._event("system",
                        f"⚠️ 操作覆盖检查已拒绝 {self._phase1_reject_count - 1} 次，强制放行。\n"
                        f"Phase 2 测试质量可能受影响（功能点缺少 API 关联，子 Agent 需要自行发现 API）。\n"
                        f"{coverage_report['message']}")
            elif coverage_report["warnings"]:
                yield self._event("system", coverage_report["message"])

            # 防护：必须设置过业务类型（LLM 没调 sitemap_set_business 时代码兜底）
            if not self.sitemap.business_summary:
                # 代码自动推断技术栈
                self._auto_infer_tech_stack()
                yield self._event("system",
                    f"⚠️ 自动推断技术栈: {self.sitemap.tech_stack or '未知'}, "
                    f"业务类型: {self.sitemap.business_summary or '未知'}")

        # 防护：Phase 2 功能点测试必须有 checklist 打勾
        if self.phase == "test" and self.sitemap and self.current_feature_id:
            fp = self.sitemap.features.get(self.current_feature_id)
            if fp and fp.checklist:
                pending = [c for c in fp.checklist if c.result == CheckResult.PENDING]
                if len(pending) == len(fp.checklist):
                    self.current_context.add_tool_result(tc["id"],
                        f"⛔ 拒绝完成：你还没有测试任何 checklist 项！\n"
                        f"当前功能点 {fp.name} 有 {len(fp.checklist)} 个待测项。")
                    yield self._event("system", f"⛔ Phase 2 完成被拒绝：{fp.name} 未执行任何测试")
                    return

        yield self._event("phase_complete", f"{self._phase_label()} 完成:\n\n{summary}")
        self.current_context.add_tool_result(tc["id"], f"阶段完成: {summary}")
        async for evt in self._advance_phase(summary):
            yield evt

    async def _advance_phase(self, summary: str) -> AsyncGenerator[str, None]:
        log.info("阶段推进: %s → 下一阶段, summary=%s", self.phase, summary[:80])
        if self.phase == "explore":
            # ★ P1-A: Phase 0 爬虫完成后评估是否需要升级模式
            # 多因子评分：支付/上传关键词 → deep；认证/API多 → standard
            _escalated = self._check_post_crawl_escalation()
            if _escalated:
                yield self._event("system",
                    f"📈 爬虫完成后自动升级扫描模式 → {_escalated}"
                    f"（检测到高危业务功能或复杂 API 结构）")

            # ★ FAST 模式：跳过 Phase 1，直接进入 Phase 2
            _user_mode = getattr(self, "user_scan_mode", "smart")
            if _user_mode == "fast" or self.llm is None:
                self.phase = "test"
                yield self._event("phase", "Phase 2: 本地规则引擎测试（FAST 模式跳过 Phase 1）")
                # 直接进入 Phase 2
                from core.parallel import run_parallel_test
                async for evt in run_parallel_test(self):
                    yield evt
                return

            self.phase = "analyze"
            self.current_context = self._new_context_for_phase(PHASE_ANALYZE_PROMPT)
            yield self._event("phase", "Phase 1: 功能分析 — 理解业务逻辑，制定测试计划")
            self.current_context.add_user(
                "站点探索已完成。请开始 Phase 1 功能分析：\n"
                "1. 回顾站点地图中的所有功能点\n"
                "2. 对每个功能点分析业务逻辑\n"
                "3. 用 `sitemap_add_feature` 补充遗漏的功能点，**每个功能点必须传**：\n"
                "   - `related_apis`: 该功能关联的 API 路径列表\n"
                "   - `module`: 所属模块层级（用 / 分隔）\n"
                "   - `page_url`: 功能对应的页面 URL\n"
                "4. 用 phase_complete 标记分析完成"
            )

        elif self.phase == "analyze":
            # ★ Phase 1 完成前检查：API 多但功能点少 → 子 Agent 补充分析
            if self.sitemap:
                async for evt in self._maybe_split_analyze():
                    yield evt

            # ★ 全量流量同步：确保 mitmproxy 抓到的所有流量 100% 进入 sitemap
            # （Phase 1 浏览器操作期间产生的新流量可能被部分遗漏，这里做一次兜底同步）
            if self.sitemap:
                sync_result = self._sync_all_flows_to_sitemap()
                if sync_result.get("new_apis", 0) > 0 or sync_result.get("new_features", 0) > 0:
                    yield self._event("system",
                        f"🔄 全量流量同步: 扫描 {sync_result['total_flows']} 条流量, "
                        f"新增 {sync_result['new_apis']} 个 API, "
                        f"{sync_result.get('new_samples', 0)} 个样本, "
                        f"{sync_result.get('new_features', 0)} 个功能点")
                else:
                    yield self._event("system",
                        f"✅ 流量同步检查: {sync_result['total_flows']} 条流量已全部覆盖")

            # ★ 将流量样本写入独立文件，供子 Agent 直接读取
            if self.sitemap:
                flush_result = self.sitemap.flush_samples_to_files()
                if flush_result["total_files"] > 0:
                    yield self._event("system",
                        f"📁 流量样本已写入 {flush_result['total_files']} 个独立文件 "
                        f"({flush_result['total_size_kb']}K)，子 Agent 将直接读取")

            # ★ Phase 1.5: 业务理解 — 在 Phase 1 后、Phase 2 前执行
            # 此时 sitemap 已经有 LLM 添加的功能点 + 业务标签 + 完整 API/样本数据
            # 无论 Phase 0 是否爬取过、走的是哪条路径，都能在此跑出有质量的业务理解
            # ★ fast/无 LLM 模式跳过业务理解（analyze_business 依赖 LLM）
            _user_mode = getattr(self, "user_scan_mode", "smart")
            if self.sitemap and self.llm is not None and _user_mode != "fast":
                yield self._event("phase",
                    "Phase 1.5: 业务理解 — 深度分析目标系统业务逻辑")
                try:
                    from core.business_understanding import analyze_business
                    bu_started = time.time()
                    bu_result = await analyze_business(
                        sitemap=self.sitemap,
                        llm=self.llm,
                        crawl_result=None,  # crawl_result 可能不存在,但 sitemap 已含足够数据
                        timeout=240.0,  # 调高到 4 分钟，应对 LLM 网关偶发慢调用 + 长上下文输出
                    )
                    bu_elapsed = time.time() - bu_started
                    self.sitemap.business_understanding = bu_result
                    try:
                        self.sitemap.save()
                    except Exception:
                        pass

                    if bu_result.get("status") in ("ok", "degraded"):
                        u = bu_result.get("understanding", {}) or {}
                        bu_summary = bu_result.get("summary", "")
                        domain_lbl = ""
                        if isinstance(u.get("domain"), dict):
                            domain_lbl = u["domain"].get("label", "")
                        n_roles = len(u.get("roles", []) or [])
                        n_promises = len(u.get("promises", []) or [])
                        n_hypotheses = len(u.get("attack_hypotheses", []) or [])
                        status_icon = "✅" if bu_result.get("status") == "ok" else "⚠️"
                        status_label = "完成" if bu_result.get("status") == "ok" else "降级完成(规则推导)"
                        yield self._event("system",
                            f"{status_icon} Phase 1.5 业务理解{status_label} (耗时 {bu_elapsed:.1f}s):\n"
                            f"  - 领域: {domain_lbl or '未明确'}\n"
                            f"  - 角色: {n_roles} 个\n"
                            f"  - 系统承诺: {n_promises} 条\n"
                            f"  - 攻击假设: {n_hypotheses} 条\n"
                            f"  - 已落入报告基本信息章节"
                            + (f"\n\n📝 系统定位:\n{bu_summary[:300]}" if bu_summary else "")
                        )
                    else:
                        err = bu_result.get("error", "未知错误")
                        yield self._event("system",
                            f"⚠️ Phase 1.5 业务理解失败/降级 ({bu_result.get('status')}): {err[:200]}\n"
                            f"  主链路继续运行,启用本地规则引擎兜底测试")
                        # ★ P0-B: 业务理解失败 → 降级到 fast 模式（跳过后续 LLM 阶段）
                        # 此前 _bu_failed 只赋值不读取，降级从未生效，现已接入 _maybe_escalate_mode
                        _new_mode = self._maybe_escalate_mode("business_understanding_failed", "downgrade")
                        if _new_mode:
                            yield self._event("system",
                                f"⚠️ 因业务理解失败，扫描模式已降级 → {_new_mode}"
                                f"（后续 LLM 依赖阶段将跳过，使用本地规则兜底）")
                except Exception as e:
                    log.warning("Phase 1.5 business understanding crashed: %s", e)
                    yield self._event("system",
                        f"⚠️ Phase 1.5 异常: {str(e)[:200]}\n  启用本地规则引擎兜底")
                    # ★ P0-B: 异常也触发降级
                    _new_mode = self._maybe_escalate_mode("business_understanding_crashed", "downgrade")
                    if _new_mode:
                        yield self._event("system",
                            f"⚠️ 因业务理解异常，扫描模式已降级 → {_new_mode}")

            self.phase = "test"
            # ★ 2026-05-22: 打 Phase 2 开始时间戳，供 Phase 2.55 补测 Agent 筛选"Phase 2 之后产生的新 API"
            self._phase2_started_at = time.time()

            # ★ 策略分支：实时模式 vs 批处理模式
            if self.scan_mode == "realtime":
                # 实时模式：停止 FlowWatcher，已测过的跳过，直接进入报告
                async for evt in self.strategy.on_phase1_complete(self, summary):
                    yield evt

                # 对未测过的功能点补一轮快速测试
                if self.sitemap:
                    untested = [
                        fp for fp in self.sitemap.features.values()
                        if not fp.deferred and fp.checklist
                        and all(c.result == CheckResult.PENDING for c in fp.checklist)
                    ]
                    if untested:
                        yield self._event("system",
                            f"⚡ 实时模式 — 补测 {len(untested)} 个未测功能点")
                        for feat in untested:
                            async for evt in self.strategy.on_feature_discovered(self, feat):
                                yield evt

                # 跳过 Phase 2 批量并行测试，直接进入 Phase 3 报告生成
                # 复用 _enter_report_phase（包含 XSS 等待 + 危害验证 + 报告提示）
                from core.parallel import _enter_report_phase
                async for evt in _enter_report_phase(self):
                    yield evt
            else:
                # 批处理模式：原有全流程
                yield self._event("phase", "Phase 2: 并行测试 — 子 Agent 测 HTTP 项 + 主 Agent 测浏览器项")
                from core.parallel import run_parallel_test
                async for evt in run_parallel_test(self):
                    yield evt

        elif self.phase == "test":
            if self.current_feature_id and self.sitemap:
                self.sitemap.finish_test(self.current_feature_id)
            from core.parallel import start_browser_feature_test
            async for evt in start_browser_feature_test(self):
                yield evt

        elif self.phase == "report":
            yield self._event("done", "渗透测试完成，报告已生成")
