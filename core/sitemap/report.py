"""Sitemap — 报告渲染 Mixin。"""

from __future__ import annotations

import time
import logging
from pathlib import Path
from collections import OrderedDict

from core.sitemap.models import CheckResult, TestStatus, FeaturePoint
from core.sitemap.constants import (
    SEVERITY_LABEL, CHECK_RESULT_ICON, CHECK_RESULT_ICON_WITH_TEXT,
    TEST_STATUS_ICON_WITH_TEXT,
)

log = logging.getLogger("pentest_agent.sitemap")


class ReportMixin:
    """实时报告 + 已证明漏洞报告的渲染与持久化。"""

    def _count_pages(self) -> int:
        """统计页面数：优先用 pages 字典，为 0 时从功能点的 page_url 去重统计。"""
        if self.pages:
            return len(self.pages)
        urls = {fp.page_url for fp in self.features.values() if fp.page_url}
        return len(urls)

    def _count_apis(self) -> int:
        """统计 API 数：优先用 apis 字典，为 0 时从功能点的 related_apis 去重统计。"""
        if self.apis:
            return len(self.apis)
        apis = set()
        for fp in self.features.values():
            for api in fp.related_apis:
                apis.add(api)
        return len(apis)

    def _report_path(self) -> Path:
        report_dir = Path("data/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        return report_dir / f"{self.task_id}-realtime-report.md"

    def _proven_report_path(self) -> Path:
        """报告 B（已证明漏洞）的本地文件路径。"""
        report_dir = Path("data/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        return report_dir / f"{self.task_id}-proven-report.md"

    def flush_proven_report(self) -> str:
        """渲染并写入【已证明漏洞】独立报告（报告 B）。"""
        try:
            from core.harm_validation import render_proven_only
        except Exception as e:
            # ★ 报告空问题修复：之前静默吞异常导致 proven 报告为空且无任何日志，
            # 现在记录 warning 便于排查 harm_validation 模块导入失败等问题。
            log.warning("flush_proven_report: 导入 render_proven_only 失败: %s", e)
            return ""
        hv_result = getattr(self, "harm_validation", None) or {}
        orphan_findings = []
        orphan_findings.extend(getattr(self, "_fast_scanner_orphan_findings", None) or [])
        orphan_findings.extend(getattr(self, "_scripted_scan_findings", None) or [])
        # ★ 优化.md 建议3：补合规章节 — 传入扫描范围信息
        _page_count = self._count_pages() if hasattr(self, "_count_pages") else 0
        _api_count = self._count_apis() if hasattr(self, "_count_apis") else 0
        _scan_scope = f"共 {_page_count} 个页面、{_api_count} 个 API 接口"
        content = render_proven_only(
            hv_result,
            target=getattr(self, "target", "") or "",
            task_id=self.task_id,
            # ★ 传入孤儿发现：当 harm_validation 无 accepted 时，至少列出
            # 广扫发现的未匹配候选，避免 proven 报告永远空
            orphan_findings=orphan_findings,
            scan_scope=_scan_scope,
        )
        try:
            self._proven_report_path().write_text(content, encoding="utf-8")
        except Exception as e:
            # ★ 报告空问题修复：写盘失败也记录日志
            log.warning("flush_proven_report: 写盘失败 %s: %s",
                        self._proven_report_path(), e)
        return content

    def _render_execution_quality_summary(self) -> list[str]:
        """生产级执行摘要：让报告明确展示测试完整性与 API 消耗。"""
        total_checks = 0
        pending = []
        skipped = []
        needs_review = 0
        vulnerable = 0
        not_vuln = 0
        for fp in self.features.values():
            for c in fp.checklist:
                total_checks += 1
                if c.result == CheckResult.PENDING:
                    pending.append((fp, c))
                elif c.result == CheckResult.SKIPPED:
                    skipped.append((fp, c))
                elif c.result == CheckResult.NEEDS_REVIEW:
                    needs_review += 1
                elif c.result == CheckResult.VULNERABLE:
                    vulnerable += 1
                elif c.result == CheckResult.NOT_VULN:
                    not_vuln += 1

        # ★ 真实完成 = 已测试（vulnerable + needs_review + not_vuln），不含 SKIPPED
        # SKIPPED 是"跳过"而非"完成"，原来把 SKIPPED 算进 completed 导致
        # Fast 模式 98.6% 完成的空心假象。
        # ★ 0 功能点/0 checklist 时完成率=0%（原为 100%，产生"100%完成 0漏洞"的空心假象）
        real_completed = vulnerable + needs_review + not_vuln
        completion_rate = (real_completed / total_checks * 100) if total_checks else 0.0
        skipped_rate = (len(skipped) / total_checks * 100) if total_checks else 0.0
        lines = ["### 1.2 生产级执行摘要", ""]
        lines.append("| 指标 | 数量 |")
        lines.append("|------|------|")
        lines.append(f"| Checklist 总数 | {total_checks} |")
        lines.append(f"| 真实完成 | {real_completed} |")
        lines.append(f"| 完成率 | {completion_rate:.1f}% |")
        lines.append(f"| 跳过 | {len(skipped)} ({skipped_rate:.1f}%) |")
        lines.append(f"| 已确认漏洞 | {vulnerable} |")
        lines.append(f"| 疑似待确认 | {needs_review} |")
        lines.append(f"| 已确认安全 | {not_vuln} |")
        lines.append(f"| 未完成 | {len(pending)} |")

        scripted_stats = getattr(self, "_scripted_scan_stats", None) or {}
        if scripted_stats:
            lines.append(f"| 脚本广扫候选 | {scripted_stats.get('findings', 0)} |")
            lines.append(f"| 脚本广扫请求样本 | {scripted_stats.get('packets', 0)} |")

        try:
            from core.llm import _monitor
            task_summary = _monitor.get_task_summary(self.task_id)
        except Exception:
            task_summary = {}
        if task_summary:
            lines.append(f"| LLM 调用次数 | {task_summary.get('calls', 0)} |")
            lines.append(f"| LLM Token 总量 | {task_summary.get('total_tokens', 0)} |")
        skill_routes = getattr(self, "skill_routes", None)
        if skill_routes and skill_routes.get("routes"):
            lines.append(f"| Skill 引导(零LLM) | {len(skill_routes['routes'])} 个 SKILL |")
        lines.append("")

        if skill_routes and skill_routes.get("routes"):
            lines.append("**Skill 引导（确定性映射 · 零 LLM）**：")
            lines.append("")
            for r in skill_routes["routes"]:
                lines.append(f"- `{r['skill_name']}`（优先级 {r['priority']}）← 治理 `{r['vuln_type']}`")
            lines.append("")

        # ★ 高跳过率诊断：跳过率 > 80% 时显示原因分析和建议
        # 避免"98.6% 完成 0 漏洞"的空心假象误导用户
        if skipped_rate > 80.0 and total_checks > 0:
            lines.append(f"> 🔴 **高跳过率告警**：{skipped_rate:.1f}% 的测试项被跳过（{len(skipped)}/{total_checks}），真实完成率仅 {completion_rate:.1f}%。")
            _term_reason = getattr(self, "termination_reason", "") or ""
            _waf_blocked = getattr(self, "_waf_blocked", False) or getattr(self, "_waf_blocked_global", False)
            _diag_causes: list[str] = []
            if _waf_blocked:
                _diag_causes.append("WAF 封禁导致高危规则（SQLi/XSS/命令注入/SSRF 等）被批量跳过")
            if "fast" in (_term_reason or "").lower():
                _diag_causes.append("FAST 模式跳过了 LLM 深度分析阶段（业务逻辑/越权/补测/危害验证）")
            if not _diag_causes:
                _diag_causes.append("目标不可达/超时/无有效凭据导致大部分规则无法执行")
            lines.append(f"> **可能原因**：{'; '.join(_diag_causes)}")
            lines.append(f"> **建议**：切换到 STANDARD/DEEP 模式重新扫描，或提供有效登录凭据以覆盖需认证的接口。")
            lines.append("")

        if pending:
            lines.append(f"> ⚠️ 仍有 {len(pending)} 项未完成。报告可用于阶段性审阅，但不应声明为完整测试。")
            lines.append("")
            priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            pending_sorted = sorted(
                pending,
                key=lambda item: (
                    priority_rank.get(getattr(item[0].priority, "value", "medium"), 2),
                    item[0].id,
                    item[1].vuln_type,
                ),
            )
            lines.append("**优先补测队列（最多 20 项）**：")
            lines.append("")
            for fp, c in pending_sorted[:20]:
                api = fp.related_apis[0] if fp.related_apis else fp.page_url
                pri = getattr(fp.priority, "value", "medium")
                lines.append(f"- `{pri}` `{fp.id}` {fp.name} / {c.vuln_type} / {api}")
            lines.append("")
        return lines

    def flush_report(self) -> str:
        """实时写入报告到本地文件。每次 checklist 变化都调用，确保结果不丢失。"""
        from core.sitemap.models import Priority

        cov = self.get_coverage()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            f"# 渗透测试报告（实时更新）",
            f"",
            f"> ⚠️ 此报告随测试进度实时更新，最后更新: {timestamp}",
            f"",
            f"## 1. 基本信息",
            f"",
            f"### 1.1 任务信息",
            f"",
            f"| 项目 | 内容 |",
            f"|------|------|",
            f"| 目标 | {self.target} |",
            f"| 任务 ID | {self.task_id} |",
            f"| 业务类型 | {self.business_summary or '待分析'} |",
            f"| 技术栈 | {self.tech_stack or '待识别'} |",
            f"| 页面数 | {self._count_pages()} |",
            f"| API 端点 | {self._count_apis()} |",
            f"| 功能点 | {cov.get('total_deduped', cov['total'])} |",
            f"| 测试进度 | {cov['checks_done']}/{cov['checks_total']} 项完成 |",
            f"| 发现漏洞 | {cov['vulns']} 个（含疑似 {sum(1 for v in cov.get('vuln_list', []) if v.get('status') == 'suspected')}） |",
            f"",
        ]

        # ★ PM-1: 可测性覆盖率透明化 — 业务 API ≤ 2 或功能点=0 时显示红色横幅
        # 避免"扫描完成 0 漏洞"的空心假象误导用户（zhenduan 诊断①空心扫描）
        _pm1_business_apis = sum(
            1 for a in (getattr(self, "apis", {}) or {}).values()
            if isinstance(a, dict) and a.get("discovered_by") != "dirscan"
        )
        _pm1_feat_cnt = cov.get('total_deduped', cov['total'])
        if _pm1_feat_cnt == 0 or _pm1_business_apis <= 2:
            lines.append(f"> 🔴 **可测性覆盖率不足**：业务 API 仅 {_pm1_business_apis} 个，功能点 {_pm1_feat_cnt} 个。")
            lines.append(f"> 本次扫描覆盖严重不足，0 漏洞不代表目标安全，建议补充凭证后重测或更换扫描模式。")
            lines.append(f"")

        # ★ 终止原因横幅：Fast 模式 / 降级模式等情况下在报告头部醒目提示
        # 避免"98.6% 完成 0 漏洞"的空心假象误导用户
        _term_reason = getattr(self, "termination_reason", "") or ""
        _phase_status = getattr(self, "phase_status", "") or ""
        if _term_reason or _phase_status:
            lines.append(f"> ⚠️ **扫描状态提醒**：{_term_reason or _phase_status}")
            lines.append(f"> 完成率含跳过项，请参考下方「真实完成」指标判断测试覆盖度。")
            lines.append(f"")

        # ★ mitmproxy 降级横幅：代理不可用时流量记录可能不完整，需醒目提示
        _traffic_degraded = getattr(self, "traffic_degraded", False)
        _traffic_degraded_reason = getattr(self, "traffic_degraded_reason", "") or ""
        if _traffic_degraded:
            lines.append(f"> 🔴 **流量抓取降级模式**：{_traffic_degraded_reason or 'mitmproxy 代理不可用，flows.jsonl 由 Playwright 降级写入，可能不完整。'}")
            lines.append(f"> 流量不完整可能影响补测覆盖度，请审慎评估本次测试结果。")
            lines.append(f"")

        # ★ PM-2: 能力降级清单 — 汇总本次扫描中失效的关键能力及影响
        # 让用户一眼看到"哪些关键环节失效了"，而非只看末尾"扫描完成"
        _pm2_degradations: list[str] = []
        if _traffic_degraded:
            _pm2_degradations.append(
                f"- **mitmproxy 流量抓取降级**：{_traffic_degraded_reason or '代理不可用'} → 补测覆盖度可能不足"
            )
        # harm_validation 失败标记（Phase 2.6 错误时由 orchestrator 写入）
        _harm_err = getattr(self, "_harm_validation_error", "") or ""
        if _harm_err:
            _pm2_degradations.append(
                f"- **危害验证失败**：{_harm_err} → 缺少 SRC 收录裁决，漏洞等级可能偏低"
            )
        # FastScanner 0 命中标记
        _fast_zero = getattr(self, "_fast_scanner_zero_hit", False)
        if _fast_zero:
            _pm2_degradations.append(
                f"- **FastScanner 本地规则 0 命中**：规则引擎未生效，可能遗漏信息泄露/未授权类漏洞"
            )
        if _pm2_degradations:
            lines.append("### 1.2 能力降级清单")
            lines.append("")
            lines.append("> 本次扫描存在以下能力降级，结果可能不完整：")
            lines.append("")
            lines.extend(_pm2_degradations)
            lines.append("")

        lines.extend(self._render_execution_quality_summary())

        # ★ 探测失败诊断章节：功能点=0 时插入诊断信息，替代空白报告
        # 避免"100% 完成 0 漏洞"的空心假象，明确告知用户探测失败的原因
        _total_features = len(self.features)
        _total_apis = len(getattr(self, "apis", {}) or {})
        if _total_features == 0 and _total_apis == 0:
            lines.append("### 1.3 探测失败诊断")
            lines.append("")
            lines.append("> 🔴 **目标探测失败**：本次扫描未发现任何功能点或 API 端点。")
            lines.append('> 报告中"0% 完成"是正常的——因为没有任何测试目标可供执行。')
            lines.append("")
            _scan_issue = getattr(self, "_scan_health_issue", None) or {}
            _traffic_health = getattr(self, "_traffic_health", None) or {}
            if _scan_issue:
                lines.append("**诊断信息**：")
                lines.append("")
                lines.append(f"- 失败类型：`{_scan_issue.get('type', 'unknown')}`")
                if _scan_issue.get("pages") is not None:
                    lines.append(f"- 已抓取页面数：{_scan_issue.get('pages', 0)}")
                if _scan_issue.get("apis") is not None:
                    lines.append(f"- 已发现 API 数：{_scan_issue.get('apis', 0)}")
                if _scan_issue.get("menu_clicked") is not None:
                    lines.append(f"- 菜单点击数：{_scan_issue.get('menu_clicked', 0)}")
                lines.append("")
            if _traffic_health:
                lines.append("**流量健康度**：")
                lines.append("")
                for _k, _v in _traffic_health.items():
                    lines.append(f"- {_k}：{_v}")
                lines.append("")
            lines.append("**可能原因与建议**：")
            lines.append("")
            lines.append("- 目标页面加载超时 → 尝试增大 `SCAN_TIMEOUT` 或使用 FAST 模式")
            lines.append("- SPA 站点前端渲染 → 检查 JS 分析器是否提取到路由")
            lines.append("- 需要登录凭据 → 在任务配置中提供有效的用户名/密码")
            lines.append("- 目标不可达 → 检查目标 URL 是否可访问、是否有 WAF 拦截")
            lines.append("- mitmproxy 未生效 → 检查代理端口 18080 是否可用")
            lines.append("")

        # 漏洞等级分布（从 vuln_list 统计）
        # ★ 区分 confirmed / suspected，避免把疑似项混入已确认统计误导用户
        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        suspected_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in cov.get("vuln_list", []):
            sev = v.get("severity", "").lower()
            if sev not in sev_counts:
                continue
            if v.get("status") == "suspected":
                suspected_counts[sev] += 1
            else:
                sev_counts[sev] += 1
        total_sev = sum(sev_counts.values())
        total_suspected = sum(suspected_counts.values())
        if total_sev > 0 or total_suspected > 0:
            lines.append("### 1.3 漏洞等级分布")
            lines.append("")
            lines.append("| 等级 | 已确认 | 疑似待确认 |")
            lines.append("|------|--------|------------|")
            sev_labels = {"critical": "🔴 严重", "high": "🟠 高危", "medium": "🟡 中危", "low": "🟢 低危"}
            for k in ("critical", "high", "medium", "low"):
                if sev_counts[k] or suspected_counts[k]:
                    lines.append(f"| {sev_labels[k]} | {sev_counts[k]} | {suspected_counts[k]} |")
            lines.append("")
        # 动态章节编号
        if total_sev > 0 or total_suspected > 0:
            bu_section = "1.4"
            rec_section = "1.5"
        else:
            bu_section = "1.3"
            rec_section = "1.4"

        # === {{bu_section}} 业务理解 ===
        bu_result = getattr(self, "business_understanding", None) or {}
        if bu_result:
            lines.append(f"### {bu_section} 业务理解")
            lines.append("")
            if bu_result.get("status") in ("ok", "degraded"):
                rec = getattr(self, "reconcile_result", None) or {}
                if rec and rec.get("status") == "ok":
                    coverage_map: dict = {}
                    promise_cov = (rec.get("reconcile_data") or {}).get("promise_coverage", []) or []
                    for pc in promise_cov:
                        if not isinstance(pc, dict):
                            continue
                        pid = pc.get("promise_id", "")
                        status = pc.get("status", "")
                        icon = {"covered": "✅ 已测",
                                "partial": "⚠️ 部分",
                                "uncovered": "❌ 未测"}.get(status, "⏸ 待测")
                        if pid:
                            coverage_map[pid] = icon
                    bu_result = {**bu_result, "coverage_map": coverage_map}
                try:
                    from core.business_understanding import render_to_markdown
                    bu_md = render_to_markdown(bu_result)
                    if bu_md.strip():
                        lines.append(bu_md)
                except Exception as _e:
                    lines.append(f"> ⚠️ 业务理解渲染失败: {_e}")
                    lines.append("")
            elif bu_result.get("status") in ("error", "timeout"):
                err = bu_result.get("error", "未知错误")
                lines.append(f"> ⚠️ 业务理解未完成 ({bu_result.get('status')}): {err[:300]}")
                lines.append("")
            else:
                lines.append("> ⏸ 业务理解尚未执行")
                lines.append("")

        # === {{rec_section}} 对账补齐发现 ===
        rec_result = getattr(self, "reconcile_result", None) or {}
        if rec_result and rec_result.get("status") == "ok":
            rec_data = rec_result.get("reconcile_data", {}) or {}
            cov_summary = rec_data.get("coverage_summary", {}) or {}
            gap_findings = rec_data.get("gap_findings", []) or []
            new_tasks = rec_data.get("new_tasks", []) or []
            rounds = rec_result.get("rounds", 1)

            lines.append(f"### {rec_section} 业务对账与能力补齐 ★")
            lines.append("")
            lines.append(
                f"*在主测试完成后，由 AI 总监对照业务理解做了 {rounds} 轮对账，"
                f"识别测试缺口并执行了针对性补齐。*"
            )
            lines.append("")
            if cov_summary:
                lines.append("**总体覆盖评估：**")
                lines.append("")
                lines.append(f"- 系统承诺总数：{cov_summary.get('promises_total', '?')}")
                lines.append(f"- 已充分覆盖：{cov_summary.get('promises_covered', '?')}")
                lines.append(f"- 部分覆盖：{cov_summary.get('promises_partial', '?')}")
                lines.append(f"- 未覆盖：{cov_summary.get('promises_uncovered', '?')}")
                lines.append(f"- 综合置信度：{cov_summary.get('overall_confidence', '?')}")
                lines.append(f"- 总评：{cov_summary.get('verdict', '?')}")
                lines.append("")
            if gap_findings:
                lines.append("**识别到的关键缺口：**")
                lines.append("")
                lines.append("| 缺口 | 危害估计 | 出货可能 | 理由 |")
                lines.append("|------|---------|---------|------|")
                for g in gap_findings[:10]:
                    if not isinstance(g, dict):
                        continue
                    gap = str(g.get("gap", "")).replace("|", "\\|")[:200]
                    sev = g.get("severity_estimate", "?")
                    lh = g.get("likelihood_estimate", "?")
                    rat = str(g.get("rationale", "")).replace("|", "\\|")[:250]
                    lines.append(f"| {gap} | {sev} | {lh} | {rat} |")
                lines.append("")
            if new_tasks:
                lines.append(f"**执行的补齐任务（{len(new_tasks)} 项）：**")
                lines.append("")
                for i, t in enumerate(new_tasks[:10], 1):
                    if not isinstance(t, dict):
                        continue
                    title = t.get("title", "") or t.get("id", f"GAP-{i:03d}")
                    role = t.get("role", "")
                    url = t.get("target_url", "")
                    param = t.get("param_to_modify", "") or t.get("param", "")
                    vtype = t.get("vulnerability_type", "")
                    why = t.get("why_top", "") or t.get("rationale", "")
                    result_status = t.get("_executed_status", "未执行")
                    result_summary = t.get("_executed_summary", "")
                    lines.append(f"**补齐任务 {i}: {title}** ({result_status})")
                    lines.append("")
                    lines.append(f"- 角色: {role}")
                    lines.append(f"- 接口: `{url}` 参数 `{param}`")
                    lines.append(f"- 漏洞类型: {vtype}")
                    lines.append(f"- 为什么补这一刀: {why}")
                    if result_summary:
                        lines.append(f"- 执行结果: {result_summary[:300]}")
                    lines.append("")
            lines.append("")

        # Phase 状态与终止原因
        phase_status = getattr(self, "phase_status", "") or ""
        termination_reason = getattr(self, "termination_reason", "") or ""
        if phase_status or termination_reason:
            lines.append("### 扫描状态")
            lines.append("")
            lines.append("| 项目 | 内容 |")
            lines.append("|------|------|")
            if phase_status:
                lines.append(f"| Phase 状态 | {phase_status} |")
            if termination_reason:
                lines.append(f"| 终止原因 | {termination_reason} |")
            lines.append("")

        # 测试执行统计（FastScanner）
        scanner_stats = getattr(self, "_fast_scanner_stats", None) or {}
        if scanner_stats:
            lines.append("### 测试执行统计")
            lines.append("")
            lines.append("| 指标 | 数量 |")
            lines.append("|------|------|")
            lines.append(f"| 总请求数 | {scanner_stats.get('total_requests', 0)} |")
            lines.append(f"| WAF 拦截（403/418/429/503） | {scanner_stats.get('blocked', 0)} |")
            lines.append(f"| 超时 | {scanner_stats.get('timeout', 0)} |")
            lines.append(f"| 请求异常 | {scanner_stats.get('error', 0)} |")
            if scanner_stats.get("log_suppressed"):
                lines.append(f"| 重复响应日志已抑制 | {scanner_stats.get('log_suppressed', 0)} |")
            # ★ 扫描受限标志：WAF 封禁/超时熔断时在报告中醒目标注
            _waf_blocked = scanner_stats.get("waf_blocked", False)
            _timeout_blocked = scanner_stats.get("timeout_blocked", False)
            _global_slowdown = scanner_stats.get("global_slowdown", False)
            if _waf_blocked or _timeout_blocked or _global_slowdown:
                lines.append("")
                _limits = []
                if _waf_blocked:
                    _limits.append("🔴 WAF 封禁")
                if _timeout_blocked:
                    _limits.append("🔴 超时熔断")
                if _global_slowdown:
                    _limits.append("🟡 全局降速")
                lines.append(f"> ⚠️ **扫描受限**：{' / '.join(_limits)} — 部分规则被跳过，测试覆盖度可能不完整。")
            lines.append("")

        # 覆盖矩阵
        lines.append(self.get_coverage_matrix())
        lines.append("")

        # 漏洞详情
        self._render_vuln_details(lines)

        # XSS 专项扫描
        self._render_xss_section(lines)

        # CSP 分析
        self._render_csp_section(lines)

        # 功能点测试详情
        self._render_feature_details(lines)

        # API 端点清单
        if self.apis:
            lines.append("## 6. API 端点清单")
            lines.append("")
            lines.append("| 方法 | URL | 需认证 |")
            lines.append("|------|-----|--------|")
            for key, api in sorted(self.apis.items()):
                auth = "是" if api.auth_required else "否"
                lines.append(f"| {api.method} | {api.url} | {auth} |")
            lines.append("")

        report_content = "\n".join(lines)
        self._report_path().write_text(report_content, encoding="utf-8")
        return report_content

    # ---- 报告子章节渲染 ----

    @staticmethod
    def _extract_params(evidence_request: str, fp) -> str:
        """从证据请求包或功能点 API 中提取参数名列表。"""
        params: list[str] = []
        # 1. 从 evidence_request 解析
        if evidence_request:
            lines = evidence_request.split("\n")
            for line in lines:
                line = line.strip()
                # URL query params: GET /path?param1=val&param2=val
                if "?" in line and ("GET" in line or "POST" in line):
                    url_part = line.split("?", 1)[-1].split(" ", 1)[0]
                    for pair in url_part.split("&"):
                        if "=" in pair:
                            p = pair.split("=", 1)[0]
                            if p and p not in params:
                                params.append(p)
                # POST body params: param1=val&param2=val (非 JSON)
                if "=" in line and "{" not in line and "<" not in line:
                    for pair in line.split("&"):
                        if "=" in pair:
                            p = pair.split("=", 1)[0]
                            if p and p not in params and not p.startswith("HTTP") and not p.startswith("--"):
                                params.append(p)
            # JSON body params
            import re
            json_matches = re.findall(r'"(\w+)"\s*:', evidence_request)
            for p in json_matches:
                if p not in params and p not in ("Content-Type", "Content-Length", "Host", "User-Agent", "Accept", "Cookie", "Authorization"):
                    params.append(p)
        # 2. 从 API endpoint params 补充
        if fp and hasattr(fp, 'related_apis') and fp.related_apis:
            # 尝试从 sitemap.apis 获取参数（fp 本身没有 params，但 APIEndpoint 有）
            pass
        return " / ".join(params) if params else "-"

    def _render_vuln_details(self, lines: list[str]) -> None:
        """渲染漏洞详情章节（3.1 已确认 + 3.2 疑似）。

        格式遵循标准漏洞报告模板：
        5.X [漏洞类型] 漏洞标题
        项目 / 内容（等级、类型、URL、参数、影响）
        复现步骤 / 请求 / 响应 / 截图 / 修复建议
        """
        from core.sitemap.models import Priority

        # ★ 去重：按 (vuln_type, 归一化URL) 去重，与 coverage.py 头部统计对齐，
        # 避免头部显示"3个漏洞"但详情章节列了5条的矛盾
        _seen_vuln_keys: set[str] = set()
        _seen_review_keys: set[str] = set()

        def _make_dedup_key(fp, c) -> str:
            """生成与 coverage.py _normalize_vuln_key 一致的去重键。"""
            try:
                from core.sitemap.coverage import _normalize_vuln_key
                return _normalize_vuln_key(fp, c.vuln_type)
            except Exception:
                return f"{fp.name}|{c.vuln_type}"

        vuln_details = []
        review_details = []
        for fp in self.features.values():
            for c in fp.checklist:
                if c.result == CheckResult.VULNERABLE:
                    key = _make_dedup_key(fp, c)
                    if key not in _seen_vuln_keys:
                        _seen_vuln_keys.add(key)
                        vuln_details.append((fp, c))
                elif c.result == CheckResult.NEEDS_REVIEW:
                    key = _make_dedup_key(fp, c)
                    if key not in _seen_review_keys:
                        _seen_review_keys.add(key)
                        review_details.append((fp, c))

        if vuln_details or review_details:
            lines.append("## 3. 漏洞详情")
            lines.append("")

            if vuln_details:
                lines.append(f"### 3.1 已确认漏洞（{len(vuln_details)} 个）")
                lines.append("")
            for i, (fp, c) in enumerate(vuln_details, 1):
                tested_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(c.tested_at)) if c.tested_at else "未知"
                sev = SEVERITY_LABEL.get(c.severity, "⚪ 未定级")
                vuln_url = fp.related_apis[0] if fp.related_apis else (fp.page_url or "")
                params_str = self._extract_params(c.evidence_request or "", fp)
                detail_text = c.detail.strip() if c.detail else "（未提供影响描述）"

                lines.append(f"#### 3.1.{i} [{c.vuln_type}] {fp.name}")
                lines.append("")
                lines.append(f"| 项目 | 内容 |")
                lines.append(f"|------|------|")
                lines.append(f"| 等级 | {sev} |")
                lines.append(f"| 类型 | {c.vuln_type} |")
                lines.append(f"| URL | `{vuln_url}` |")
                lines.append(f"| 参数 | {params_str} |")
                lines.append(f"| 影响 | {detail_text} |")
                lines.append("")

                # 复现步骤
                lines.append("复现步骤:")
                lines.append("")
                if c.reproduce_steps:
                    raw_steps = c.reproduce_steps.replace("\\n", "\n")
                    for step_line in raw_steps.split("\n"):
                        if step_line.strip():
                            lines.append(step_line.strip())
                    lines.append("")
                else:
                    lines.append("（未提供复现步骤）")
                    lines.append("")

                # 请求
                lines.append("请求:")
                lines.append("")
                if c.evidence_request:
                    lines.append("```http")
                    lines.append(c.evidence_request)
                    lines.append("```")
                    lines.append("")
                elif c.evidence_flow_id:
                    lines.append(f"> 证据 flow_id: `{c.evidence_flow_id}`（可通过 proxy_get_flow_detail 查看完整数据包）")
                    lines.append("")
                else:
                    lines.append("（无请求包）")
                    lines.append("")

                # 响应
                lines.append("响应:")
                lines.append("")
                if c.evidence_response:
                    lines.append("```http")
                    lines.append(c.evidence_response)
                    lines.append("```")
                    lines.append("")
                else:
                    lines.append("（无响应包）")
                    lines.append("")

                # 截图
                lines.append("截图: （如有）")
                lines.append("")

                # 修复建议
                lines.append("修复建议:")
                lines.append("")
                if c.fix_suggestion:
                    raw_fix = c.fix_suggestion.replace("\\n", "\n")
                    for fix_line in raw_fix.split("\n"):
                        if fix_line.strip():
                            lines.append(fix_line.strip())
                    lines.append("")
                else:
                    lines.append("（未提供修复建议）")
                    lines.append("")

                lines.append("---")
                lines.append("")

            if review_details:
                lines.append(f"### 3.2 疑似漏洞（需人工确认，共 {len(review_details)} 项）")
                lines.append("")
                lines.append("> 以下项目在自动测试中出现可疑信号但未达到自动判定标准，"
                             "建议人工根据下面的请求/响应证据进一步研判。")
                lines.append("")

                for i, (fp, c) in enumerate(review_details, 1):
                    tested_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(c.tested_at)) if c.tested_at else "未知"
                    sev = SEVERITY_LABEL.get(c.severity, "⚪ 未定级")
                    vuln_url = fp.related_apis[0] if fp.related_apis else (fp.page_url or "")
                    params_str = self._extract_params(c.evidence_request or "", fp)
                    detail_text = c.detail.strip() if c.detail else "（未提供怀疑依据）"

                    lines.append(f"#### 3.2.{i} [{c.vuln_type}] {fp.name}")
                    lines.append("")
                    lines.append(f"| 项目 | 内容 |")
                    lines.append(f"|------|------|")
                    lines.append(f"| 等级 | {sev} |")
                    lines.append(f"| 类型 | {c.vuln_type} |")
                    lines.append(f"| URL | `{vuln_url}` |")
                    lines.append(f"| 参数 | {params_str} |")
                    lines.append(f"| 影响 | {detail_text} |")
                    lines.append("")

                    # 复现步骤
                    lines.append("复现步骤:")
                    lines.append("")
                    if c.reproduce_steps:
                        for step_line in c.reproduce_steps.replace("\\n", "\n").split("\n"):
                            if step_line.strip():
                                lines.append(step_line.strip())
                        lines.append("")
                    else:
                        lines.append("（未提供复现步骤）")
                        lines.append("")

                    # 请求
                    lines.append("请求:")
                    lines.append("")
                    if c.evidence_request:
                        lines.append("```http")
                        lines.append(c.evidence_request)
                        lines.append("```")
                        lines.append("")
                    elif c.evidence_flow_id:
                        lines.append(f"> 证据 flow_id: `{c.evidence_flow_id}`（可通过 proxy_get_flow_detail 查看完整数据包）")
                        lines.append("")
                    else:
                        lines.append("（无请求包）")
                        lines.append("")

                    # 响应
                    lines.append("响应:")
                    lines.append("")
                    if c.evidence_response:
                        lines.append("```http")
                        lines.append(c.evidence_response)
                        lines.append("```")
                        lines.append("")
                    else:
                        lines.append("（无响应包）")
                        lines.append("")

                    # 截图
                    lines.append("截图: （如有）")
                    lines.append("")

                    # 修复建议
                    lines.append("修复建议:")
                    lines.append("")
                    if c.fix_suggestion:
                        for fix_line in c.fix_suggestion.replace("\\n", "\n").split("\n"):
                            if fix_line.strip():
                                lines.append(fix_line.strip())
                        lines.append("")
                    else:
                        lines.append("（未提供修复建议）")
                        lines.append("")

                    lines.append("**人工确认建议**：")
                    lines.append("")
                    lines.append("- [ ] 复现请求并对比正常响应，看异常信号是否稳定出现")
                    lines.append("- [ ] 检查响应中的关键字段是否真的暴露了越权数据 / 注入回显 / 异常信息")
                    lines.append("- [ ] 若确认是漏洞 → 在 sitemap 中改标 `vulnerable` 并补充 PoC")
                    lines.append("- [ ] 若确认是误报 → 改标 `not_vuln` 并简述判定依据")
                    lines.append("")
                    lines.append("---")
                    lines.append("")
        else:
            lines.append("## 3. 漏洞详情")
            lines.append("")
            lines.append("暂未发现漏洞。")
            lines.append("")

    def _render_xss_section(self, lines: list[str]) -> None:
        """渲染 XSS 专项扫描章节（3.5）。"""
        xss_findings = getattr(self, "xss_findings", None) or []
        if not xss_findings:
            return

        confirmed = [f for f in xss_findings if f.get("status") == "confirmed"]
        review = [f for f in xss_findings if f.get("status") == "needs_review"]
        fp_xss = [f for f in xss_findings if f.get("status") == "false_positive"]

        lines.append("## 3.5 XSS 专项扫描结果")
        lines.append("")
        lines.append(
            f"扫描完成。共发现 **{len(confirmed)} 个确认漏洞**、"
            f"**{len(review)} 个待复核**、"
            f"{len(fp_xss)} 个误报已过滤。"
        )
        lines.append("")

        if confirmed:
            lines.append("### ✅ 已确认的 XSS 漏洞")
            lines.append("")
            for i, f in enumerate(confirmed, 1):
                sev = SEVERITY_LABEL.get(f.get("severity", "medium"), "⚪")
                lines.append(f"#### XSS-{i}: {f.get('title', '')}")
                lines.append("")
                lines.append(f"| 项目 | 内容 |")
                lines.append(f"|------|------|")
                lines.append(f"| **类型** | {f.get('xss_type', '?')} XSS |")
                lines.append(f"| **等级** | {sev} |")
                lines.append(f"| **URL** | `{f.get('url','')}` |")
                lines.append(f"| **方法** | {f.get('method', 'GET')} |")
                lines.append(f"| **注入点** | {f.get('injection_point', '')} 参数 `{f.get('param', '')}` |")
                lines.append(f"| **Payload** | `{(f.get('payload','') or '')[:200]}` |")
                if f.get("echo_contexts"):
                    lines.append(f"| **回显上下文** | {', '.join(f['echo_contexts'])} |")
                if f.get("browser_triggered"):
                    lines.append(f"| **浏览器实测** | ✅ 已触发 ({f.get('browser_evidence', '')[:80]}) |")
                lines.append(f"| **置信度** | {f.get('judge_confidence', 0):.2f} |")
                lines.append("")
                if f.get("description"):
                    lines.append(f"**漏洞描述**：{f['description']}")
                    lines.append("")
                if f.get("reproduce_steps"):
                    lines.append("**复现步骤**：")
                    lines.append("")
                    for step in f["reproduce_steps"].replace("\\n", "\n").split("\n"):
                        if step.strip():
                            lines.append(step.strip())
                    lines.append("")
                if f.get("fix_suggestion"):
                    lines.append("**修复建议**：")
                    lines.append("")
                    for fix in f["fix_suggestion"].replace("\\n", "\n").split("\n"):
                        if fix.strip():
                            lines.append(fix.strip())
                    lines.append("")
                if f.get("judge_reasoning"):
                    lines.append(f"<details><summary>LLM 研判理由</summary>\n\n{f['judge_reasoning']}\n\n</details>")
                    lines.append("")
                lines.append("---")
                lines.append("")

        if review:
            lines.append("### 🟡 待复核的 XSS 候选")
            lines.append("")
            lines.append("| # | URL | 参数 | Payload | 上下文 | 置信度 |")
            lines.append("|---|-----|------|---------|--------|--------|")
            for i, f in enumerate(review[:30], 1):
                url = (f.get('url') or '')[:50]
                param = f.get('param', '')
                payload = (f.get('payload', '') or '')[:60].replace("|", "\\|")
                ctx = ", ".join((f.get('echo_contexts') or [])[:2])
                conf = f.get('judge_confidence', 0)
                lines.append(f"| {i} | `{url}` | `{param}` | `{payload}` | {ctx} | {conf:.2f} |")
            lines.append("")
            if len(review) > 30:
                lines.append(f"> 还有 {len(review) - 30} 个待复核候选未在此列出。")
                lines.append("")

            lines.append("#### 🟡 待复核明细")
            lines.append("")
            for i, f in enumerate(review[:30], 1):
                sev = SEVERITY_LABEL.get(f.get("severity", "medium"), "⚪")
                lines.append(f"**复核 {i}: {f.get('title', '') or f.get('xss_type','XSS') + ' 候选'}**")
                lines.append("")
                lines.append(f"| 项目 | 内容 |")
                lines.append(f"|------|------|")
                lines.append(f"| **类型** | {f.get('xss_type', '?')} XSS |")
                lines.append(f"| **风险等级（候选）** | {sev} |")
                lines.append(f"| **URL** | `{f.get('url','')}` |")
                lines.append(f"| **方法** | {f.get('method', 'GET')} |")
                lines.append(f"| **注入点** | {f.get('injection_point', '')} 参数 `{f.get('param', '')}` |")
                lines.append(f"| **Payload** | `{(f.get('payload','') or '')[:200]}` |")
                if f.get("echo_contexts"):
                    lines.append(f"| **回显上下文** | {', '.join(f['echo_contexts'])} |")
                lines.append(f"| **置信度** | {f.get('judge_confidence', 0):.2f} |")
                lines.append("")
                if f.get("description"):
                    lines.append(f"**怀疑依据**：{f['description']}")
                    lines.append("")
                if f.get("judge_reasoning"):
                    lines.append(f"<details><summary>LLM 研判理由</summary>\n\n{f['judge_reasoning']}\n\n</details>")
                    lines.append("")
                lines.append("---")
                lines.append("")

        if fp_xss:
            lines.append(f"### ⚪ 已过滤的误报候选（{len(fp_xss)} 个）")
            lines.append("")
            lines.append("> 以下 XSS 候选被自动判定为误报。建议抽查置信度高的项确认判定是否准确。")
            lines.append("")
            lines.append("| # | URL | 参数 | Payload | 上下文 | 误报理由 |")
            lines.append("|---|-----|------|---------|--------|----------|")
            for i, f in enumerate(fp_xss[:30], 1):
                url = (f.get('url') or '')[:50]
                param = f.get('param', '')
                payload = (f.get('payload', '') or '')[:60].replace("|", "\\|")
                ctx = ", ".join((f.get('echo_contexts') or [])[:2])
                reason = (f.get('judge_reasoning') or f.get('description') or '')[:120].replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {i} | `{url}` | `{param}` | `{payload}` | {ctx} | {reason} |")
            lines.append("")
            if len(fp_xss) > 30:
                lines.append(f"> 还有 {len(fp_xss) - 30} 个误报候选未在此列出。")
                lines.append("")

        # 扫描器类型分布
        from collections import Counter
        xss_type_counter = Counter()
        for f in xss_findings:
            xss_type_counter[f.get("xss_type", "unknown")] += 1
        if xss_type_counter:
            lines.append("### 📊 XSS 类型分布")
            lines.append("")
            lines.append("| XSS 类型 | 数量 |")
            lines.append("|---------|------|")
            for tn, cnt in xss_type_counter.most_common():
                lines.append(f"| {tn} | {cnt} |")
            lines.append("")

        lines.append("")

    def _render_csp_section(self, lines: list[str]) -> None:
        """渲染 CSP 分析章节（3.6）。"""
        csp_analyses = getattr(self, "csp_analyses", None) or {}
        if not csp_analyses:
            return

        lines.append("## 3.6 CSP / 响应头安全策略分析")
        lines.append("")
        lines.append(f"扫描了 **{len(csp_analyses)} 个 host** 的 CSP 配置。")
        lines.append("")
        lines.append("| Host | 评分 | 缓解强度 | report-only | Bypass 路径数 |")
        lines.append("|------|------|---------|-------------|---------------|")
        for host, csp in csp_analyses.items():
            if isinstance(csp, dict):
                score = csp.get("score", 0)
                mit = csp.get("mitigation_level", "?")
                ro = csp.get("report_only", False)
                bypass_count = len(csp.get("bypass_paths", []) or [])
            else:
                score = getattr(csp, "score", 0)
                mit = getattr(csp, "mitigation_level", "?")
                ro = getattr(csp, "report_only", False)
                bypass_count = len(getattr(csp, "bypass_paths", []) or [])
            ro_str = "是 ⚠️" if ro else "否"
            lines.append(f"| `{host}` | {score:.1f}/10 | {mit} | {ro_str} | {bypass_count} |")
        lines.append("")
        for host, csp in csp_analyses.items():
            if isinstance(csp, dict):
                bypass = csp.get("bypass_paths", []) or []
                raw = csp.get("raw_header", "")
            else:
                bypass = getattr(csp, "bypass_paths", []) or []
                raw = getattr(csp, "raw_header", "")
            if not bypass:
                continue
            lines.append(f"#### `{host}` 的 CSP bypass 路径")
            lines.append("")
            if raw:
                lines.append(f"原始 CSP header:\n\n```\n{raw[:1000]}\n```")
                lines.append("")
            for bp in bypass:
                lines.append(f"- {bp}")
            lines.append("")
        lines.append("")

    def _render_feature_details(self, lines: list[str]) -> None:
        """渲染功能点测试详情章节（4）。"""
        from core.sitemap.models import Priority

        lines.append("## 4. 功能点测试详情")
        lines.append("")

        priority_order = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3}
        sorted_features = sorted(self.features.values(), key=lambda f: priority_order.get(f.priority, 9))

        modules: OrderedDict[str, list[FeaturePoint]] = OrderedDict()
        for fp in sorted_features:
            mod = fp.module or "其他"
            if mod not in modules:
                modules[mod] = []
            modules[mod].append(fp)

        for mod_name, fps in modules.items():
            vuln_in_mod = sum(1 for fp in fps for c in fp.checklist if c.result == CheckResult.VULNERABLE)
            mod_suffix = f" — 🔴 {vuln_in_mod} 个漏洞" if vuln_in_mod else ""
            lines.append(f"### 📁 {mod_name}（{len(fps)} 个功能点）{mod_suffix}")
            lines.append("")

            for fp in fps:
                lines.append(f"#### {fp.name} [{fp.priority.value}] — {TEST_STATUS_ICON_WITH_TEXT.get(fp.test_status, '未知')}")
                lines.append("")
                if fp.description:
                    lines.append(f"- 描述: {fp.description}")
                if fp.page_url:
                    lines.append(f"- 页面: {fp.page_url}")
                if fp.related_apis:
                    lines.append(f"- API: {', '.join(fp.related_apis[:5])}")
                lines.append("")

                if fp.checklist:
                    lines.append(f"| 漏洞类型 | 结果 | 详情 |")
                    lines.append(f"|---------|------|------|")
                    for c in fp.checklist:
                        result_text = CHECK_RESULT_ICON_WITH_TEXT.get(c.result, "?")
                        detail = c.detail[:200] if c.detail else "-"
                        lines.append(f"| {c.vuln_type} | {result_text} | {detail} |")
                    lines.append("")
