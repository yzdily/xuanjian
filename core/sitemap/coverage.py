"""Sitemap — 覆盖率统计 + 覆盖矩阵 Mixin。"""

from __future__ import annotations

import logging
from typing import Any

from core.sitemap.models import FeaturePoint, CheckItem, CheckResult, Priority, TestStatus
from core.config import (
    BROWSER_REQUIRED_VULNS, VULN_TO_SKILL, VULN_DETAIL_HINTS,
)
from core.sitemap.constants import CHECK_RESULT_ICON

log = logging.getLogger("pentest_agent.sitemap")


class CoverageMixin:
    """覆盖率统计、覆盖矩阵、checklist 查询。"""

    def activate_deferred(self) -> list[FeaturePoint]:
        """激活所有 deferred 功能点：补生成 checklist，标记为可测试。"""
        activated = []
        for fp in self.features.values():
            if fp.deferred:
                fp.deferred = False
                auto_tests = self._auto_suggest_tests(fp.name, fp.description, fp.priority, fp.related_apis)
                # ★ 上下文感知过滤
                auto_tests = self._context_filter_tests(auto_tests, fp.related_apis, fp.description)
                act_has_page = self._has_frontend_page(fp.page_url)
                fp.checklist = [CheckItem(
                    vuln_type=t,
                    needs_browser=(t in BROWSER_REQUIRED_VULNS)
                ) for t in auto_tests]
                activated.append(fp)
        return activated

    def start_test(self, feature_id: str) -> None:
        if feature_id in self.features:
            self.features[feature_id].test_status = TestStatus.IN_PROGRESS
            self.features[feature_id].test_started_at = __import__("time").time()

    def finish_test(self, feature_id: str, reason: str = "normal") -> None:
        """结束功能点测试，将剩余 PENDING 项标记为 SKIPPED。

        reason:
        - "normal": worker 正常完成（LLM 调 worker_done 或所有项已 mark）
        - "anti_loop": 反内卷强制收尾（worker 多轮无进展）
        - "error": worker 异常退出（LLM 崩溃/超时/网络错误）
        - "single_packet": 单包模式跳过浏览器测试
        reason 会写进每个 SKIPPED 项的 detail，让报告能区分
        "接口无漏洞" vs "worker 崩溃没测到"。
        """
        if feature_id in self.features:
            fp = self.features[feature_id]
            fp.test_finished_at = __import__("time").time()

            # 将所有 PENDING 项标记为 SKIPPED（测试结束未覆盖的项）
            # ★ 补全 detail：区分正常结束 vs 异常退出，让报告"跳过原因"列有实际内容
            reason_detail_map = {
                "normal": "测试流程正常结束，该项未被 worker 覆盖（可能不适用或预算耗尽）",
                "anti_loop": "反内卷强制收尾：worker 多轮无进展，该项未测",
                "error": "⚠️ worker 异常退出（LLM 崩溃/超时/网络错误），该项未测，建议人工补测",
                "single_packet": "单包模式跳过浏览器测试",
            }
            skip_detail = reason_detail_map.get(reason, reason_detail_map["normal"])

            for c in fp.checklist:
                if c.result == CheckResult.PENDING:
                    c.result = CheckResult.SKIPPED
                    # 保留已有 detail（反内卷抢救的 needs_review 不应被覆盖）
                    if not c.detail:
                        c.detail = skip_detail

            has_vuln = any(c.result == CheckResult.VULNERABLE for c in fp.checklist)

            if has_vuln:
                fp.test_status = TestStatus.VULN_FOUND
            else:
                fp.test_status = TestStatus.TESTED

    def get_coverage(self) -> dict[str, Any]:
        active = [f for f in self.features.values() if f.checklist]
        deferred_count = sum(1 for f in self.features.values() if f.deferred)
        total = len(active)

        # ★ 按 API 路径去重计数，与 get_coverage_matrix 的去重逻辑保持一致，
        # 避免报告头部「功能点 N」与矩阵行数不一致。
        from urllib.parse import urlparse
        seen_api_keys: set[str] = set()
        for f in active:
            dedup_key = ""
            if f.related_apis:
                first_api = f.related_apis[0]
                api_url = first_api.split(" ", 1)[-1] if " " in first_api else first_api
                pu = urlparse(api_url)
                dedup_key = f"{pu.netloc.lower()}{pu.path}".rstrip("/")
            elif f.page_url:
                pu = urlparse(f.page_url)
                dedup_key = f"{pu.netloc.lower()}{pu.path}".rstrip("/")
            if dedup_key:
                seen_api_keys.add(dedup_key)
            else:
                # 无 API 也无 page_url 的功能点单独计数
                seen_api_keys.add(f"_noid_{f.id}")
        total_deduped = len(seen_api_keys)

        if total == 0:
            return {"total": 0, "total_deduped": 0, "tested": 0, "coverage": 0, "vulns": 0,
                    "vuln_items": 0, "vuln_list": [],
                    "checks_total": 0, "checks_done": 0, "deferred": deferred_count,
                    "phase_status": getattr(self, "phase_status", ""),
                    "termination_reason": getattr(self, "termination_reason", ""),
                    "fast_scanner_stats": getattr(self, "_fast_scanner_stats", None) or {},}
        tested = sum(1 for f in active
                     if f.test_status in (TestStatus.TESTED, TestStatus.VULN_FOUND))
        vulns = sum(1 for f in active
                    if f.test_status == TestStatus.VULN_FOUND)
        checks_total = sum(len(f.checklist) for f in active)
        checks_done = sum(1 for f in active
                         for c in f.checklist if c.result != CheckResult.PENDING)

        seen_vulns: set[str] = set()
        vuln_list: list[dict[str, str]] = []
        # ★ 同时统计已确认(vulnerable)与疑似(needs_review)，避免报告头部
        # "发现漏洞"只算 confirmed、把疑似项完全隐藏，导致用户误以为 0 漏洞。
        # 疑似项 severity 后缀 "(疑似)" 便于报告区分展示。
        for f in active:
            for c in f.checklist:
                if c.result == CheckResult.VULNERABLE:
                    dedup_key = f"{f.name}|{c.vuln_type}"
                    if dedup_key not in seen_vulns:
                        seen_vulns.add(dedup_key)
                        sev = c.severity or ("critical" if f.priority.value in ("critical",) else "high")
                        vuln_list.append({
                            "feature": f.name,
                            "vuln_type": c.vuln_type,
                            "detail": c.detail,
                            "severity": sev,
                            "status": "confirmed",
                        })
                elif c.result == CheckResult.NEEDS_REVIEW:
                    dedup_key = f"{f.name}|{c.vuln_type}|suspected"
                    if dedup_key not in seen_vulns:
                        seen_vulns.add(dedup_key)
                        sev = c.severity or "medium"
                        vuln_list.append({
                            "feature": f.name,
                            "vuln_type": c.vuln_type,
                            "detail": c.detail,
                            "severity": sev,
                            "status": "suspected",
                        })

        return {
            "total": total,
            "total_deduped": total_deduped,
            "tested": tested,
            "coverage": round(tested / total * 100, 1),
            "not_tested": total - tested,
            "vulns": len(vuln_list),
            "vuln_features": vulns,
            "vuln_items": len(vuln_list),
            "vuln_list": vuln_list,
            "checks_total": checks_total,
            "checks_done": checks_done,
            "deferred": deferred_count,
            # Phase 状态与终止原因（由 orchestrator 设置）
            "phase_status": getattr(self, "phase_status", ""),
            "termination_reason": getattr(self, "termination_reason", ""),
            "fast_scanner_stats": getattr(self, "_fast_scanner_stats", None) or {},
        }

    def reclaim_unused_api_slots(self) -> dict:
        """回收被 MAX_API_TEST_OWNERS 占坑但实际未测试的 API 计数。"""
        from core.config import BROWSER_REQUIRED_VULNS

        actual_count: dict[str, int] = {}
        for fp in self.features.values():
            if not fp.checklist:
                continue
            has_real_result = any(c.result != CheckResult.PENDING for c in fp.checklist)
            if not has_real_result:
                continue
            for api in fp.related_apis:
                key = self._normalize_api_key(api)
                if key:
                    actual_count[key] = actual_count.get(key, 0) + 1

        reclaimed = 0
        for key, booked in list(self._api_test_count.items()):
            actual = actual_count.get(key, 0)
            if actual < booked:
                self._api_test_count[key] = actual
                reclaimed += 1

        reactivated = 0
        for fp in self.features.values():
            if fp.test_status != TestStatus.TESTED or fp.checklist:
                continue
            if "跳过重复测试" not in fp.description:
                continue

            all_saturated = True
            for api in fp.related_apis:
                key = self._normalize_api_key(api)
                if self._api_test_count.get(key, 0) < self.MAX_API_TEST_OWNERS:
                    all_saturated = False
                    break

            if not all_saturated:
                vulns = self._infer_vulns_from_api(
                    fp.related_apis[0].split(" ")[0] if " " in fp.related_apis[0] else "GET",
                    fp.related_apis[0] if fp.related_apis else "",
                )
                has_page = self._has_frontend_page(fp.page_url)
                fp.checklist = [CheckItem(
                    vuln_type=v,
                    needs_browser=(v in BROWSER_REQUIRED_VULNS),
                ) for v in vulns]
                fp.test_status = TestStatus.NOT_TESTED
                fp.description = fp.description.replace("（API 已被 ", "（已回收，原").rstrip("）") + "，重新测试）"
                for api in fp.related_apis:
                    key = self._normalize_api_key(api)
                    if key:
                        self._api_test_count[key] = self._api_test_count.get(key, 0) + 1
                reactivated += 1

        return {"reclaimed_apis": reclaimed, "reactivated_features": reactivated}

    def get_untested_features(self) -> list[FeaturePoint]:
        priority_order = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3}
        untested = [f for f in self.features.values()
                    if f.test_status in (TestStatus.NOT_TESTED, TestStatus.IN_PROGRESS)
                    and f.checklist]
        return sorted(untested, key=lambda f: priority_order.get(f.priority, 9))

    def get_coverage_matrix(self) -> str:
        """生成动态多级功能清单 + 测试覆盖矩阵。"""
        if not self.features:
            return "暂无功能点数据"

        lines = ["## 测试覆盖矩阵\n"]
        lines.append("图例: 🔴=存在漏洞  ✅=已测无漏洞  🟡=需人工确认  ⬜=未测  ➖=不适用\n")

        priority_order = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3}
        sorted_features = sorted(self.features.values(), key=lambda f: priority_order.get(f.priority, 9))

        # ★ 按 API 路径去重：爬虫自动生成的功能点与业务理解生成的功能点可能
        # 指向同一组 API，在矩阵中重复出现且状态矛盾。这里以「首条 API 路径」
        # 为键去重，保留优先级更高（critical > high）的那条。
        seen_api_keys: dict[str, FeaturePoint] = {}
        for fp in sorted_features:
            # 取第一条 API 的 host+path 作为去重键
            dedup_key = ""
            if fp.related_apis:
                first_api = fp.related_apis[0]
                # 形如 "GET https://host/path" → 取 path 部分
                api_url = first_api.split(" ", 1)[-1] if " " in first_api else first_api
                from urllib.parse import urlparse
                pu = urlparse(api_url)
                dedup_key = f"{pu.netloc.lower()}{pu.path}".rstrip("/")
            elif fp.page_url:
                from urllib.parse import urlparse
                pu = urlparse(fp.page_url)
                dedup_key = f"{pu.netloc.lower()}{pu.path}".rstrip("/")
            if not dedup_key:
                # 无 API 也无 page_url 的功能点不去重，直接保留
                seen_api_keys[f"_noid_{fp.id}"] = fp
                continue
            if dedup_key in seen_api_keys:
                # 已存在：保留优先级更高的那条（priority_order 值越小优先级越高）
                existing = seen_api_keys[dedup_key]
                if priority_order.get(fp.priority, 9) < priority_order.get(existing.priority, 9):
                    seen_api_keys[dedup_key] = fp
            else:
                seen_api_keys[dedup_key] = fp

        deduped_features = list(seen_api_keys.values())
        # 重新按优先级排序（去重后顺序可能变化）
        deduped_features.sort(key=lambda f: priority_order.get(f.priority, 9))

        rows: list[tuple[list[str], FeaturePoint]] = []
        max_depth = 1
        for fp in deduped_features:
            mod = fp.module or "其他"
            levels = [lv.strip() for lv in mod.split("/") if lv.strip()]
            if not levels:
                levels = ["其他"]
            max_depth = max(max_depth, len(levels))
            rows.append((levels, fp))

        level_names = ["一级模块", "二级功能", "三级功能", "四级功能", "五级功能"]
        header_parts = []
        sep_parts = []
        for i in range(max_depth):
            col_name = level_names[i] if i < len(level_names) else f"{i+1}级"
            header_parts.append(f" {col_name} ")
            sep_parts.append("--------")
        header = "|" + "|".join(header_parts) + "| 功能点 | API / 页面路径 | 优先级 | 测试结果 |"
        sep = "|" + "|".join(sep_parts) + "|--------|---------------|--------|---------|"
        lines.append(header)
        lines.append(sep)

        rows.sort(key=lambda r: (r[0], priority_order.get(r[1].priority, 9)))

        prev_levels: list[str] = [""] * max_depth
        vuln_count = 0

        for levels, fp in rows:
            padded = levels + [""] * (max_depth - len(levels))

            results_parts = []
            for c in fp.checklist:
                icon = CHECK_RESULT_ICON.get(c.result, "⬜")
                if c.result == CheckResult.VULNERABLE:
                    vuln_count += 1
                    results_parts.append(f"{icon}{c.vuln_type}")
                elif c.result in (CheckResult.NOT_VULN, CheckResult.NEEDS_REVIEW):
                    results_parts.append(f"{icon}{c.vuln_type}")
            pending_count = len([c for c in fp.checklist if c.result == CheckResult.PENDING])
            display = " ".join(results_parts) if results_parts else "—"
            if pending_count > 0:
                display += f" ⬜×{pending_count}"

            api_display = ""
            if fp.related_apis:
                api_display = "<br>".join(fp.related_apis[:2])
                if len(fp.related_apis) > 2:
                    api_display += f"<br>+{len(fp.related_apis)-2}个"
            elif fp.page_url:
                from urllib.parse import urlparse
                api_display = urlparse(fp.page_url).path or "/"

            level_cells = []
            for i in range(max_depth):
                val = padded[i]
                if val and val != prev_levels[i]:
                    level_cells.append(f"**{val}**")
                    for j in range(i + 1, max_depth):
                        prev_levels[j] = ""
                else:
                    level_cells.append("")
                prev_levels[i] = val

            name_short = fp.name[:35] + "…" if len(fp.name) > 35 else fp.name
            row = "| " + " | ".join(level_cells) + f" | {name_short} | {api_display} | {fp.priority.value} | {display} |"
            lines.append(row)

        cov = self.get_coverage()
        top_modules = len(set(r[0][0] for r in rows if r[0]))
        lines.append(f"\n**统计**: {top_modules} 个一级模块, {len(rows)} 个功能点, "
                     f"{cov['checks_done']}/{cov['checks_total']} 项测试完成, "
                     f"发现 {vuln_count} 个漏洞")

        return "\n".join(lines)

    def get_feature_checklist_for_llm(self, feature_id: str) -> str:
        """获取某功能点的 checklist（给 LLM 看）。"""
        fp = self.features.get(feature_id)
        if not fp:
            return "功能点不存在"

        lines = [
            f"## {fp.name} — 测试 Checklist\n",
            f"优先级: {fp.priority.value}",
            f"页面: {fp.page_url}",
            f"关联 API: {', '.join(fp.related_apis) if fp.related_apis else '待发现'}",
            "",
        ]

        pending = fp.get_pending_checks()
        completed = fp.get_completed_checks()

        if pending:
            lines.append(f"### 待测试 ({len(pending)} 项)")
            for c in pending:
                skill_hint = VULN_TO_SKILL.get(c.vuln_type, "")
                browser_tag = " 🌐" if c.needs_browser else ""
                detail_hint = VULN_DETAIL_HINTS.get(c.vuln_type, "")
                if skill_hint:
                    lines.append(f"⬜ **{c.vuln_type}**{browser_tag} → `knowledge_load_skill(\"{skill_hint}\")`")
                else:
                    lines.append(f"⬜ **{c.vuln_type}**{browser_tag} → 用 `knowledge_search` 搜索方法论")
                if detail_hint:
                    lines.append(f"   💡 {detail_hint}")

        if completed:
            lines.append(f"\n### 已完成 ({len(completed)} 项)")
            for c in completed:
                icon = CHECK_RESULT_ICON.get(c.result, "?")
                lines.append(f"{icon} **{c.vuln_type}** — {c.detail or c.result.value}")

        return "\n".join(lines)

    def to_summary(self) -> str:
        """站点地图摘要（给 LLM 看）。"""
        cov = self.get_coverage()
        lines = [
            f"## 站点地图摘要",
            f"- 目标: {self.target}",
            f"- 技术栈: {self.tech_stack or '待识别'}",
            f"- 业务类型: {self.business_summary or '待分析'}",
            f"- 页面: {len(self.pages)} 个",
            f"- API 端点: {len(self.apis)} 个",
            f"- 活跃功能点: {cov['total']} 个",
            f"- 测试项: {cov['checks_done']}/{cov['checks_total']} 完成",
            f"- 已发现漏洞: {cov['vulns']} 个",
        ]
        if cov.get('deferred', 0) > 0:
            lines.append(f"- 待激活功能点（需登录后台）: {cov['deferred']} 个")

        untested = self.get_untested_features()
        if untested:
            lines.append(f"\n### 待测试功能点 (按优先级)")
            for f in untested[:10]:
                pending = len(f.get_pending_checks())
                lines.append(f"- [{f.priority.value}] **{f.name}** — {pending} 项待测")

        deferred = [f for f in self.features.values() if f.deferred]
        if deferred:
            lines.append(f"\n### 待激活功能点（需突破登录后激活）")
            for f in deferred:
                lines.append(f"- 🔒 [{f.priority.value}] {f.name} — {f.description[:40]}")

        tested_with_vulns = [f for f in self.features.values() if f.test_status == TestStatus.VULN_FOUND]
        if tested_with_vulns:
            lines.append(f"\n### 已发现漏洞")
            for f in tested_with_vulns:
                vulns = [c for c in f.checklist if c.result == CheckResult.VULNERABLE]
                for v in vulns:
                    lines.append(f"- 🔴 {f.name} → {v.vuln_type}: {v.detail[:60]}")

        return "\n".join(lines)
