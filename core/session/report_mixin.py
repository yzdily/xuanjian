"""
ReportMixin — 报告增量更新相关方法。

方法：
- _current_vuln_keys: 当前 sitemap 已确认漏洞去重键集合
- _snapshot_report_state: 记录报告阶段关键指标快照
- _compute_report_delta: 比对当前 sitemap 与上次报告快照
"""

from __future__ import annotations

from core.log import get_logger

log = get_logger("session.report")


class ReportMixin:
    """报告增量更新相关方法。"""

    def _current_vuln_keys(self) -> set[str]:
        """当前 sitemap 已确认的漏洞去重键集合：'feature_name|vuln_type'。"""
        if not self.sitemap:
            return set()
        try:
            cov = self.sitemap.get_coverage()
        except Exception:
            return set()
        keys: set[str] = set()
        for v in cov.get("vuln_list", []) or []:
            keys.add(f"{v.get('feature', '')}|{v.get('vuln_type', '')}")
        return keys

    def _snapshot_report_state(self) -> None:
        """记录本次进入报告阶段时的关键指标，作为下次增量判断的基线。"""
        if not self.sitemap:
            self._last_report_snapshot = {"vulns": 0, "tested": 0, "total": 0, "vuln_keys": set()}
            return
        try:
            cov = self.sitemap.get_coverage()
        except Exception:
            cov = {}
        self._last_report_snapshot = {
            "vulns": int(cov.get("vulns", 0) or 0),
            "tested": int(cov.get("tested", 0) or 0),
            "total": int(cov.get("total", 0) or 0),
            "vuln_keys": self._current_vuln_keys(),
        }

    def _compute_report_delta(self) -> dict:
        """比对当前 sitemap 与上次报告快照，输出 delta 摘要供 LLM 参考。"""
        if not self.sitemap:
            return {
                "changed": False,
                "new_vulns": 0,
                "new_features": 0,
                "tested_now": 0,
                "total_now": 0,
                "summary": "（无 sitemap，无法计算 delta）",
                "new_vuln_keys": [],
            }
        try:
            cov = self.sitemap.get_coverage()
        except Exception as e:
            return {
                "changed": False,
                "new_vulns": 0,
                "new_features": 0,
                "tested_now": 0,
                "total_now": 0,
                "summary": f"（获取覆盖率失败: {e}）",
                "new_vuln_keys": [],
            }

        now_keys = self._current_vuln_keys()
        now_vulns = int(cov.get("vulns", 0) or 0)
        now_tested = int(cov.get("tested", 0) or 0)
        now_total = int(cov.get("total", 0) or 0)

        snap = self._last_report_snapshot
        if snap is None:
            # 首次进入：把当前所有漏洞都视为"新增"，确保第一次追问也会触发重报
            new_vuln_keys = sorted(now_keys)
            new_vulns = now_vulns
            new_features = now_total
            prev_summary = "（无上次报告快照，本轮视为首次报告生成）"
        else:
            new_vuln_keys = sorted(now_keys - snap.get("vuln_keys", set()))
            new_vulns = len(new_vuln_keys)
            new_features = max(0, now_total - int(snap.get("total", 0) or 0))
            prev_summary = (
                f"上次报告时：已测 {snap.get('tested', 0)}/{snap.get('total', 0)}，"
                f"漏洞 {snap.get('vulns', 0)} 个"
            )

        changed = (new_vulns > 0) or (new_features > 0) or (now_tested != (snap or {}).get("tested", -1))

        # 拼接 LLM 可读的摘要
        lines = [
            prev_summary,
            f"本次：已测 {now_tested}/{now_total}，漏洞 {now_vulns} 个",
            f"新增漏洞：{new_vulns} 个" + (f" → {', '.join(new_vuln_keys[:10])}" if new_vuln_keys else ""),
            f"新增功能点：{new_features} 个",
        ]
        return {
            "changed": bool(changed),
            "new_vulns": new_vulns,
            "new_features": new_features,
            "tested_now": now_tested,
            "total_now": now_total,
            "summary": "\n".join(lines),
            "new_vuln_keys": new_vuln_keys,
        }

    def _compute_real_completion(self) -> dict:
        """计算真实完成率，区分真实检测与跳过。

        返回:
            real_done: 真实完成检查数（NOT_VULN + VULNERABLE + NEEDS_REVIEW）
            skipped: 跳过检查数（SKIPPED）
            pending: 待测检查数（PENDING）
            total: 总检查数
            real_rate: 真实完成率 = real_done / total
            skip_rate: 跳过率 = skipped / total
        """
        if not self.sitemap:
            return {"real_done": 0, "skipped": 0, "pending": 0, "total": 0,
                    "real_rate": 0.0, "skip_rate": 0.0, "pending_rate": 0.0}
        try:
            cov = self.sitemap.get_coverage()
        except Exception:
            return {"real_done": 0, "skipped": 0, "pending": 0, "total": 0,
                    "real_rate": 0.0, "skip_rate": 0.0, "pending_rate": 0.0}

        from core.sitemap.constants import CheckResult
        real_done = 0
        skipped = 0
        pending = 0
        total = 0
        # ★ P0-2: validated/speculative 分母解耦
        valid_done = 0
        valid_total = 0
        spec_done = 0
        spec_total = 0
        try:
            for fp in self.sitemap.features.values():
                if not fp.checklist:
                    continue
                fp_origin = getattr(fp, "origin", "validated")
                for c in fp.checklist:
                    total += 1
                    if fp_origin == "speculative":
                        spec_total += 1
                    else:
                        valid_total += 1
                    if c.result == CheckResult.SKIPPED:
                        skipped += 1
                    elif c.result == CheckResult.PENDING:
                        pending += 1
                    else:
                        real_done += 1
                        if fp_origin == "speculative":
                            spec_done += 1
                        else:
                            valid_done += 1
        except Exception:
            pass

        real_rate = round(real_done / total * 100, 1) if total > 0 else 0.0
        skip_rate = round(skipped / total * 100, 1) if total > 0 else 0.0
        pending_rate = round(pending / total * 100, 1) if total > 0 else 0.0
        validated_rate = round(valid_done / valid_total * 100, 1) if valid_total > 0 else 0.0
        speculative_rate = round(spec_done / spec_total * 100, 1) if spec_total > 0 else 0.0
        return {
            "real_done": real_done,
            "skipped": skipped,
            "pending": pending,
            "total": total,
            "real_rate": real_rate,
            "skip_rate": skip_rate,
            "pending_rate": pending_rate,
            # ★ P0-2: 分母解耦后的分类统计
            "validated_total": valid_total,
            "validated_done": valid_done,
            "validated_rate": validated_rate,
            "speculative_total": spec_total,
            "speculative_done": spec_done,
            "speculative_rate": speculative_rate,
        }

    def _detect_hollowing(self) -> dict | None:
        """检测测试过程是否空心化。

        空心化判定条件（满足任一即判定，且漏洞数 = 0）：
        1. 原始条件：真实完成率 < 10% 且 跳过率 > 70%
        2. ★ P1-1 新增：真实完成率 < 5% 且 (跳过率 + 未测率) > 80%
           — 覆盖"大面积未测(pending)而非跳过(skipped)"的场景

        返回 None 表示未空心化；返回 dict 包含告警信息和根因诊断。
        """
        rc = self._compute_real_completion()
        if rc["total"] == 0:
            return None

        try:
            cov = self.sitemap.get_coverage()
            vulns = int(cov.get("vulns", 0) or 0)
        except Exception:
            vulns = 0

        _pending_rate = rc.get("pending_rate", 0.0)
        _uncovered_rate = rc["skip_rate"] + _pending_rate

        # 空心化判定（两条路径，满足任一即触发）
        _hollowed = (
            (rc["real_rate"] < 10.0 and rc["skip_rate"] > 70.0 and vulns == 0)
            or (rc["real_rate"] < 5.0 and _uncovered_rate > 80.0 and vulns == 0)
        )

        if _hollowed:
            # 根因诊断
            causes = []
            fs_stats = {}
            try:
                fs_stats = self.sitemap.get_coverage().get("fast_scanner_stats", {}) or {}
            except Exception:
                pass

            if fs_stats.get("waf_blocked"):
                causes.append("WAF 封禁导致后续测试全部跳过")
            if fs_stats.get("timeout_blocked"):
                causes.append("超时熔断导致测试中止")

            # 检查 flows 是否为空
            flows_empty = getattr(self, "_flows_no_new_api", False)
            if flows_empty:
                causes.append("流量捕获为空，补测链路断裂（flows_no_new_api）")

            # 检查 catch-all 端点比例
            ghost_count = getattr(self.sitemap, "_ghost_endpoint_count", 0)
            total_apis = len(getattr(self.sitemap, "apis", {}))
            if total_apis > 0 and ghost_count / total_apis > 0.5:
                causes.append(f"虚假端点比例过高（{ghost_count}/{total_apis}）")

            if not causes:
                if _pending_rate > 50.0:
                    causes.append(f"大面积未测（pending {rc.get('pending', 0)} 项 / {_pending_rate}%），补测结果可能未回写完成率")
                else:
                    causes.append("检测项大面积跳过，疑似 FAST 模式全量跳过 LLM 检测")

            return {
                "is_hollowed": True,
                "alert_level": "danger",
                "real_done": rc["real_done"],
                "skipped": rc["skipped"],
                "pending": rc.get("pending", 0),
                "total": rc["total"],
                "real_rate": rc["real_rate"],
                "skip_rate": rc["skip_rate"],
                "pending_rate": _pending_rate,
                "vulns": vulns,
                "causes": causes,
                "message": (
                    f"⚠️ 空心化告警：测试过程疑似空心化。"
                    f"真实完成 {rc['real_done']}/{rc['total']} 项（{rc['real_rate']}%），"
                    f"跳过 {rc['skipped']} 项（{rc['skip_rate']}%），"
                    f"未测 {rc.get('pending', 0)} 项（{_pending_rate}%），"
                    f"发现漏洞 {vulns} 个。"
                    f"根因：{'；'.join(causes)}"
                ),
            }
        return None

    def _generate_hollowing_alert_markdown(self) -> str:
        """生成空心化告警的 Markdown 文本，用于报告头部展示。

        如果未检测到空心化，返回空字符串。
        """
        h = self._detect_hollowing()
        if not h:
            return ""

        lines = [
            f"> ## ⚠️ 空心化告警",
            f"> ",
            f"> **测试过程疑似空心化**——报告的完成率数字不能反映真实测试覆盖度。",
            f"> ",
            f"> | 指标 | 值 |",
            f"> |------|-----|",
            f"> | 真实完成 | {h['real_done']}/{h['total']} 项（{h['real_rate']}%）|",
            f"> | 跳过 | {h['skipped']} 项（{h['skip_rate']}%）|",
            f"> | 发现漏洞 | {h['vulns']} 个 |",
            f"> ",
            f"> **根因诊断**：",
        ]
        for cause in h["causes"]:
            lines.append(f"> - {cause}")
        lines.append("> ")
        lines.append("> **建议**：检查 WAF 封禁状态、流量捕获模式、扫描模式配置，必要时人工补测。")
        return "\n".join(lines)
