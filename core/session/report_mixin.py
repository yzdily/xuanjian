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
