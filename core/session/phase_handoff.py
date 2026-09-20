"""阶段边界接力（阶段 5-E2）。

## 问题

`_new_context_for_phase()` 在每个阶段边界**创建全新的 ContextManager**（这是对的 —— 否则上下文
必然爆炸），但原实现只把「站点地图摘要」注入到 `phase == "test"`，其它阶段**什么都不带**：

- 上一阶段做到哪、还有什么没测 → 新阶段不知道
- 已确认的漏洞证据 → 新阶段不知道，可能重复测试或漏掉深挖

实测 M4：长任务压缩后，被移除的测试样本结论**无法从摘要恢复**（60 轮丢 53 条）。

## 设计

**接力物 = 摘要 + 未完成项列表 + 关键证据引用（不含全文）**

关键取舍：**样本结论的权威载体是 sitemap，不是对话历史。**
`sitemap.features[].checklist[]` 里每条 `CheckItem` 都有 `result` / `severity` / `evidence_flow_id`，
是**结构化且持久化**的 —— 上下文怎么压缩都不会丢。所以阶段接力从 sitemap 重建，
而不是指望 LLM 摘要记住一切（摘要只是辅助，受 token 预算约束必然有损）。

**证据只给引用不给全文**：`evidence_flow_id` 指向已有的流量记录，新阶段按需取用；
`evidence_request` / `evidence_response`（完整 HTTP 报文）**绝不进接力物** ——
既省 token，也避免把凭证/敏感数据扩散到更多上下文里。

## token 预算联动

`build_handoff()` 受 `budget_chars` 约束：超出则按优先级截断，并在文本里**显式标注已截断**
（含总数），避免模型误以为"就这么多"。
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: 接力物默认上限（字符）。可按 phase 覆盖。
DEFAULT_MAX_FEATURES = 30
DEFAULT_MAX_VULNS = 40
DEFAULT_BUDGET_CHARS = 8000

_PRIORITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}


def _pvalue(fp) -> str:
    """取优先级取值（兼容 Enum 与字符串）。"""
    p = getattr(fp, "priority", None)
    return str(getattr(p, "value", p) or "medium").lower()


@dataclass
class HandoffStats:
    """接力物统计（供 ContextGauge 打点与验收）。"""

    features_total: int = 0
    features_pending: int = 0
    pending_checks: int = 0
    confirmed_vulns: int = 0
    deferred_features: int = 0
    included_features: int = 0
    included_vulns: int = 0
    truncated: bool = False
    chars: int = 0
    evidence_refs: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "features_total": self.features_total,
            "features_pending": self.features_pending,
            "pending_checks": self.pending_checks,
            "confirmed_vulns": self.confirmed_vulns,
            "deferred_features": self.deferred_features,
            "included_features": self.included_features,
            "included_vulns": self.included_vulns,
            "truncated": self.truncated,
            "chars": self.chars,
            "evidence_refs": list(self.evidence_refs),
        }


def _iter_confirmed(sitemap):
    """遍历已确认漏洞：(feature, check_item)。

    以 `CheckResult.VULNERABLE` 为准（而非 feature.test_status），
    因为同一个功能点可能既有漏洞项也有正常项。
    """
    try:
        from core.sitemap.models import CheckResult
        vulnerable = CheckResult.VULNERABLE
    except Exception:                                     # pragma: no cover
        vulnerable = None

    for fp in (getattr(sitemap, "features", {}) or {}).values():
        for c in (getattr(fp, "checklist", []) or []):
            if vulnerable is not None and c.result == vulnerable:
                yield fp, c


def build_handoff(
    sitemap,
    *,
    to_phase: str,
    from_phase: str = "",
    max_features: int = DEFAULT_MAX_FEATURES,
    max_vulns: int = DEFAULT_MAX_VULNS,
    budget_chars: int = DEFAULT_BUDGET_CHARS,
    include_summary: bool = True,
) -> tuple[str, HandoffStats]:
    """从 sitemap 重建阶段接力物。

    Returns:
        ``(text, stats)``。``text`` 为空字符串表示无内容可接力（如 sitemap 为空）。
    """
    stats = HandoffStats()
    if sitemap is None:
        return "", stats

    features = getattr(sitemap, "features", {}) or {}
    if not features:
        return "", stats

    try:
        cov = sitemap.get_coverage()
    except Exception:                                     # pragma: no cover
        cov = {}

    pending_features = []
    try:
        pending_features = list(sitemap.get_untested_features())
    except Exception:                                     # pragma: no cover
        pending_features = []

    confirmed = list(_iter_confirmed(sitemap))
    deferred = [f for f in features.values() if getattr(f, "deferred", False)]

    stats.features_total = cov.get("total", len(features))
    stats.features_pending = len(pending_features)
    stats.pending_checks = sum(len(f.get_pending_checks()) for f in pending_features)
    stats.confirmed_vulns = len(confirmed)
    stats.deferred_features = len(deferred)

    lines: list[str] = []
    head = f"## 阶段交接（{from_phase or '上一阶段'} → {to_phase}）" if to_phase else "## 阶段交接"
    lines.append(head)

    if include_summary:
        lines.append("")
        lines.append("### 覆盖概览")
        lines.append(f"- 功能点: {stats.features_total} 个"
                     f"（未完成 {stats.features_pending} / 待激活 {stats.deferred_features}）")
        lines.append(f"- 测试项: {cov.get('checks_done', 0)}/{cov.get('checks_total', 0)} 完成"
                     f"（待测 {stats.pending_checks}）")
        lines.append(f"- 已确认漏洞: {stats.confirmed_vulns} 个")

    # ---- 未完成项（按优先级，sitemap 已排好序）----
    if pending_features:
        lines.append("")
        lines.append(f"### 未完成项（共 {stats.features_pending} 个，按优先级）")
        for f in pending_features[:max_features]:
            pend = f.get_pending_checks()
            http_n = sum(1 for c in pend if not getattr(c, "needs_browser", False))
            brw_n = len(pend) - http_n
            apis = getattr(f, "related_apis", []) or []
            api_note = f"  · `{apis[0]}`" if apis else ""
            types = "、".join(c.vuln_type for c in pend[:4])
            more = f" 等 {len(pend)} 项" if len(pend) > 4 else ""
            lines.append(
                f"- [{_PRIORITY_LABEL.get(_pvalue(f), _pvalue(f))}] **{f.name}**"
                f" — 待测 {len(pend)} 项（HTTP {http_n} / 浏览器 {brw_n}）"
                f"{api_note}\n    待测类型: {types}{more}"
            )
            stats.included_features += 1
        if stats.features_pending > stats.included_features:
            stats.truncated = True
            lines.append(f"- …（还有 {stats.features_pending - stats.included_features} 个未完成项未列出，"
                         f"可用 `sitemap_get_coverage` 查看全部）")

    # ---- 已确认漏洞（只给引用，不给报文全文）----
    if confirmed:
        lines.append("")
        lines.append(f"### 已确认漏洞（共 {stats.confirmed_vulns} 个；证据以 flow 引用给出，按需取用）")
        for fp, c in confirmed[:max_vulns]:
            sev = (getattr(c, "severity", "") or "medium").lower()
            ref = getattr(c, "evidence_flow_id", "") or ""
            if ref:
                stats.evidence_refs.append(ref)
            ref_note = f"（证据 flow: `{ref}`）" if ref else "（无 flow 引用）"
            detail = (getattr(c, "detail", "") or "")[:80]
            lines.append(f"- [{_PRIORITY_LABEL.get(sev, sev)}] {fp.name} → **{c.vuln_type}**{ref_note}"
                         + (f"\n    {detail}" if detail else ""))
            stats.included_vulns += 1
        if stats.confirmed_vulns > stats.included_vulns:
            stats.truncated = True
            lines.append(f"- …（还有 {stats.confirmed_vulns - stats.included_vulns} 条未列出）")

    # ---- 待激活（需突破登录）----
    if deferred:
        lines.append("")
        lines.append(f"### 待激活功能点（需突破登录后激活，共 {len(deferred)} 个）")
        for f in deferred[:10]:
            desc = (getattr(f, "description", "") or "")[:40]
            lines.append(f"- 🔒 [{_PRIORITY_LABEL.get(_pvalue(f), _pvalue(f))}] {f.name}"
                         + (f" — {desc}" if desc else ""))

    # ---- token 预算：超限则按整体截断并显式标注 ----
    text = "\n".join(lines)
    if len(text) > budget_chars:
        stats.truncated = True
        keep = text[:budget_chars].rsplit("\n", 1)[0]
        text = (keep + "\n\n> ⚠️ 交接内容已按上下文预算截断；"
                "完整清单请调用 `sitemap_get_coverage` 工具获取。")

    stats.chars = len(text)
    return text, stats
