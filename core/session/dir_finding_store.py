"""DirScan 敏感发现 → sitemap 台账 的**唯一**写入入口。

★ T1 (0923 v2)。为什么需要这个模块（0923 实测）：

同一个能力存在两条路径，行为不一致：
- 被动侦察路径 ``core/session/explore_mixin.py`` 会写台账 ✅
- 正常 Phase 0 路径 ``core/session/chat_loop.py`` 只 ``yield`` 到终端，从不写台账 ❌

后果：同一次扫描里终端显示「🔴 5 条 HIGH」，4 分钟后报告显示「发现 0 个漏洞」，
全链路丢数据。而 ``core/sitemap/coverage.py`` 明确写着「纳入 DirScan 敏感发现
为已确认漏洞」并读 ``_dirscan_sensitive_vulns`` —— 即数据源从来没人写。

本模块提供唯一入口，两条路径共用，并把两条硬约束固化下来：

1. **默认 fail-safe**：缺少 ``review_status`` 的发现一律按 ``needs_review`` 处理，
   绝不默认 ``confirmed``（0923 的教训：无证据的 HIGH 写进给银行客户的报告
   = 对金融机构报假漏洞）。
2. **失败不得静默**：原实现的 ``try: sitemap._dirscan_sensitive_vulns.append(...)
   except Exception: pass`` 把**属性访问本身**包在 try 里，AttributeError 会被
   静默吞掉 → 被动路径同样会静默丢数据。本模块显式区分"不可用"并记 WARNING。
"""

from __future__ import annotations

from typing import Any, Iterable

from core.log import get_logger

log = get_logger("dir_finding_store")

# ★ 判定谓词下沉在 core.sitemap.dir_findings（FOUNDATION 层），此处仅重导出。
#   原因：core/sitemap/coverage.py 的两个消费点都要用它，而 core.sitemap 属底座，
#   不能反向依赖 core.session（A1 分层契约，scripts/layer_lint.py 硬拦）。
from core.sitemap.dir_findings import (
    LEDGER_ATTR,
    REVIEW_CONFIRMED,
    REVIEW_NEEDS_REVIEW,
    is_confirmed,
)

__all__ = [
    "REVIEW_CONFIRMED", "REVIEW_NEEDS_REVIEW", "LEDGER_ATTR",
    "is_confirmed", "persist_dir_findings",
]


def _ensure_ledger(sitemap: Any) -> list | None:
    """确保 sitemap 上有可写的台账列表。

    Returns:
        可写的 list；不可用时返回 ``None``（调用方据此返回 0，且日志已留痕）。
    """
    if sitemap is None:
        return None
    ledger = getattr(sitemap, LEDGER_ATTR, None)
    if ledger is None:
        # 正常构造的 Sitemap 在 __init__ 已建该字段；这里只是防御旧版反序列化对象。
        try:
            setattr(sitemap, LEDGER_ATTR, [])
        except Exception:
            log.warning(
                "[dir_finding_store] sitemap 不支持写入台账，本次发现无法记录",
                exc_info=True,
            )
            return None
        ledger = getattr(sitemap, LEDGER_ATTR, None)
    if not isinstance(ledger, list):
        log.warning(
            "[dir_finding_store] 台账字段类型异常(%s)，本次不写入",
            type(ledger).__name__,
        )
        return None
    return ledger


def persist_dir_findings(
    sitemap: Any,
    findings: Iterable[Any],
    *,
    source: str = "dirscan_active",
    detail_limit: int = 500,
) -> int:
    """把 DirScan 的 findings 写入 sitemap 台账。

    幂等：同一 ``(url, vuln_type)`` 已存在时跳过，避免两条路径都跑到时重复计数。

    Args:
        sitemap: 目标 sitemap 实例；``None`` 时直接返回 0。
        findings: ``DirFinding`` 序列（也接受带同名属性的任意对象）。
        source: 来源标记，``dirscan_active``（正常 Phase 0）/ ``dirscan_passive``（被动侦察）。
        detail_limit: detail 字段截断长度。

    Returns:
        实际写入条数。``0`` 既可能是"无内容"，也可能是"sitemap 不可用"
        —— 后者一定已在日志里留 WARNING（不静默）。
    """
    ledger = _ensure_ledger(sitemap)
    if ledger is None:
        return 0

    existing: set[tuple[str, str]] = {
        (str(row.get("url", "")), str(row.get("vuln_type", "")))
        for row in ledger
        if isinstance(row, dict)
    }

    written = 0
    confirmed = 0
    for f in findings or ():
        url = getattr(f, "url", "") or ""
        vtype = getattr(f, "vuln_type", "") or "info_disclosure"
        if (url, vtype) in existing:
            continue
        # ★ fail-safe：缺失即视为待复核，绝不默认 confirmed
        review = getattr(f, "review_status", "") or REVIEW_NEEDS_REVIEW
        if review == REVIEW_CONFIRMED:
            confirmed += 1
        ledger.append({
            "vuln_type": vtype,
            "severity": getattr(f, "severity", "") or "medium",
            "url": url,
            "detail": (getattr(f, "detail", "") or "")[:detail_limit],
            "evidence": (getattr(f, "evidence", "") or "")[:1000],
            "source": source,
            "review_status": review,
            "review_reason": getattr(f, "review_reason", "") or "",
            "evidence_quality": getattr(f, "evidence_quality", "") or "",
            "body_sha256": getattr(f, "body_sha256", "") or "",
            "path": getattr(f, "path", "") or "",
        })
        existing.add((url, vtype))
        written += 1

    if written:
        log.info(
            "[dir_finding_store] 台账写入 %d 条（source=%s，confirmed=%d，needs_review=%d）",
            written, source, confirmed, written - confirmed,
        )
    return written
