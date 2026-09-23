"""DirScan 敏感发现判定策略（T8 / T15，从 _scanner.py 抽出）。

抽出原因（两个都成立）：
1. ``core/dir_scanner/_scanner.py`` 抽出前 953 行，超过仓库 800 行门槛；
2. 策略是**纯逻辑**（输入 DirEntry / DirScanResult，输出发现或否决），
   拆出来后可以脱离 HTTP 桩直接单测。

缺陷对应（0923 实测）：
- **D1 / D2**：命中路径关键字即出 ``high``，零响应体验证 → 三站（sjcj / ics /
  citicaibank，均为银行）产出一字不差的同一批 5 条 HIGH，实测 **100% 误报**。
- **D4 / E2**：误报逃逸的真因不是"wildcard 不参与门控"，而是**单基线通配符检测
  覆盖不了多簇兜底页** —— ics 同站同时存在 4113B 与 2569B 两个不同兜底体。
- **E1**：``wildcard_detected`` 不能当否决票（只要基线探测随机路径返回非 404
  就为 True，SPA/WAF/自定义 200 兜底页全命中）→ 必须用 body_hash 簇证据。
"""

from __future__ import annotations

from typing import Iterable

from ._models import DirEntry, DirFinding, DirScanResult

# ★ T8：复用 fast_scanner 已有的内容指纹校验，禁止另造第三套。
#   真实实现位于 core/fast_scanner/_fp_filters.py:320（不是 _checks_server.py，
#   那里只是调用点）。返回 quality ∈ {"content_match", "header_only", ""}。
#   依赖方向：dir_scanner(MID) → fast_scanner，无循环。
try:
    from core.fast_scanner._fp_filters import (
        _is_business_deny as _fp_is_business_deny,
        _verify_sensitive_path_content as _fp_verify_sensitive_path,
    )
    HAS_FP_VERIFIER = True
except Exception:  # pragma: no cover - 指纹模块缺失时降级为"无强证据"
    HAS_FP_VERIFIER = False

    def _fp_verify_sensitive_path(path: str, text: str) -> tuple[bool, str]:
        return False, ""

    def _fp_is_business_deny(text: str) -> bool:
        return False


# ★ T15 多簇兜底页判定阈值。三个条件同时满足才算"一簇兜底页"：
#   - 总样本 ≥ 5：小样本不做判定，避免"1/1 = 100%"式误判
#   - 单簇 ≥ 3 条：至少 3 条不同路径共享同一响应体
#   - 单簇占比 ≥ 60%
#   注：原方案写"单簇 ≥5 条"，在稀疏目标（ics 那次只留下 5 条 entries）下会漏判
#   —— 实测该场景是 4/5 = 80%，明明是兜底页却过不了 5 条线。
CATCH_ALL_MIN_TOTAL = 5
CATCH_ALL_MIN_CLUSTER = 3
CATCH_ALL_MIN_RATE = 0.6


def compute_catch_all_clusters(
    body_hashes: "Iterable[str]",
) -> dict[str, int]:
    """从一批响应体哈希中计算"兜底页簇"（纯函数）。

    Args:
        body_hashes: 已存活路径的 ``DirEntry.body_hash`` 序列（空串会被忽略）。

    Returns:
        ``{hash: 命中条数}``，按条数降序；空 dict 表示未检出兜底页。

    Examples:
        实测 ics.aibank.com 形态::

            >>> compute_catch_all_clusters(["a"] * 4 + ["b"])
            {'a': 4}
    """
    counts: dict[str, int] = {}
    for _h in body_hashes or ():
        if _h:
            counts[_h] = counts.get(_h, 0) + 1
    total = sum(counts.values())
    if total < CATCH_ALL_MIN_TOTAL:
        return {}
    clusters = {
        _h: _c for _h, _c in counts.items()
        if _c >= CATCH_ALL_MIN_CLUSTER and _c / total >= CATCH_ALL_MIN_RATE
    }
    return dict(sorted(clusters.items(), key=lambda _kv: -_kv[1]))


def close_abandoned_coroutines(coros: Iterable) -> None:
    """关闭因提前中止而不再 await 的协程。

    早期 catch-all 中止时会放弃剩余任务，而这些协程对象在列表推导里
    已被创建 → 不关闭会触发 ``RuntimeWarning: coroutine ... was never awaited``
    并占用资源。显式 close 让中止路径保持干净。
    """
    for _c in coros or ():
        try:
            if hasattr(_c, "close") and not getattr(_c, "cr_frame", None) is None:
                _c.close()
        except Exception:
            pass


def classify_sensitive_entry(
    entry: DirEntry,
    keywords: Iterable[tuple[str, str, str]],
) -> DirFinding | None:
    """对单个存活条目做敏感路径判定（带内容证据）。

    Args:
        entry: 已通过状态码白名单与 wildcard 过滤的存活条目。
        keywords: ``SENSITIVE_PATTERNS`` —— ``(路径关键字, 漏洞类型, 严重度)``。

    Returns:
        ``DirFinding``（带 ``review_status`` / ``evidence_quality``）；不构成
        发现时返回 ``None``。

    判定链（顺序不可调换）：
        ① 路径关键字命中？未命中 → None
        ② 业务层拒绝（如 ``{"code":500,"message":"用户未登录"}``）→ None
        ③ 内容指纹校验：
           - 明确否定 → **None（丢弃）**，与 fast_scanner 的
             ``if not matched: return None`` 语义保持一致。
             覆盖三种情形：有指纹但内容不匹配（SPA/兜底页）、无指纹且响应体像
             HTML 外壳、响应体过短。
           - ``content_match`` → ``confirmed``，保留原严重度
           - ``header_only``（无指纹可用的弱证据）→ ``needs_review``，严重度压到
             ``medium`` 及以下
    """
    _hit = None
    for keyword, vtype, severity in keywords:
        if keyword in entry.path.lower():
            _hit = (keyword, vtype, severity)
            break
    if _hit is None:
        return None
    _, _vtype, _sev = _hit

    _body = entry.body_text or ""
    if _fp_is_business_deny(_body):
        return None

    _matched, _quality = _fp_verify_sensitive_path(entry.path, _body)
    if not _matched:
        return None

    if _quality == "content_match":
        _final_sev, _review = _sev, "confirmed"
    else:
        # 无强证据：medium + needs_review（进"待复核"而非"已确认漏洞"）
        _final_sev = "medium" if _sev in ("high", "critical") else _sev
        _review = "needs_review"
        _quality = _quality or "header_only"

    return DirFinding(
        vuln_type=_vtype, severity=_final_sev, url=entry.url,
        detail=(f"目录扫描发现敏感路径: {entry.path} "
                f"(HTTP {entry.status}, {entry.length}B, {entry.content_type}, "
                f"指纹={_quality or 'none'})"
                + ("" if _review == "confirmed"
                   else " [内容校验未通过，待人工复核]")),
        evidence=(f"GET {entry.url} -> {entry.status} {entry.content_type} "
                  f"| verified={_matched} | quality={_quality or 'none'} "
                  f"| title={entry.title or '-'} "
                  f"| body_sha256={entry.body_hash[:32] or '-'} "
                  f"| snippet={_body[:200]!r}"),
        review_status=_review,
        evidence_quality=_quality or "none",
        body_sha256=entry.body_hash or "",
        path=entry.path,
    )


def apply_catch_all_veto(result: DirScanResult, *, log=None) -> dict[str, int]:
    """多簇兜底页检测 + 目录类发现强制降级（**在扫描收尾调用**）。

    为什么放在收尾而不是逐条判定：簇证据必须等全部路径扫完才完整。只看前几条会
    漏掉"第二簇"—— 实测 ics.aibank.com 同时存在 4113B 与 2569B 两个兜底体，
    单基线 wildcard 只覆盖了其中一簇，另一簇的敏感路径一路走到 finding 生成。

    为什么是"降级"而不是"丢弃"：产品要求 P16 —— 未通过校验的发现不得丢数据
    （可事后复核）。清空 findings 会让真实泄露永久不可见；置为 ``needs_review``
    则既不进"已确认漏洞"，又保留复核通道。

    Args:
        result: 扫描结果（就地修改 ``catch_all_*`` 与 findings 的降级字段）。
        log: 可选 logger。

    Returns:
        检出的兜底页簇 ``{hash: 条数}``。
    """
    total = len(result.entries)
    clusters = compute_catch_all_clusters([e.body_hash for e in result.entries])
    result.catch_all_clusters = clusters
    if not clusters:
        return {}

    _top_hash, _top_cnt = max(clusters.items(), key=lambda _kv: _kv[1])
    result.catch_all_detected = True
    result.catch_all_hash = _top_hash
    result.catch_all_rate = round(_top_cnt / max(total, 1) * 100, 1)

    for _f in result.findings:
        _f.review_status = "needs_review"
        _f.review_reason = (
            f"catch-all 路由（{len(clusters)} 簇兜底页，"
            f"最大簇 {_top_cnt}/{total}），路径存活判定不可信"
        )
        if _f.severity in ("high", "critical"):
            _f.severity = "medium"

    if log and result.findings:
        log.warning(
            "[DirScan] catch-all 多簇检测: %d 簇兜底页（最大 %d/%d = %.1f%%），"
            "目录类发现 %d 条已整体降级为 needs_review（不丢数据，可复核）",
            len(clusters), _top_cnt, total,
            _top_cnt / max(total, 1) * 100, len(result.findings),
        )
    return clusters
