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

# ★ 924 补充：**路径归一化探针**单独用更严苛的（更容易判为兜底页的）阈值。
#
# 为什么需要：`..;/actuator/env`、`;/actuator/env`、`%2e%2e/...` 这类路径本身就是
# 用来"绕过网关/WAF 归一化"的构造，它命中站点兜底路由（SPA fallback / 软 404）
# 的概率远高于普通业务路径。实测 task_1790223312_c75b16：
#   DirScan `发现=9 wildcard=False`（未触发 catch-all 预警），
#   但 FastScanner 侧对同一 URL 反复拿到 `200 OK body=2569` —— 与站点兜底体尺寸一致。
#   即：**同一簇兜底页，FastScanner 看到了，DirScan 漏判了**。
#
# 成因（待产物验证）：默认阈值要求「同哈希 ≥3 条且占比 ≥60%」，9 条 entries 里
# 需 ≥6 条同哈希；而兜底页常含动态内容（nonce/时间戳）→ 每次 body_hash 都不同
# → 聚不成簇。对归一化探针放宽为「≥2 条且占比 ≥50%」，让这类构造不再是漏网之鱼。
CATCH_ALL_PROBE_MIN_CLUSTER = 2
CATCH_ALL_PROBE_MIN_RATE = 0.5
#: 路径归一化探针的路径特征（大小写不敏感匹配）
NORMALIZATION_PROBE_MARKERS = ("..;/", ";/", "%2e", "....//", "%252e")

# ★ F9：3xx 重定向状态码 —— 归一化探针返回这些状态时视为命中兜底路由。
#   之前只认 2xx，302 探针（如 ..;/actuator/env → 登录页/SPA fallback）逃逸 →
#   被挂成 alive API → 进权威 API 表与期望矩阵 → CI 恒红。
#   301/302/303/307/308 都是"重定向到别处"的语义，绝非该路径的真实敏感数据。
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})

# ★ F9：3xx 重定向状态码 —— 归一化探针返回这些状态时视为命中兜底路由。
#   之前只认 2xx，302 探针（如 ..;/actuator/env → 登录页/SPA fallback）逃逸 →
#   被挂成 alive API → 进权威 API 表与期望矩阵 → CI 恒红。
#   301/302/303/307/308 都是"重定向到别处"的语义，绝非该路径的真实敏感数据。
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


def is_normalization_probe_path(path: str) -> bool:
    """该路径是否为**路径归一化绕过探针**（``..;/`` / ``;/`` / ``%2e`` 等）。

    与 ``core/framework_scan/path_normalization.py`` 的构造同一族。
    """
    _p = str(path or "").lower()
    return any(_m in _p for _m in NORMALIZATION_PROBE_MARKERS)


def is_single_probe_catch_all_hit(entry: DirEntry) -> bool:
    """单条归一化探针是否命中站点兜底路由（语义判定，不依赖成簇）。

    **动机（S1 / 0924_e_aibank_actuator_probe_optimization）**：
    ``apply_catch_all_veto`` 的成簇法要求「≥2 条探针共享同一 body_hash」；
    当 ``..;/actuator/env`` 是**唯一**命中兜底体的探针时（兄弟路径 404 / 异体）
    聚不成簇 → 漏判 → 该探针照旧被挂成 alive API（进而进权威 API 表与期望矩阵）。
    且动态兜底体（nonce/时间戳）会让每条 body_hash 都不同，成簇法同样失效。

    判定（与 ``classify_sensitive_entry`` 的内容校验同源，禁止另造指纹规则）：
        ① 路径是归一化探针（``..;/`` / ``;/`` / ``%2e`` …）
        ② 状态码为 2xx 或 3xx 重定向（F9：302 探针不再逃逸）
        ③ 响应体**未通过**该路径的内容指纹校验（``_fp_verify_sensitive_path``
           返回 matched=False）→ 说明返回的是站点兜底/外壳内容，
           而非该路径对应的真实敏感数据。
           3xx 重定向一律视为未通过（重定向到别处 ≠ 该路径的真实数据）。
    三条件同时成立 → 判为"命中兜底路由"，调用方据此跳过 API 挂载。

    正例保护：探针返回真实敏感内容时指纹校验必为 ``content_match``
    （如 actuator/env 的 JSON 特征）→ 不标记，保留挂载。
    """
    _path = getattr(entry, "path", "")
    if not is_normalization_probe_path(_path):
        return False
    _status = int(getattr(entry, "status", 0) or 0)
    # ★ F9：扩展为 2xx ∪ 3xx 重定向。
    #   之前 `if _status < 200 or _status >= 300: return False` 只认 2xx，
    #   302 探针（..;/actuator/env → 登录页/SPA fallback）逃逸。
    is_2xx = 200 <= _status < 300
    is_redirect = _status in _REDIRECT_STATUS
    if not is_2xx and not is_redirect:
        return False
    if is_redirect:
        # 3xx 重定向到别处 ≠ 该路径的真实敏感数据，一律判为兜底命中。
        return True
    _body = getattr(entry, "body_text", "") or ""
    _matched, _quality = _fp_verify_sensitive_path(_path, _body)
    if _matched:
        # content_match（强证据）或 header_only（弱正证据）都不拦：
        # body 至少证明该路径返回的不是兜底页。
        return False
    # matched=False：路径有指纹但内容未命中（SPA/软 404），或无指纹且
    # 响应体像 HTML 外壳/过短 —— 正是"存活判定不可信"的形态。
    return True


def compute_catch_all_clusters(
    body_hashes: "Iterable[str]",
    *,
    min_total: int | None = None,
    min_cluster: int | None = None,
    min_rate: float | None = None,
) -> dict[str, int]:
    """从一批响应体哈希中计算"兜底页簇"（纯函数）。

    Args:
        body_hashes: 已存活路径的 ``DirEntry.body_hash`` 序列（空串会被忽略）。
        min_total: 最少样本数；``None`` 用 ``CATCH_ALL_MIN_TOTAL``。
        min_cluster: 单簇最少条数；``None`` 用 ``CATCH_ALL_MIN_CLUSTER``。
        min_rate: 单簇最低占比；``None`` 用 ``CATCH_ALL_MIN_RATE``。
            ★ 924：归一化探针子集用 ``CATCH_ALL_PROBE_*`` 传入更宽松的值。

    Returns:
        ``{hash: 命中条数}``，按条数降序；空 dict 表示未检出兜底页。

    Examples:
        实测 ics.aibank.com 形态::

            >>> compute_catch_all_clusters(["a"] * 4 + ["b"])
            {'a': 4}
    """
    _min_total = CATCH_ALL_MIN_TOTAL if min_total is None else int(min_total)
    _min_cluster = CATCH_ALL_MIN_CLUSTER if min_cluster is None else int(min_cluster)
    _min_rate = CATCH_ALL_MIN_RATE if min_rate is None else float(min_rate)

    counts: dict[str, int] = {}
    for _h in body_hashes or ():
        if _h:
            counts[_h] = counts.get(_h, 0) + 1
    total = sum(counts.values())
    if total < _min_total:
        return {}
    clusters = {
        _h: _c for _h, _c in counts.items()
        if _c >= _min_cluster and _c / total >= _min_rate
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
        检出的兜底页簇 ``{hash: 条数}``（含归一化探针子集命中）。
    """
    total = len(result.entries)
    clusters = compute_catch_all_clusters([e.body_hash for e in result.entries])

    # ★ 924：归一化探针子集单独再判一次（更宽松阈值）。
    #   原因：这类路径命中兜底路由的概率远高于普通路径，而默认阈值（≥3 条且
    #   占比 ≥60%）对"兜底页含动态内容 → 每条 body_hash 都不同"的场景会漏判。
    #   实测 task_1790223312_c75b16：DirScan 报 `发现=9 wildcard=False`（无预警），
    #   但 `..;/actuator/env` 稳定返回 `200 / 2569B` 兜底体。
    _probe_entries = [e for e in result.entries
                      if is_normalization_probe_path(getattr(e, "path", ""))]
    _probe_clusters: dict[str, int] = {}
    if _probe_entries:
        _probe_clusters = compute_catch_all_clusters(
            [e.body_hash for e in _probe_entries],
            min_total=CATCH_ALL_PROBE_MIN_CLUSTER,
            min_cluster=CATCH_ALL_PROBE_MIN_CLUSTER,
            min_rate=CATCH_ALL_PROBE_MIN_RATE,
        )
    result.catch_all_probe_clusters = _probe_clusters

    # ★ 924-S1：单例归一化探针**语义判定**（不依赖成簇，补成簇法的盲区）。
    #   成簇法要求「≥2 条探针共享同一 body_hash」；当 `..;/actuator/env` 是唯一
    #   命中兜底体的探针（兄弟路径 404 / 异体）时聚不成簇 → 漏判。且动态兜底体
    #    （nonce/时间戳）会让 body_hash 每次都不同，成簇法同样失效。
    #   对每条**尚未被簇判定标记**的探针做内容校验：2xx 且响应体未通过该路径的
    #   指纹校验（返回的是站点兜底/外壳内容）→ 判为兜底页命中。
    if _probe_entries:
        _single_hits = [
            _e for _e in _probe_entries
            if not getattr(_e, "probe_suspected_catch_all", False)
            and is_single_probe_catch_all_hit(_e)
        ]
        for _e in _single_hits:
            try:
                setattr(_e, "probe_suspected_catch_all", True)
            except Exception:
                pass
        if _single_hits and log:
            log.warning(
                "[DirScan] 单例归一化探针判定兜底页: %d/%d 条探针返回 2xx 但内容"
                "未通过指纹校验（不成簇）; 疑似兜底路径: %s",
                len(_single_hits), len(_probe_entries),
                sorted({getattr(_e, "path", "") for _e in _single_hits})[:5],
            )

    result.catch_all_clusters = clusters
    if not clusters and not _probe_clusters:
        return {}

    # 归一化探针命中：把这些探针条目本身降级（不牵连全量 findings）
    if _probe_clusters:
        _probe_hashes = set(_probe_clusters)
        _probe_paths = {getattr(e, "path", "") for e in _probe_entries
                        if e.body_hash in _probe_hashes}
        for _e in _probe_entries:
            if _e.body_hash in _probe_hashes:
                # 路径存活判定不可信 —— 由调用方（scanner）据此跳过 API 挂载
                try:
                    setattr(_e, "probe_suspected_catch_all", True)
                except Exception:
                    pass
        if log:
            log.warning(
                "[DirScan] 归一化探针兜底页检测: %d/%d 条探针共享兜底体"
                "（阈值 ≥%d 条且占比 ≥%.0f%%）；疑似兜底路径: %s",
                sum(_probe_clusters.values()), len(_probe_entries),
                CATCH_ALL_PROBE_MIN_CLUSTER, CATCH_ALL_PROBE_MIN_RATE * 100,
                sorted(_probe_paths)[:5],
            )

    if not clusters:
        return dict(_probe_clusters)

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
    return {**clusters, **_probe_clusters}
