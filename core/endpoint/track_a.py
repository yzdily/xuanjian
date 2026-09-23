"""Track A — 按风险域分批派活（§1.5 P0）。

## 为什么单独成模块

`core/parallel/_orch_phases/_run_parallel_test.py` 原有 791 行，已贴近 D6 架构门
（core/ 下单文件 >800 行需豁免）。Track A 的适配逻辑（FeaturePoint → 端点 → 域分组
→ 排序标注）属于 `core/endpoint` 的职责，放在编排文件里既越界又会撑爆行数，
故独立为本模块：编排侧只保留 3 行调用。

## 为什么是"同域聚拢排序"而不是"按域拆散重组"

分组成员是 WorkerAgent "共享上下文"的载体（同组功能点串行测试、复用同一 LLM 上下文）。
按域拆散重组会破坏该复用并抬高 token 成本。故按"分组的主域"排序，
让同域分组连续派活（域级探针/凭据可复用）。

## 回滚

``XJ_TRACK_A=0`` → `apply_track_a` 原样返回、不产生事件，零副作用。
"""
from __future__ import annotations

import os
from typing import Any

_TRACK_A_ENV = "XJ_TRACK_A"


def track_a_enabled() -> bool:
    """Track A 开关（默认开）。``XJ_TRACK_A=0/false/off/no`` → 关闭。"""
    return str(os.getenv(_TRACK_A_ENV, "1")).strip().lower() not in ("0", "false", "off", "no")


def _fp_to_endpoints(fps: list[Any]) -> list[dict[str, Any]]:
    """把 FeaturePoint 摊平成端点 dict（供风险域分类）。

    数据源优先级：``related_apis``（"METHOD url"）→ ``page_url``（GET）
    → ``name``（当路径）。**保证每个功能点至少产出一个端点**，
    不因某类数据缺失而整组漏打域标签。
    """
    out: list[dict[str, Any]] = []
    for fp in fps:
        apis = [str(a).strip() for a in (getattr(fp, "related_apis", None) or [])]
        apis = [a for a in apis if a]
        if not apis:
            pu = str(getattr(fp, "page_url", "") or "").strip()
            apis = [f"GET {pu}" if pu else f"GET /{getattr(fp, 'name', '')}"]
        for a in apis:
            if " " in a:
                m, _, u = a.partition(" ")
                out.append({"method": m.upper(), "url": u})
            else:
                out.append({"method": "GET", "url": a})
    return out


def batch_groups_by_risk_domain(
    feature_groups: list[tuple[str, list]],
    *,
    host: str | None = None,
) -> tuple[list[tuple[str, list]], dict]:
    """按风险域聚拢 feature 分组并标注域。

    Returns:
        ``(new_groups, stats)``

        - ``new_groups``：同序聚拢后的 ``[(f"[域] 组名", [fp, ...]), ...]``；
          域判定全为兜底域（general）时组名不加前缀（避免 "[general]" 噪声）。
        - ``stats``：``{"enabled", "dispatched_domains", "missing_domains",
          "group_domains", "domains", "total_groups", "total_endpoints",
          "domain_endpoint_count"}``
    """
    from core.endpoint.risk_domain import (
        DOMAIN_LIST,
        classify_risk_domain,
        group_by_risk_domain,
    )

    # 1) 每组摊平端点 → 打域标签
    per_group_eps: list[list[dict[str, Any]]] = []
    for _name, fps in feature_groups:
        eps = _fp_to_endpoints(list(fps or []))
        for ep in eps:
            ep["_tags"] = {
                "risk_domain": classify_risk_domain(ep.get("url"), ep.get("method", "GET"))
            }
        per_group_eps.append(eps)

    # 2) ★ 真正的 Track A 调用：全量端点按域分组（复用既有实现，不另造）
    all_eps = [ep for eps in per_group_eps for ep in eps]
    domain_groups = group_by_risk_domain(all_eps)

    # 3) 每组取"主域"：组内命中次数最多的显式域；同票按 DOMAIN_LIST 序；
    #    无显式域命中 → 兜底 "general"
    order_idx = {d: i for i, d in enumerate(DOMAIN_LIST)}
    group_domains: dict[str, str] = {}
    for (name, _fps), eps in zip(feature_groups, per_group_eps):
        tally: dict[str, int] = {}
        for ep in eps:
            doms = (ep.get("_tags") or {}).get("risk_domain") or ["general"]
            if isinstance(doms, str):
                doms = [doms]
            for d in doms:
                if d in order_idx:
                    tally[d] = tally.get(d, 0) + 1
        if tally:
            best = max(tally.items(), key=lambda kv: (kv[1], -order_idx[kv[0]]))[0]
        else:
            best = "general"
        group_domains[name] = best

    # 4) 同域聚拢排序（稳定：域序优先，组内保持原相对顺序）
    indexed = list(enumerate(feature_groups))
    indexed.sort(key=lambda t: (order_idx.get(group_domains[t[1][0]], len(DOMAIN_LIST)), t[0]))

    new_groups: list[tuple[str, list]] = []
    for _i, (name, fps) in indexed:
        dom = group_domains[name]
        label = f"[{dom}] {name}" if dom != "general" else name
        new_groups.append((label, fps))

    # 5) 派活覆盖度：显式域是否都拿到了组（"按域派活"的可观测证据）
    dispatched = sorted({d for d in group_domains.values() if d != "general"},
                        key=lambda d: order_idx.get(d, 999))
    stats: dict[str, Any] = {
        "enabled": True,
        "dispatched_domains": dispatched,
        "missing_domains": [d for d in DOMAIN_LIST if d not in dispatched],
        # 原始组名 → 主域（用原始名，避免与加了前缀的派活名混淆）
        "group_domains": dict(group_domains),
        # 域 → 该域下的原始组名
        "domains": {d: [n for n, dm in group_domains.items() if dm == d] for d in dispatched},
        "total_groups": len(new_groups),
        "total_endpoints": len(all_eps),
        "domain_endpoint_count": {d: len(v) for d, v in domain_groups.items()},
    }
    return new_groups, stats


def track_a_summary(stats: dict) -> str:
    """Track A 一行摘要（system 事件用）。"""
    disp = stats.get("dispatched_domains") or []
    if not disp:
        return "🧭 Track A: 本批端点未命中任何显式风险域（全部走通用编排）"
    return (
        f"🧭 Track A 按域派活: {stats['total_groups']} 组 / "
        f"{len(disp)} 域 → " + "、".join(disp)
    )


def worker_id_for(group_name: str, idx: int) -> str:
    """worker_id = ``"<域>-w<序号>"``；无 Track A 标注时退化为 ``"w<序号>"``。

    worker_id 只作唯一键（卡死检测 dict / ``/api/stop`` 取消），**格式不参与解析**，
    前缀纯为让"按域派活"在事件流与日志里可观测（域标注来自 `apply_track_a`）。
    """
    name = str(group_name or "")
    if name.startswith("["):
        dom, sep, _rest = name[1:].partition("]")
        if sep and dom:
            return f"{dom}-w{idx}"
    return f"w{idx}"


def _resolve_host(session: Any) -> str:
    from urllib.parse import urlparse

    for attr in ("target_url", "target", "url"):
        v = getattr(session, attr, None) or getattr(getattr(session, "sitemap", None), attr, None)
        if v:
            return urlparse(str(v)).netloc.lower() or str(v)
    return ""


def apply_track_a(
    session: Any,
    feature_groups: list[tuple[str, list]],
) -> tuple[list[tuple[str, list]], dict | None]:
    """编排侧唯一入口：对 feature_groups 应用 Track A，并回写 session 观测数据。

    Returns:
        ``(feature_groups, event_or_None)``。event 为待 yield 的 system 事件。
        关闭（XJ_TRACK_A=0）或失败降级时 event 多为 None（失败会带告警事件）。
    """
    if not feature_groups or not track_a_enabled():
        return feature_groups, None
    try:
        new_groups, stats = batch_groups_by_risk_domain(
            feature_groups, host=_resolve_host(session)
        )
        # 暴露给报告/UI/后续域级探针消费（原为空转的域标签在此落地）
        session._track_a_batches = stats
        return new_groups, session._event("system", track_a_summary(stats))
    except Exception as e:  # 域分批非关键路径：留痕后降级，绝不静默吞
        return feature_groups, session._event(
            "system", f"⚠️ Track A 按域派活失败，已降级: {e}"
        )


__all__ = [
    "track_a_enabled",
    "batch_groups_by_risk_domain",
    "track_a_summary",
    "worker_id_for",
    "apply_track_a",
]
