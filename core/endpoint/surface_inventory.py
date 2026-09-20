"""G2 — 接口面完整度盘点（surface inventory）。

对标参考：H:\\api-pentest-extension\\skills\\bug-legacy\\scripts\\surface_inventory.py

职责：对端点池做完整度度量，输出"接口面账本"——
  - 去重端点数（method+path 去重，query 不计）
  - 已分析 / 待分析数
  - 静态资产数（不计入测试面）
  - 跨域端点数（is_same_host=False）
  - 按风险域分组的端点数（消费 G1 标签）

G4 覆盖账本（coverage_tracker.py）以本模块的 surface 清单为"期望面"，
G3 coverage_derive 以 (surface × risk_domain) 推导期望漏洞类型。

设计原则（Security Engineer 视角）：
  - 只读盘点，不阻塞主扫描；纯 stdlib。
  - 静态资产从测试面剔除（避免对 .js/.css 做 API 漏洞测试，浪费 + 噪声）。
  - 跨域端点单独标注（SSRF/越权测试时需授权确认，不能默认进测试面）。
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from .risk_domain import DOMAIN_LABELS, tag_endpoints


def build_surface_inventory(
    endpoints: Iterable[Any],
    *,
    host: str | None = None,
) -> dict[str, Any]:
    """构建接口面完整度账本。

    Args:
        endpoints: 可迭代的端点（dict / 对象 / api_key 字符串），形态同 tag_endpoints。
        host: 目标主域，用于 is_same_host 判定。

    Returns:
        dict 含：
          - total: 原始端点数
          - unique: 去重后端点数（method+path）
          - testable: 可测试端点数（去静态资产 + 跨域后）
          - static_assets: 静态资产数
          - cross_host: 跨域端点数
          - by_risk_domain: {域: 端点数}（多域端点在多域计数）
          - surfaces: 去重后的端点清单（含 _tags）
    """
    tagged = tag_endpoints(endpoints, host=host)

    # 去重键：METHOD + path（不含 query）
    seen: dict[str, dict[str, Any]] = {}
    for ep in tagged:
        method = str(ep.get("method", "GET")).upper()
        url = str(ep.get("url", ""))
        path = url.split("?", 1)[0] or url
        key = f"{method} {path}"
        if key not in seen:
            ep["_surface_key"] = key
            seen[key] = ep

    surfaces = list(seen.values())
    static_count = sum(1 for s in surfaces if (s.get("_tags") or {}).get("is_static_asset"))
    cross_count = sum(1 for s in surfaces if (s.get("_tags") or {}).get("is_same_host") is False)
    testable = len(surfaces) - static_count - sum(
        1 for s in surfaces
        if (s.get("_tags") or {}).get("is_static_asset")
        and (s.get("_tags") or {}).get("is_same_host") is False
    )
    # 修正 testable：跨域且非静态也算待授权，先从 testable 剔除跨域
    testable = len(surfaces) - static_count - cross_count
    if testable < 0:
        testable = 0

    domain_counter: Counter[str] = Counter()
    for s in surfaces:
        doms = (s.get("_tags") or {}).get("risk_domain") or ["general"]
        if isinstance(doms, str):
            doms = [doms]
        for d in doms:
            domain_counter[d] += 1

    by_domain = {d: {"count": c, "label": DOMAIN_LABELS.get(d, d)}
                 for d, c in sorted(domain_counter.items(), key=lambda x: -x[1])}

    return {
        "total": len(tagged),
        "unique": len(surfaces),
        "testable": testable,
        "static_assets": static_count,
        "cross_host": cross_count,
        "by_risk_domain": by_domain,
        "surfaces": surfaces,
    }


def _dedup_path(url: str) -> str:
    """URL → 去 query、去 scheme/host 的小写路径（跨源去重键用）。"""
    u = (url or "").strip()
    if not u:
        return ""
    try:
        pu = urlparse(u if "://" in u else f"//{u}")
        return ((pu.path or "").lower().split("?", 1)[0]) or "/"
    except Exception:
        p = u.split("?", 1)[0]
        return p.lower()


def union_sources(
    *sources: Any,
    host: str | None = None,
) -> dict[str, Any]:
    """多源并集去重（§1.5 G2：Burp + OpenAPI + JS + sitemap）。

    背景：`build_surface_inventory` 原先只收单一来源（sitemap.apis），
    JS 分析 / 抓包 / OpenAPI 里"发现了但没进 sitemap.apis"的端点会漏出测试面，
    覆盖度对"单一来源"负责而非对"并集"负责 → 漏报。

    每 个 source 接受三种形态：
      - 端点可迭代（dict / 对象 / "METHOD url" 字符串）
      - 含 ``surfaces`` / ``endpoints`` / ``apis`` 键的 dict（取其值）
      - Sitemap 对象（自动取 apis / js_api_calls / js_routes）
    也支持 ``(名称, 来源)`` 二元组，用于在 provenance 里保留可读来源名。

    Returns:
        ``{"endpoints": [...], "unique": int, "sources": {名: 条数},
        "contributions": {名: 新增条数}, "duplicates": int}``
    """
    from .risk_domain import _extract_method_url

    def _norm_method(m: str) -> str:
        m = (m or "").strip().upper()
        # JS 静态分析常拿不到方法（UNKNOWN）→ 归 GET（读语义，兜底安全）
        return m if m in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS") else "GET"

    def _iter_source(src: Any) -> list[Any]:
        if src is None:
            return []
        # Sitemap 形态
        if hasattr(src, "apis") or hasattr(src, "js_api_calls"):
            out: list[Any] = list(getattr(src, "apis", None) or {})
            if isinstance(out, dict):
                out = list(out.values())
            for attr in ("js_api_calls", "js_routes"):
                out.extend(list(getattr(src, attr, None) or []))
            return out
        if isinstance(src, Mapping):
            for key in ("surfaces", "endpoints", "apis"):
                v = src.get(key)
                if v is not None:
                    return list(v.values()) if isinstance(v, Mapping) else list(v)
            return [src]
        if isinstance(src, (str, bytes)):
            return [src]
        try:
            return list(src)
        except TypeError:
            return [src]

    merged: dict[str, dict[str, Any]] = {}
    source_counts: dict[str, int] = {}
    contributions: dict[str, int] = {}
    duplicates = 0

    for idx, raw in enumerate(sources):
        if isinstance(raw, tuple) and len(raw) == 2 and isinstance(raw[0], str):
            name, body = raw[0], raw[1]
        else:
            name, body = f"source{idx + 1}", raw

        items = _iter_source(body)
        source_counts[name] = len(items)
        added = 0
        for ep in items:
            method, url = _extract_method_url(ep)
            method = _norm_method(method)
            url = str(url or "").strip()
            if not url:
                continue
            # 去重键：方法 + path（去 query、去 scheme/host）——跨源同端点合并
            key = f"{method} {_dedup_path(url)}"
            if key in merged:
                duplicates += 1
                prov = merged[key].setdefault("_sources", [])
                if name not in prov:
                    prov.append(name)
                continue
            row = dict(ep) if isinstance(ep, Mapping) else {"method": method, "url": url}
            row["method"] = method
            row["url"] = url
            row["_sources"] = [name]
            merged[key] = row
            added += 1
        contributions[name] = added

    endpoints = list(merged.values())
    return {
        "endpoints": endpoints,
        "unique": len(endpoints),
        "sources": source_counts,
        "contributions": contributions,
        "duplicates": duplicates,
        "host": host or "",
    }


def inventory_summary(inv: dict[str, Any]) -> str:
    """生成接口面完整度一句话摘要（报告用）。"""
    return (
        f"接口面：去重 {inv['unique']} 个（可测 {inv['testable']}，"
        f"静态资产 {inv['static_assets']}，跨域待授权 {inv['cross_host']}），"
        f"风险域分布："
        + "、".join(
            f"{d['label']} {d['count']}" for d in inv["by_risk_domain"].values()
        )
    )


__all__ = ["build_surface_inventory", "inventory_summary", "union_sources"]
