"""
core/diff/differ.py — 多维度差分算法

输入：两个 sitemap.json 字典（snapshot_a 旧、snapshot_b 新）
输出：DiffResult，包含 pages / endpoints / features 三个维度的变更

## 比对规则
1. **API 端点**：以 `"METHOD url"` 为 key（与 sitemap.apis 字典一致）
   - key 在 a 不在 b → REMOVED
   - key 在 b 不在 a → ADDED
   - 都存在 → 比较参数集合 / content_type / auth_required，差异 → MODIFIED
2. **页面**：以 url 为 key
   - 比较 title / forms 数量 / buttons
3. **功能点**：以 feature_id 为 key（feat_001...）
   - 由于 feature_id 不稳定（重新生成会变），优先按 name 做"软匹配"对照
   - 比较 priority / related_apis / module
"""

from __future__ import annotations

from typing import Any

from core.diff.models import (
    ChangeKind,
    DiffResult,
    EndpointChange,
    FeatureChange,
    PageChange,
)


# ============================================================
# Endpoints
# ============================================================

def _diff_endpoint_fields(a: dict, b: dict) -> dict[str, Any]:
    """比较两个 endpoint dict，返回有差异的字段映射 {field: {old, new}}。"""
    diffs: dict[str, Any] = {}
    watched = ("auth_required", "content_type", "source_type", "confidence",
               "test_strategy")
    for k in watched:
        va, vb = a.get(k), b.get(k)
        if va != vb:
            diffs[k] = {"old": va, "new": vb}
    return diffs


def _diff_endpoints(a: dict, b: dict) -> list[EndpointChange]:
    apis_a: dict[str, dict] = a.get("apis", {}) or {}
    apis_b: dict[str, dict] = b.get("apis", {}) or {}
    keys_a = set(apis_a.keys())
    keys_b = set(apis_b.keys())

    out: list[EndpointChange] = []

    # 删除
    for k in sorted(keys_a - keys_b):
        ep = apis_a[k]
        out.append(EndpointChange(
            kind=ChangeKind.REMOVED,
            key=k,
            method=ep.get("method", ""),
            url=ep.get("url", ""),
        ))

    # 新增
    for k in sorted(keys_b - keys_a):
        ep = apis_b[k]
        out.append(EndpointChange(
            kind=ChangeKind.ADDED,
            key=k,
            method=ep.get("method", ""),
            url=ep.get("url", ""),
            added_params=list(ep.get("params") or []),
        ))

    # 改动
    for k in sorted(keys_a & keys_b):
        epa, epb = apis_a[k], apis_b[k]
        params_a = set(epa.get("params") or [])
        params_b = set(epb.get("params") or [])
        added = sorted(params_b - params_a)
        removed = sorted(params_a - params_b)
        field_diffs = _diff_endpoint_fields(epa, epb)
        if added or removed or field_diffs:
            out.append(EndpointChange(
                kind=ChangeKind.MODIFIED,
                key=k,
                method=epb.get("method", ""),
                url=epb.get("url", ""),
                diff_fields=field_diffs,
                added_params=added,
                removed_params=removed,
            ))

    return out


# ============================================================
# Pages
# ============================================================

def _diff_pages(a: dict, b: dict) -> list[PageChange]:
    pages_a: dict[str, dict] = a.get("pages", {}) or {}
    pages_b: dict[str, dict] = b.get("pages", {}) or {}
    urls_a = set(pages_a.keys())
    urls_b = set(pages_b.keys())

    out: list[PageChange] = []

    for u in sorted(urls_a - urls_b):
        out.append(PageChange(
            kind=ChangeKind.REMOVED,
            url=u,
            title=pages_a[u].get("title", ""),
        ))
    for u in sorted(urls_b - urls_a):
        pg = pages_b[u]
        out.append(PageChange(
            kind=ChangeKind.ADDED,
            url=u,
            title=pg.get("title", ""),
            added_forms=len(pg.get("forms") or []),
        ))
    for u in sorted(urls_a & urls_b):
        pa, pb = pages_a[u], pages_b[u]
        diff_fields: dict[str, Any] = {}
        if pa.get("title") != pb.get("title"):
            diff_fields["title"] = {"old": pa.get("title"), "new": pb.get("title")}
        forms_a = len(pa.get("forms") or [])
        forms_b = len(pb.get("forms") or [])
        added_forms = max(0, forms_b - forms_a)
        removed_forms = max(0, forms_a - forms_b)
        # buttons 集合差
        btns_a = set(pa.get("buttons") or [])
        btns_b = set(pb.get("buttons") or [])
        if btns_a != btns_b:
            diff_fields["buttons"] = {
                "added": sorted(btns_b - btns_a),
                "removed": sorted(btns_a - btns_b),
            }
        if diff_fields or added_forms or removed_forms:
            out.append(PageChange(
                kind=ChangeKind.MODIFIED,
                url=u,
                title=pb.get("title", ""),
                diff_fields=diff_fields,
                added_forms=added_forms,
                removed_forms=removed_forms,
            ))
    return out


# ============================================================
# Features
# ============================================================

def _feature_fingerprint(f: dict) -> str:
    """功能点的指纹：name + module + sorted(related_apis)。

    feat_id 不稳定（重新生成时序号会变），所以用语义指纹来做对照。
    """
    apis = sorted(f.get("related_apis") or [])
    return f"{f.get('name', '')}|{f.get('module', '')}|{'|'.join(apis)}"


def _diff_features(a: dict, b: dict) -> list[FeatureChange]:
    feats_a: dict[str, dict] = a.get("features", {}) or {}
    feats_b: dict[str, dict] = b.get("features", {}) or {}

    # 用指纹建索引：fp → feature_id
    fp_to_id_a: dict[str, str] = {}
    for fid, fp_obj in feats_a.items():
        fp_to_id_a.setdefault(_feature_fingerprint(fp_obj), fid)
    fp_to_id_b: dict[str, str] = {}
    for fid, fp_obj in feats_b.items():
        fp_to_id_b.setdefault(_feature_fingerprint(fp_obj), fid)

    fps_a = set(fp_to_id_a.keys())
    fps_b = set(fp_to_id_b.keys())

    out: list[FeatureChange] = []

    # 删除
    for fp in sorted(fps_a - fps_b):
        fid = fp_to_id_a[fp]
        feat = feats_a[fid]
        out.append(FeatureChange(
            kind=ChangeKind.REMOVED,
            feature_id=fid,
            name=feat.get("name", ""),
        ))

    # 新增
    for fp in sorted(fps_b - fps_a):
        fid = fp_to_id_b[fp]
        feat = feats_b[fid]
        out.append(FeatureChange(
            kind=ChangeKind.ADDED,
            feature_id=fid,
            name=feat.get("name", ""),
            added_apis=list(feat.get("related_apis") or []),
        ))

    # 同指纹但还要看其他字段（priority/test_status 等）的变化
    # 按 name+module 做更宽松的二次匹配，发现"同名功能但 API 列表已变"的情况
    name_module_a: dict[str, str] = {}
    for fid, feat in feats_a.items():
        key = f"{feat.get('name', '')}|{feat.get('module', '')}"
        name_module_a.setdefault(key, fid)

    used_b: set[str] = set()
    for fp in fps_a & fps_b:
        used_b.add(fp_to_id_b[fp])

    # 找出 b 中"在 added 列表里但其实是同名的旧功能改了 API"的情况，转为 MODIFIED
    new_added: list[FeatureChange] = []
    for change in list(out):
        if change.kind != ChangeKind.ADDED:
            new_added.append(change)
            continue
        feat_b = feats_b.get(change.feature_id, {})
        nm_key = f"{feat_b.get('name', '')}|{feat_b.get('module', '')}"
        old_fid = name_module_a.get(nm_key)
        if old_fid and old_fid in feats_a:
            # 同名功能存在于旧版本，但指纹不同（API 列表变化）→ MODIFIED
            feat_a = feats_a[old_fid]
            apis_a_set = set(feat_a.get("related_apis") or [])
            apis_b_set = set(feat_b.get("related_apis") or [])
            mod_change = FeatureChange(
                kind=ChangeKind.MODIFIED,
                feature_id=change.feature_id,
                name=change.name,
                added_apis=sorted(apis_b_set - apis_a_set),
                removed_apis=sorted(apis_a_set - apis_b_set),
            )
            field_diffs: dict[str, Any] = {}
            if feat_a.get("priority") != feat_b.get("priority"):
                field_diffs["priority"] = {
                    "old": feat_a.get("priority"),
                    "new": feat_b.get("priority"),
                }
            mod_change.diff_fields = field_diffs
            new_added.append(mod_change)
            # 同时把 REMOVED 列表里这条对应项移掉
            new_added = [c for c in new_added
                         if not (c.kind == ChangeKind.REMOVED and c.feature_id == old_fid)]
        else:
            new_added.append(change)
    return new_added


# ============================================================
# 主入口
# ============================================================

def diff_snapshots(
    snapshot_a: dict,
    snapshot_b: dict,
    tag_a: str = "",
    tag_b: str = "",
) -> DiffResult:
    """比较两个 sitemap 快照。

    Args:
        snapshot_a: 旧版本 sitemap.json 的 dict
        snapshot_b: 新版本 sitemap.json 的 dict
        tag_a, tag_b: 仅用于在 DiffResult 里记录元信息
    """
    if not isinstance(snapshot_a, dict) or not isinstance(snapshot_b, dict):
        raise TypeError("snapshot 必须是 dict（来自 sitemap.json）")

    pages = _diff_pages(snapshot_a, snapshot_b)
    endpoints = _diff_endpoints(snapshot_a, snapshot_b)
    features = _diff_features(snapshot_a, snapshot_b)

    summary = {
        "pages_added": sum(1 for p in pages if p.kind == ChangeKind.ADDED),
        "pages_removed": sum(1 for p in pages if p.kind == ChangeKind.REMOVED),
        "pages_modified": sum(1 for p in pages if p.kind == ChangeKind.MODIFIED),
        "endpoints_added": sum(1 for e in endpoints if e.kind == ChangeKind.ADDED),
        "endpoints_removed": sum(1 for e in endpoints if e.kind == ChangeKind.REMOVED),
        "endpoints_modified": sum(1 for e in endpoints if e.kind == ChangeKind.MODIFIED),
        "features_added": sum(1 for f in features if f.kind == ChangeKind.ADDED),
        "features_removed": sum(1 for f in features if f.kind == ChangeKind.REMOVED),
        "features_modified": sum(1 for f in features if f.kind == ChangeKind.MODIFIED),
    }

    return DiffResult(
        target=snapshot_b.get("target", "") or snapshot_a.get("target", ""),
        snapshot_a=tag_a,
        snapshot_b=tag_b,
        pages=pages,
        endpoints=endpoints,
        features=features,
        summary=summary,
    )


__all__ = ["diff_snapshots"]
