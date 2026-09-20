"""
core/diff/models.py — Diff 数据模型

设计原则：
- 与 core/sitemap/models.py 保持解耦：不直接 import FeaturePoint 等运行时对象，
  而是基于 sitemap.json 序列化后的 dict 字段（key, method, url, params...）来比对。
  这样即便未来 sitemap 模型升级，diff 只需要改 differ.py，不影响数据契约。
- 所有 dataclass 可被直接 json 序列化（`dataclasses.asdict` 即可）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChangeKind(str, Enum):
    ADDED = "added"          # 新增
    REMOVED = "removed"      # 删除
    MODIFIED = "modified"    # 改动（参数变化、字段变化等）
    UNCHANGED = "unchanged"  # 未变（一般不放进 DiffResult）


# ------------------------------------------------------------
# 单元变更
# ------------------------------------------------------------

@dataclass
class EndpointChange:
    """一个 API 端点的变更。"""
    kind: ChangeKind
    key: str                          # "METHOD url"，与 sitemap 的 apis 字典一致
    method: str = ""
    url: str = ""
    # 仅当 MODIFIED 时填充：哪些字段变了
    diff_fields: dict[str, Any] = field(default_factory=dict)
    # 参数变化（用于回归扫描时优先针对新参数）
    added_params: list[str] = field(default_factory=list)
    removed_params: list[str] = field(default_factory=list)


@dataclass
class PageChange:
    """一个页面的变更。"""
    kind: ChangeKind
    url: str
    title: str = ""
    diff_fields: dict[str, Any] = field(default_factory=dict)
    added_forms: int = 0
    removed_forms: int = 0


@dataclass
class FeatureChange:
    """一个功能点的变更。"""
    kind: ChangeKind
    feature_id: str
    name: str = ""
    diff_fields: dict[str, Any] = field(default_factory=dict)
    added_apis: list[str] = field(default_factory=list)
    removed_apis: list[str] = field(default_factory=list)


# ------------------------------------------------------------
# 顶层结果
# ------------------------------------------------------------

@dataclass
class DiffResult:
    """两个 sitemap 快照的差分结果。"""
    target: str = ""
    snapshot_a: str = ""               # 旧版本 tag
    snapshot_b: str = ""               # 新版本 tag

    pages: list[PageChange] = field(default_factory=list)
    endpoints: list[EndpointChange] = field(default_factory=list)
    features: list[FeatureChange] = field(default_factory=list)

    # 元数据（counts 由 differ 计算后填入）
    summary: dict[str, int] = field(default_factory=dict)

    def has_changes(self) -> bool:
        return any([self.pages, self.endpoints, self.features])

    def changed_endpoints_keys(self) -> list[str]:
        """返回需要回归测试的 API key 列表（新增 + 改动）。"""
        return [
            e.key for e in self.endpoints
            if e.kind in (ChangeKind.ADDED, ChangeKind.MODIFIED)
        ]

    def changed_feature_ids(self) -> list[str]:
        """返回需要回归测试的功能点 id 列表（新增 + 改动）。"""
        return [
            f.feature_id for f in self.features
            if f.kind in (ChangeKind.ADDED, ChangeKind.MODIFIED)
        ]


__all__ = [
    "ChangeKind",
    "EndpointChange",
    "PageChange",
    "FeatureChange",
    "DiffResult",
]
