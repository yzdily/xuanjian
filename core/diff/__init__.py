"""
core/diff — Sitemap 差分 + 增量回归扫描

## 价值
渗透项目的最大痛点：客户每周迭代，每次都要全量重扫，又慢又烦。
本模块基于已有的 sitemap.json（结构化业务认知），实现：
1. 对同一目标做两次爬取，自动告诉你"新增/改动/删除"了哪些功能点
2. 只对差异点做漏洞测试，跳过没变的（增量回归）
3. 可视化版本对比 UI

## 模块结构
- models.py     — DiffResult / ChangeSet 等数据模型
- snapshot.py   — 把 sitemap 拍成快照（只读复制，不动旧代码）
- differ.py     — 多维度差分算法（URL/参数/JS/表单/API）
- regression.py — 增量回归调度（包装现有 orchestrator）

## 零侵入接入
通过 core.events 的 `crawl.snapshot.done` 事件钩入，旧代码完全不知道我们存在。
"""

from core.diff.models import (
    ChangeKind,
    EndpointChange,
    PageChange,
    FeatureChange,
    DiffResult,
)
from core.diff.snapshot import take_snapshot, list_snapshots, load_snapshot
from core.diff.differ import diff_snapshots

__all__ = [
    "ChangeKind",
    "EndpointChange",
    "PageChange",
    "FeatureChange",
    "DiffResult",
    "take_snapshot",
    "list_snapshots",
    "load_snapshot",
    "diff_snapshots",
]
