"""
core/diff/snapshot.py — Sitemap 快照管理

## 职责
- 把 `data/tasks/<task_id>-sitemap.json` 复制到 `data/sitemap_snapshots/<host>/<tag>/`
- 提供 list / load 接口给 differ.py 和 WebUI 使用

## 零侵入说明
本模块**只读**地使用 sitemap 的持久化文件，不调用 Sitemap 类的方法。
通过订阅 `crawl.snapshot.done` 事件自动拍快照（订阅在 register.py 中）。
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.log import get_logger

log = get_logger("diff.snapshot")

SNAPSHOT_ROOT = Path("data/sitemap_snapshots")
TASK_SITEMAP_DIR = Path("data/tasks")


@dataclass
class SnapshotMeta:
    """快照元数据（保存在 meta.json）。"""
    host: str
    tag: str
    target: str
    task_id: str
    created_at: float
    pages_count: int
    apis_count: int
    features_count: int
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "tag": self.tag,
            "target": self.target,
            "task_id": self.task_id,
            "created_at": self.created_at,
            "created_at_human": time.strftime("%Y-%m-%d %H:%M:%S",
                                              time.localtime(self.created_at)),
            "pages_count": self.pages_count,
            "apis_count": self.apis_count,
            "features_count": self.features_count,
            "note": self.note,
        }


def _host_of(target: str) -> str:
    """从 target URL 提取 host，作为快照目录的 key。"""
    if not target:
        return "unknown"
    try:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = (parsed.hostname or "").lower()
        return host or "unknown"
    except Exception:
        return "unknown"


def _safe_tag(tag: str) -> str:
    """Tag 安全化：去除路径分隔符等危险字符。"""
    if not tag:
        return time.strftime("%Y%m%d-%H%M%S")
    bad = '/\\:*?"<>|'
    cleaned = "".join(c for c in tag if c not in bad).strip()
    return cleaned or time.strftime("%Y%m%d-%H%M%S")


def take_snapshot(
    task_id: str,
    tag: str = "",
    note: str = "",
    sitemap_json_path: Path | str | None = None,
) -> SnapshotMeta | None:
    """把指定 task 的 sitemap 持久化文件复制为一个快照。

    Args:
        task_id: 任务 ID，对应 data/tasks/<task_id>-sitemap.json
        tag: 快照标签（如 "v1.0", "2026-05-31"），留空自动用时间戳
        note: 备注
        sitemap_json_path: 可选，直接指定源文件路径（一般不传，自动拼）

    Returns:
        成功返回 SnapshotMeta，失败返回 None（不抛异常，不影响调用方）。
    """
    src = Path(sitemap_json_path) if sitemap_json_path else (
        TASK_SITEMAP_DIR / f"{task_id}-sitemap.json"
    )
    if not src.exists():
        log.warning("sitemap 文件不存在，跳过快照: %s", src)
        return None

    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("sitemap 文件解析失败 %s: %s", src, e)
        return None

    target = data.get("target", "") or task_id
    host = _host_of(target)
    safe_tag_str = _safe_tag(tag)

    dst_dir = SNAPSHOT_ROOT / host / safe_tag_str
    # 如果同 tag 已存在，加时间戳后缀避免覆盖
    if dst_dir.exists():
        safe_tag_str = f"{safe_tag_str}-{time.strftime('%H%M%S')}"
        dst_dir = SNAPSHOT_ROOT / host / safe_tag_str

    try:
        dst_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst_dir / "sitemap.json")

        meta = SnapshotMeta(
            host=host,
            tag=safe_tag_str,
            target=target,
            task_id=task_id,
            created_at=time.time(),
            pages_count=len(data.get("pages", {})),
            apis_count=len(data.get("apis", {})),
            features_count=len(data.get("features", {})),
            note=note,
        )
        (dst_dir / "meta.json").write_text(
            json.dumps(meta.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        log.info("拍摄快照成功: host=%s tag=%s pages=%d apis=%d features=%d",
                 host, safe_tag_str, meta.pages_count, meta.apis_count, meta.features_count)
        return meta
    except Exception as e:
        log.warning("拍摄快照失败: %s", e)
        return None


def list_snapshots(host: str = "") -> list[dict[str, Any]]:
    """列出所有快照，按时间倒序。

    Args:
        host: 过滤 host；空串返回所有 host 的快照。
    """
    if not SNAPSHOT_ROOT.exists():
        return []

    out: list[dict[str, Any]] = []
    if host:
        host_dirs = [SNAPSHOT_ROOT / host] if (SNAPSHOT_ROOT / host).is_dir() else []
    else:
        host_dirs = [d for d in SNAPSHOT_ROOT.iterdir() if d.is_dir()]

    for hd in host_dirs:
        for tag_dir in hd.iterdir():
            if not tag_dir.is_dir():
                continue
            meta_file = tag_dir / "meta.json"
            if not meta_file.exists():
                continue
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                out.append(meta)
            except Exception as e:
                log.warning("读取 meta 失败 %s: %s", meta_file, e)

    out.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return out


def load_snapshot(host: str, tag: str) -> dict[str, Any] | None:
    """加载快照的 sitemap.json 内容。"""
    f = SNAPSHOT_ROOT / host / tag / "sitemap.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("加载快照失败 %s: %s", f, e)
        return None


def delete_snapshot(host: str, tag: str) -> bool:
    """删除指定快照。"""
    d = SNAPSHOT_ROOT / host / tag
    if not d.exists():
        return False
    try:
        shutil.rmtree(d)
        log.info("删除快照: %s/%s", host, tag)
        return True
    except Exception as e:
        log.warning("删除快照失败: %s", e)
        return False


__all__ = [
    "take_snapshot",
    "list_snapshots",
    "load_snapshot",
    "delete_snapshot",
    "SnapshotMeta",
    "SNAPSHOT_ROOT",
]
