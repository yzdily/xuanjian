"""
core/replay/store.py — 剧本持久化

格式：data/replays/<run_id>/
                ├── script.jsonl   # 每行一个 ReplayFrame
                └── meta.json      # ScriptMeta

性能：
- script.jsonl 用 append-only，写入是 O(1)，跑长任务不会变慢
- 读取时全量解析（一次 run 的帧数量级 100~10000，不会爆内存）
- 单 run > 100MB 自动截断（防止失控）
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from threading import Lock
from typing import Any

from core.log import get_logger
from core.replay.frame import ReplayFrame, ScriptMeta

log = get_logger("replay.store")

REPLAY_ROOT = Path("data/replays")
MAX_SCRIPT_SIZE = 100 * 1024 * 1024  # 100MB
# ★ 2026-08-05：预计算 MB 上限，避免日志里 `MAX_SCRIPT_SIZE // 1024 // 1024`
# 在历史/缓存版本中误算为 0（曾出现 "超过 0MB" 的误导性日志）
_MAX_SCRIPT_SIZE_MB = MAX_SCRIPT_SIZE // (1024 * 1024)

_run_locks: dict[str, Lock] = {}
_run_locks_master = Lock()
# ★ 2026-08-05：每个 run 的大小超限警告只输出一次，避免数百次重复 WARNING 刷屏
_size_warned_runs: set[str] = set()


def _lock_for(run_id: str) -> Lock:
    with _run_locks_master:
        if run_id not in _run_locks:
            _run_locks[run_id] = Lock()
        return _run_locks[run_id]


def _run_dir(run_id: str) -> Path:
    return REPLAY_ROOT / run_id


def _script_file(run_id: str) -> Path:
    return _run_dir(run_id) / "script.jsonl"


def _meta_file(run_id: str) -> Path:
    return _run_dir(run_id) / "meta.json"


# ============================================================
# 写入
# ============================================================

def save_frame(frame: ReplayFrame, meta_patch: dict[str, Any] | None = None) -> bool:
    """追加一帧到剧本。失败返回 False，不抛异常。"""
    run_id = frame.run_id
    if not run_id:
        log.warning("ReplayFrame 缺少 run_id，跳过")
        return False

    try:
        script_path = _script_file(run_id)
        with _lock_for(run_id):
            # 大小保护
            if script_path.exists() and script_path.stat().st_size > MAX_SCRIPT_SIZE:
                # ★ 每个 run 只警告一次，避免 save_frame 被高频调用时刷屏
                if run_id not in _size_warned_runs:
                    _size_warned_runs.add(run_id)
                    log.warning("剧本 %s 超过 %dMB，停止追加", run_id, _MAX_SCRIPT_SIZE_MB)
                return False

            script_path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(frame.to_dict(), ensure_ascii=False)
            with script_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

            # 更新 meta
            _update_meta(run_id, frame, meta_patch or {})
        return True
    except Exception as e:
        log.warning("save_frame 失败: %s", e)
        return False


def _update_meta(run_id: str, frame: ReplayFrame, patch: dict[str, Any]) -> None:
    """读 → 改 → 写 meta.json（已在外层加锁）。"""
    meta_path = _meta_file(run_id)
    if meta_path.exists():
        try:
            existing = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    else:
        existing = {}

    if "started_at" not in existing or not existing.get("started_at"):
        existing["started_at"] = frame.timestamp
    existing["run_id"] = run_id
    existing["ended_at"] = frame.timestamp
    existing["frame_count"] = int(existing.get("frame_count", 0)) + 1
    for k, v in patch.items():
        if v is not None:
            existing[k] = v
    # 更新人类可读时间
    if existing.get("started_at"):
        existing["started_at_human"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(existing["started_at"]))
    if existing.get("ended_at"):
        existing["ended_at_human"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(existing["ended_at"]))

    tmp = meta_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(meta_path)


# ============================================================
# 读取
# ============================================================

def load_script(run_id: str) -> tuple[list[ReplayFrame], dict[str, Any]]:
    """加载一个剧本的所有帧 + 元数据。"""
    frames: list[ReplayFrame] = []
    meta: dict[str, Any] = {}

    sf = _script_file(run_id)
    if sf.exists():
        try:
            for line in sf.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    frames.append(ReplayFrame.from_dict(json.loads(line)))
                except Exception as e:
                    log.warning("跳过损坏帧: %s", e)
        except Exception as e:
            log.warning("读取 script 失败: %s", e)

    mf = _meta_file(run_id)
    if mf.exists():
        try:
            meta = json.loads(mf.read_text(encoding="utf-8"))
        except Exception:
            meta = {}

    return frames, meta


def list_runs(limit: int = 200) -> list[dict[str, Any]]:
    """列出所有 run，按 ended_at 倒序。"""
    if not REPLAY_ROOT.exists():
        return []
    out: list[dict[str, Any]] = []
    for d in REPLAY_ROOT.iterdir():
        if not d.is_dir():
            continue
        mf = d / "meta.json"
        if not mf.exists():
            continue
        try:
            meta = json.loads(mf.read_text(encoding="utf-8"))
            out.append(meta)
        except Exception as e:
            log.warning("读取 meta 失败: %s", e)
    out.sort(key=lambda x: x.get("ended_at", 0), reverse=True)
    return out[:limit] if limit > 0 else out


def delete_run(run_id: str) -> bool:
    d = _run_dir(run_id)
    if not d.exists():
        return False
    try:
        shutil.rmtree(d)
        return True
    except Exception as e:
        log.warning("删除 run 失败: %s", e)
        return False


__all__ = [
    "save_frame",
    "load_script",
    "list_runs",
    "delete_run",
    "REPLAY_ROOT",
    "MAX_SCRIPT_SIZE",
]
