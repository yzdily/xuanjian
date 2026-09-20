"""
迁移 default-*.md 历史孤儿笔记到对应任务。

§12 修复前 worker_agent 未传 task_id，导致子 Agent 笔记写到 default-*.md。
本脚本按目标 URL 反查 sitemap 的 target 字段，把 default-*.md 的内容拆分追加
到匹配的 {task_id}-*.md，迁移完成后清空 default-*.md。

用法: python scripts/migrate_default_notes.py
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

TASKS_DIR = Path("data/tasks")
NOTES_DIR = Path("data/notes")
BACKUP_DIR = Path("data/notes/_migration_backup")

# 笔记文件类型
NOTE_TYPES = ["result", "info", "infer"]


def load_task_targets() -> dict[str, str]:
    """返回 {task_id: target_url} 映射，用于按 URL 反查归属任务。"""
    mapping: dict[str, str] = {}
    for sitemap_path in TASKS_DIR.glob("*-sitemap.json"):
        try:
            data = json.loads(sitemap_path.read_text(encoding="utf-8"))
            task_id = sitemap_path.stem.replace("-sitemap.json", "").replace("-sitemap", "")
            # 文件名形如 task_xxx-sitemap.json → task_id = task_xxx
            task_id = sitemap_path.name.replace("-sitemap.json", "")
            target = (data.get("target") or "").strip()
            if task_id and target:
                mapping[task_id] = target
        except Exception:
            continue
    return mapping


def extract_urls_from_text(text: str) -> set[str]:
    """从文本中提取所有 https?:// URL，返回小写集合。"""
    urls = set()
    for m in re.finditer(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", text, re.IGNORECASE):
        urls.add(m.group(0).lower().rstrip(".,);]"))
    return urls


def find_matching_task(entry_text: str, task_targets: dict[str, str]) -> str | None:
    """根据笔记条目中的 URL 匹配到对应 task_id。"""
    entry_urls = extract_urls_from_text(entry_text)
    if not entry_urls:
        return None
    for task_id, target in task_targets.items():
        target_lower = target.lower().rstrip("/")
        # 检查条目中是否有 URL 以该任务 target 为前缀
        for url in entry_urls:
            url_host = re.match(r"https?://([^/]+)", url)
            target_host = re.match(r"https?://([^/]+)", target_lower)
            if url_host and target_host and url_host.group(1) == target_host.group(1):
                return task_id
            # 更精确匹配：URL 包含 target 的 host+path
            if target_lower in url or url in target_lower:
                return task_id
    return None


def split_default_notes_by_timestamp(content: str) -> list[tuple[str, str]]:
    """把 default-*.md 按 ## [时间戳] 标题拆分成多个条目。

    返回 [(timestamp_or_title, entry_text), ...]
    """
    entries: list[tuple[str, str]] = []
    # 匹配 ## [时间戳] 或 ## 标题 作为分隔符
    parts = re.split(r"(?=^## \[?\d{4}-\d{2}-\d{2})", content, flags=re.MULTILINE)
    current_ts = ""
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # 提取时间戳标题
        ts_match = re.match(r"^## \[?(\d{4}-\d{2}-\d{2}[^\]]*)\]?", part)
        if ts_match:
            current_ts = ts_match.group(1)
            entries.append((current_ts, part))
        else:
            # 没有时间戳前缀，归到上一个条目或单独成段
            if entries:
                last_ts, last_text = entries[-1]
                entries[-1] = (last_ts, last_text + "\n\n" + part)
            else:
                entries.append(("unknown", part))
    return entries


def migrate_note_type(note_type: str, task_targets: dict[str, str]) -> dict:
    """迁移一种类型的笔记。返回统计信息。"""
    default_file = NOTES_DIR / f"default-{note_type}.md"
    if not default_file.exists():
        return {"note_type": note_type, "found": False, "migrated": 0, "unmatched": 0}

    content = default_file.read_text(encoding="utf-8").strip()
    if not content:
        return {"note_type": note_type, "found": True, "empty": True, "migrated": 0, "unmatched": 0}

    # 备份原文件
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_path = BACKUP_DIR / f"default-{note_type}.md.bak"
    shutil.copy2(default_file, backup_path)

    entries = split_default_notes_by_timestamp(content)
    migrated = 0
    unmatched_entries: list[str] = []
    matched_tasks: dict[str, list[str]] = {}

    for ts, entry_text in entries:
        task_id = find_matching_task(entry_text, task_targets)
        if task_id:
            task_note = NOTES_DIR / f"{task_id}-{note_type}.md"
            # 追加到任务笔记
            with task_note.open("a", encoding="utf-8") as f:
                f.write("\n\n" + entry_text + "\n")
            migrated += 1
            matched_tasks.setdefault(task_id, []).append(ts)
        else:
            unmatched_entries.append(entry_text)

    # 把无法匹配的条目保留在 default-{type}.md
    if unmatched_entries:
        default_file.write_text(
            "# 未匹配任务的孤儿笔记（迁移脚本保留）\n\n"
            + "\n\n---\n\n".join(unmatched_entries),
            encoding="utf-8",
        )
    else:
        # 全部迁移完成，写一个标记
        default_file.write_text(
            f"# default-{note_type}.md 已迁移\n\n"
            f"> 迁移脚本已把所有条目按 URL 匹配追加到对应 task_*-{note_type}.md。\n"
            f"> 原始内容备份在 _migration_backup/default-{note_type}.md.bak\n",
            encoding="utf-8",
        )

    return {
        "note_type": note_type,
        "found": True,
        "total_entries": len(entries),
        "migrated": migrated,
        "unmatched": len(unmatched_entries),
        "matched_tasks": matched_tasks,
        "backup": str(backup_path),
    }


def main():
    print("=" * 60)
    print("default-*.md 历史孤儿笔记迁移脚本")
    print("=" * 60)

    if not NOTES_DIR.exists():
        print(f"✗ 笔记目录不存在: {NOTES_DIR}")
        return

    task_targets = load_task_targets()
    print(f"\n[1] 加载到 {len(task_targets)} 个任务的 target URL:")
    for tid, tgt in list(task_targets.items())[:5]:
        print(f"    {tid}: {tgt}")
    if len(task_targets) > 5:
        print(f"    ... +{len(task_targets) - 5} more")

    print(f"\n[2] 开始迁移笔记:")
    for note_type in NOTE_TYPES:
        result = migrate_note_type(note_type, task_targets)
        print(f"\n  ● {note_type}:")
        if not result.get("found"):
            print(f"    跳过（文件不存在）")
            continue
        if result.get("empty"):
            print(f"    跳过（文件为空）")
            continue
        print(f"    总条目: {result.get('total_entries', 0)}")
        print(f"    已迁移: {result['migrated']}")
        print(f"    未匹配: {result['unmatched']}")
        print(f"    备份: {result.get('backup', '')}")
        for task_id, tss in (result.get("matched_tasks") or {}).items():
            print(f"    → {task_id}: {len(tss)} 条")

    print("\n[3] 迁移完成。")
    print(f"    原始文件备份目录: {BACKUP_DIR}")
    print(f"    未匹配的条目保留在 data/notes/default-*.md")


if __name__ == "__main__":
    main()
