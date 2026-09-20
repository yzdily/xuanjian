"""Web 层路径单源（XUANJIAN_MASTER_PLAN §3.1 D9 S6）。

所有 web 子模块统一从此处取「项目根目录 PROJECT_ROOT」与「web 目录 WEB_ROOT」，
消除 server.py / traffic_api.py / reports_api.py 等各自 ``Path(__file__).parent``
解析的漂移（曾在多文件中以不同层数 parent 解析，易因目录结构调整而错位）。

原为 ``web/_security.py`` 内联定义，现抽为独立单源模块；``web/_security.py`` 继续
re-export 以保持 ``from web._security import PROJECT_ROOT`` 既有调用方的兼容（D4 S1）。
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Iterable

from core.log import get_logger

log = get_logger("web.paths")

# web/_paths.py 位于 web/ 下 → .parent = web 目录，.parent.parent = 项目根。
WEB_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = WEB_ROOT.parent


def move_to_trash(paths: Iterable[Path], trash_root: Path, ts: str | None = None) -> str:
    """把已存在的文件/目录**移动**到回收区 ``<trash_root>/<YYYYmmdd-HHMMSS>/``。

    删除会话/附件时统一走此函数，而不是 ``unlink``/``rmtree`` —— 误删可人工找回。
    硬约束：``trash_root`` 必须位于 ``data/reports/`` 与 ``data/tasks/`` **之外**，
    否则回收区内容会被报告中心/会话列表的目录遍历当成正常文件列出。

    Args:
        paths: 待移动的文件或目录（不存在的会被跳过）。
        trash_root: 回收区根目录（如 ``data/_trash``）。
        ts: 时间戳目录名，默认按当前时间生成（便于测试注入）。

    Returns:
        实际移动到的回收目录路径字符串；没有任何移动时返回 ``""``。
    """
    stamp = ts or time.strftime("%Y%m%d-%H%M%S")
    dest_dir = Path(trash_root) / stamp
    moved = False
    for src in paths:
        try:
            if not src.exists():
                continue
        except OSError as exc:
            log.warning("回收区跳过（无法访问）%s: %s", src, exc)
            continue
        dest_dir.mkdir(parents=True, exist_ok=True)
        target = dest_dir / src.name
        idx = 1
        while target.exists():                        # 同秒重名不覆盖
            target = dest_dir / f"{src.name}.{idx}"
            idx += 1
        try:
            shutil.move(str(src), str(target))
            moved = True
        except OSError as exc:                        # 单个失败不影响其余资产
            log.warning("移入回收区失败 %s: %s", src, exc)
    return str(dest_dir) if moved else ""
