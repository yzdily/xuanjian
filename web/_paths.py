"""Web 层路径单源（XUANJIAN_MASTER_PLAN §3.1 D9 S6）。

所有 web 子模块统一从此处取「项目根目录 PROJECT_ROOT」与「web 目录 WEB_ROOT」，
消除 server.py / traffic_api.py / reports_api.py 等各自 ``Path(__file__).parent``
解析的漂移（曾在多文件中以不同层数 parent 解析，易因目录结构调整而错位）。

原为 ``web/_security.py`` 内联定义，现抽为独立单源模块；``web/_security.py`` 继续
re-export 以保持 ``from web._security import PROJECT_ROOT`` 既有调用方的兼容（D4 S1）。
"""

from __future__ import annotations

from pathlib import Path

# web/_paths.py 位于 web/ 下 → .parent = web 目录，.parent.parent = 项目根。
WEB_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = WEB_ROOT.parent
