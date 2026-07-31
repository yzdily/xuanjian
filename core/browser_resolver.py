"""浏览器路径解析 — 统一检测 Playwright Chromium / 系统 Chrome / Edge。

解决跨用户/跨机器路径硬编码问题：
- 优先使用 PLAYWRIGHT_BROWSERS_PATH 环境变量
- 其次检测 ms-playwright 目录（项目内 / 用户 LocalAppData）
- 然后检测系统安装的 Chrome / Edge
- 失败时返回 None 并记录清晰的错误指引
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from core.log import get_logger

log = get_logger("browser_resolver")

_IS_WINDOWS = sys.platform == "win32"
_IS_MAC = sys.platform == "darwin"


def find_browser_executable() -> Optional[str]:
    """检测可用的浏览器可执行文件路径。

    检测顺序：
    1. PLAYWRIGHT_BROWSERS_PATH 环境变量指定的目录
    2. 项目内 ms-playwright 目录
    3. 用户 LocalAppData/ms-playwright
    4. Windows: 系统 Chrome / Edge
       macOS:  /Applications/Google Chrome.app / Microsoft Edge.app
       Linux:  /usr/bin/google-chrome / chromium / chromium-browser

    Returns:
        浏览器可执行文件路径，或 None（未找到）
    """
    # 1. Playwright 环境变量
    pw_env = os.getenv("PLAYWRIGHT_BROWSERS_PATH", "")
    if pw_env:
        p = _find_chromium_in_dir(Path(pw_env))
        if p:
            return str(p)

    # 2. 项目内 ms-playwright
    project_pw = Path(__file__).parent.parent / "ms-playwright"
    if project_pw.exists():
        p = _find_chromium_in_dir(project_pw)
        if p:
            return str(p)

    # 3. 用户 LocalAppData/ms-playwright (Windows) 或 ~/.cache/ms-playwright (Linux/Mac)
    if _IS_WINDOWS:
        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            user_pw = Path(local_app) / "ms-playwright"
            if user_pw.exists():
                p = _find_chromium_in_dir(user_pw)
                if p:
                    return str(p)
    else:
        user_pw = Path.home() / ".cache" / "ms-playwright"
        if user_pw.exists():
            p = _find_chromium_in_dir(user_pw)
            if p:
                return str(p)

    # 4. 系统浏览器
    for path in _system_browser_paths():
        if Path(path).exists():
            return path

    return None


def _find_chromium_in_dir(base: Path) -> Optional[Path]:
    """在 ms-playwright 目录中查找 chromium 可执行文件。"""
    if not base.exists():
        return None
    # 匹配 chromium-* 目录
    for chrom_dir in sorted(base.glob("chromium-*"), reverse=True):
        if _IS_WINDOWS:
            exe = chrom_dir / "chrome-win64" / "chrome.exe"
            if exe.exists():
                return exe
            exe = chrom_dir / "chrome-win" / "chrome.exe"
            if exe.exists():
                return exe
        elif _IS_MAC:
            exe = chrom_dir / "chrome-mac" / "Chromium.app" / "Contents" / "MacOS" / "Chromium"
            if exe.exists():
                return exe
        else:
            exe = chrom_dir / "chrome-linux" / "chrome"
            if exe.exists():
                return exe
    return None


def _system_browser_paths() -> list[str]:
    """返回系统安装的浏览器候选路径列表。"""
    paths = []
    if _IS_WINDOWS:
        paths = [
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            os.path.expandvars("%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe"),
            # Edge 作为备选
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        ]
    elif _IS_MAC:
        paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    else:  # Linux
        paths = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/snap/bin/chromium",
        ]
    return paths


def get_launch_executable_path() -> Optional[str]:
    """获取 Playwright launch() 的 executable_path 参数值。

    如果 Playwright 自带 Chromium 可用则返回 None（让 Playwright 自己管理），
    否则返回系统浏览器路径。

    失败时记录清晰的错误指引。
    """
    # 先检查 Playwright 自带的 Chromium 是否可用
    # 通过环境变量优先
    pw_env = os.getenv("PLAYWRIGHT_BROWSERS_PATH", "")
    if pw_env:
        p = _find_chromium_in_dir(Path(pw_env))
        if p:
            return None  # Playwright 自带可用，不覆盖

    # 检查项目内和用户的 ms-playwright
    for base in [
        Path(__file__).parent.parent / "ms-playwright",
        Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright" if _IS_WINDOWS else Path.home() / ".cache" / "ms-playwright",
    ]:
        if base.exists():
            p = _find_chromium_in_dir(base)
            if p:
                return None  # Playwright 自带可用

    # Playwright Chromium 不可用，找系统浏览器
    browser_path = find_browser_executable()
    if browser_path:
        log.info("Playwright Chromium 不可用，使用系统浏览器: %s", browser_path)
        return browser_path

    # 全部失败，记录清晰指引
    log.error(
        "未找到可用的浏览器！请执行以下任一操作：\n"
        "  1. 安装 Playwright Chromium: python -m playwright install chromium\n"
        "  2. 安装 Google Chrome 或 Microsoft Edge\n"
        "  3. 设置 PLAYWRIGHT_BROWSERS_PATH 环境变量指向 ms-playwright 目录"
    )
    return None
