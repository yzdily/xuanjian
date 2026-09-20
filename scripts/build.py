#!/usr/bin/env python3
"""
build.py — XuanJian PyInstaller 打包脚本（Windows）

用法:
    python scripts/build.py
    python scripts/build.py --clean
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import shutil
import subprocess
import sys
from pathlib import Path

# ============================================================
# 路径配置
# ============================================================

SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = SCRIPT_DIR.parent.resolve()
CONFIG_PATH = SCRIPT_DIR / "build_config.yaml"

# ============================================================
# 默认配置（当 yaml 不可用时 fallback）
# ============================================================

DEFAULT_CONFIG = {
    "app_name": "玄鉴 XuanJian",
    "app_version": "0.1.0",
    "exe_name": "XuanJian",
    "output_dir": "dist",
    "entry_script": "start.py",
    "icon": None,
    "include": {
        "python_packages": ["core", "web", "mcp_servers", "scripts"],
        "static_dirs": ["skills_my"],
        "files": [".env.example", "pyproject.toml", "LICENSE", "README.md", "DISCLAIMER.md"],
        "exclude_patterns": ["__pycache__", "*.pyc", ".git", "data", "burp-plugin", "crypto_hook", "build", "dist"],
    },
    "playwright": {
        "browsers": ["chromium"],
        "install_if_missing": True,
        "include_in_package": True,
    },
    "hidden_imports": [
        "uvicorn.logging",
        "uvicorn.loops.auto",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets.auto",
        "engineio.async_drivers.threading",
        "mitmproxy.tools.main",
        "mitmproxy.addons.default_addons",
        "ddddocr",
        "rapidocr_onnxruntime",
        "PIL._tkinter_finder",
        "yaml",
        "dotenv",
    ],
    "pyinstaller": {
        "onefile": True,
        "console": True,
        "windowed": False,
        "upx": False,
        "clean": True,
        "noconfirm": True,
        "log_level": "WARN",
    },
}


# ============================================================
# 工具函数
# ============================================================

def log(msg: str):
    print(f"[build] {msg}")


def load_config() -> dict:
    """读取 build_config.yaml，若失败则返回默认配置。"""
    if not CONFIG_PATH.exists():
        log("未找到 build_config.yaml，使用默认配置")
        return DEFAULT_CONFIG

    try:
        import yaml
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        if not config:
            return DEFAULT_CONFIG
        # 与默认配置做浅合并，保证必要键存在
        merged = DEFAULT_CONFIG.copy()
        merged.update(config)
        return merged
    except Exception as exc:
        log(f"读取 build_config.yaml 失败 ({exc})，使用默认配置")
        return DEFAULT_CONFIG


def ensure_pyinstaller() -> None:
    """确保 PyInstaller 已安装。"""
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        log("PyInstaller 未安装，正在安装...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pyinstaller>=6.0", "-q"],
            check=True,
        )
        log("PyInstaller 安装完成")


def ensure_playwright_browsers(config: dict) -> Path | None:
    """检查并自动下载 Playwright 浏览器；返回需要打包的浏览器目录（或 None）。"""
    pw_cfg = config.get("playwright", {})
    browsers = pw_cfg.get("browsers", [])
    if not browsers:
        return None

    # 确保 playwright 模块可用
    try:
        import playwright  # noqa: F401
    except ImportError:
        log("playwright 未安装，正在安装...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "playwright>=1.40.0", "-q"],
            check=True,
        )

    # 定位浏览器目录
    local_app_data = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
    playwright_dir = Path(local_app_data) / "ms-playwright"

    # 简单判断：是否存在 chromium-* 目录
    def _has_chromium() -> bool:
        return any(playwright_dir.glob("chromium-*"))

    need_download = False
    if "chromium" in browsers and not _has_chromium():
        need_download = True

    if need_download and pw_cfg.get("install_if_missing", True):
        log("正在下载 Playwright Chromium（可能需要几分钟）...")
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=True,
        )

    if pw_cfg.get("include_in_package", True) and playwright_dir.exists():
        log(f"将 Playwright 浏览器目录打包: {playwright_dir}")
        return playwright_dir
    return None


def filter_excluded(src: Path, patterns: list[str]) -> bool:
    """若路径匹配任何排除模式，返回 True。"""
    rel = src.as_posix()
    name = src.name
    for pat in patterns:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel, pat):
            return True
    return False


def collect_add_data(config: dict) -> list[str]:
    """根据配置生成 PyInstaller --add-data 参数列表。"""
    items: list[str] = []
    excludes = config.get("include", {}).get("exclude_patterns", [])

    # Python 包
    for pkg in config.get("include", {}).get("python_packages", []):
        src = PROJECT_DIR / pkg
        if src.exists() and not filter_excluded(src, excludes):
            items.append(f"{src};{pkg}")

    # 静态目录
    for d in config.get("include", {}).get("static_dirs", []):
        src = PROJECT_DIR / d
        if src.exists() and not filter_excluded(src, excludes):
            items.append(f"{src};{d}")

    # 独立文件
    for f in config.get("include", {}).get("files", []):
        src = PROJECT_DIR / f
        if src.exists() and not filter_excluded(src, excludes):
            items.append(f"{src};.")

    return items


# ============================================================
# 主流程
# ============================================================

def build(clean: bool = False) -> None:
    config = load_config()
    ensure_pyinstaller()

    output_dir = PROJECT_DIR / config.get("output_dir", "dist")
    work_dir = PROJECT_DIR / "build"
    spec_dir = work_dir

    if clean and work_dir.exists():
        log("清理 build 缓存...")
        shutil.rmtree(work_dir, ignore_errors=True)
    if clean and output_dir.exists():
        log("清理 dist 输出...")
        shutil.rmtree(output_dir, ignore_errors=True)

    output_dir.mkdir(parents=True, exist_ok=True)

    exe_name = config.get("exe_name", "XuanJian")
    entry_script = PROJECT_DIR / config.get("entry_script", "start.py")
    if not entry_script.exists():
        raise FileNotFoundError(f"入口脚本不存在: {entry_script}")

    # 浏览器
    playwright_dir = ensure_playwright_browsers(config)

    # 基础命令
    pi_cfg = config.get("pyinstaller", {})
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name", exe_name,
        "--distpath", str(output_dir),
        "--workpath", str(work_dir),
        "--specpath", str(spec_dir),
        "--log-level", str(pi_cfg.get("log_level", "WARN")),
    ]

    if pi_cfg.get("onefile", True):
        cmd.append("--onefile")
    if pi_cfg.get("console", True):
        cmd.append("--console")
    if pi_cfg.get("windowed", False):
        cmd.append("--windowed")
    if pi_cfg.get("noconfirm", True):
        cmd.append("--noconfirm")
    if pi_cfg.get("clean", True):
        cmd.append("--clean")

    # UPX（若有安装可启用压缩）
    if pi_cfg.get("upx", False):
        cmd.append("--upx-dir=upx")

    # 图标
    icon = config.get("icon")
    if icon:
        icon_path = PROJECT_DIR / icon
        if icon_path.exists():
            cmd.extend(["--icon", str(icon_path)])

    # 隐藏导入
    for hi in config.get("hidden_imports", []):
        cmd.extend(["--hidden-import", hi])

    # 数据文件
    for add_data in collect_add_data(config):
        cmd.extend(["--add-data", add_data])

    # Playwright 浏览器目录
    if playwright_dir and playwright_dir.exists():
        cmd.extend(["--add-data", f"{playwright_dir};ms-playwright"])

    # 入口脚本
    cmd.append(str(entry_script))

    log("开始执行 PyInstaller...")
    log("命令行:\n  " + " ".join(cmd))
    print("-" * 60)

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        log(f"PyInstaller 构建失败: {exc}")
        sys.exit(1)

    print("-" * 60)
    exe_path = output_dir / f"{exe_name}.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        log(f"构建成功: {exe_path}")
        log(f"体积: {size_mb:.1f} MB")
        log("提示: 双击 exe 即可运行，无需 Python 环境")
    else:
        log(f"未找到输出文件: {exe_path}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="XuanJian PyInstaller 打包脚本")
    parser.add_argument("--clean", action="store_true", help="构建前清理缓存和旧输出")
    args = parser.parse_args()
    build(clean=args.clean)


if __name__ == "__main__":
    main()
