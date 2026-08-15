"""回放/录制运行时构建器 — recipe → 可执行运行时。

record_golden.py（完整 venv）与 test_golden_replay.py（沙箱）共用本模块：
  - 录制端：按 recipe 构建运行时 → 跑怪物方法 → 落 golden JSON
  - 回放端：按同一 recipe 构建运行时 → 跑当前实现 → 与 golden diff

沙箱无浏览器/无 mock_spa 静态目录时，构建器抛 ``RuntimeUnavailable``；
test_golden_replay.py 捕获后 ``pytest.skip``，保证沙箱 pytest 全绿。
样本落盘后，回放测试在完整 venv 自动激活——行为等价即解锁 decompose。
"""
from __future__ import annotations

import os
import socket
import threading
from pathlib import Path
from typing import Any

# recipe.runtime 取值
RUNTIME_MOCK_SPA = "mock_spa"          # crawl_round / crawl_page_inner：本地 mock_spa + playwright
RUNTIME_FAST_NO_LLM = "fast_no_llm"    # chat：AgentSession(llm=None) fast 路径，无需浏览器

_MOCK_SPA_PORT = 9876
_mock_spa_lock = threading.Lock()
_mock_spa_started: dict[int, str] = {}  # port -> base_url（进程内单例）


class RuntimeUnavailable(Exception):
    """当前环境无法重建 recipe 所述运行时（缺 playwright / 缺 mock_spa 资源 / ...）。"""


# ------------------------------------------------------------------
# mock_spa 服务器（进程内后台线程，单例）
# ------------------------------------------------------------------
def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _mock_spa_static_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "mock_spa" / "static"


def ensure_mock_spa(port: int = _MOCK_SPA_PORT) -> str:
    """启动 mock_spa（若未运行）并返回 base_url。

    Raises:
        RuntimeUnavailable: mock_spa 静态目录缺失（仓库未带 tests/mock_spa/static）。
    """
    with _mock_spa_lock:
        if port in _mock_spa_started:
            return _mock_spa_started[port]
        static = _mock_spa_static_dir()
        if not static.exists():
            raise RuntimeUnavailable(
                f"mock_spa 静态目录不存在: {static}（需完整仓库 + tests/mock_spa/static）"
            )
        if not _port_in_use(port):
            # 后台线程启动 server；server.py 的 run_server 会 chdir 到 mock_spa 目录
            import sys as _sys
            mock_spa_dir = static.parent
            if str(mock_spa_dir) not in _sys.path:
                _sys.path.insert(0, str(mock_spa_dir))
            # server.py 用相对 STATIC_DIR，需切 cwd；线程内临时切
            from tests.mock_spa.server import run_server  # noqa: E402

            def _run():
                orig = os.getcwd()
                try:
                    os.chdir(mock_spa_dir)
                    run_server(port)
                except Exception:
                    pass  # 端口冲突/资源缺失 → _port_in_use 下一轮会判定
                finally:
                    os.chdir(orig)

            t = threading.Thread(target=_run, name="mock_spa", daemon=True)
            t.start()
            # 等待就绪（最多 ~3s）
            import time as _time
            for _ in range(30):
                if _port_in_use(port):
                    break
                _time.sleep(0.1)
            if not _port_in_use(port):
                raise RuntimeUnavailable(f"mock_spa 未能启动在 127.0.0.1:{port}")
        base = f"http://127.0.0.1:{port}"
        _mock_spa_started[port] = base
        return base


# ------------------------------------------------------------------
# playwright 可用性探测
# ------------------------------------------------------------------
def _require_playwright():
    try:
        import playwright  # noqa: F401
    except Exception as e:
        raise RuntimeUnavailable(f"playwright 未安装: {e}") from e


# ------------------------------------------------------------------
# AutoCrawler 构建（crawl_round / crawl_page_inner 共用）
# ------------------------------------------------------------------
def build_crawler(recipe: dict) -> Any:
    """按 recipe 构建 AutoCrawler。

    recipe 字段：
      - target: 目标 URL（默认 mock_spa base）
      - fast_mode: bool（默认 True，缩小 max_pages 加速回放）
      - port: mock_spa 端口（默认 9876）
    """
    _require_playwright()
    port = int(recipe.get("port", _MOCK_SPA_PORT))
    base = ensure_mock_spa(port)
    target = recipe.get("target") or base
    fast_mode = bool(recipe.get("fast_mode", True))
    # 禁用代理：mock_spa 直连，避免 _check_proxy 探测 18080 失败拖慢回放
    os.environ["BROWSER_PROXY"] = os.environ.get("BROWSER_PROXY", "")
    os.environ["BROWSER_HEADLESS"] = "true"
    from core.crawler.crawler_core import AutoCrawler  # noqa: E402

    return AutoCrawler(target=target, fast_mode=fast_mode, on_progress=None)


async def build_page_for_inner(recipe: dict) -> tuple[Any, Any]:
    """为 _crawl_page_inner 回放构建 (crawler, page)。

    _crawl_page_inner 需要一个已存在的 playwright Page；本函数打开浏览器并新建 page，
    调用方负责在 finally 中关闭（page/browser/pw）。
    """
    _require_playwright()
    crawler = build_crawler(recipe)
    from playwright.async_api import async_playwright

    pw = await async_playwright().start()
    browser = await pw.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
    ctx = await browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 800})
    page = await ctx.new_page()
    # 把关闭句柄挂到 page 上，方便调用方 finally 清理
    page._golden_pw = pw  # type: ignore[attr-defined]
    page._golden_browser = browser  # type: ignore[attr-defined]
    page._golden_ctx = ctx  # type: ignore[attr-defined]
    return crawler, page


async def close_page(page) -> None:
    """关闭 build_page_for_inner 产出的 page 及其浏览器。"""
    try:
        await page._golden_ctx.close()  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        await page._golden_browser.close()  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        await page._golden_pw.stop()  # type: ignore[attr-defined]
    except Exception:
        pass


# ------------------------------------------------------------------
# chat session 构建
# ------------------------------------------------------------------
def build_chat_session(recipe: dict) -> Any:
    """按 recipe 构建 AgentSession。

    recipe 字段：
      - runtime: RUNTIME_FAST_NO_LLM（默认）—— 纯 fast 路径，无浏览器无 LLM
      - target: 可选，注入 self.target_url（用于恢复场景回放）
    recipe 不含 fast_no_llm 时（如需浏览器的扫描场景）→ 需浏览器，抛 RuntimeUnavailable。
    """
    runtime = recipe.get("runtime", RUNTIME_FAST_NO_LLM)
    if runtime != RUNTIME_FAST_NO_LLM:
        # 非纯 fast 路径的 chat 回放需要浏览器/LLM，沙箱不可用
        _require_playwright()
    from core.session import AgentSession  # noqa: E402

    session = AgentSession(llm=None, skip_recover=True)
    target = recipe.get("target")
    if target:
        session.target_url = target  # type: ignore[attr-defined]
    return session
