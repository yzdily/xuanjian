"""页面级超时与噪音感知机制。

这是爬虫的"工作哲学"模块。本文件包含：

1. **轮询噪音探测器（_NoiseDetector）**：识别 refetchInterval / WebSocket 重连
   等永不停歇的请求，避免 networkidle 永远不触发导致整页超时。
   仅在单页内生效，每次进入 _crawl_page 重置。

2. **智能等待 idle（_smart_wait_for_idle）**：替代固定的
   page.wait_for_load_state('networkidle') —— 一旦发现噪音就立刻 return 切快照。

3. **自适应页面超时包装（_run_crawl_page_with_adaptive_timeout）**：
   外层时间兜底，内部菜单循环靠"进度感知"自己控节奏。

设计原则（防误伤 / 防卡死）：
- 阈值按【单 API path 频率】算，不是总请求数
- 必须同一 path 在 5s 窗口内重复 ≥ NOISE_PATH_THRESHOLD 次
- 已抓数据全部保留，仅停止"等待新请求"
- 黑名单仅在当前页内生效，下个页面重新计数
- 只看 xhr/fetch，文档/资源不计
- 可通过环境变量 PENTEST_NOISE_DETECT=0 关闭
"""

from __future__ import annotations

import asyncio
import os
from urllib.parse import urlparse


# ============================================================
# 全局开关 + 噪音判定阈值
# ============================================================
_NOISE_DETECT_ENABLED = os.environ.get("PENTEST_NOISE_DETECT", "1") != "0"
NOISE_WINDOW_S = 5.0          # 观察窗口
NOISE_PATH_THRESHOLD = 8       # 同一 path 在窗口内被请求 N 次 → 判定为噪音

# ★ 2026-05-22 v4: 页面级超时改为"进度感知"哲学
# ----------------------------------------------------------
# 旧版 v2/v3 痛点：固定 180s 页面硬超时 + v3 内部 150s 菜单预算
#   → bitget 首页 99 个菜单点到第 5 个就被强制 cancel，丢 94 个数据
#   → 即使爬虫还在持续产 API（"在工作"），也被时间算尽
#
# v4 哲学（与用户达成共识）：
#   1. 只要爬虫"在工作"（captured 在增长 / 菜单在点完），就让它继续
#   2. "不在工作"（PAGE_PROGRESS_SILENCE_S 静默）→ 视为卡死，主动 break（保数据）
#   3. 页面绝对兜底（HARD）提到 30 分钟，仅防极端坏账（实际由任务级 25 分钟兜住）
#
# 进度感知由 _crawl_page_inner 内部菜单循环实现（监控 captured 长度变化 + clicked_count）
# 本文件常量仅作为外层兜底，不再左右页面爬取节奏。
# ----------------------------------------------------------
NOISE_PAGE_SOFT_TIMEOUT_S = 60         # 软超时：到点检查噪音状态（保留供噪音页面快退出）
NOISE_PAGE_HARD_TIMEOUT_S = 1800       # ★ v4: 30 分钟页面绝对兜底（由 v3 的 180s 提到）
NOISE_MAX_PAGE_DURATION_S = NOISE_PAGE_HARD_TIMEOUT_S  # 向后兼容保留旧名字

# ★ v4 新增：页面菜单循环的"进度静默"阈值
# 30 秒内：captured 没增加 + clicked_count 没增加 + 没新 url → 判定卡死，break。
# 该值用于 _crawl_page_inner 的菜单循环里。
# ★ 2026-08-13: 从 30s 提升到 45s，支持环境变量 PENTEST_PAGE_SILENCE_S 覆盖
# 日志显示 60s 静默即判定爬完，但实际可能只是页面加载慢或 API 响应延迟
PAGE_PROGRESS_SILENCE_S = int(os.environ.get("PENTEST_PAGE_SILENCE_S", "45"))
PAGE_MENU_LOOP_HARD_S = 1800           # 30 分钟兜底（与 NOISE_PAGE_HARD_TIMEOUT_S 同步）


class _NoiseDetector:
    """单页轮询噪音探测器（per-page，每个 _crawl_page 一份）。"""

    __slots__ = ("_window", "_blacklist", "_enabled")

    def __init__(self, enabled: bool = True):
        # path → list[timestamp]
        self._window: dict[str, list[float]] = {}
        self._blacklist: set[str] = set()
        self._enabled = enabled

    @staticmethod
    def _path_key(url: str) -> str:
        try:
            p = urlparse(url)
            # 去 query/hash，保留 host+path 作为唯一键
            return f"{p.netloc}{p.path}"
        except Exception:
            return url[:200]

    def record(self, url: str, resource_type: str) -> None:
        """记录一次请求。仅 xhr/fetch 进入计数，避免文档/JS/图片误算。"""
        if not self._enabled:
            return
        if resource_type not in ("xhr", "fetch"):
            return
        key = self._path_key(url)
        if key in self._blacklist:
            return
        now = asyncio.get_running_loop().time()
        bucket = self._window.setdefault(key, [])
        bucket.append(now)
        # 只保留窗口内的时间戳
        cutoff = now - NOISE_WINDOW_S
        if bucket and bucket[0] < cutoff:
            self._window[key] = [t for t in bucket if t >= cutoff]
            bucket = self._window[key]
        # 触发判定
        if len(bucket) >= NOISE_PATH_THRESHOLD:
            self._blacklist.add(key)

    def has_noise(self) -> bool:
        return bool(self._blacklist)

    def blacklist_snapshot(self) -> list[str]:
        return sorted(self._blacklist)


async def _smart_wait_for_idle(
    page,
    detector: "_NoiseDetector",
    *,
    max_wait_s: float = 5.0,
    quiet_threshold_s: float = 1.2,
):
    """智能等待：替代固定的 wait_for_load_state('networkidle', 5000)。

    策略：
    - 持续轮询 detector，一旦发现噪音 → 立刻 return（快照模式）
    - 否则尝试常规 networkidle 等待
    - 最多等 max_wait_s，超时也 return（不抛异常）

    这样既能在正常页面像以前一样等够 networkidle，
    又能在噪音页面立刻退出，不影响数据完整性。
    """
    if not _NOISE_DETECT_ENABLED:
        # 开关关闭 → 退化为原有行为
        try:
            await page.wait_for_load_state("networkidle", timeout=int(max_wait_s * 1000))
        except Exception:
            pass
        return

    loop = asyncio.get_running_loop()
    deadline = loop.time() + max_wait_s
    # 先快速尝试一次 networkidle（quiet_threshold_s），让正常页面快速通过
    try:
        await page.wait_for_load_state(
            "networkidle", timeout=int(quiet_threshold_s * 1000)
        )
        return  # 已 idle，正常路径
    except Exception:
        pass
    # 还没 idle → 进入噪音感知轮询
    while loop.time() < deadline:
        if detector.has_noise():
            return  # 检测到噪音，立刻切快照
        try:
            await page.wait_for_load_state(
                "networkidle", timeout=500
            )
            return  # idle 了
        except Exception:
            pass
        await asyncio.sleep(0.2)
    # 超时也直接 return，不抛


async def _run_crawl_page_with_adaptive_timeout(
    coro_factory,
    detector_getter,
    soft_timeout_s: float = NOISE_PAGE_SOFT_TIMEOUT_S,
    hard_timeout_s: float = NOISE_PAGE_HARD_TIMEOUT_S,
):
    """以"自适应超时"运行一个 _crawl_page 协程。

    策略：
    - soft_timeout_s 内完成 → 立即返回结果（绝大多数页面）
    - soft 到期但页面有噪音 → 立即取消任务（快速放弃噪音页面）
    - soft 到期但页面无噪音 → 延长到 hard_timeout_s（给大菜单页面充分时间）
    - hard_timeout_s 仍未完成 → 取消并抛 asyncio.TimeoutError

    Args:
        coro_factory: 一个 callable，返回新创建的协程（不能直接传协程，因为可能要重新创建）
        detector_getter: 一个 callable，返回 _NoiseDetector 实例（None 表示尚未初始化）
                          如果 detector 不可用，soft 阶段后默认延长到 hard。
    """
    coro = coro_factory()
    task = asyncio.create_task(coro)

    try:
        # 第一阶段：soft 等待
        try:
            return await asyncio.wait_for(asyncio.shield(task), timeout=soft_timeout_s)
        except asyncio.TimeoutError:
            pass  # 进入第二阶段判断

        # soft 到期：检查噪音状态决定是否延长
        det = None
        try:
            det = detector_getter()
        except Exception:
            det = None

        has_noise = bool(det and det.has_noise()) if det else False

        if has_noise:
            # 有噪音 → 快速放弃，按 soft 超时处理
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            raise asyncio.TimeoutError(f"噪音页面超过 {soft_timeout_s}s")

        # 没噪音 → 这是一个慢正常页面（如菜单 36+ 项），延长到 hard
        remaining = hard_timeout_s - soft_timeout_s
        try:
            return await asyncio.wait_for(asyncio.shield(task), timeout=remaining)
        except asyncio.TimeoutError:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            raise asyncio.TimeoutError(f"硬超时 {hard_timeout_s}s")
    except asyncio.CancelledError:
        if not task.done():
            task.cancel()
        raise
