"""空心化检测 — 单源判定谓词（对应 XUANJIAN_MASTER_PLAN §3.5 A3 去重）。

背景：原 ``report_mixin._detect_hollowing`` 与 ``report_mcp`` 各自内联同一组
双条件，且 ``report_mcp.py:163`` 注释自承"同步 report_mixin 但无法强制"，
两份实现已发生过漂移。本模块抽出**纯谓词**，两处直接调用，杜绝再次漂移。

设计：只抽「是否空心化」的布尔判定（真正重复的部分）；
各调用方的「根因诊断 / reasons 文案」保持原位（二者文案本就不同，不应合并）。
"""

from __future__ import annotations


def is_hollowed(
    real_rate: float,
    skip_rate: float,
    pending_rate: float,
    vuln_count: int,
    total: int,
) -> bool:
    """是否判定为空心化扫描。

    双条件（满足任一即触发，且漏洞数 == 0、总数 > 0）：

      1. ``real_rate < 10%`` 且 ``skip_rate > 70%``
         —— 原始条件：大量检测项被跳过而非真实执行。
      2. ``real_rate < 5%``  且 ``(skip_rate + pending_rate) > 80%``
         —— P1-1 新增：覆盖"大面积未测(pending)而非跳过(skipped)"的场景。

    Args:
        real_rate: 真实完成率（百分比，0-100）。
        skip_rate: 跳过率（百分比）。
        pending_rate: 待测率（百分比）。
        vuln_count: 已确认漏洞数。
        total: 检测项总数。

    Returns:
        True 表示空心化；False 表示正常或无数据（total<=0 / 有漏洞）。
    """
    if total <= 0:
        return False
    if vuln_count != 0:
        return False
    uncovered = skip_rate + pending_rate
    return (
        (real_rate < 10.0 and skip_rate > 70.0)
        or (real_rate < 5.0 and uncovered > 80.0)
    )
