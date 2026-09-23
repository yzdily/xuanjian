"""DirScan 台账行的判定谓词（FOUNDATION 层，纯函数）。

★ 为什么单独成模块：``_dirscan_sensitive_vulns`` 台账有**两个**消费点 ——
``core/sitemap/coverage.py::get_coverage``（纳入已确认漏洞）与
``::get_coverage_matrix``（渲染「🔴 DirScan 敏感发现」表格）。

0923 实测发现只改了前者，矩阵视图零状态过滤 → 即使 get_coverage 已过滤，
报告矩阵仍会把未验证发现原样印出来。

判定谓词下沉到 ``core.sitemap``：
- 两个消费点都在 core.sitemap，直接同层引用即可；
- ``core.session.dir_finding_store``（写入侧）反向引用它会违反 A1 分层契约
  （``core.sitemap`` 是 FOUNDATION，不得依赖 ``core.session``），故此处只放纯函数。
"""

from __future__ import annotations

from typing import Any

# 校验结论取值（与 core/dir_scanner/_models.py::DirFinding.review_status 对齐）
REVIEW_CONFIRMED = "confirmed"
REVIEW_NEEDS_REVIEW = "needs_review"

# 台账字段名（写入/读取两侧共用，避免各自硬编码字符串漂移）
LEDGER_ATTR = "_dirscan_sensitive_vulns"


def is_confirmed(row: Any) -> bool:
    """台账行是否属于"已确认漏洞"（**唯一判定入口**）。

    ★ fail-safe：缺少 ``review_status`` 一律视为**未确认**。
    0923 的教训是反向的 —— 默认 ``confirmed`` 会把无证据的误报
    写进给银行客户的报告（对金融机构报假漏洞）。

    Args:
        row: 台账行（预期为 dict）。

    Returns:
        True 仅当显式 ``review_status == "confirmed"``。
    """
    if not isinstance(row, dict):
        return False
    return (row.get("review_status") or REVIEW_NEEDS_REVIEW) == REVIEW_CONFIRMED


def split_by_review(rows: Any) -> tuple[list[dict], list[dict]]:
    """把台账行拆成 ``(已确认, 待复核)`` 两组。

    两个消费点都应通过本函数取值，保证结论一致。
    """
    confirmed: list[dict] = []
    pending: list[dict] = []
    for row in rows or ():
        if not isinstance(row, dict):
            continue
        (confirmed if is_confirmed(row) else pending).append(row)
    return confirmed, pending
