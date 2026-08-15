"""统一可观测性 / 计量聚合出口（XUANJIAN_MASTER_PLAN §3.5 A8 / §3.6 O6）。

把散落在各处的运行时指标收口为一个可序列化的聚合点，供 ``/metrics`` 端点
（web/api/system_api.py）与未来 Prometheus 抓取使用。当前聚合：
- LLM 调用成本（来自 core.llm._monitor.Metrics，caller / task 级 token 与耗时）
- 扫描聚合统计（来自 core.scan_store.get_stats，若可用）

设计为惰性导入 + 全防御：任何子数据源缺失 / 抛错都不影响整体返回，避免拖垮
健康检查 / 监控端点（对应运维 O6「/metrics 端点供 Prometheus 抓取」）。
"""

from __future__ import annotations

from typing import Any


def collect_metrics() -> dict[str, Any]:
    """收集当前进程可观测性指标，返回可被 JSON 序列化的字典。

    所有子数据源均惰性导入并包裹异常，单点失败不影响整体结构。
    """
    metrics: dict[str, Any] = {"llm": None, "scans": None}

    # LLM 成本（caller / task 级 token 与耗时）
    try:
        from core.llm._monitor import Metrics

        metrics["llm"] = Metrics().get_summary()
    except Exception:
        metrics["llm"] = None

    # 扫描聚合统计（漏洞数 / 完成率等）
    try:
        from core.scan_store import get_stats

        metrics["scans"] = get_stats()
    except Exception:
        metrics["scans"] = None

    return metrics
