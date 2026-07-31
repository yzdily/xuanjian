"""
仪表盘 API — 漏洞统计、趋势、分布数据聚合。

为前端仪表盘提供图表所需的数据源。
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import APIRouter

from core.log import get_logger
from core.scan_store import get_stats as _get_store_stats, list_scans, get_vulns

log = get_logger("web.dashboard_api")

router = APIRouter()


@router.get("/api/dashboard/stats")
async def dashboard_stats():
    """获取仪表盘聚合统计。"""
    # 从 SQLite 获取基础统计
    stats = _get_store_stats()

    # 从 data/tasks 计算覆盖率
    tasks_dir = Path("data/tasks")
    task_count = 0
    feature_count = 0
    vuln_count = 0
    scan_times = []

    if tasks_dir.exists():
        for f in tasks_dir.glob("*-sitemap.json"):
            task_count += 1
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                features = data.get("features", {})
                feature_count += len(features)
                for fp in features.values():
                    for c in fp.get("checklist", []):
                        if c.get("result") == "vulnerable":
                            vuln_count += 1
                scan_times.append(f.stat().st_mtime)
            except Exception:
                pass

    # 扫描频率（近7天每天任务数）
    now = time.time()
    day_secs = 86400
    daily_scans = []
    for i in range(6, -1, -1):
        start = now - (i + 1) * day_secs
        end = now - i * day_secs
        count = sum(1 for t in scan_times if start <= t < end)
        daily_scans.append(count)

    # 漏洞类型分布
    vuln_type_dist = {}
    if tasks_dir.exists():
        for f in tasks_dir.glob("*-sitemap.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                for fp in data.get("features", {}).values():
                    for c in fp.get("checklist", []):
                        if c.get("result") == "vulnerable":
                            vt = c.get("vuln_type", "未知")
                            vuln_type_dist[vt] = vuln_type_dist.get(vt, 0) + 1
            except Exception:
                pass

    # 漏洞严重级别分布
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if tasks_dir.exists():
        for f in tasks_dir.glob("*-sitemap.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                for fp in data.get("features", {}).values():
                    for c in fp.get("checklist", []):
                        if c.get("result") == "vulnerable":
                            sev = (c.get("severity") or "info").lower()
                            if sev in severity_dist:
                                severity_dist[sev] += 1
                            else:
                                severity_dist["info"] += 1
            except Exception:
                pass

    return {
        "total_scans": stats.get("total_scans", 0) or task_count,
        "total_vulns": stats.get("total_vulns", 0) or vuln_count,
        "total_features": feature_count,
        "by_severity": severity_dist,
        "by_type": [{"name": k, "count": v} for k, v in sorted(vuln_type_dist.items(), key=lambda x: -x[1])],
        "daily_scans": daily_scans,
        "scan_coverage": {
            "critical": severity_dist.get("critical", 0),
            "high": severity_dist.get("high", 0),
            "medium": severity_dist.get("medium", 0),
            "low": severity_dist.get("low", 0),
            "info": severity_dist.get("info", 0),
        },
    }
