"""fast_scanner 快速入口与结果转换（从原 fast_scanner.py 机械拆分，内容逐字保留）。"""

from __future__ import annotations

from ._engine import FastScanner
from ._models import ScanTarget, ScanResult, VulnFinding


# ============================================================
# 快速入口
# ============================================================

async def quick_scan(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    params: dict | None = None,
    auth_headers: dict | None = None,
    proxy: str | None = None,
    max_workers: int = 20,
    enabled_rules: list[str] | None = None,
) -> ScanResult:
    """快速扫描入口函数。

    用法:
        result = await quick_scan(
            url="http://example.com/api/users",
            params={"id": "1"},
            auth_headers={"Cookie": "session=xxx"},
        )
        print(f"发现 {result.vuln_count} 个漏洞")
    """
    target = ScanTarget(
        url=url,
        method=method,
        headers=headers or {},
        params=params or {},
        auth_headers=auth_headers or {},
    )
    scanner = FastScanner(max_workers=max_workers, proxy=proxy)
    return await scanner.scan_target(target, enabled_rules=enabled_rules)


async def batch_quick_scan(
    urls: list[str],
    auth_headers: dict | None = None,
    proxy: str | None = None,
    max_workers: int = 20,
) -> list[ScanResult]:
    """批量快速扫描多个 URL"""
    targets = [
        ScanTarget(url=url, auth_headers=auth_headers or {})
        for url in urls
    ]
    scanner = FastScanner(max_workers=max_workers, proxy=proxy)
    return await scanner.scan_targets(targets)


# ============================================================
# 结果转换工具（供 orchestrator 集成）
# ============================================================

def convert_findings_to_checklist_results(
    findings: list[VulnFinding],
) -> list[dict]:
    """将 FastScanner 的发现转换为 checklist 结果格式。

    供 orchestrator 回写到 sitemap 使用。
    """
    results = []
    for f in findings:
        results.append({
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "url": f.url,
            "method": f.method,
            "detail": f.detail,
            "evidence": f.evidence[:500] if f.evidence else "",
            "evidence_request": f.payload,
            "evidence_response": f.evidence[:500] if f.evidence else "",
            "fix_suggestion": f.fix_suggestion,
            "source": "fast_scanner",
        })
    return results
