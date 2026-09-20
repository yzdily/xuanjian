"""testflow local 执行者 — FastScanner 按域裁剪桥（v3 §五 Stage 3 执行者三分 R4）。

原则：FastScanner.scan_target 的 ``enabled_rules`` 子集参数**已存在**
（fast_scanner.py:1102），本模块只做两件事，不重复实现任何检测逻辑：
  1. 域 → 规则子集映射（上传接口不再跑 SQLi 规则）
  2. (fp, step) → ScanTarget 构造 + 单点执行 + 结果写回 sitemap

engine 注入方式::

    from core.testflow.local_runner import make_local_runner
    engine = TestflowEngine(session, sitemap,
                            local_runner=make_local_runner(session, session_info))
"""
from __future__ import annotations

import logging
from typing import Any, Callable

log = logging.getLogger("testflow.local_runner")

__all__ = ["DOMAIN_TO_RULES", "fast_scan_fp", "make_local_runner"]

# 8 域 → fast_scanner 规则子集（R4：local 步骤按域裁剪）
# 空列表 = 该域无本地规则（business/config 走 llm/tool 执行者）→ 显式 NotImplementedError
DOMAIN_TO_RULES: dict[str, list[str]] = {
    "authz": ["unauthorized", "auth_matrix", "jwt", "cors"],
    "csrf": ["csrf"],
    "injection": ["sql_injection", "command_injection", "xxe", "ssti"],
    "ssrf": ["ssrf"],
    "upload": ["file_upload"],
    "file": ["path_traversal", "info_disclosure"],
    "business": [],   # 逻辑缺陷本地规则缺位 → llm 执行者承接
    "config": [],     # config 域走 tool（config_switch_probe/deep_dive）
}


def _scan_target_of(fp: Any, auth_headers: dict[str, str], base: str = "") -> "Any":
    """FeaturePoint → ScanTarget（related_apis 优先，page_url 兜底）。"""
    from core.fast_scanner import ScanTarget

    method, url = "GET", ""
    for api_str in (fp.related_apis or []):
        parts = (api_str or "").split(" ", 1)
        if len(parts) == 2 and parts[0].isupper():
            method, url = parts[0], parts[1]
            break
        if len(parts) == 1 and parts[0]:
            method, url = "GET", parts[0]
            break
    if not url:
        url = fp.page_url or ""
    if url and not url.startswith("http") and base:
        url = f"{base.rstrip('/')}{url}"
    return ScanTarget(url=url, method=method, auth_headers=dict(auth_headers))


async def fast_scan_fp(
    fp: Any,
    *,
    rules: list[str] | None = None,
    session_info: dict | None = None,
    proxy: str | None = None,
    sitemap: Any = None,
    domain: str = "",
) -> list[Any]:
    """对单个 fp 执行按域裁剪的 FastScanner 扫描。

    Args:
        rules: 规则子集；None = 用 DOMAIN_TO_RULES[domain]；两者皆缺 → 全规则
        domain: 域名（rules 未显式给时查表）

    Returns:
        findings 列表（core.fast_scanner.VulnFinding）
    """
    if rules is None:
        rules = DOMAIN_TO_RULES.get(domain or "", [])
    if not rules:
        raise NotImplementedError(f"域 {domain or '?'} 无本地规则子集（应由 llm/tool 执行者承接）")

    from core.fast_scanner import FastScanner

    auth_headers = dict((session_info or {}).get("headers", {}) or {})
    base = ""
    if sitemap is not None:
        base = (getattr(sitemap, "target", "") or "").rstrip("/")
    target = _scan_target_of(fp, auth_headers, base)
    if not target.url:
        raise NotImplementedError("fp 无可扫描 URL（无 related_apis / page_url）")

    scanner = FastScanner(proxy=proxy) if proxy else FastScanner()
    result = await scanner.scan_target(target, enabled_rules=rules)
    findings = list(result.findings or [])

    # 结果写回：命中 → mark_check（带 domain，聚合进矩阵格）
    if sitemap is not None:
        try:
            from core.parallel._orchestrator_helpers import _write_fast_scanner_results
            _write_fast_scanner_results(findings, [fp], sitemap)
        except Exception as exc:
            log.debug("fast_scan_fp 结果写回失败（不影响扫描）: %s", exc)
    return findings


def make_local_runner(
    session: Any,
    session_info: dict | None = None,
    proxy: str | None = None,
) -> Callable[..., Any]:
    """构造 engine.local_runner 注入件：async callable(step=, fp=, rules=, domain=)。"""

    async def _run(step: dict, fp: Any, rules: list[str] | None = None,
                   domain: str = "") -> list[Any]:
        return await fast_scan_fp(
            fp,
            rules=rules or step.get("rules"),
            session_info=session_info,
            proxy=proxy or getattr(session, "_testflow_proxy", None),
            sitemap=getattr(session, "sitemap", None),
            domain=domain or str(step.get("domain", "")),
        )

    return _run
