"""SupplementalTestAgent — Phase 2.55 补测 Agent

设计目标（2026-05-22）：
=================================================================
问题背景：
  Phase 2 主测试期间，子 Agent 通过 proxy_send_request 等工具会触发大量
  新流量。其中部分流量打到了「之前 sitemap 里没有的 API」（典型场景：
  fuzz /users/1 时从响应里发现了 /users/1/orgs，去 GET 了一下）。这些
  新发现的 API 当前不会被自动测试，会被遗漏。

本 Agent 的职责：
  1. 扫描 flows.jsonl 里 Phase 2 之后产生的全部流量
  2. 严格按 scope（target host + extra_scope）过滤
  3. 排除已在 sitemap.apis 里的（A 类 PoC 变体）
  4. 仅保留 2xx 响应的活 API
  5. 对每个新 API：
     - 优先挂到 path 前缀最相似的 feature；找不到才建新 feature
     - 走主 sitemap.add_feature 路径，自动建 checklist
  6. 启动 WorkerAgent 独立子 Agent，复用主 Agent 的 SKILL/工具/流程
  7. 单 API 超时 60s，总预算 30min；失败兜底，绝不阻塞 Phase 2.6

不递归：补测过程中再发现的新 API 只记录、不再测，写入报告附录。

★ 本包由原 core/supplemental_test_agent.py 拆分而来，所有公开/私有名保持兼容。
  子模块：
    _constants   — 配置常量与第三方域名黑名单
    _discovery   — L1 自动发现层（flows 扫描 + 主动目录爆破）
    _attach      — L2 挂载层（新 API 挂到 sitemap feature）
    _runner      — 主入口 run_supplemental_test / 本地规则版 run_supplemental_test_local
"""

from __future__ import annotations

import time  # re-export: 测试与外部通过 core.supplemental_test_agent.time 访问

# ============================================================
# 配置常量与第三方域名黑名单
# ============================================================
from ._constants import (
    PER_API_TIMEOUT_S,
    TOTAL_BUDGET_S,
    FEATURES_PER_WORKER,
    _THIRD_PARTY_BLACKLIST,
)

# ============================================================
# L1 自动发现层
# ============================================================
from ._discovery import (
    _DiscoveredAPI,
    discover_new_apis_from_flows,
    _host_in_scope,
    _is_third_party,
    _is_non_business_path,
    discover_apis_from_dirscan,
    _NON_BUSINESS_PATH_SUFFIXES,
    _NON_BUSINESS_PATH_SEGMENTS,
    _SENSITIVE_DIR_SEGMENTS,
    _SENSITIVE_FILE_SUFFIXES,
    _SENSITIVE_ENDPOINT_PREFIXES,
    _ADMIN_PANEL_PATHS,
    _AUTH_PATH_PREFIXES,
    # 兜底层 1/2 + 流量字典过滤（从旧单文件恢复，包化拆分时丢失）
    _filter_flow_dicts_for_new_apis,
    _fallback_cdp_recapture,
    _fallback_passive_js_analysis,
)

# ============================================================
# L2 挂载层
# ============================================================
from ._attach import (
    attach_apis_to_sitemap,
    _find_best_matching_feature,
    _gen_feature_name,
    _gen_feature_desc,
    _normalize_related_api_for_scan,
)

# ============================================================
# 主入口
# ============================================================
from ._runner import (
    run_supplemental_test,
    _run_worker_with_timeout,
    run_supplemental_test_local,
    # 兜底层 3 + 质量度量报告（从旧单文件恢复，包化拆分时丢失）
    _generate_coverage_warning,
    _build_supplemental_quality_report,
)

# ============================================================
# __all__ — 公开 API
# ============================================================
__all__ = [
    # 主入口
    "run_supplemental_test",
    "run_supplemental_test_local",
    # 发现层
    "discover_new_apis_from_flows",
    "discover_apis_from_dirscan",
    # 挂载层
    "attach_apis_to_sitemap",
]
