"""Sitemap — 主类（核心 CRUD + 序列化）。

Mixin 拆分：
- ApiSamplesMixin  → api_samples.py（API 样本管理）
- FeatureGenMixin  → feature_gen.py（功能点生成 + 动态发现）
- CoverageMixin    → coverage.py（覆盖率统计 + 矩阵）
- ReportMixin      → report.py（报告渲染）
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, fields
from pathlib import Path

from core.sitemap.models import (
    TestStatus, CheckResult, Priority,
    PageInfo, APIEndpoint, CheckItem, FeaturePoint,
)
from core.sitemap.constants import STATIC_EXTS, STATIC_PATH_SEGS
from core.sitemap.api_samples import ApiSamplesMixin
from core.sitemap.feature_gen import FeatureGenMixin
from core.sitemap.coverage import CoverageMixin
from core.sitemap.report import ReportMixin

log = logging.getLogger("pentest_agent.sitemap")


class Sitemap(ApiSamplesMixin, FeatureGenMixin, CoverageMixin, ReportMixin):
    """站点地图 + 功能点清单 + 测试覆盖矩阵。"""

    def __init__(self, target: str, task_id: str = "default"):
        self.target = target
        self.task_id = task_id
        self.pages: dict[str, PageInfo] = {}
        self.apis: dict[str, APIEndpoint] = {}
        self.features: dict[str, FeaturePoint] = {}
        self.business_summary: str = ""
        self.tech_stack: str = ""
        self._feature_counter = 0
        self.pending_discoveries: list[dict] = []
        # ★ 并发安全锁：保护 save/checklist 写入，防止多子 Agent 并发写入损坏数据
        import threading
        self._save_lock = threading.Lock()
        # ★ API 完整请求样本
        self.api_samples: dict[str, dict] = {}
        # ★ JS 分析结果
        self.js_routes: list[dict] = []
        self.js_api_calls: list[dict] = []
        # ★ 加密配置
        self.crypto_configs: list[dict] = []
        # ★ 多角色菜单/认证上下文
        self.roles_crawled: list[str] = []
        self.login_status: dict[str, bool] = {}
        self.menu_tree_responses: list[dict] = []
        self.menu_contexts: dict[str, dict] = {}
        # ★ GraphQL / WebSocket / SSE 实时通道证据
        self.realtime_channels: list[dict] = []
        # ★ API 测试计数
        self._api_test_count: dict[str, int] = {}
        self.MAX_API_TEST_OWNERS = 3
        # ★ Phase 状态与终止原因（由 orchestrator 设置）
        self.phase_status: str = ""
        self.termination_reason: str = ""
        self._fast_scanner_stats: dict = {}
        self._persist_path = Path("data/tasks") / f"{task_id}-sitemap.json"
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)

    # ---- 页面 ----

    def add_page(self, url: str, title: str = "", description: str = "") -> PageInfo:
        if url not in self.pages:
            self.pages[url] = PageInfo(url=url, title=title, description=description)
        else:
            if title:
                self.pages[url].title = title
            if description:
                self.pages[url].description = description
        return self.pages[url]

    def mark_visited(self, url: str) -> None:
        if url in self.pages:
            self.pages[url].visited = True

    # ---- 多角色上下文 ----

    def sync_role_context_from_crawl(self, crawl_result: dict | None) -> None:
        """从爬取结果同步角色、登录状态和菜单树响应上下文。"""
        if not crawl_result:
            return

        roles = crawl_result.get("roles_crawled", []) or []
        seen_roles = set()
        self.roles_crawled = []
        for role in roles:
            role_name = str(role or "anonymous")
            if role_name not in seen_roles:
                seen_roles.add(role_name)
                self.roles_crawled.append(role_name)

        login_status = crawl_result.get("login_status", {}) or {}
        self.login_status = {str(k): bool(v) for k, v in login_status.items()}
        self.menu_tree_responses = [
            item for item in (crawl_result.get("menu_tree_responses", []) or [])
            if isinstance(item, dict)
        ]

        menu_contexts: dict[str, dict] = {}
        for item in self.menu_tree_responses:
            role = str(item.get("role") or item.get("auth_context", {}).get("role") or "anonymous")
            ctx = menu_contexts.setdefault(role, {
                "role": role,
                "account": item.get("account", ""),
                "credential_id": item.get("credential_id", ""),
                "login_success": self.login_status.get(role, role == "anonymous"),
                "menu_api_urls": [],
                "sources": [],
                "menu_response_count": 0,
            })
            url = item.get("url", "")
            source = item.get("source", "")
            if url and url not in ctx["menu_api_urls"]:
                ctx["menu_api_urls"].append(url)
            if source and source not in ctx["sources"]:
                ctx["sources"].append(source)
            if item.get("account") and not ctx.get("account"):
                ctx["account"] = item.get("account", "")
            if item.get("credential_id") and not ctx.get("credential_id"):
                ctx["credential_id"] = item.get("credential_id", "")
            ctx["menu_response_count"] += 1
        self.menu_contexts = menu_contexts

    # ---- API ----

    def add_api(self, method: str, url: str, discovered_by: str = "", **kwargs) -> APIEndpoint | None:
        from urllib.parse import urlparse
        from core.sitemap.api_samples import _is_high_priority_source, classify_api_source

        if method.upper() == "CONNECT":
            return None
        path_lower = url.split('?')[0].lower()
        if any(path_lower.endswith(ext) for ext in STATIC_EXTS):
            return None
        if any(seg in path_lower for seg in STATIC_PATH_SEGS):
            return None

        key = f"{method} {url}"
        source_meta = classify_api_source(
            discovered_by=discovered_by,
            resource_type=str(kwargs.get("resource_type", "")),
            has_sample=bool(kwargs.get("request_body_sample") or kwargs.get("response_sample")),
        )
        for meta_key, meta_value in source_meta.items():
            kwargs.setdefault(meta_key, meta_value)
        endpoint_fields = {f.name for f in fields(APIEndpoint)}
        endpoint_kwargs = {k: v for k, v in kwargs.items() if k in endpoint_fields}

        if key not in self.apis:
            # ★ 跨 host 去重：同 method + 同 path 但不同 host 时，实际流量优先
            parsed = urlparse(url)
            _path = parsed.path.rstrip("/")
            _method_upper = method.upper()
            _is_new_high = _is_high_priority_source(discovered_by)

            for existing_key in list(self.apis.keys()):
                existing_api = self.apis[existing_key]
                existing_parsed = urlparse(existing_api.url)
                if (existing_api.method.upper() == _method_upper and
                    existing_parsed.path.rstrip("/") == _path and
                    existing_parsed.netloc != parsed.netloc):
                    # 同 method + 同 path，但 host 不同
                    existing_source = getattr(existing_api, 'discovered_by', '') or ''
                    if _is_new_high and not _is_high_priority_source(existing_source):
                        # 新的是实际流量，旧的是爬虫推测 → 删旧存新
                        log.info("API 跨 host 覆盖: %s → %s (来源:%s)",
                                 existing_key, key, discovered_by)
                        del self.apis[existing_key]
                        break
                    elif not _is_new_high and _is_high_priority_source(existing_source):
                        # 旧的是实际流量，新的是爬虫推测 → 跳过新的
                        return self.apis[existing_key]

            self.apis[key] = APIEndpoint(method=method, url=url, discovered_by=discovered_by, **endpoint_kwargs)
        return self.apis[key]

    # ---- 持久化 ----

    def save(self) -> None:
        import os
        # ★ 加锁保护整个 写盘流程（序列化 + tmp + rename），
        # 防止多子 Agent 并发 save 导致 .json.tmp 互相覆盖 / 文件损坏
        with self._save_lock:
            data = {
                "target": self.target,
                "task_id": self.task_id,
                "business_summary": self.business_summary,
                "tech_stack": self.tech_stack,
                "pages": {k: asdict(v) for k, v in self.pages.items()},
                "apis": {k: asdict(v) for k, v in self.apis.items()},
                "features": {k: asdict(v) for k, v in self.features.items()},
                "pending_discoveries": self.pending_discoveries,
                "api_samples": self.api_samples,
                "js_routes": self.js_routes,
                "js_api_calls": self.js_api_calls,
                "crypto_configs": self.crypto_configs,
                "roles_crawled": getattr(self, "roles_crawled", []) or [],
                "login_status": getattr(self, "login_status", {}) or {},
                "menu_tree_responses": getattr(self, "menu_tree_responses", []) or [],
                "menu_contexts": getattr(self, "menu_contexts", {}) or {},
                "realtime_channels": getattr(self, "realtime_channels", []) or [],
                "xss_findings": getattr(self, "xss_findings", []) or [],
                "csp_analyses": getattr(self, "csp_analyses", {}) or {},
                "business_understanding": getattr(self, "business_understanding", {}) or {},
                "reconcile_result": getattr(self, "reconcile_result", {}) or {},
                "harm_validation": getattr(self, "harm_validation", {}) or {},
                # ★ FastScanner 孤儿发现（未匹配功能点的漏洞），确保不丢失
                "_fast_scanner_orphan_findings": getattr(self, "_fast_scanner_orphan_findings", []) or [],
                # ★ 脚本广扫孤儿发现，统一进入 HarmValidator 裁决
                "_scripted_scan_findings": getattr(self, "_scripted_scan_findings", []) or [],
                "_scripted_scan_stats": getattr(self, "_scripted_scan_stats", {}) or {},
            }
            try:
                raw = json.dumps(data, ensure_ascii=False, indent=2, default=str)
                tmp = self._persist_path.with_suffix(".json.tmp")
                tmp.write_text(raw, encoding="utf-8")
                # 原子替换：tmp → 正式文件，避免半截写入
                os.replace(tmp, self._persist_path)
            except Exception as exc:
                log.error("sitemap save 失败: %s", exc)
        self.flush_report()
        try:
            self.flush_proven_report()
        except Exception:
            pass

    def load(self) -> bool:
        from core.sitemap.api_samples import classify_api_source

        if not self._persist_path.exists():
            return False
        data = json.loads(self._persist_path.read_text(encoding="utf-8"))
        self.business_summary = data.get("business_summary", "")
        self.tech_stack = data.get("tech_stack", "")
        for k, v in data.get("pages", {}).items():
            self.pages[k] = PageInfo(**v)
        for k, v in data.get("apis", {}).items():
            if isinstance(v, dict):
                source_meta = classify_api_source(
                    discovered_by=v.get("discovered_by", ""),
                    resource_type=str(v.get("resource_type", "")),
                    has_sample=bool(v.get("request_body_sample") or v.get("response_sample")),
                )
                for meta_key, meta_value in source_meta.items():
                    v.setdefault(meta_key, meta_value)
                endpoint_fields = {f.name for f in fields(APIEndpoint)}
                v = {field_name: field_value for field_name, field_value in v.items()
                     if field_name in endpoint_fields}
            self.apis[k] = APIEndpoint(**v)
        for k, v in data.get("features", {}).items():
            checklist_data = v.pop("checklist", [])
            v["priority"] = Priority(v["priority"])
            v["test_status"] = TestStatus(v["test_status"])
            v["checklist"] = []
            fp = FeaturePoint(**v)
            for cd in checklist_data:
                cd["result"] = CheckResult(cd["result"])
                fp.checklist.append(CheckItem(**cd))
            self.features[k] = fp
            self._feature_counter = max(self._feature_counter, int(k.split("_")[1]))
        self.pending_discoveries = data.get("pending_discoveries", [])
        self.api_samples = data.get("api_samples", {})
        self.js_routes = data.get("js_routes", [])
        self.js_api_calls = data.get("js_api_calls", [])
        self.crypto_configs = data.get("crypto_configs", [])
        self.roles_crawled = data.get("roles_crawled", [])
        self.login_status = data.get("login_status", {})
        self.menu_tree_responses = data.get("menu_tree_responses", [])
        self.menu_contexts = data.get("menu_contexts", {})
        self.realtime_channels = data.get("realtime_channels", [])
        self.xss_findings = data.get("xss_findings", [])
        self.csp_analyses = data.get("csp_analyses", {})
        self.business_understanding = data.get("business_understanding", {})
        self.reconcile_result = data.get("reconcile_result", {})
        self.harm_validation = data.get("harm_validation", {})
        # ★ 恢复 FastScanner 孤儿发现
        self._fast_scanner_orphan_findings = data.get("_fast_scanner_orphan_findings", [])
        # ★ 恢复脚本广扫孤儿发现
        self._scripted_scan_findings = data.get("_scripted_scan_findings", [])
        self._scripted_scan_stats = data.get("_scripted_scan_stats", {})
        return True
