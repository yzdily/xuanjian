"""
crawl_merger — AutoCrawler 多轮爬取结果合并工具

场景：
- 主爬取（匿名）+ Step 2 补偿（登录）的双轮爬取，需要把两份 crawl_result 合并成一份
- 未来可能扩展为 N 轮（不同角色、不同认证方式）

字段处理策略：
- API endpoints：按 (method, url) 元组去重
- Forms：按 (page, action, method) 元组去重
- Pages / login_status：字典合并（后者覆盖前者）
- Roles / js_endpoints / menu_coverage：保序去重
- api_doc_hits：按 url 去重
- crawled_elements：列表拼接（保留全部，build_menu_tree_from_crawl 需要）
- role_comparison：优先使用有对比的结果
- JS 深度分析字段（js_auth_patterns 等）：列表去重 / 字典合并 / 数值求和
- 计数字段（apis_inferred_verified / forms_submitted / total_clickable_elements / menu_with_api / menu_without_api）：求和
- 派生计数字段（apis_total / pages_total / forms_total / crawl_rounds / js_endpoints_found / menu_clicked）：基于合并后的列表长度重算

设计原则：
- 纯数据函数，无 IO 无副作用，便于单测
- 直接修改 primary 字典（in-place），返回 primary 的引用，方便链式调用
- 从 chat_loop.py 抽出 120 行内联代码，调用方变成 1 行
"""

from __future__ import annotations

from typing import Any
import hashlib
import json

from core.realtime_protocols import dedupe_realtime_channels


# JS 深度分析字段（合并策略：列表去重 / 字典合并 / 数值求和）
_JS_KEYS = [
    "js_api_calls",
    "js_auth_patterns",
    "js_sensitive_info",
    "js_source_maps",
    "js_routes",
    "js_stats",
]


def _json_signature(value: Any) -> str:
    """为不可 hash 的 dict/list 生成稳定去重签名。"""
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(value)


def _dedupe_json(items: list[Any]) -> list[Any]:
    """对可能包含 dict/list 的列表做保序去重。"""
    seen: set[str] = set()
    deduped: list[Any] = []
    for item in items:
        sig = _json_signature(item)
        if sig not in seen:
            seen.add(sig)
            deduped.append(item)
    return deduped


def _dedupe_menu_tree_responses(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """菜单树响应按 url/source/role/body 去重，保留多角色菜单差异。"""
    seen: set[tuple[str, str, str, str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        body = str(item.get("response_body", ""))
        body_sig = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()
        auth_ctx = item.get("auth_context", {}) if isinstance(item.get("auth_context"), dict) else {}
        role = str(item.get("role") or auth_ctx.get("role") or "anonymous")
        account = str(item.get("account") or auth_ctx.get("account") or "")
        credential_id = str(item.get("credential_id") or auth_ctx.get("credential_id") or role)
        key = (
            str(item.get("url", "")),
            str(item.get("source", "")),
            role,
            account,
            credential_id,
            body_sig,
        )
        if key not in seen:
            seen.add(key)
            item.setdefault("role", role)
            item.setdefault("account", account)
            item.setdefault("credential_id", credential_id)
            item.setdefault("auth_context", {
                "role": role,
                "account": account,
                "credential_id": credential_id,
            })
            deduped.append(item)
    return deduped


def _build_menu_contexts(items: list[dict[str, Any]], login_status: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """按角色汇总菜单树响应上下文，供越权分析和提示使用。"""
    contexts: dict[str, dict[str, Any]] = {}
    login_status = login_status or {}
    for item in items:
        if not isinstance(item, dict):
            continue
        auth_ctx = item.get("auth_context", {}) if isinstance(item.get("auth_context"), dict) else {}
        role = str(item.get("role") or auth_ctx.get("role") or "anonymous")
        ctx = contexts.setdefault(role, {
            "role": role,
            "account": item.get("account") or auth_ctx.get("account") or "",
            "credential_id": item.get("credential_id") or auth_ctx.get("credential_id") or role,
            "login_success": bool(login_status.get(role, role == "anonymous")),
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
        ctx["menu_response_count"] += 1
    return contexts


def merge_crawl_results(primary: dict[str, Any], secondary: dict[str, Any]) -> dict[str, Any]:
    """把 secondary 的爬取结果合并到 primary，返回 primary 引用。

    primary 会被原地修改。如果 secondary 是空（或 None），primary 不变。

    Args:
        primary: 主爬取结果（一般是匿名轮）
        secondary: 待合并的爬取结果（一般是登录轮）

    Returns:
        合并后的 primary（同一个对象）
    """
    if not secondary:
        return primary

    # 1) API endpoints — 去重
    merged_apis = primary.get("api_endpoints", []) + secondary.get("api_endpoints", [])
    seen_api = set()
    deduped_apis = []
    for a in merged_apis:
        k = (a.get("method", ""), a.get("url", ""))
        if k not in seen_api:
            seen_api.add(k)
            deduped_apis.append(a)

    # 2) Pages — 字典合并（后者覆盖前者）
    merged_pages = {**primary.get("pages", {}), **secondary.get("pages", {})}

    # 3) Forms — 去重（按 page+action+method）
    merged_forms = primary.get("forms", []) + secondary.get("forms", [])
    seen_form = set()
    deduped_forms = []
    for f in merged_forms:
        fk = (f.get("page", ""), f.get("action", ""), f.get("method", ""))
        if fk not in seen_form:
            seen_form.add(fk)
            deduped_forms.append(f)

    # 4) Roles — 保序去重（先出现的优先）
    merged_roles = []
    seen_role = set()
    for r in primary.get("roles_crawled", []) + secondary.get("roles_crawled", []):
        if r not in seen_role:
            seen_role.add(r)
            merged_roles.append(r)

    # 5) login_status — 字典合并
    merged_login_status = {
        **primary.get("login_status", {}),
        **secondary.get("login_status", {}),
    }

    # 6) crawled_elements — 列表拼接（保留全部，Phase 1 build_menu_tree_from_crawl 需要）
    merged_elements = primary.get("crawled_elements", []) + secondary.get("crawled_elements", [])

    # 7) js_endpoints — 列表去重
    merged_js_eps = list(dict.fromkeys(
        primary.get("js_endpoints", []) + secondary.get("js_endpoints", [])
    ))

    # 8) menu_coverage — 列表拼接去重（元素是 dict，不能用 dict.fromkeys）
    merged_menu_cov = _dedupe_json(
        primary.get("menu_coverage", []) + secondary.get("menu_coverage", [])
    )

    # 9) api_doc_hits — 列表拼接去重（按 url）
    merged_doc_hits = primary.get("api_doc_hits", []) + secondary.get("api_doc_hits", [])
    seen_doc = set()
    deduped_doc_hits = []
    for d in merged_doc_hits:
        du = d.get("url", d) if isinstance(d, dict) else d
        if du not in seen_doc:
            seen_doc.add(du)
            deduped_doc_hits.append(d)

    # 10) role_comparison — 优先使用有对比的结果
    merged_comparison = secondary.get("role_comparison") or primary.get("role_comparison", {})

    # 10.5) menu_tree_responses — 完整菜单树响应合并，供 BrowseWorker 优先消费
    merged_menu_tree_responses = _dedupe_menu_tree_responses(
        primary.get("menu_tree_responses", []) + secondary.get("menu_tree_responses", [])
    )

    # 10.6) extra_scope — 关联域白名单保序合并，供 fallback 菜单树纳入微前端/子应用页面
    merged_extra_scope = []
    seen_scope = set()
    for domain in primary.get("extra_scope", []) + secondary.get("extra_scope", []):
        domain = str(domain or "").lower().lstrip(".")
        if domain and domain not in seen_scope:
            seen_scope.add(domain)
            merged_extra_scope.append(domain)

    # 10.7) realtime_channels — GraphQL / WebSocket / SSE 证据合并
    merged_realtime_channels = dedupe_realtime_channels(
        primary.get("realtime_channels", []) + secondary.get("realtime_channels", [])
    )

    # 11) JS 深度分析字段 — 逐个合并（列表拼接去重 / 字典合并 / 数值求和）
    # 注意：列表元素可能是 dict（如 js_auth_patterns 的 {type, description, snippet}），
    # dict 不可 hash 不能用 dict.fromkeys 去重，所以走"基于 JSON 序列化的去重"路径，
    # 对纯 hashable 列表（如 str）继续用 fromkeys 保留高性能。
    for jk in _JS_KEYS:
        cv = primary.get(jk)
        lv = secondary.get(jk)
        if cv is None and lv is None:
            continue
        if isinstance(cv, list) or isinstance(lv, list):
            combined = (cv or []) + (lv or [])
            try:
                primary[jk] = list(dict.fromkeys(combined))
            except TypeError:
                # 列表元素不可 hash（dict / list），改用 JSON 序列化去重
                primary[jk] = _dedupe_json(combined)
        elif isinstance(cv, dict) or isinstance(lv, dict):
            primary[jk] = {**(cv or {}), **(lv or {})}
        elif isinstance(cv, (int, float)) or isinstance(lv, (int, float)):
            primary[jk] = (cv or 0) + (lv or 0)

    # ---- 写回 primary ----
    primary["api_endpoints"] = deduped_apis
    primary["apis_total"] = len(deduped_apis)
    primary["apis_inferred_verified"] = (
        primary.get("apis_inferred_verified", 0) + secondary.get("apis_inferred_verified", 0)
    )
    primary["pages"] = merged_pages
    primary["pages_total"] = len(merged_pages)
    primary["forms"] = deduped_forms
    primary["forms_total"] = len(deduped_forms)
    primary["forms_submitted"] = (
        primary.get("forms_submitted", 0) + secondary.get("forms_submitted", 0)
    )
    primary["roles_crawled"] = merged_roles
    primary["crawl_rounds"] = len(merged_roles)
    primary["login_status"] = merged_login_status
    primary["crawled_elements"] = merged_elements
    primary["total_clickable_elements"] = (
        primary.get("total_clickable_elements", 0)
        + secondary.get("total_clickable_elements", 0)
    )
    primary["js_endpoints"] = merged_js_eps
    primary["js_endpoints_found"] = len(merged_js_eps)
    primary["menu_coverage"] = merged_menu_cov
    primary["menu_clicked"] = len(merged_menu_cov)
    primary["menu_with_api"] = sum(1 for m in merged_menu_cov if isinstance(m, dict) and m.get("apis_triggered", 0) > 0)
    primary["menu_without_api"] = sum(1 for m in merged_menu_cov if isinstance(m, dict) and m.get("apis_triggered", 0) == 0)
    primary["menu_tree_responses"] = merged_menu_tree_responses
    primary["menu_contexts"] = _build_menu_contexts(merged_menu_tree_responses, merged_login_status)
    primary["extra_scope"] = merged_extra_scope
    primary["realtime_channels"] = merged_realtime_channels
    primary["realtime_channels_total"] = len(merged_realtime_channels)
    primary["api_doc_hits"] = deduped_doc_hits
    primary["role_comparison"] = merged_comparison

    return primary
