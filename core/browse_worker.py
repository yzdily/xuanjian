"""
BrowseWorker — Phase 1 浏览器操作子 Agent

每个 BrowseWorker 负责一组菜单页面的深度操作和流量抓取。
独立 LLM 上下文，串行执行，共享同一个浏览器实例。

设计原则：
- 每组控制在 15-25 个 Tab 总量（约 5-8 个菜单页面）
- 独立上下文避免长对话幻觉
- 操作完毕后上报抓到的 API 列表，由主 Agent 汇总
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncGenerator, TYPE_CHECKING

from core.llm import LLMClient, Message, parse_tool_call_arguments
from core.context import ContextManager
from core.tools import build_browse_worker_tools
from core.tool_executor import ToolExecutor
from core.config import MAX_TOOL_RESULT, REPEAT_TOOL_THRESHOLD
from core.log import get_logger
from core.realtime_protocols import classify_realtime_flow, dedupe_realtime_channels

if TYPE_CHECKING:
    from core.sitemap import Sitemap

log = get_logger("browse_worker")


# ---- 菜单树分组逻辑 ----

# 每组目标 Tab 总量（控制子 Agent 的工作量和上下文长度）
TARGET_TABS_PER_GROUP = 20
MAX_TABS_PER_GROUP = 30
MIN_TABS_PER_GROUP = 8


MENU_API_KEYWORDS = (
    "menu/tree", "menu/user-menu", "menu/list", "menu/nav",
    "permission/menu", "sys/menu", "system/menu", "sidebar",
    "/api/routes", "/getrouters", "/api/menu", "/api/menus",
    "/api/nav", "/api/navigation", "/api/sidebar",
)

MENU_NODE_KEYS = (
    "menuType", "menuName", "children", "name", "path", "url", "route", "router",
    "title", "label", "component", "routes", "items", "menus", "meta", "perms", "permission",
)

MENU_CHILD_KEYS = ("children", "childList", "subMenus", "subList", "items", "nodes", "menus", "routes")
MENU_PATH_KEYS = ("page_url", "path", "url", "route", "router", "menuUrl", "menuPath")
MENU_NAME_KEYS = ("menuName", "name", "title", "label", "text")
MENU_META_NAME_KEYS = ("title", "name", "label")
NEGATIVE_MENU_HINTS = ("product", "category", "catalog", "dept", "department", "region", "area", "dict", "dictionary", "config-tree")


def _contains_menu_keyword(text: str) -> bool:
    text_l = (text or "").lower()
    return any(kw in text_l for kw in MENU_API_KEYWORDS)


def _unwrap_menu_payload(parsed: object) -> list[dict] | None:
    """从常见 API 包装层里取出菜单树列表。"""
    if isinstance(parsed, list):
        return parsed if any(isinstance(x, dict) for x in parsed) else None
    if not isinstance(parsed, dict):
        return None

    for key in ("data", "result", "rows", "list", "menus", "routes", "children", "items"):
        value = parsed.get(key)
        if isinstance(value, list) and any(isinstance(x, dict) for x in value):
            return value
        if isinstance(value, dict):
            nested = _unwrap_menu_payload(value)
            if nested:
                return nested
    return None


def _node_children(node: dict) -> list[dict]:
    for key in MENU_CHILD_KEYS:
        value = node.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []


def _node_name(node: dict, fallback: str = "") -> str:
    for key in MENU_NAME_KEYS:
        value = node.get(key)
        if value:
            return str(value).strip()
    meta = node.get("meta")
    if isinstance(meta, dict):
        for key in MENU_META_NAME_KEYS:
            value = meta.get(key)
            if value:
                return str(value).strip()
    return fallback


def _node_path(node: dict) -> str:
    for key in MENU_PATH_KEYS:
        value = node.get(key)
        if value:
            return str(value).strip()
    return ""


def _combine_route_path(parent_path: str, path: str) -> str:
    if not path:
        return parent_path or "/"
    if path.startswith(("http://", "https://", "#")):
        return path
    if path.startswith("/"):
        return path
    parent = (parent_path or "").rstrip("/")
    if not parent or parent == "/":
        return "/" + path.lstrip("/")
    return parent + "/" + path.lstrip("/")


def _route_to_page_url(route_path: str, crawl_result: dict) -> str:
    if not route_path:
        return ""
    if route_path.startswith(("http://", "https://")):
        return route_path

    target = crawl_result.get("target", "") or ""
    if not target:
        return route_path

    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(target)
        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
        origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    except Exception:
        base = target.rstrip("/")
        origin = base

    if route_path.startswith("#"):
        return base + route_path

    route = "/" + route_path.lstrip("/")
    router_mode = (crawl_result.get("router_mode") or "").lower()
    if router_mode == "history":
        return origin.rstrip("/") + route
    return base.rstrip("/") + "#" + route


def _route_entry_url_candidates(page_url: str, path: str, raw_path: str = "") -> list[str]:
    """生成 route/page_url 入口候选；hash SPA 同时兼容 base#/x 与 base/#/x。"""
    out: list[str] = []

    def add(value: str) -> None:
        value = str(value or "").strip()
        if value and value not in out:
            out.append(value)

    add(page_url)
    if "#/" in page_url and "/#/" not in page_url:
        add(page_url.replace("#/", "/#/", 1))
    add(path)
    add(raw_path)
    return out


def _flatten_menu_nodes(nodes: list[dict], limit: int = 200) -> list[dict]:
    out: list[dict] = []

    def walk(items: list[dict]) -> None:
        for item in items:
            if not isinstance(item, dict) or len(out) >= limit:
                continue
            out.append(item)
            walk(_node_children(item))

    walk(nodes)
    return out


def _normalize_menu_node(node: dict, crawl_result: dict, parent_path: str = "") -> dict | None:
    children = _node_children(node)
    raw_path = _node_path(node)
    path = _combine_route_path(parent_path, raw_path) if raw_path else parent_path
    name = _node_name(node, _page_name_from_url(path) if path else "未命名")

    normalized_children = [
        child for child in (_normalize_menu_node(c, crawl_result, path) for c in children) if child
    ]

    raw_type = str(node.get("menuType") or node.get("type") or "").upper()
    has_component = bool(node.get("component") or node.get("page_url"))
    # Vue Router / AntD Pro 常见父节点会同时有 path + routes，但没有 component；这种应当作为模块。
    is_module = raw_type == "M" or (normalized_children and raw_type != "C" and not has_component)
    is_page = raw_type == "C" or has_component or raw_path or not normalized_children

    if is_module and normalized_children:
        return {
            "menuType": "M",
            "menuName": name,
            "name": name,
            "path": path or "/",
            "source": node.get("source", "menu_api"),
            "children": normalized_children,
        }

    if is_page:
        page_url = str(node.get("page_url") or "") or _route_to_page_url(path, crawl_result)
        entry_urls = _route_entry_url_candidates(page_url, path, raw_path)
        return {
            "menuType": "C",
            "menuName": name,
            "name": name,
            "path": path or raw_path or "/",
            "page_url": page_url,
            "entry_selector": str(node.get("selector") or node.get("entry_selector") or ""),
            "entry_urls": entry_urls,
            "source": node.get("source", "menu_api"),
            "component": node.get("component", ""),
            "meta": node.get("meta") if isinstance(node.get("meta"), dict) else {"tabs": []},
            "children": normalized_children,
        }
    return None


def normalize_menu_tree_to_ruoyi_like(menu_tree: list[dict], crawl_result: dict) -> list[dict]:
    """把 RuoYi / Vue Router / AntD Pro / 自研菜单树统一成 BrowseWorker 可消费结构。"""
    normalized = [
        node for node in (_normalize_menu_node(n, crawl_result, "") for n in menu_tree if isinstance(n, dict)) if node
    ]

    # 顶级全是页面时，按路径第一段补一层模块，避免 group_menus_by_tab_weight 过度碎片化。
    if normalized and all(n.get("menuType") == "C" for n in normalized):
        modules: dict[str, dict] = {}
        for node in normalized:
            parts = [seg for seg in str(node.get("path", "/")).split("/") if seg]
            prefix = parts[0] if parts else "root"
            modules.setdefault(prefix, {
                "menuType": "M",
                "menuName": prefix if prefix != "root" else "首页",
                "name": prefix if prefix != "root" else "首页",
                "path": "/" + prefix if prefix != "root" else "/",
                "source": "menu_api",
                "children": [],
            })["children"].append(node)
        return list(modules.values())
    return normalized


def _score_menu_candidate(data: list[dict], source: str, url: str, crawl_result: dict) -> tuple[float, list[str]]:
    nodes = _flatten_menu_nodes(data)
    if not nodes:
        return 0.0, ["没有可用节点"]

    total = len(nodes)
    with_path = sum(1 for n in nodes if _node_path(n))
    with_children = sum(1 for n in nodes if _node_children(n))
    with_component = sum(1 for n in nodes if n.get("component"))
    with_menu_fields = sum(1 for n in nodes if any(k in n for k in MENU_NODE_KEYS))
    with_permission = sum(1 for n in nodes if any(k in n for k in ("perms", "permission", "permissions", "authority", "hidden", "redirect", "icon", "meta")))

    score = 0.0
    reasons: list[str] = []
    if source == "keyword_match" or _contains_menu_keyword(url):
        score += 40
        reasons.append("来源或 URL 命中菜单关键词")
    if source == "heuristic_detect":
        score += 12
        reasons.append("启发式菜单候选")

    path_ratio = with_path / total
    children_ratio = with_children / total
    component_ratio = with_component / total
    menu_field_ratio = with_menu_fields / total
    permission_ratio = with_permission / total
    score += path_ratio * 25 + children_ratio * 15 + component_ratio * 15 + menu_field_ratio * 20 + permission_ratio * 10
    reasons.append(f"路径字段比例 {path_ratio:.0%}，子节点比例 {children_ratio:.0%}，组件比例 {component_ratio:.0%}")

    js_paths = {str(r.get("path", "")).rstrip("/") for r in crawl_result.get("js_routes", []) if isinstance(r, dict)}
    candidate_paths = {str(_node_path(n)).rstrip("/") for n in nodes if _node_path(n)}
    overlap = len(js_paths & candidate_paths)
    if overlap:
        score += min(overlap * 3, 18)
        reasons.append(f"与 JS 路由有 {overlap} 个交集")

    url_l = (url or "").lower()
    if any(hint in url_l for hint in NEGATIVE_MENU_HINTS):
        score -= 25
        reasons.append("URL 含业务数据树关键词，降权")
    if total == 1 and not with_children:
        score -= 20
        reasons.append("单节点且无子节点，降权")

    return score, reasons


def _add_menu_candidate(candidates: list[dict], data: object, source: str, url: str, crawl_result: dict,
                        auth_context: dict | None = None) -> None:
    tree = _unwrap_menu_payload(data)
    if not tree:
        return
    if not any(isinstance(n, dict) and any(k in n for k in MENU_NODE_KEYS) for n in tree[:10]):
        return
    normalized = normalize_menu_tree_to_ruoyi_like(tree, crawl_result)
    if not normalized:
        return
    if auth_context:
        for node in normalized:
            if isinstance(node, dict):
                meta = node.setdefault("meta", {})
                if isinstance(meta, dict):
                    meta.setdefault("auth_context", auth_context)
    score, reasons = _score_menu_candidate(tree, source, url, crawl_result)
    if _contains_menu_keyword(url):
        score += 10
    if score < 30:
        return
    candidates.append({
        "source": source,
        "url": url,
        "score": score,
        "reasons": reasons,
        "tree": normalized,
        "raw_count": len(tree),
    })


def parse_menu_tree(crawl_result: dict) -> list[dict] | None:
    """从爬取结果中提取菜单树，并统一归一化成 BrowseWorker 可消费的 menuType=M/C 结构。"""
    candidates: list[dict] = []
    menu_api_url = ""

    # 0. 从 on_response 缓存的完整菜单树 JSON 中提取候选（最可靠，不截断）
    for cached in crawl_result.get("menu_tree_responses", []) or []:
        resp_body = cached.get("response_body", "")
        if not resp_body:
            continue
        try:
            parsed = json.loads(resp_body)
            url = cached.get("url", "")
            source = cached.get("source", "unknown")
            auth_context = cached.get("auth_context") if isinstance(cached.get("auth_context"), dict) else {
                "role": cached.get("role", "anonymous"),
                "account": cached.get("account", ""),
                "credential_id": cached.get("credential_id", ""),
            }
            _add_menu_candidate(candidates, parsed, source, url, crawl_result, auth_context=auth_context)
            if not menu_api_url and _contains_menu_keyword(url):
                menu_api_url = url
        except Exception:
            pass

    # 1. 从 api_endpoints 的 response_body 中提取候选（mitmproxy 场景）
    for api in crawl_result.get("api_endpoints", []) or []:
        api_url = api.get("url", "")
        resp_body = api.get("response_body", "")
        if _contains_menu_keyword(api_url) and not menu_api_url:
            menu_api_url = api_url
        if not resp_body:
            continue
        try:
            parsed = json.loads(resp_body)
            source = "api_response_keyword" if _contains_menu_keyword(api_url) else "api_response_heuristic"
            _add_menu_candidate(candidates, parsed, source, api_url, crawl_result)
        except Exception:
            pass

    # 2. 流量中没有完整响应 → 主动请求菜单树 API，作为候选参与评分
    if menu_api_url and not candidates:
        log.info("爬取流量中发现菜单树 API，尝试主动补全: %s", menu_api_url)
        try:
            import urllib.request
            auth_token = _get_auth_token(crawl_result)
            headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
            req = urllib.request.Request(menu_api_url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=10)
            parsed = json.loads(resp.read())
            _add_menu_candidate(candidates, parsed, "active_fetch", menu_api_url, crawl_result)
        except Exception as e:
            log.warning("主动请求菜单树失败: %s", e)

    if candidates:
        candidates.sort(key=lambda c: c["score"], reverse=True)
        best = candidates[0]
        log.info(
            "选择菜单树候选 [%s] score=%.1f url=%s raw=%d normalized=%d reason=%s",
            best["source"], best["score"], best["url"][:100], best["raw_count"], len(best["tree"]),
            "; ".join(best["reasons"][:3]),
        )
        return best["tree"]

    # 3. 后端没有菜单 API（或候选质量不足）→ 用爬虫产物自动构造
    fallback = build_menu_tree_from_crawl(crawl_result)
    if fallback:
        log.info("从爬虫产物自动构造菜单树: %d 个一级模块", len(fallback))
        return fallback

    return None


def build_menu_tree_from_crawl(crawl_result: dict) -> list[dict] | None:
    """从爬虫产物（crawled_elements + pages）反向构造 RuoYi 格式菜单树。

    输出 schema 兼容 group_menus_by_tab_weight / build_group_checklist：
        [
          {
            "menuType": "M",          # 一级模块（按 URL 路径前缀分组）
            "menuName": "user",
            "name": "user",
            "path": "/user",
            "children": [
              {
                "menuType": "C",      # 具体页面（按 page_url 唯一）
                "menuName": "/user/profile",
                "name": "用户资料",
                "path": "/user/profile",
                "meta": {
                  "tabs": [           # 该页面下的按钮（无真正 Tab 时也用 tabs 字段承载）
                    {
                      "name": "操作区",
                      "buttons": [
                        {"name": "编辑", "selector": "...", "text": "编辑"},
                        ...
                      ]
                    }
                  ]
                },
                "children": [],
              }, ...
            ]
          }, ...
        ]

    返回 None 表示信息不足以构造（如爬虫几乎没爬到东西）。
    """
    elements = crawl_result.get("crawled_elements") or []
    # ★ 即使 crawled_elements 为空，也继续用 crawl_result["pages"] 构造
    # 爬虫实际访问过的页面（哪怕没有点任何菜单）也应该进入 Phase 1
    crawl_pages = crawl_result.get("pages") or {}
    if not elements and not crawl_pages:
        return None

    # ★ 2026-05-25：按 page_url 聚合 forms（form 在 crawl_result["forms"] 里，每条带 page+fields）
    # 用于在 checklist 里给 LLM 渲染"该页面要填什么字段"，避免它瞎填表
    forms_by_page: dict[str, list[dict]] = {}
    for f in (crawl_result.get("forms") or []):
        page_url = f.get("page") or ""
        if not page_url:
            continue
        forms_by_page.setdefault(page_url, []).append({
            "method": (f.get("method") or "POST").upper(),
            "action": f.get("action", ""),
            "fields": [n for n in (f.get("fields") or []) if n],  # 字段名列表
            "submitted": bool(f.get("submitted")),
        })

    target = crawl_result.get("target", "")
    target_host = ""
    try:
        from urllib.parse import urlparse as _up
        target_host = _up(target).netloc.lower() if target else ""
    except Exception:
        pass

    extra_scope = {
        str(domain or "").lower().lstrip(".")
        for domain in (crawl_result.get("extra_scope") or [])
        if domain
    }

    # 仅保留主站 + extra_scope 白名单页面（防止第三方脚本/广告按钮污染，同时覆盖微前端/子应用）
    def _in_scope(url: str) -> bool:
        if not url or not target_host:
            return False
        try:
            from urllib.parse import urlparse as _up
            parsed = _up(url)
            if parsed.scheme not in ("http", "https"):
                return False
            host = parsed.netloc.lower()
            if host == target_host or host.endswith("." + target_host):
                return True
            host_name = host.split(":")[0] if ":" in host else host
            target_name = target_host.split(":")[0] if ":" in target_host else target_host
            if host_name == target_name:
                return True
            if host in extra_scope:
                return True
            return any(host.endswith("." + domain) for domain in extra_scope)
        except Exception:
            return False

    # Step 1: 按 page_url 聚合元素 → 每个 page 是一个 menuType=C 节点
    from urllib.parse import urlparse as _up
    pages: dict[str, dict] = {}  # page_url → {name, path, menus[], buttons[]}
    for el in elements:
        page_url = el.get("page_url") or ""
        if not _in_scope(page_url):
            continue
        if page_url not in pages:
            try:
                p = _up(page_url)
                path = p.path or "/"
            except Exception:
                path = page_url
            pages[page_url] = {
                "page_url": page_url,
                "path": path,
                "name": _page_name_from_url(path) or path,
                "menus": [],     # 该页里的"菜单"型元素（用作子页面入口）
                "buttons": [],   # 该页里的"按钮"型元素（具体操作）
            }

        item = {
            "name": (el.get("text") or "").strip()[:30],
            "selector": el.get("selector", ""),
            "text": el.get("text", "").strip(),
            "tag": el.get("tag", ""),
            "triggered_apis": int(el.get("triggered_apis", 0) or 0),
        }
        if not item["name"]:
            continue
        if el.get("is_menu"):
            pages[page_url]["menus"].append(item)
        else:
            pages[page_url]["buttons"].append(item)

    # ★ 补充：把爬虫实际访问过但无 crawled_elements 的页面也加入
    # 这些页面（如 /security/agents, /organization）虽然没有识别到菜单/按钮，
    # 但 BrowseWorker 访问后可以手动探索，不能丢弃
    for page_url, page_data in crawl_pages.items():
        if not _in_scope(page_url):
            continue
        if page_url in pages:
            continue  # 已经从 elements 加入过了
        try:
            p = _up(page_url)
            path = p.path or "/"
        except Exception:
            path = page_url
        # 过滤掉静态资源页面
        if any(path.lower().endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".ico", ".woff", ".ttf")):
            continue
        pages[page_url] = {
            "page_url": page_url,
            "path": path,
            "name": _page_name_from_url(path) or path,
            "menus": [],
            "buttons": [],
        }

    if not pages:
        return None

    # Step 2: 按 path 第一段做一级模块分组
    modules: dict[str, dict] = {}  # prefix → {name, children}
    for url, info in pages.items():
        path_parts = [seg for seg in (info["path"] or "/").split("/") if seg]
        prefix = path_parts[0] if path_parts else "root"
        # 路径太短或无意义的，归到 root
        if not prefix or len(prefix) > 60:
            prefix = "root"
        # 跳过纯文件后缀（如 robots.txt / sitemap.xml）→ 归类到 misc
        if any(prefix.lower().endswith(ext) for ext in (".txt", ".xml", ".html", ".json", ".js", ".css")):
            prefix = "misc"

        if prefix not in modules:
            modules[prefix] = {
                "menuType": "M",
                "menuName": prefix,
                "name": prefix,
                "path": "/" + prefix,
                "children": [],
            }

        # 该 page 的按钮 → 拼成一个虚拟 "tab"，让 build_group_checklist 能渲染
        # ★ 2026-05-25：按钮项保留 selector + tag，让 checklist 能直接渲染给 LLM 抄
        tabs = []
        if info["buttons"]:
            tabs.append({
                "name": "页面操作",
                "buttons": [
                    {
                        "name": b["name"],
                        "selector": b.get("selector", ""),
                        "text": b.get("text", b["name"]),
                        "tag": b.get("tag", ""),
                    }
                    for b in info["buttons"]
                ],
            })

        entry_selector = ""
        if info["menus"]:
            entry_selector = str(info["menus"][0].get("selector") or "")
        page_node = {
            "menuType": "C",
            "menuName": info["name"],
            "name": info["name"],
            "path": info["path"],
            "page_url": url,                       # ★ 自定义字段：BrowseWorker 可直接 browser_goto
            "entry_selector": entry_selector,      # ★ 双入口：优先点击菜单 selector，失败再 route/page_url 直达
            "entry_urls": _route_entry_url_candidates(url, info["path"]),
            "meta": {"tabs": tabs} if tabs else {},
            "children": [],
            # ★ 自定义字段：菜单项的 selector，BrowseWorker 也可以直接 browser_click
            "menu_items": [
                {"name": m["name"], "selector": m["selector"]} for m in info["menus"]
            ],
            # ★ 2026-05-25：把该页面的表单信息挂上，checklist 里给 LLM 渲染字段填写表
            "forms": forms_by_page.get(url, []),
        }
        modules[prefix]["children"].append(page_node)

    # Step 3: 输出排序：按 children 多的优先（业务密度高）
    result = sorted(modules.values(), key=lambda m: len(m["children"]), reverse=True)

    # 给 root / misc 这种"杂项"组改个友好名
    name_map = {"root": "首页", "misc": "辅助资源"}
    for m in result:
        if m["name"] in name_map:
            m["menuName"] = name_map[m["name"]]
            m["name"] = name_map[m["name"]]

    return result


def _page_name_from_url(path: str) -> str:
    """从 URL 路径生成可读的页面名。/api/user/profile → user / profile。"""
    if not path:
        return ""
    parts = [seg for seg in path.split("/") if seg]
    if not parts:
        return "首页"
    # 跳过 api/v1 这种通用前缀
    skip = {"api", "v1", "v2", "v3", "v4", "rest", "public"}
    meaningful = [p for p in parts if p.lower() not in skip and not p.lower().startswith("v") or len(p) > 3]
    if meaningful:
        return " / ".join(meaningful[:3])
    return " / ".join(parts[-2:])


def _get_auth_token(crawl_result: dict) -> str | None:
    """从爬取结果或 FlowStore 中提取 JWT/Bearer token。"""
    from core.intent import _extract_token_value, _looks_like_auth_token

    auth_header_names = {
        "authorization", "x-auth-token", "x-access-token", "access-token",
        "id-token", "id_token", "token", "jwt", "c-token", "sc-id-token",
    }

    def _pick_token(headers: dict) -> str | None:
        for hk, hv in (headers or {}).items():
            hk_lower = str(hk).lower()
            if hk_lower not in auth_header_names and "token" not in hk_lower:
                continue
            token = _extract_token_value(hv) if isinstance(hv, str) else ""
            if token and _looks_like_auth_token(token):
                return token
        return None

    # 1. 从爬取结果的 API headers 中找
    for api in crawl_result.get("api_endpoints", []):
        headers = api.get("headers", {})
        token = _pick_token(headers)
        if token:
            return token

    # 2. 从 FlowStore 中找
    try:
        from mcp_servers.proxy_mcp import _store, _load_new_flows
        _load_new_flows()
        for flow_id in reversed(list(_store._order)):
            flow = _store.get(flow_id)
            if flow and flow.request_headers:
                token = _pick_token(flow.request_headers)
                if token:
                    return token
    except Exception:
        pass

    # 3. 从浏览器 localStorage 中找
    try:
        import asyncio
        from mcp_servers.browser_mcp import _ensure_browser
        actual = getattr(_ensure_browser, "fn", _ensure_browser)

        async def _get_token():
            page = await actual()
            token = await page.evaluate("""() => {
                const keys = ['token', 'access_token', 'accessToken', 'auth_token', 'authToken', 'jwt', 'id_token', 'idToken', 'Authorization', 'Sc-Id-Token', 'c-token'];
                for (const store of [localStorage, sessionStorage]) {
                    for (const key of keys) {
                        const val = store.getItem(key);
                        if (val && val.length > 10) return val.startsWith('Bearer ') ? val.slice(7).trim() : val;
                    }
                }
                return null;
            }""")
            return token

        loop = asyncio.get_event_loop()
        if loop.is_running():
            # 如果在异步环境中，无法同步获取
            return None
        return loop.run_until_complete(_get_token())
    except Exception:
        pass

    return None


def _count_tabs(node: dict) -> int:
    """递归统计一个菜单节点下的 Tab 总数。"""
    count = 0
    meta = node.get("meta", {}) or {}
    tabs = meta.get("tabs", []) if isinstance(meta, dict) else []
    count += len(tabs)
    for child in node.get("children", []) or []:
        count += _count_tabs(child)
    # 没有 Tab 的页面（menuType=C）也算 1 个工作单位
    if node.get("menuType") == "C" and count == 0:
        count = 1
    return count


def _count_pages(node: dict) -> int:
    """递归统计一个菜单节点下的页面数。"""
    count = 0
    if node.get("menuType") == "C":
        count = 1
    for child in node.get("children", []) or []:
        count += _count_pages(child)
    return count


def _collect_menu_page_keys(node: dict, keys: set[str]) -> None:
    """收集菜单树里已经覆盖的 page_url/path，用于排除重复 JS 路由。"""
    if not isinstance(node, dict):
        return
    for value in (node.get("page_url"), node.get("path"), node.get("url")):
        if value:
            keys.add(str(value).rstrip("/"))
    for child in node.get("children", []) or []:
        _collect_menu_page_keys(child, keys)


def _build_js_route_groups(menu_tree: list[dict], crawl_result: dict | None) -> list[dict]:
    """把 JS 静态分析发现但尚未访问的隐藏路由转成 BrowseWorker 可执行虚拟菜单组。"""
    if not crawl_result:
        return []

    js_routes = crawl_result.get("js_routes") or []
    if not js_routes:
        return []

    covered: set[str] = set()
    for node in menu_tree or []:
        _collect_menu_page_keys(node, covered)
    for page_url in (crawl_result.get("pages") or {}).keys():
        covered.add(str(page_url).rstrip("/"))

    nodes: list[dict] = []
    seen: set[str] = set()
    for route in js_routes:
        if not isinstance(route, dict):
            continue
        url = route.get("url") or ""
        path = route.get("path") or ""
        if not url or not path:
            continue

        url_key = str(url).rstrip("/")
        path_key = str(path).rstrip("/")
        if url_key in seen or url_key in covered or path_key in covered:
            continue
        if any(path_key.lower().endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".ttf", ".map")):
            continue

        seen.add(url_key)
        name = _page_name_from_url(path_key) or path_key or "JS隐藏路由"
        nodes.append({
            "menuType": "C",
            "menuName": f"[JS] {name}",
            "name": f"[JS隐藏路由] {name}",
            "path": path,
            "page_url": url,
            "source": "js_routes",
            "component": route.get("component", ""),
            "meta": {"tabs": []},
            "children": [],
        })
        if len(nodes) >= MAX_TABS_PER_GROUP:
            break

    if not nodes:
        return []

    return [{
        "name": "JS隐藏路由",
        "menus": nodes,
        "tab_count": len(nodes),
        "page_count": len(nodes),
    }]


def group_menus_by_tab_weight(menu_tree: list[dict], crawl_result: dict | None = None) -> list[dict]:
    """按 Tab 总量均衡分组。

    策略：
    1. 先按一级模块（menuType=M）拆分
    2. 一级模块的 Tab 总量 <= MAX_TABS_PER_GROUP → 独占一组
    3. Tab 总量 > MAX_TABS_PER_GROUP → 拆分子菜单
    4. Tab 总量太少的模块 → 合并到相邻组
    5. 追加 JS 静态分析发现且未覆盖的隐藏路由虚拟组

    Returns:
        [{"name": "组名", "menus": [菜单节点], "tab_count": N, "page_count": M}]
    """
    # Step 1: 计算每个一级模块的 Tab 权重
    modules = []
    for node in menu_tree:
        name = node.get("name", "") or node.get("menuName", "") or "未知"
        menu_type = node.get("menuType", "")
        tabs = _count_tabs(node)
        pages = _count_pages(node)
        children = node.get("children", []) or []

        if menu_type == "M" and children:
            modules.append({
                "name": name,
                "node": node,
                "children": children,
                "tab_count": tabs,
                "page_count": pages,
            })
        elif menu_type == "C":
            # 顶级页面（不在任何模块下）
            modules.append({
                "name": name,
                "node": node,
                "children": [node],
                "tab_count": max(tabs, 1),
                "page_count": 1,
            })

    if not modules:
        return []

    # Step 2: 分组
    groups = []
    pending_menus = []  # 待合并的小模块
    pending_tabs = 0
    pending_pages = 0
    pending_names = []

    for mod in modules:
        if mod["tab_count"] > MAX_TABS_PER_GROUP:
            # 大模块：需要拆分子菜单
            # 先 flush 之前的 pending
            if pending_menus:
                groups.append({
                    "name": " + ".join(pending_names),
                    "menus": pending_menus,
                    "tab_count": pending_tabs,
                    "page_count": pending_pages,
                })
                pending_menus, pending_tabs, pending_pages, pending_names = [], 0, 0, []

            # 拆分大模块的子菜单
            sub_group_menus = []
            sub_tabs = 0
            sub_pages = 0
            for child in mod["children"]:
                child_tabs = _count_tabs(child)
                child_pages = _count_pages(child)
                if sub_tabs + child_tabs > MAX_TABS_PER_GROUP and sub_group_menus:
                    groups.append({
                        "name": f"{mod['name']}(上)",
                        "menus": sub_group_menus,
                        "tab_count": sub_tabs,
                        "page_count": sub_pages,
                    })
                    sub_group_menus = []
                    sub_tabs = 0
                    sub_pages = 0
                sub_group_menus.append(child)
                sub_tabs += max(child_tabs, 1)
                sub_pages += max(child_pages, 1)
            if sub_group_menus:
                groups.append({
                    "name": f"{mod['name']}(下)" if len(groups) > 0 and groups[-1]["name"].startswith(mod["name"]) else mod["name"],
                    "menus": sub_group_menus,
                    "tab_count": sub_tabs,
                    "page_count": sub_pages,
                })

        elif pending_tabs + mod["tab_count"] > MAX_TABS_PER_GROUP:
            # 加上这个模块会超 → 先 flush pending，再把当前模块开新 pending
            if pending_menus:
                groups.append({
                    "name": " + ".join(pending_names),
                    "menus": pending_menus,
                    "tab_count": pending_tabs,
                    "page_count": pending_pages,
                })
            pending_menus = list(mod["children"])
            pending_tabs = mod["tab_count"]
            pending_pages = mod["page_count"]
            pending_names = [mod["name"]]

        else:
            # 累积到 pending
            pending_menus.extend(mod["children"])
            pending_tabs += mod["tab_count"]
            pending_pages += mod["page_count"]
            pending_names.append(mod["name"])

    # flush 剩余
    if pending_menus:
        groups.append({
            "name": " + ".join(pending_names),
            "menus": pending_menus,
            "tab_count": pending_tabs,
            "page_count": pending_pages,
        })

    groups.extend(_build_js_route_groups(menu_tree, crawl_result))

    return groups


def build_group_checklist(menus: list[dict]) -> str:
    """为一组菜单生成结构化 checklist（注入子 Agent 上下文）。

    每个按钮展开为具体操作指令，LLM 按行执行即可。

    ★ 2026-05-25 改造：
    - 按钮项直接渲染真实 selector，LLM 不需要"猜"，照抄即可
    - 表单页面渲染字段填写表（基于 FORM_FILL_RULES 智能推断每个字段填什么值）
    - 搜索按钮改为"先 fill 再 click"
    - 删除按钮改为"跳过 UI 操作（主 Agent 阶段会用 proxy_send_request 直接构造 DELETE）"
    - 上传按钮跳过文件选择（Playwright 不支持，改为只记录接口）
    """
    from core.crawler.models import FORM_FILL_RULES

    lines = []
    page_idx = 0

    # 按钮名称 → 操作类型映射
    def _btn_action(btn_name: str) -> str:
        """根据按钮名称推导具体操作步骤。"""
        name = btn_name.lower()
        if any(kw in name for kw in ("新增", "新建", "创建", "添加", "add", "create", "new")):
            return ("点击此按钮 → 弹窗出现后**先 browser_get_content 拿到 form 字段的真实 selector** "
                    "→ 按本页『表单字段填写表』逐个 browser_fill → 点提交按钮 → "
                    "**等待 1.5 秒** → proxy_get_traffic → 关闭弹窗")
        if any(kw in name for kw in ("编辑", "修改", "edit", "update", "配置", "设置")):
            return ("点击表格第一行的此按钮（selector 里的 :nth-of-type 加上 1）→ 弹窗后修改一个字段 → "
                    "提交 → 等 1.5 秒 → proxy_get_traffic → 关闭")
        if any(kw in name for kw in ("删除", "移除", "remove", "delete")):
            return ("⚠️ **跳过 UI 点击**（弹窗确认/取消都不会触发 DELETE 请求或者会真删）。"
                    "这类接口由主 Agent 在后续阶段用 proxy_send_request 直接构造请求测试。"
                    "本步直接打 ✅ 跳过即可。")
        if any(kw in name for kw in ("查询", "搜索", "search")):
            return ("**先 browser_fill 搜索框**（selector 一般是同区域的 input[placeholder*=搜索] 或 "
                    "input[type=text]，值填 'test'）→ 再点击此按钮 → 等 1.5 秒 → proxy_get_traffic")
        if any(kw in name for kw in ("查看", "详情", "view", "detail")):
            return "点击表格第一行的此按钮 → 等 1.5 秒 → proxy_get_traffic → 关闭/返回"
        if any(kw in name for kw in ("list", "刷新", "重置", "reset")):
            return "点击 → 等 1.5 秒 → proxy_get_traffic"
        if any(kw in name for kw in ("导出", "下载", "export", "download")):
            return "点击 → 等 2 秒（导出可能慢）→ proxy_get_traffic"
        if any(kw in name for kw in ("导入", "上传", "import", "upload")):
            return ("⚠️ **不要选文件**（Playwright file chooser 跳过）。点击此按钮 → 弹窗弹出后 "
                    "→ proxy_get_traffic（抓预签名/初始化接口）→ 关闭弹窗")
        if any(kw in name for kw in ("启", "停", "禁用", "启用", "toggle", "enable", "disable", "switch")):
            return "点击切换状态 → 等 1.5 秒 → proxy_get_traffic"
        if any(kw in name for kw in ("执行", "运行", "生成", "同步", "推送", "重发", "重试")):
            return "点击 → 等 1.5 秒 → proxy_get_traffic（观察触发的 API）"
        if any(kw in name for kw in ("保存", "save", "提交", "submit", "确认", "确定", "ok")):
            return "填写必要字段 → 点击 → 等 1.5 秒 → proxy_get_traffic"
        if any(kw in name for kw in ("取消", "关闭", "cancel", "close", "返回", "back")):
            return "**跳过**（这类按钮不会触发后端 API）。直接打 ✅"
        # 默认：未知按钮，让 LLM 谨慎点
        return "点击此按钮 → 等 1.5 秒 → proxy_get_traffic"

    def _suggest_fill_value(field_name: str) -> str:
        """根据字段名推断填写值（参考 FORM_FILL_RULES 的关键词匹配逻辑）。"""
        if not field_name:
            return "test"
        n = field_name.lower()
        # 精确匹配优先
        if n in FORM_FILL_RULES:
            return FORM_FILL_RULES[n]
        # 关键词包含匹配
        for keyword, value in FORM_FILL_RULES.items():
            if keyword in n:
                return value
        # 兜底：看类型暗示
        if any(kw in n for kw in ("id", "no", "num")):
            return "1"
        if any(kw in n for kw in ("date", "time")):
            return "2026-01-01"
        if any(kw in n for kw in ("desc", "remark", "note")):
            return "test description"
        return "test"

    def _render_form_fields(forms: list[dict]) -> list[str]:
        """渲染表单字段填写表（每个字段告诉 LLM 该填什么）。"""
        if not forms:
            return []
        out = []
        for fi, form in enumerate(forms, 1):
            fields = form.get("fields") or []
            method = form.get("method", "POST")
            action = form.get("action", "") or "(同页)"
            tag = f"表单#{fi} {method} {action[:60]}"
            if not fields:
                out.append(f"      📝 {tag} （未抓到具体字段，提交时按 placeholder 提示填）")
                continue
            out.append(f"      📝 {tag}")
            for fld in fields[:20]:  # 单表单最多列 20 个字段
                val = _suggest_fill_value(fld)
                # 提示 selector 怎么写（多种候选都给 LLM）
                out.append(
                    f"        - `{fld}` → 填 '{val}' "
                    f"（selector 优先级：input[name='{fld}'] / "
                    f"input[id='{fld}'] / input[placeholder*='{fld}']）"
                )
            if len(fields) > 20:
                out.append(f"        - ... 还有 {len(fields) - 20} 个字段，按相同规则填")
        return out

    def _render(node: dict, depth: int = 0):
        nonlocal page_idx
        name = node.get("name", "") or node.get("menuName", "") or ""
        menu_type = node.get("menuType", "C")
        meta = node.get("meta", {}) or {}
        children = node.get("children", []) or []
        tabs = meta.get("tabs", []) if isinstance(meta, dict) else []
        indent = "  " * depth

        if not name:
            return

        if menu_type == "M":
            lines.append(f"\n{indent}**📂 {name}**")
            for child in children:
                _render(child, depth + 1)
        elif menu_type == "C":
            page_idx += 1
            tab_count = len(tabs)
            btn_count = sum(len(t.get("buttons", [])) for t in tabs) if tabs else 0
            tab_hint = f" | {tab_count} 个 Tab" if tab_count > 0 else ""
            btn_hint = f" | {btn_count} 个操作" if btn_count > 0 else ""
            lines.append(f"\n{indent}⬜ **[{page_idx}] {name}**{tab_hint}{btn_hint}")

            # ★ 双入口：优先点击菜单 selector，失败或菜单隐藏时用 page_url/route 直达
            page_url = node.get("page_url", "")
            entry_selector = node.get("entry_selector", "") or node.get("selector", "")
            raw_entry_urls = node.get("entry_urls") or []
            if isinstance(raw_entry_urls, str):
                raw_entry_urls = [raw_entry_urls]
            entry_urls = [u for u in raw_entry_urls if u]
            if page_url and page_url not in entry_urls:
                entry_urls.insert(0, page_url)
            if node.get("path") and node.get("path") not in entry_urls:
                entry_urls.append(node.get("path"))
            if entry_selector and entry_urls:
                lines.append(
                    f"{indent}  ⬜ 进入页面双入口：先 browser_click(selector='{entry_selector}') → 等 1.5 秒 → "
                    f"proxy_get_traffic；如果点不到/菜单隐藏，browser_goto('{entry_urls[0]}') → 等 1.5 秒 → proxy_get_traffic"
                )
            elif entry_selector:
                lines.append(
                    f"{indent}  ⬜ 进入页面：browser_click(selector='{entry_selector}') → 等 1.5 秒 → proxy_get_traffic"
                )
            elif entry_urls:
                lines.append(
                    f"{indent}  ⬜ 进入页面：browser_goto('{entry_urls[0]}') → 等 1.5 秒 → "
                    f"proxy_get_traffic（抓页面加载 API）"
                )
            else:
                lines.append(f"{indent}  ⬜ 进入页面 → 等 1.5 秒 → proxy_get_traffic（抓加载 API）")
            if len(entry_urls) > 1:
                lines.append(f"{indent}     备用 route/page_url：" + "；".join(entry_urls[1:3]))

            # ★ 菜单项 selector（如果有）
            menu_items = node.get("menu_items") or []
            for mi in menu_items[:10]:
                mi_name = mi.get("name", "")
                mi_sel = mi.get("selector", "")
                if mi_name and mi_sel:
                    lines.append(
                        f"{indent}  ⬜ 子菜单 [{mi_name}] selector=`{mi_sel}` "
                        f"→ 点击 → 等 1.5 秒 → proxy_get_traffic"
                    )

            # ★ 表单字段填写表（让 LLM 知道该页面提交时该填什么）
            forms = node.get("forms") or []
            if forms:
                lines.append(f"{indent}  📋 **本页表单字段填写表**（提交时照此填，不要瞎填 'test'）：")
                for ln in _render_form_fields(forms):
                    lines.append(f"{indent}{ln}")

            # ★ Tab + 按钮
            if tabs:
                for tab in tabs:
                    tab_name = tab.get("name", "")
                    buttons = tab.get("buttons", [])
                    if tab_name and tab_name != "页面操作":
                        lines.append(f"{indent}  📑 Tab:「{tab_name}」")
                        lines.append(
                            f"{indent}    ⬜ 点击切换到此 Tab → 等 1.5 秒 → proxy_get_traffic"
                        )
                    for btn in buttons:
                        btn_name = btn.get("name", "")
                        btn_sel = btn.get("selector", "")
                        btn_text = btn.get("text", btn_name)
                        if not btn_name:
                            continue
                        action = _btn_action(btn_name)
                        # ★ 把 selector 直接渲染出来，LLM 抄过去就行
                        if btn_sel:
                            lines.append(
                                f"{indent}    ⬜ [{btn_name}] selector=`{btn_sel}` "
                                f"(text='{btn_text[:20]}')"
                            )
                            lines.append(f"{indent}        → {action}")
                        else:
                            # 没拿到 selector → 让 LLM 用文本定位
                            lines.append(
                                f"{indent}    ⬜ [{btn_name}] selector=`text={btn_text[:30]}` "
                                f"(无精确 selector，用文本定位)"
                            )
                            lines.append(f"{indent}        → {action}")
            else:
                # 无 Tab 的页面，提示扫描可交互元素
                lines.append(
                    f"{indent}  ⬜ browser_get_content → 从返回的 buttons/forms 列表中"
                    f"逐个挑选可点元素 → 按上述 action 模板操作 → proxy_get_traffic"
                )

            for child in children:
                _render(child, depth + 1)

    for menu in menus:
        _render(menu)

    lines.append(f"\n**本组共 {page_idx} 个页面。**")
    lines.append(
        "\n## ⚠️ 操作铁律（违反 = 漏抓 API）\n"
        "1. **selector 直接抄上面给的**，不要自己用 browser_evaluate 写 JS 找元素。\n"
        "2. **每次 click/fill 之后必须等 1.5 秒再 proxy_get_traffic**，否则 XHR 还没发完就抓到空。\n"
        "3. **进入页面优先 selector，失败立刻用备用 browser_goto(route/page_url)**，不要卡在同一个菜单 selector 上重试。\n"
        "4. **找不到按钮**（权限不足/角色限制/页面已变）→ 跳过打 ✅，**不要卡在同一个 selector 上重试**。\n"
        "5. **每个 ⬜ 操作完打 ✅**，不准跳着做也不准漏。做完一个页面再做下一个。\n"
        "6. **填表时**：优先按『表单字段填写表』填；如果某字段是下拉/单选，先 browser_get_content "
        "看 select 的 option，挑第一个非空的 option 用 fill 或 click。\n"
        "7. **删除/取消/关闭按钮**：上面已标 '跳过' 的就是不点，直接打 ✅。"
    )
    return "\n".join(lines)


# ---- 子 Agent 执行 ----

BROWSE_WORKER_MAX_ROUNDS = 200  # 每个子 Agent 最大轮次（最大组 29 Tab × 6-7 轮 = 200 左右）


class BrowseTaskLedger:
    """BrowseWorker 机器级任务账本。

    目标不是替代 LLM 的 checklist，而是从菜单树和真实工具调用中维护一个可度量的覆盖率：
    - 计划访问哪些页面
    - 哪些页面已经 browser_goto / browser_get_content / proxy_get_traffic
    - 已执行多少点击/填写/截图等操作
    """

    def __init__(self, menus: list[dict]):
        self.pages: list[dict] = []
        self._by_url: dict[str, dict] = {}
        self._by_path: dict[str, dict] = {}
        self._by_entry_selector: dict[str, dict] = {}
        self._action_sigs: set[str] = set()
        self._interaction_sigs: set[str] = set()
        self.current_page_id = ""
        self.last_interaction_id = ""
        self.tool_actions = 0
        self.traffic_captures = 0
        self._collect_pages(menus)

    def _collect_pages(self, menus: list[dict]) -> None:
        def walk(node: dict, parent: str = "") -> None:
            if not isinstance(node, dict):
                return
            name = node.get("name") or node.get("menuName") or parent or "未命名页面"
            menu_type = node.get("menuType", "C")
            children = node.get("children") or []
            if menu_type == "C":
                page_id = f"P{len(self.pages) + 1:03d}"
                meta = node.get("meta") if isinstance(node.get("meta"), dict) else {}
                tabs = meta.get("tabs") if isinstance(meta, dict) else []
                raw_entry_urls = node.get("entry_urls") or []
                if isinstance(raw_entry_urls, str):
                    raw_entry_urls = [raw_entry_urls]
                entry_urls = []
                for candidate in [node.get("page_url"), node.get("path"), *raw_entry_urls]:
                    candidate = str(candidate or "").strip()
                    if candidate and candidate not in entry_urls:
                        entry_urls.append(candidate)
                task = {
                    "id": page_id,
                    "name": str(name),
                    "path": str(node.get("path") or ""),
                    "page_url": str(node.get("page_url") or ""),
                    "entry_selector": str(node.get("entry_selector") or node.get("selector") or ""),
                    "entry_urls": entry_urls,
                    "source": str(node.get("source") or "menu"),
                    "expected_actions": 1,
                    "visited": False,
                    "content_checked": False,
                    "traffic_checked": False,
                    "actions_done": 0,
                    "interactions": [],
                    "_interactions_by_selector": {},
                    "_interactions_by_name": {},
                    "last_tool": "",
                }
                self._collect_interactions_for_page(task, node, tabs)
                task["expected_actions"] = max(1, len(task["interactions"]))
                self.pages.append(task)
                if task.get("entry_selector"):
                    self._by_entry_selector[self._norm_selector(task["entry_selector"])] = task
                for entry_url in task.get("entry_urls", []):
                    normalized = self._norm(entry_url)
                    if not normalized:
                        continue
                    if entry_url.startswith(("http://", "https://")):
                        self._by_url[normalized] = task
                    else:
                        self._by_path[normalized] = task
                if task["page_url"]:
                    self._by_url[self._norm(task["page_url"])] = task
                if task["path"]:
                    self._by_path[self._norm(task["path"])] = task
            for child in children:
                walk(child, str(name))

        for menu in menus or []:
            walk(menu)

    def _collect_interactions_for_page(self, task: dict, node: dict, tabs: list) -> None:
        """从菜单节点生成按钮/Tab/表单级交互任务。"""
        def add_interaction(kind: str, name: str, selector: str = "", source: str = "") -> None:
            name = str(name or "").strip()
            selector = str(selector or "").strip()
            if not name and not selector:
                return
            sig = f"{task['id']}:{kind}:{selector or name}"
            if sig in self._interaction_sigs:
                return
            self._interaction_sigs.add(sig)
            item = {
                "id": f"{task['id']}-I{len(task['interactions']) + 1:02d}",
                "kind": kind,
                "name": name or selector,
                "selector": selector,
                "source": source,
                "done": False,
                "traffic_checked": False,
                "attempts": 0,
                "last_tool": "",
            }
            task["interactions"].append(item)
            if selector:
                task["_interactions_by_selector"][self._norm_selector(selector)] = item
            if name:
                task["_interactions_by_name"][self._norm_selector(name)] = item

        if task.get("entry_selector"):
            add_interaction("page_entry", task.get("name", "进入页面"), task.get("entry_selector", ""), "entry_selector")

        for mi in node.get("menu_items") or []:
            if isinstance(mi, dict):
                add_interaction("menu_item", mi.get("name", ""), mi.get("selector", ""), "menu_items")

        if isinstance(tabs, list):
            for tab in tabs:
                if not isinstance(tab, dict):
                    continue
                tab_name = tab.get("name", "")
                if tab_name and tab_name != "页面操作":
                    add_interaction("tab", tab_name, tab.get("selector", ""), "tabs")
                for btn in tab.get("buttons") or []:
                    if not isinstance(btn, dict):
                        continue
                    add_interaction(
                        "button",
                        btn.get("name") or btn.get("text") or "",
                        btn.get("selector") or (f"text={btn.get('text', '')}" if btn.get("text") else ""),
                        "buttons",
                    )

        for form in node.get("forms") or []:
            if not isinstance(form, dict):
                continue
            fields = form.get("fields") or []
            form_name = f"{form.get('method', 'POST')} {form.get('action') or '同页表单'}"
            add_interaction("form", form_name, "", "forms")
            for field in fields[:20]:
                add_interaction("form_field", str(field), f"input[name='{field}']", "forms")

    def _norm(self, value: str) -> str:
        return (value or "").strip().rstrip("/")

    def _norm_selector(self, value: str) -> str:
        normalized = " ".join((value or "").strip().lower().split())
        return normalized.replace('"', "'")

    def _match_page(self, value: str) -> dict | None:
        key = self._norm(value)
        if not key:
            return None
        if key in self._by_url:
            return self._by_url[key]
        if key in self._by_path:
            return self._by_path[key]
        for task in self.pages:
            url = self._norm(task.get("page_url", ""))
            path = self._norm(task.get("path", ""))
            if url and (key == url or key.endswith(url) or url.endswith(key)):
                return task
            if path and (key == path or key.endswith(path) or key.endswith("#" + path)):
                return task
        return None

    def _current_page(self) -> dict | None:
        if not self.current_page_id:
            return None
        for task in self.pages:
            if task["id"] == self.current_page_id:
                return task
        return None

    def _match_interaction(self, task: dict, func_name: str, args: dict) -> dict | None:
        selector = str(args.get("selector") or args.get("text") or "")
        if selector:
            key = self._norm_selector(selector)
            if key in task.get("_interactions_by_selector", {}):
                return task["_interactions_by_selector"][key]
            text_key = key[5:] if key.startswith("text=") else key
            if text_key in task.get("_interactions_by_name", {}):
                return task["_interactions_by_name"][text_key]
            for item in task.get("interactions", []):
                item_sel = self._norm_selector(item.get("selector", ""))
                item_name = self._norm_selector(item.get("name", ""))
                if item_sel and (key == item_sel or key.endswith(item_sel) or item_sel.endswith(key)):
                    return item
                if item_name and (text_key == item_name or text_key in item_name or item_name in text_key):
                    return item

        if func_name == "browser_fill":
            return self._first_pending_interaction(task, {"form_field", "form"})
        if func_name == "browser_screenshot":
            return self._first_pending_interaction(task, {"button", "tab", "menu_item", "form"})
        return None

    def _first_pending_interaction(self, task: dict, kinds: set[str] | None = None) -> dict | None:
        for item in task.get("interactions", []):
            if item.get("done"):
                continue
            if kinds and item.get("kind") not in kinds:
                continue
            return item
        return None

    def _mark_interaction_done(self, task: dict, item: dict, func_name: str) -> None:
        item["attempts"] = int(item.get("attempts", 0)) + 1
        item["done"] = True
        item["last_tool"] = func_name
        self.last_interaction_id = item.get("id", "")
        task["actions_done"] = sum(1 for it in task.get("interactions", []) if it.get("done"))

    def _mark_last_interaction_traffic(self) -> None:
        if not self.last_interaction_id:
            return
        for task in self.pages:
            for item in task.get("interactions", []):
                if item.get("id") == self.last_interaction_id:
                    item["traffic_checked"] = True
                    return

    def mark_tool(self, func_name: str, args: dict) -> None:
        if func_name == "browser_goto":
            task = self._match_page(str(args.get("url", "")))
            if task:
                task["visited"] = True
                task["last_tool"] = func_name
                self.current_page_id = task["id"]
            return

        if func_name == "browser_click":
            selector = self._norm_selector(str(args.get("selector") or args.get("text") or ""))
            entry_task = self._by_entry_selector.get(selector)
            if entry_task:
                entry_task["visited"] = True
                entry_task["last_tool"] = func_name
                self.current_page_id = entry_task["id"]

        task = self._current_page()
        if not task:
            return

        if func_name == "browser_get_content":
            task["content_checked"] = True
            task["last_tool"] = func_name
        elif func_name == "proxy_get_traffic":
            task["traffic_checked"] = True
            task["last_tool"] = func_name
            self.traffic_captures += 1
            self._mark_last_interaction_traffic()
        elif func_name in {"browser_click", "browser_fill", "browser_hover", "browser_screenshot"}:
            sig = f"{task['id']}:{func_name}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"
            if sig not in self._action_sigs:
                self._action_sigs.add(sig)
                item = self._match_interaction(task, func_name, args)
                if item:
                    self._mark_interaction_done(task, item, func_name)
                else:
                    dynamic = {
                        "id": f"{task['id']}-D{len(task.get('interactions', [])) + 1:02d}",
                        "kind": func_name.replace("browser_", ""),
                        "name": str(args.get("selector") or args.get("name") or func_name),
                        "selector": str(args.get("selector") or ""),
                        "source": "runtime",
                        "done": True,
                        "traffic_checked": False,
                        "attempts": 1,
                        "last_tool": func_name,
                    }
                    task.setdefault("interactions", []).append(dynamic)
                    self.last_interaction_id = dynamic["id"]
                    task["actions_done"] = sum(1 for it in task.get("interactions", []) if it.get("done"))
                self.tool_actions += 1
            task["last_tool"] = func_name

    def mark_phase_complete(self) -> None:
        for task in self.pages:
            if task["visited"]:
                task["traffic_checked"] = task["traffic_checked"] or self.traffic_captures > 0

    def stats(self) -> dict:
        total = len(self.pages)
        visited = sum(1 for p in self.pages if p["visited"])
        content_checked = sum(1 for p in self.pages if p["content_checked"])
        traffic_checked = sum(1 for p in self.pages if p["traffic_checked"])
        interactions = [it for p in self.pages for it in p.get("interactions", [])]
        expected_actions = sum(int(p["expected_actions"]) for p in self.pages)
        actions_done = sum(1 for it in interactions if it.get("done"))
        interactions_with_traffic = sum(1 for it in interactions if it.get("traffic_checked"))
        return {
            "pages_total": total,
            "pages_visited": visited,
            "pages_content_checked": content_checked,
            "pages_traffic_checked": traffic_checked,
            "actions_expected": expected_actions,
            "actions_done": actions_done,
            "interactions_total": len(interactions),
            "interactions_done": actions_done,
            "interactions_with_traffic": interactions_with_traffic,
            "traffic_captures": self.traffic_captures,
            "coverage": round(visited / total, 3) if total else 0,
            "interaction_coverage": round(actions_done / len(interactions), 3) if interactions else 0,
        }

    def next_pending(self, limit: int = 5) -> list[dict]:
        return [p for p in self.pages if not p["visited"]][:limit]

    def next_pending_interactions(self, limit: int = 5) -> list[dict]:
        pending = []
        for page in self.pages:
            for item in page.get("interactions", []):
                if item.get("done"):
                    continue
                pending.append({
                    "page_id": page["id"],
                    "page_name": page["name"],
                    "id": item["id"],
                    "kind": item.get("kind", ""),
                    "name": item.get("name", ""),
                    "selector": item.get("selector", ""),
                })
                if len(pending) >= limit:
                    return pending
        return pending

    def render_plan(self, limit: int = 30) -> str:
        if not self.pages:
            return "未生成结构化页面账本（菜单树为空或无法识别页面节点）。"
        lines = [f"本组结构化账本：共 {len(self.pages)} 个页面任务。"]
        for task in self.pages[:limit]:
            target = task.get("page_url") or task.get("path") or "(无 URL)"
            interactions = task.get("interactions", [])
            entry = []
            if task.get("entry_selector"):
                entry.append(f"selector=`{task['entry_selector']}`")
            if task.get("entry_urls"):
                entry.append("route=" + " / ".join(task.get("entry_urls", [])[:2]))
            entry_hint = "；入口 " + "；".join(entry) if entry else ""
            lines.append(f"- {task['id']} {task['name']} → {target}（交互 {len(interactions)} 个{entry_hint}）")
            for item in interactions[:5]:
                selector = f" selector=`{item.get('selector')}`" if item.get("selector") else ""
                lines.append(
                    f"  - {item['id']} [{item.get('kind')}] {item.get('name')}{selector}"
                )
            if len(interactions) > 5:
                lines.append(f"  - ... 还有 {len(interactions) - 5} 个交互任务")
        if len(self.pages) > limit:
            lines.append(f"- ... 还有 {len(self.pages) - limit} 个页面任务")
        return "\n".join(lines)

    def progress_summary(self) -> str:
        s = self.stats()
        pending = self.next_pending(3)
        pending_interactions = self.next_pending_interactions(3)
        pending_hint = "，下一批待访问：" + "；".join(
            f"{p['id']} {p['name']}" for p in pending
        ) if pending else "，无待访问页面"
        interaction_hint = "，待交互：" + "；".join(
            f"{it['page_id']}/{it['id']} {it['kind']}:{it['name']}"
            for it in pending_interactions
        ) if pending_interactions else "，无待交互"
        return (
            f"页面覆盖 {s['pages_visited']}/{s['pages_total']}，"
            f"内容检查 {s['pages_content_checked']}，流量检查 {s['pages_traffic_checked']}，"
            f"交互动作 {s['interactions_done']}/{s['interactions_total']}，"
            f"交互后抓流量 {s['interactions_with_traffic']}/{s['interactions_done']}，"
            f"抓流量 {s['traffic_captures']} 次{pending_hint}{interaction_hint}"
        )


class BrowseWorker:
    """Phase 1 浏览器操作子 Agent。

    负责一组菜单页面的深度操作和流量抓取。
    共享主 Agent 的浏览器实例（串行执行，不并发）。
    """

    def __init__(
        self,
        worker_id: str,
        llm: LLMClient,
        sitemap: "Sitemap",
        group: dict,
        target_info: str,
        has_credentials: bool,
        extra_scope: list | None = None,
    ):
        self.worker_id = worker_id
        self.llm = llm
        self.sitemap = sitemap
        self.group = group  # {"name", "menus", "tab_count", "page_count"}
        self.target_info = target_info
        self.has_credentials = has_credentials
        self.extra_scope = extra_scope or []  # 关联域名白名单
        self.ledger = BrowseTaskLedger(self.group.get("menus") or [])

        self.context = ContextManager(llm=self.llm, compress_mode="browse")
        self.tool_executor = ToolExecutor(
            sitemap=sitemap,
            has_credentials=has_credentials,
            task_id=sitemap.task_id,
        )

        self._init_context()

    def _init_context(self):
        """构建子 Agent 的独立上下文。"""
        # 基础 prompt
        prompts_dir = Path(__file__).parent / "prompts"
        if (prompts_dir / "solver.md").exists():
            self.context.add_system(
                (prompts_dir / "solver.md").read_text(encoding="utf-8")
            )

        # Phase 1 角色定义
        scope_hint = ""
        if self.extra_scope:
            scope_hint = (
                f"\n\n## 关联域名（可以访问）\n\n"
                f"以下域名是目标产品的关联域，在操作中遇到指向这些域的链接/跳转时，"
                f"**可以跟进访问**，不要跳过：\n"
                + "\n".join(f"- `{d}`" for d in self.extra_scope)
            )
        self.context.add_system(
            "## 你的角色：Phase 1 浏览器操作子 Agent\n\n"
            "你负责操作一组菜单页面，通过浏览器深度操作抓取完整的业务 API 流量。\n"
            "你是多个子 Agent 之一，每个子 Agent 负责不同的菜单组。\n"
            "浏览器已登录，你可以直接操作。操作完成后调用 `phase_complete` 结束。\n\n"
            "## 已知站点信息\n\n"
            f"{self.sitemap.to_summary()}"
            f"{scope_hint}"
        )

        # 生成本组 checklist
        checklist = build_group_checklist(self.group["menus"])
        ledger_plan = self.ledger.render_plan()

        # ★ 2026-05-26：操作 SOP 外移到 core/prompts/browse_sop.md，路径 A/B 共用
        # 同一份操作规约 + 表单填值规范 + 防死循环策略，避免散落不同文件难维护
        try:
            sop_text = (prompts_dir / "browse_sop.md").read_text(encoding="utf-8")
        except Exception as _e:
            log.warning("加载 browse_sop.md 失败（不影响主流程）: %s", _e)
            sop_text = ""

        # ★ 2026-05-25：checklist + 工具说明 + 操作规约 全部放进 system message
        # 原因：ContextManager.compress() 只压缩 history（user/assistant/tool），不动 system_messages。
        # 老版放在 user message 里，第 10 轮触发压缩后 LLM 就看不到 checklist 了，
        # 后面的几十轮失去剧本就会瞎点 → 漏抓 API。
        # 现在放 system，LLM 在 200 轮内永远能看到完整 selector 和字段表。
        self.context.add_system(
            f"## 本次任务：操作「{self.group['name']}」模块\n\n"
            f"以下是菜单树分析初步识别的 **{self.group['page_count']} 个页面**、"
            f"**{self.group['tab_count']} 个 Tab**，作为你探索的起步入口。\n\n"
            "## 你能用的工具（仅这些，没有别的）\n"
            "- `browser_goto(url)` —— 进入页面（**优先用 page_url 直接 goto**，比点菜单稳）\n"
            "- `browser_get_content()` —— 摸清当前页面有哪些可点元素（返回 forms/buttons/links 含真实 selector）\n"
            "- `browser_get_accessibility_tree()` —— 当 get_content 返回按钮很少时用，从无障碍树发现隐藏的交互元素\n"
            "- `browser_click(selector)` —— 点击。**selector 优先抄下面 checklist 上给的**\n"
            "- `browser_hover(selector)` —— 悬停到元素上，触发 hover 才出现的操作按钮/子菜单（如表格行的编辑按钮）\n"
            "- `browser_fill(selector, value)` —— 填表。邮箱/手机号/日期都要按合法格式填\n"
            "- `browser_screenshot(name)` —— 截图（也可以当『等页面渲染完』用）\n"
            "- `proxy_get_traffic()` —— 抓最近的 HTTP 流量。**这是你的最终目的，每次操作后必调**\n"
            "- `note_add(type, content)` —— 偶尔记录关键发现（如：某页面发现了未在 checklist 中的接口）\n"
            "- `phase_complete(summary)` —— 本组操作完成\n\n"
            f"{sop_text}\n\n"
            "## 结构化页面账本（机器会按真实工具调用统计页面 + 按钮/Tab/表单覆盖率）\n\n"
            f"{ledger_plan}\n\n"
            "## 核心目标：最大化 API 发现\n\n"
            "checklist 只是起步的已知页面入口。每次进入新页面后，你都必须"
            "通过 browser_get_content 或 browser_get_accessibility_tree 扫描页面上"
            "的侧边栏或导航栏链接，把发现的任何未访问页面入口追加到你的操作列表。\n\n"
            "## 完成条件（全部满足才能调 phase_complete）\n\n"
            "1. 所有已发现的页面入口都已经访问过\n"
            "2. 每个页面上的可交互元素（按钮/Tab/表单/筛选/排序/分页）都尝试过\n"
            "3. 连续操作多个页面都没有产生新的业务 API\n\n"
            "禁止因某个页面按钮难点击就推断所有页面都如此，每个页面独立判断。\n\n"
            "## 操作 Checklist（起步入口，selector 已标出。操作过程中自行扩展）\n\n"
            f"{checklist}"
        )

        # user message 只留"开工"指令，简短 → 即使被压缩也无所谓
        self.context.add_user(
            f"开始操作「{self.group['name']}」模块。"
            f"从 Checklist 给出的已知入口起步，每进入一个页面就扫描导航栏/侧边栏，"
            f"把发现的任何新页面入口都加入操作列表。"
            f"所有可见页面和交互元素都操作完毕、无新 API 产生后，调用 phase_complete。"
        )

    async def run(self) -> AsyncGenerator[dict, None]:
        """运行子 Agent 直到完成或超时。"""
        round_num = 0
        _last_tool_sig = ""
        _repeat_count = 0
        completed = False
        # ★ 2026-05-28：STALE 判断升级为"双维度"（API 增量 + checklist 进度）
        # 只有同时满足"无新 API"且"无 checklist 进展"才判定为 STALE。
        # 纯展示页（无 API 但 LLM 在推进 checklist）不再被误杀。
        STALE_ROUNDS_LIMIT = 15
        STALE_NUDGE_AT = 10
        STALE_FINAL_CHANCE = 5  # STALE 退出前给的额外轮次（从10降至5）
        PROGRESS_CHECK_INTERVAL = 30  # 每 N 轮注入一次进度检查点
        last_api_count = len(self.sitemap.apis) if self.sitemap else 0
        rounds_since_new_api = 0
        _nudged = False
        _final_chance_given = False  # 是否已给过"最后机会"
        _progress_reset_count = 0  # has_recent_progress 重置计数（防止无限续命）
        _MAX_PROGRESS_RESETS = 2  # 最多允许 2 次"有进度"续命，之后强制退出
        # ★ checklist 进度追踪：通过检测 LLM 回复中的 ✅ 标记来判断是否在推进
        _last_checklist_progress_round = 0  # 上次检测到 ✅ 进展的轮次
        _checklist_done_count = 0  # 累计检测到的 ✅ 数量
        # ★ 工具白名单：BrowseWorker 专用，砍掉 evaluate / js_* / sitemap_* / proxy_send 等
        worker_tools = build_browse_worker_tools()

        while round_num < BROWSE_WORKER_MAX_ROUNDS and not completed:
            round_num += 1

            # ---- 双维度 STALE 检测 ----
            if self.sitemap:
                cur = len(self.sitemap.apis)
                if cur > last_api_count:
                    last_api_count = cur
                    rounds_since_new_api = 0
                    _nudged = False
                    _final_chance_given = False
                else:
                    rounds_since_new_api += 1

                # ★ 中途轻推：连续 N/2 轮无新 API 时，注入一条推进提示
                if rounds_since_new_api == STALE_NUDGE_AT and not _nudged:
                    _nudged = True
                    self.context.add_user(
                        f"⚠️ 已连续 {STALE_NUDGE_AT} 轮没有新 API 进来。"
                        "你现在卡在哪一个 ⬜ 上？\n"
                        "如果同一个 selector 失败超过 2 次：**立刻打 ✅ 跳过**，去做下一个未完成的 ⬜。\n"
                        "如果你已经完成了大部分页面：调 `phase_complete(summary)` 结束本组。\n"
                        "不要再尝试同一个失败的操作。"
                    )

                if rounds_since_new_api >= STALE_ROUNDS_LIMIT:
                    # ★ 双维度判断：如果 LLM 最近 10 轮内有 checklist 进展，不退出
                    has_recent_progress = (round_num - _last_checklist_progress_round) <= 10
                    # ★ 2026-08-05：限制"有进度"续命次数，防止 LLM 反复输出 ✅ 但无实际 API 进展导致无限循环
                    if has_recent_progress and _progress_reset_count < _MAX_PROGRESS_RESETS:
                        _progress_reset_count += 1
                        log.warning("[%s] STALE 但有 checklist 进度，第 %d 次续命（上限 %d）",
                                    self.worker_id, _progress_reset_count, _MAX_PROGRESS_RESETS)
                        rounds_since_new_api = STALE_NUDGE_AT  # 重置到 nudge 之后，避免立即再触发
                        _nudged = True
                    elif not _final_chance_given:
                        # ★ 退出前"最后机会"：扫描未完成项，注入强制推进指令
                        _final_chance_given = True
                        # 从 system messages 中提取未完成的 ⬜ 数量（粗略估计）
                        unchecked_hint = ""
                        for sm in self.context.system_messages:
                            if "Checklist" in sm.content:
                                unchecked_count = sm.content.count("⬜")
                                if unchecked_count > 0:
                                    unchecked_hint = f"你还有约 {unchecked_count} 个 ⬜ 未完成。"
                                break
                        self.context.add_user(
                            f"🚨 即将因无进展退出（已连续 {STALE_ROUNDS_LIMIT} 轮无新 API 且无 checklist 进展）。\n"
                            f"{unchecked_hint}\n"
                            f"你还有 {STALE_FINAL_CHANCE} 轮机会：\n"
                            f"1. 立即用 `browser_goto` 进入下一个未完成的 ⬜ 页面\n"
                            f"2. 或者调用 `phase_complete(summary)` 结束本组\n"
                            f"不要再重试已失败的操作！"
                        )
                        # 给额外轮次
                        rounds_since_new_api = STALE_ROUNDS_LIMIT - STALE_FINAL_CHANCE
                    else:
                        # 最后机会也用完了，真的退出
                        yield {
                            "type": "browse_worker_done",
                            "worker": self.worker_id,
                            "group": self.group["name"],
                            "rounds": round_num,
                            "reason": f"已连续无进展（API+checklist 双维度），提前结束（共 {round_num} 轮）",
                            "ledger": self.ledger.stats(),
                        }
                        return

            # ---- 周期性进度注入（防止 LLM 遵循度衰减） ----
            if round_num > 1 and round_num % PROGRESS_CHECK_INTERVAL == 0:
                api_count = len(self.sitemap.apis) if self.sitemap else 0
                self.context.add_user(
                    f"📊 进度检查点（第 {round_num}/{BROWSE_WORKER_MAX_ROUNDS} 轮）：\n"
                    f"- 已抓 API：{api_count} 个\n"
                    f"- 已完成 ✅：约 {_checklist_done_count} 项\n"
                    f"- 机器账本：{self.ledger.progress_summary()}\n\n"
                    f"请继续按 system 中的 Checklist 执行下一个 ⬜，优先处理机器账本里的待访问页面和待交互按钮/Tab/表单。\n"
                    f"提醒：进入页面 selector 点不到就立刻用备用 route/page_url 直达；每个页面必须深入操作，交互后要抓流量，不要只浏览不操作。"
                )

            yield {
                "type": "browse_worker_thinking",
                "worker": self.worker_id,
                "group": self.group["name"],
                "round": round_num,
            }

            try:
                messages = self.context.get_messages()
                # ★ 2026-08-05：补 caller 埋点，此前 77% 的 LLM 调用 caller 为空无法追踪
                response = await asyncio.to_thread(
                    self.llm.chat, messages, worker_tools,
                    caller=f"browse:{self.worker_id}"
                )
            except Exception as e:
                yield {
                    "type": "browse_worker_error",
                    "worker": self.worker_id,
                    "error": str(e),
                }
                break

            self.context.add_assistant(response)

            # ★ checklist 进度检测：如果 LLM 回复中包含 ✅，说明在推进任务
            if response.content and "✅" in response.content:
                new_done = response.content.count("✅")
                if new_done > 0:
                    _checklist_done_count += new_done
                    _last_checklist_progress_round = round_num

            if response.reasoning_content:
                yield {
                    "type": "browse_worker_reasoning",
                    "worker": self.worker_id,
                    "content": response.reasoning_content[:200],
                }

            if response.content:
                yield {
                    "type": "browse_worker_message",
                    "worker": self.worker_id,
                    "content": response.content[:300],
                }

            if response.tool_calls:
                for tc in response.tool_calls:
                    func_name = tc["function"]["name"]
                    args, _args_failed = parse_tool_call_arguments(
                        tc["function"]["arguments"], caller="browse_worker")

                    # 重复检测
                    tool_sig = f"{func_name}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"
                    if tool_sig == _last_tool_sig:
                        _repeat_count += 1
                    else:
                        _last_tool_sig = tool_sig
                        _repeat_count = 1

                    if _repeat_count >= REPEAT_TOOL_THRESHOLD:
                        self.context.add_tool_result(tc["id"],
                            f"⚠️ 连续 {_repeat_count} 次相同操作，已中断。换一种方式或跳到下一个。")
                        _repeat_count = 0
                        _last_tool_sig = ""
                        continue

                    # phase_complete = 本组完成
                    if func_name == "phase_complete":
                        self.ledger.mark_phase_complete()
                        self.context.add_tool_result(
                            tc["id"],
                            f"✅ 本组操作完成\n机器账本：{self.ledger.progress_summary()}"
                        )
                        completed = True
                        break

                    # 不允许 done（只有主 Agent 能调）
                    if func_name == "done":
                        self.context.add_tool_result(tc["id"],
                            "你是子 Agent，请用 phase_complete 结束本组任务")
                        continue

                    # 不允许 sitemap_add_feature（由主 Agent 统一处理）
                    if func_name == "sitemap_add_feature":
                        self.context.add_tool_result(tc["id"],
                            "功能点由主 Agent 统一添加，你只需操作页面抓流量。继续下一个操作。")
                        continue

                    # 执行工具
                    args_brief = json.dumps(args, ensure_ascii=False)[:150]

                    # ★ 为关键操作生成友好的日志摘要
                    friendly_desc = f"{func_name}({args_brief})"
                    if func_name == "browser_click":
                        selector = args.get("selector", args.get("text", ""))
                        friendly_desc = f"点击: {selector[:60]}"
                    elif func_name == "browser_fill":
                        selector = args.get("selector", "")
                        value = args.get("value", "")[:20]
                        friendly_desc = f"填写: {selector[:40]} = '{value}'"
                    elif func_name == "browser_goto":
                        url = args.get("url", "")
                        friendly_desc = f"访问: {url[:80]}"
                    elif func_name == "proxy_get_traffic":
                        friendly_desc = "抓取流量"
                    elif func_name == "browser_get_content":
                        friendly_desc = "获取页面内容"
                    elif func_name == "browser_screenshot":
                        friendly_desc = f"截图: {args.get('name', '')}"
                    elif func_name == "browser_evaluate":
                        js = args.get("js_code", "")[:40]
                        friendly_desc = f"执行JS: {js}..."
                    elif func_name == "sitemap_add_feature":
                        friendly_desc = f"添加功能点: {args.get('name', '')}"

                    yield {
                        "type": "browse_worker_tool",
                        "worker": self.worker_id,
                        "tool": friendly_desc,
                    }

                    self.ledger.mark_tool(func_name, args)

                    try:
                        result = await self.tool_executor.execute(func_name, args)
                    except Exception as e:
                        result = f"工具执行出错: {e}"

                    # ★ 自动从流量中提取 API（复用 session.py 的逻辑）
                    if func_name == "proxy_get_traffic" and self.sitemap:
                        self._extract_api_samples(result)

                    # ★ 关键工具结果推送到前端（让用户看到抓到了什么）
                    if func_name == "proxy_get_traffic":
                        if result and "暂无流量" in result:
                            yield {
                                "type": "browse_worker_tool_result",
                                "worker": self.worker_id,
                                "content": "⚠️ 抓取流量为空！浏览器可能未走代理，请检查 mitmproxy 是否正常运行。",
                            }
                        elif result:
                            # 从结果中提取 API URL 列表摘要
                            traffic_lines = result.strip().split("\n")
                            api_urls = []
                            for tl in traffic_lines:
                                tl = tl.strip()
                                # 匹配 [flow_xxx] METHOD URL → STATUS 格式
                                if tl.startswith("[flow_"):
                                    parts = tl.split("]", 1)
                                    if len(parts) > 1:
                                        api_urls.append(parts[1].strip()[:80])
                                # 也匹配纯 METHOD URL 格式
                                elif any(tl.startswith(m + " ") for m in
                                         ("GET", "POST", "PUT", "DELETE", "PATCH")):
                                    api_urls.append(tl[:80])
                            if api_urls:
                                summary = f"📡 抓到 {len(api_urls)} 条流量:\n" + "\n".join(
                                    f"  {u}" for u in api_urls[:8])
                                if len(api_urls) > 8:
                                    summary += f"\n  ... +{len(api_urls) - 8} 条"
                                yield {
                                    "type": "browse_worker_tool_result",
                                    "worker": self.worker_id,
                                    "content": summary,
                                }

                    # ★ 截图完成后推送图片路径给前端
                    if func_name == "browser_screenshot" and result:
                        screenshot_name = args.get("name", "screenshot")
                        yield {
                            "type": "browse_worker_screenshot",
                            "worker": self.worker_id,
                            "name": screenshot_name,
                        }

                    if len(result) > MAX_TOOL_RESULT:
                        result = result[:MAX_TOOL_RESULT] + "\n... (截断)"

                    self.context.add_tool_result(tc["id"], result)
            else:
                # 无工具调用 = LLM 输出纯文本（可能是总结），继续等
                if not response.content:
                    break

            # 上下文压缩
            # ★ 2026-08-05：browse_worker 用更激进的压缩阈值（15轮 vs 默认30轮）
            # 此前 browse_worker 上下文膨胀到 124K（45次100K+调用），严重浪费 input tokens
            if self.context.turn_count >= 15 or self.context.should_compress():
                self.context.compress()

        # 保存 sitemap
        self.sitemap.save()

        yield {
            "type": "browse_worker_done",
            "worker": self.worker_id,
            "group": self.group["name"],
            "rounds": round_num,
            "completed": completed,
            "ledger": self.ledger.stats(),
        }

    def _extract_api_samples(self, traffic_text: str):
        """从 proxy_get_traffic 结果中提取 API 样本（复用 session.py 逻辑）。"""
        import re
        flow_ids = re.findall(r'\[(flow_[a-f0-9]+)\]', traffic_text)
        if not flow_ids:
            return
        try:
            from mcp_servers.proxy_mcp import _store, _load_new_flows
            _load_new_flows()
            for fid in flow_ids:
                flow = _store.get(fid)
                if not flow:
                    continue
                if flow.method.upper() == "CONNECT":
                    continue
                url = flow.url
                static_exts = ('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff', '.ttf', '.map', '.gif')
                if any(url.split('?')[0].lower().endswith(ext) for ext in static_exts):
                    continue
                self.sitemap.add_api(flow.method, url.split("?")[0],
                                     discovered_by="browse_worker")
                self.sitemap.add_api_sample(
                    method=flow.method,
                    url=url,
                    headers=flow.request_headers,
                    body=flow.request_body,
                    status_code=flow.status_code,
                    discovered_by="browse_worker",
                    response_body=flow.response_body,
                    response_headers=getattr(flow, 'response_headers', None) or {},
                    content_type=getattr(flow, 'content_type', '') or '',
                    flow_id=fid,
                    trigger_context={
                        "worker": self.worker_id,
                        "module": self.group.get("name", "") if isinstance(self.group, dict) else "",
                        "tool": "proxy_get_traffic",
                    },
                )
                channels = classify_realtime_flow(
                    method=flow.method,
                    url=url,
                    request_headers=flow.request_headers,
                    request_body=flow.request_body or "",
                    response_headers=getattr(flow, 'response_headers', None) or {},
                    response_body=flow.response_body or "",
                    status_code=flow.status_code,
                    discovered_by="browse_worker",
                )
                if channels:
                    self.sitemap.realtime_channels = dedupe_realtime_channels(
                        getattr(self.sitemap, "realtime_channels", []) + channels
                    )
        except Exception as e:
            log.warning("[%s] 提取 API 样本失败: %s", self.worker_id, e)
