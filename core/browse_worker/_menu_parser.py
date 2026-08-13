"""菜单树解析 — 从爬取结果中提取并归一化菜单树。

★ 本模块由原 core/browse_worker.py 拆分而来，所有公开/私有名保持兼容。
"""

from __future__ import annotations

import json

from core.log import get_logger

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
            from ._menu_grouper import _get_auth_token
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
