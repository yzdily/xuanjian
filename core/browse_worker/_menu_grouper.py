"""菜单树分组 — 按 Tab 总量均衡分组 + 生成结构化 checklist。

★ 本模块由原 core/browse_worker.py 拆分而来，所有公开/私有名保持兼容。
"""

from __future__ import annotations

from ._menu_parser import (
    _page_name_from_url,
    MAX_TABS_PER_GROUP,
    TARGET_TABS_PER_GROUP,
    MIN_TABS_PER_GROUP,
)


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
