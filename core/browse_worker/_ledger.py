"""BrowseTaskLedger — BrowseWorker 机器级任务账本。

★ 本模块由原 core/browse_worker.py 拆分而来，所有公开/私有名保持兼容。
"""

from __future__ import annotations

import json


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
