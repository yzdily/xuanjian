"""
AnalyzePhaseMixin — Phase 1 分析相关辅助方法。

方法：
- _maybe_split_analyze: Phase 1 完成时子 Agent 补充分析
- _check_operation_coverage: Phase 1 完成前操作覆盖度量
- _auto_infer_tech_stack: 代码自动推断技术栈和业务类型
- _build_traversal_checklist: 从菜单树生成遍历 checklist
"""

from __future__ import annotations

import json
from typing import AsyncGenerator

from core.sitemap import Priority, CheckResult
from core.log import get_logger

log = get_logger("session.analyze")


class AnalyzePhaseMixin:
    """Phase 1 分析相关辅助方法。"""

    async def _maybe_split_analyze(self) -> AsyncGenerator[str, None]:
        """Phase 1 完成时检查：如果已知 API 很多但功能点覆盖不足，启用子 Agent 补充分析。"""
        from core.analyze_worker import (
            ANALYZE_SPLIT_THRESHOLD, group_apis_by_prefix, run_analyze_workers
        )

        if not self.sitemap:
            return

        # 收集所有已知 API（从 sitemap.apis + 功能点 related_apis 去重）
        all_apis: set[str] = set()
        for key in self.sitemap.apis:
            all_apis.add(key)
        for fp in self.sitemap.features.values():
            for api in fp.related_apis:
                all_apis.add(api)

        # 已有功能点关联的 API
        covered_apis: set[str] = set()
        for fp in self.sitemap.features.values():
            for api in fp.related_apis:
                covered_apis.add(api)

        uncovered = all_apis - covered_apis
        total_features = len(self.sitemap.features)

        log.info("Phase 1 检查: %d 个已知 API, %d 个功能点, %d 个未覆盖 API",
                 len(all_apis), total_features, len(uncovered))

        # 判断是否需要子 Agent 补充
        # 条件：未覆盖 API > 阈值 或 总 API > 阈值且功能点明显偏少
        need_split = False
        apis_to_analyze: list[str] = []

        if len(uncovered) > ANALYZE_SPLIT_THRESHOLD:
            need_split = True
            apis_to_analyze = sorted(uncovered)
            yield self._event("system",
                f"⚠️ 发现 {len(uncovered)} 个 API 未被功能点覆盖（超过阈值 {ANALYZE_SPLIT_THRESHOLD}），"
                f"启用子 Agent 分组分析")
        elif len(all_apis) > ANALYZE_SPLIT_THRESHOLD and total_features < len(all_apis) // 5:
            # API 很多但功能点明显偏少（API:功能点 > 5:1）
            need_split = True
            apis_to_analyze = sorted(all_apis)
            yield self._event("system",
                f"⚠️ {len(all_apis)} 个 API 但只有 {total_features} 个功能点（比例失衡），"
                f"启用子 Agent 分组分析补充")

        if not need_split:
            return

        # 分组
        api_groups = group_apis_by_prefix(apis_to_analyze)
        yield self._event("system",
            f"📋 API 分为 {len(api_groups)} 组:\n" +
            "\n".join(f"  - 「{name}」: {len(apis)} 个 API" for name, apis in api_groups))

        # 并行启动子 Agent
        all_new_features: list[dict] = []
        async for worker_id, features in run_analyze_workers(
            llm=self.llm,
            target_url=getattr(self, "target_url", ""),
            business_info=self.sitemap.business_summary,
            tech_stack=self.sitemap.tech_stack,
            api_groups=api_groups,
            has_credentials=self.has_credentials,
            max_concurrent=3,
        ):
            yield self._event("system",
                f"✅ 子 Agent [{worker_id}] 完成: 识别出 {len(features)} 个功能点")
            all_new_features.extend(features)

        # 汇总：写入 sitemap（去重）
        added = 0
        skipped = 0
        existing_names = {fp.name.lower() for fp in self.sitemap.features.values()}
        for feat in all_new_features:
            name = feat.get("name", "").strip()
            if not name:
                continue

            # 检查是否已有同名功能点
            if name.lower() in existing_names:
                skipped += 1
                continue

            priority_map = {"critical": Priority.CRITICAL, "high": Priority.HIGH,
                            "medium": Priority.MEDIUM, "low": Priority.LOW}
            priority = priority_map.get(feat.get("priority", "medium"), Priority.MEDIUM)

            related_apis = feat.get("related_apis", [])
            if isinstance(related_apis, str):
                related_apis = [related_apis]

            fp = self.sitemap.add_feature(
                name=name,
                description=feat.get("description", ""),
                page_url=feat.get("page_url", ""),
                priority=priority,
                related_apis=related_apis,
                requires_auth=feat.get("requires_auth", True),
                deferred=feat.get("requires_auth", True),
                module=feat.get("module", ""),
            )
            if fp:
                added += 1
                existing_names.add(name.lower())  # 更新去重集合

        self.sitemap.save()
        yield self._event("system",
            f"📊 子 Agent 分析汇总: 新增 {added} 个功能点, 跳过 {skipped} 个重复\n"
            f"当前共 {len(self.sitemap.features)} 个功能点")

    def _check_operation_coverage(self) -> dict:
        """Phase 1 完成前的操作覆盖度量。

        检查维度：
        1. 功能点中有多少关联了 API（有 related_apis 的占比）
        2. 抓到的 API 中写操作（POST/PUT/DELETE）的占比
        3. 功能点平均关联 API 数

        返回: {"blocked": bool, "warnings": list[str], "message": str}
        """
        if not self.sitemap:
            return {"blocked": False, "warnings": [], "message": ""}

        features = [f for f in self.sitemap.features.values() if not f.deferred]
        total_features = len(features)
        if total_features == 0:
            return {"blocked": True, "warnings": [], "message": "⛔ 无功能点"}

        # 维度1：功能点 API 关联率
        with_apis = [f for f in features if f.related_apis]
        api_coverage = len(with_apis) / total_features

        # 维度2：写操作 API 占比
        all_apis = set()
        write_apis = set()
        for f in features:
            for api in f.related_apis:
                all_apis.add(api)
                parts = api.split(" ", 1)
                if len(parts) == 2 and parts[0] in ("POST", "PUT", "DELETE", "PATCH"):
                    write_apis.add(api)
        # 也从 sitemap.api_samples 统计
        for key in self.sitemap.api_samples:
            all_apis.add(key)
            if key.split(" ")[0] in ("POST", "PUT", "DELETE", "PATCH"):
                write_apis.add(key)

        write_ratio = len(write_apis) / max(len(all_apis), 1)

        # 维度3：平均关联 API 数
        total_api_refs = sum(len(f.related_apis) for f in features)
        avg_apis_per_feature = total_api_refs / total_features

        # 评判逻辑
        blocked = False
        warnings = []

        # 硬性拦截：功能点 API 关联率低于 30%
        if api_coverage < 0.3 and total_features > 5:
            blocked = True
            warnings.append(
                f"功能点 API 关联率过低: {len(with_apis)}/{total_features} ({api_coverage:.0%}) 有关联 API。\n"
                "大量功能点没有 related_apis，说明你没有深入操作页面抓取 API。\n"
                "请回到每个菜单页面，执行操作（新增/编辑/删除/搜索），用 proxy_get_traffic 抓取。"
            )

        # 软性警告：写操作占比低于 10%
        if write_ratio < 0.10 and len(all_apis) > 10:
            warnings.append(
                f"⚠️ 写操作 API 占比极低: {len(write_apis)}/{len(all_apis)} ({write_ratio:.0%}) 是 POST/PUT/DELETE。\n"
                "这说明你可能只看了列表页面的 GET 请求，没有点击新增/编辑/删除按钮。\n"
                "子 Agent 需要这些写操作接口来测试越权和注入漏洞。"
            )

        # 软性警告：平均关联 API 数过低
        if avg_apis_per_feature < 1.5 and total_features > 5:
            warnings.append(
                f"⚠️ 功能点平均关联 {avg_apis_per_feature:.1f} 个 API（建议 ≥ 2）。\n"
                "每个菜单页面通常至少有 2-3 个 API（列表查询 + 增删改），数量过少说明操作不够深入。"
            )

        # 构建消息
        stats = (
            f"📊 **操作覆盖度量**:\n"
            f"- 功能点: {total_features} 个, 有 API 关联: {len(with_apis)} 个 ({api_coverage:.0%})\n"
            f"- API 总数: {len(all_apis)}, 写操作: {len(write_apis)} ({write_ratio:.0%})\n"
            f"- 平均每功能点关联 {avg_apis_per_feature:.1f} 个 API\n"
        )
        if blocked:
            message = f"⛔ 操作覆盖不达标，拒绝进入测试阶段：\n\n{stats}\n{''.join(warnings)}"
        elif warnings:
            message = f"{stats}\n{''.join(warnings)}\n\n⚠️ 覆盖质量一般，建议补充操作后再继续。已放行。"
        else:
            message = f"{stats}✅ 覆盖质量良好。"

        return {"blocked": blocked, "warnings": warnings, "message": message}

    def _auto_infer_tech_stack(self) -> None:
        """代码自动推断技术栈和业务类型（LLM 兜底）。"""
        if not self.sitemap:
            return

        tech_hints = []
        biz_hints = []

        # 从 API 路径推断
        api_paths = " ".join(k.lower() for k in self.sitemap.apis.keys())
        feature_texts = " ".join(
            f"{f.name} {f.description}".lower() for f in self.sitemap.features.values()
        )

        # 技术栈推断
        if ".php" in api_paths or "phpsessid" in api_paths:
            tech_hints.append("PHP")
        if "jsessionid" in api_paths or ".do" in api_paths or ".action" in api_paths or "/actuator" in api_paths:
            tech_hints.append("Java/Spring")
        if "connect.sid" in api_paths or "express" in api_paths:
            tech_hints.append("Node.js/Express")
        if "csrfmiddlewaretoken" in feature_texts or "/admin/" in api_paths:
            tech_hints.append("Python/Django")
        if ".aspx" in api_paths or "__viewstate" in feature_texts:
            tech_hints.append(".NET/ASP")
        if "/wp-admin" in api_paths or "/wp-json" in api_paths:
            tech_hints.append("WordPress")
        if "/graphql" in api_paths:
            tech_hints.append("GraphQL")
        if any(k in api_paths for k in ("/api/", "/v1/", "/v2/")):
            tech_hints.append("REST API")

        # 业务类型推断
        if any(k in feature_texts for k in ("订单", "order", "购物", "商品", "cart", "支付", "pay")):
            biz_hints.append("电商/商城")
        if any(k in feature_texts for k in ("登录", "login", "注册", "register")):
            biz_hints.append("Web 应用")
        if any(k in feature_texts for k in ("admin", "管理", "后台", "dashboard")):
            biz_hints.append("管理后台")
        if any(k in feature_texts for k in ("充值", "提现", "钱包", "余额", "transfer")):
            biz_hints.append("金融/支付")
        if any(k in feature_texts for k in ("消息", "评论", "关注", "动态", "社区")):
            biz_hints.append("社交/社区")

        if tech_hints and not self.sitemap.tech_stack:
            self.sitemap.tech_stack = ", ".join(tech_hints)
        if biz_hints and not self.sitemap.business_summary:
            self.sitemap.business_summary = ", ".join(biz_hints)
        elif not self.sitemap.business_summary:
            self.sitemap.business_summary = "Web 应用（自动推断）"

    def _build_traversal_checklist(self, crawl_result: dict) -> str:
        """从爬取结果中的菜单树 API 响应自动生成结构化遍历 checklist。

        将 JSON 菜单树解析为：
        - 每个菜单的名称、路由
        - 每个菜单下的 Tab 列表（menuType='T'）
        - 每个 Tab/菜单下的按钮权限（menuType='F'）

        返回 Markdown 格式的 checklist，直接注入 LLM 上下文。

        ★ 兜底：后端没有菜单 API 时，自动用爬虫产物（CrawledElement）反向构造菜单树。
        """
        # 1. 优先从爬取流量中找菜单树 API 响应
        menu_data = None
        for api in crawl_result.get("api_endpoints", []):
            api_url = api.get("url", "")
            resp_body = api.get("response_body", "")
            if resp_body and any(kw in api_url.lower() for kw in
                ("menu/tree", "menu/user-menu", "menu/list", "menu/nav",
                 "permission/menu", "sys/menu", "system/menu")):
                try:
                    parsed = json.loads(resp_body)
                    data = parsed.get("data", parsed)
                    if isinstance(data, list) and data:
                        # 验证是否真的是菜单树
                        first = data[0] if data else {}
                        if isinstance(first, dict) and any(
                            k in first for k in ("menuType", "menuName", "children", "name", "path")
                        ):
                            menu_data = data
                            break
                except Exception:
                    pass

        # 2. 后端没有菜单 API → 用爬虫产物自动构造
        if not menu_data:
            try:
                from core.browse_worker import build_menu_tree_from_crawl
                menu_data = build_menu_tree_from_crawl(crawl_result)
            except Exception as e:
                log.warning("build_menu_tree_from_crawl 失败: %s", e)

        if not menu_data:
            # 实在构造不出来 → 返回通用 checklist
            return (
                "### 遍历 Checklist\n\n"
                "未从爬取流量中找到菜单树 API，且爬虫数据不足。请手动操作：\n"
                "1. 先用 `browser_evaluate` 获取侧边栏所有菜单项\n"
                "2. 把菜单列表打印出来作为 checklist\n"
                "3. 逐个执行上面的「标准操作流程」\n"
            )

        # 2. 递归解析菜单树，生成结构化 checklist
        lines = ["### 遍历 Checklist（从菜单树 API 自动生成）\n"]
        lines.append("按以下清单逐个操作，每完成一个打 ✅：\n")

        menu_idx = 0

        def _parse_menu(node: dict, depth: int = 0):
            nonlocal menu_idx
            name = node.get("name", "") or node.get("menuName", "") or node.get("title", "")
            menu_type = node.get("menuType", "C")
            path = node.get("path", "")
            meta = node.get("meta", {}) or {}
            children = node.get("children", []) or []
            tabs = meta.get("tabs", []) if isinstance(meta, dict) else []

            if not name:
                return

            indent = "  " * depth

            if menu_type == "M":
                # 一级菜单（目录）
                lines.append(f"\n{indent}**📂 {name}** (path: {path})")
                for child in children:
                    _parse_menu(child, depth + 1)

            elif menu_type == "C":
                # 具体页面（有路由组件）
                menu_idx += 1
                component = node.get("component", "")
                tab_count = len(tabs)
                btn_count = sum(
                    len(tab.get("buttons", []))
                    for tab in tabs
                ) if tabs else 0

                tab_hint = f" | {tab_count} 个 Tab" if tab_count > 0 else ""
                btn_hint = f" | {btn_count} 个按钮权限" if btn_count > 0 else ""

                lines.append(f"{indent}⬜ **[{menu_idx}] {name}**{tab_hint}{btn_hint}")

                # 列出每个 Tab
                if tabs:
                    for tab in tabs:
                        tab_name = tab.get("name", "")
                        tab_perms = tab.get("perms", "")
                        buttons = tab.get("buttons", [])
                        btn_names = [b.get("name", "") for b in buttons if b.get("name")]
                        btn_str = f" → 按钮: {', '.join(btn_names)}" if btn_names else ""
                        lines.append(f"{indent}  - Tab: **{tab_name}**{btn_str}")

                # 没有 Tab 的子页面也可能有 children（如子菜单）
                for child in children:
                    _parse_menu(child, depth + 1)

        for node in menu_data:
            _parse_menu(node)

        lines.append(f"\n**共 {menu_idx} 个页面需要操作。**\n")
        lines.append(
            "⚠️ 每个 Tab 都必须点击切换 + proxy_get_traffic。\n"
            "⚠️ 按钮权限（如「新增规则」「删除」「导出」）提示了该页面有哪些操作，尽量都点一遍。\n"
            "⚠️ 操作完一个页面后输出：`✅ [N/总数] 菜单名 → X个API（含N个写操作）`\n"
        )

        return "\n".join(lines)
