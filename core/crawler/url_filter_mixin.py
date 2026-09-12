"""
UrlFilterMixin — URL 队列治理：去重 / 模式聚类 / seed URL 抓取 / 占位符回填。

包含的方法：
- _is_duplicate_id_page    : 判断是否已大量入队的列表详情子页
- _get_seed_urls           : 从 robots.txt + sitemap.xml 抓种子 URL
- _collect_placeholder_routes : 收集带占位符的路由模板（如 /user/{id}、/edit/:id）
- _backfill_with_ids       : 用真实 ID 池回填占位符路由

注意：本 mixin 不包含 _normalize_url —— 它和 self._is_spa 强耦合，留在主类中。
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


class UrlFilterMixin:
    """URL 治理 mixin。"""

    def _is_duplicate_id_page(self, url: str, visited: set, max_per_pattern: int = 3) -> bool:
        """判断 URL 是否是已大量入队的列表详情子页，防止耗光页面配额。

        策略：把路径中的纯数字/UUID 段替换为 {id}，生成路径模式。
        同一模式超过 max_per_pattern 次则跳过。
        例：/users/975966309/accounts → /users/{id}/accounts（模式）
        """
        try:
            from urllib.parse import urlparse as _up
            path = _up(url).path
            # 把纯数字段和 UUID 替换为 {id}
            import re as _re
            pattern = _re.sub(
                r'/([0-9]{4,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
                r'/{id}',
                path,
                flags=_re.IGNORECASE
            )
            # 没有 ID 段，不过滤
            if '{id}' not in pattern:
                return False
            count = self._id_page_pattern_count.get(pattern, 0)
            if count >= max_per_pattern:
                return True
            self._id_page_pattern_count[pattern] = count + 1
            return False
        except Exception:
            return False

    async def _get_seed_urls(self, page) -> list[str]:
        """从 robots.txt 和 sitemap.xml 获取种子 URL。
        
        使用 httpx 独立请求，不破坏当前 page 的浏览器状态（SPA 登录态/路由状态）。
        """
        import httpx

        seeds = []
        base = f"{urlparse(self.target).scheme}://{self.target_domain}"

        # 尝试从 page 的 cookie 中获取认证信息（如果已登录）
        headers = {"User-Agent": "Mozilla/5.0 (compatible; AutoCrawler/1.0)"}
        try:
            browser_cookies = await page.context.cookies()
            if browser_cookies:
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in browser_cookies)
                headers["Cookie"] = cookie_str
        except Exception:
            pass

        async with httpx.AsyncClient(
            timeout=5.0, verify=False, follow_redirects=True, headers=headers
        ) as client:
            for path in ["/robots.txt", "/sitemap.xml"]:
                try:
                    resp = await client.get(base + path)
                    if resp.status_code == 200:
                        text = resp.text
                        # 提取 URL
                        urls = re.findall(r'https?://[^\s<>"\']+', text)
                        # 提取 Disallow 路径
                        disallows = re.findall(r'Disallow:\s*(/\S+)', text)
                        for d in disallows:
                            seeds.append(base + d)
                        seeds.extend(urls)
                except Exception:
                    pass

        return [u for u in seeds if self._is_in_scope(u)]

    def _collect_placeholder_routes(self, spa_routes: list, menu_paths: set, result) -> list[str]:
        """收集所有"带占位符"的路由模板（包含 :id、{id}、/edit、/detail 等）。

        来源：
        - SPA Router 提取的路由（如 /user/:id）
        - 菜单 API 返回的 path（如 /system/user/edit/{id}）
        - 已爬取页面里的 a[href] 模板（如 /detail.html?id=）
        - js_analysis.routes 提取出来的路由
        """
        candidates: set[str] = set()

        # 1. SPA 路由
        for r in (spa_routes or []):
            if r and (":" in r or "{" in r or "/edit" in r or "/detail" in r or "/view" in r or "/info" in r):
                candidates.add(r)

        # 2. 菜单 API 路径
        for p in (menu_paths or set()):
            if p and (":" in p or "{" in p or "/edit" in p or "/detail" in p or "/view" in p):
                candidates.add(p)

        # 3. JS 分析提取的路由
        try:
            js_a = getattr(result, "js_analysis", None)
            if js_a and getattr(js_a, "routes", None):
                for r in js_a.routes:
                    rp = getattr(r, "path", None) or (r.get("path") if isinstance(r, dict) else None)
                    if rp and (":" in rp or "{" in rp or "/edit" in rp or "/detail" in rp):
                        candidates.add(rp)
        except Exception:
            pass

        return list(candidates)

    def _backfill_with_ids(
        self,
        placeholder_routes: list[str],
        id_pool: dict[str, set[str]],
        base_no_hash: str,
        visited: set,
    ) -> list[str]:
        """用 id_pool 中的 ID 回填占位符路由，每个模板最多生成 3 个 URL（最大ID + 最小ID + 兜底"1"）。"""
        import re as _re

        backfilled: list[str] = []
        seen: set[str] = set()

        # 把所有 ID 池里的 id 按"路径前缀"建索引
        # 同时建一个"全局 id 集合"用于兜底
        all_ids: set[str] = set()
        for ids in id_pool.values():
            all_ids.update(ids)

        def _pick_ids(template: str) -> list[str]:
            """从 id_pool 中找最匹配此 template 的 ID。"""
            # 1. 先找前缀完全匹配的
            template_prefix = template.rstrip("/").split(":")[0].split("{")[0].rstrip("/")
            best_ids: set[str] = set()
            for prefix, ids in id_pool.items():
                if template_prefix and (prefix.endswith(template_prefix) or template_prefix.endswith(prefix)):
                    best_ids.update(ids)
            # 2. fallback：用全部 ID
            if not best_ids:
                best_ids = all_ids
            # 3. 选 max + min + 1 兜底
            picked: list[str] = []
            numeric = sorted([int(i) for i in best_ids if i.isdigit()])
            if numeric:
                picked.append(str(numeric[-1]))  # 最大
                if len(numeric) > 1:
                    picked.append(str(numeric[0]))  # 最小
            # 加一个非数字 ID（如 UUID）样本
            non_numeric = [i for i in best_ids if not i.isdigit()]
            if non_numeric:
                picked.append(non_numeric[0])
            # 兜底 "1"
            if "1" not in picked:
                picked.append("1")
            return picked[:3]

        for template in placeholder_routes:
            ids = _pick_ids(template)
            for id_val in ids:
                # 替换 :id / {id} / :xxxId / {xxxId}
                filled = _re.sub(r":[a-zA-Z_][a-zA-Z0-9_]*", id_val, template)
                filled = _re.sub(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}", id_val, filled)
                # 拼成完整 URL
                if self._is_spa:
                    full_url = f"{base_no_hash}#/{filled.lstrip('/')}"
                else:
                    full_url = f"{base_no_hash}{filled if filled.startswith('/') else '/' + filled}"
                # 如果模板里没占位符（如 /admin/user/edit），尾部追加 ID
                if filled == template and not template.endswith("/"):
                    # 模板是 /admin/user/edit 这种没占位符的形式，给它追加 /{id}
                    full_url_with_id = f"{full_url.rstrip('/')}/{id_val}"
                    if full_url_with_id not in seen:
                        seen.add(full_url_with_id)
                        backfilled.append(full_url_with_id)
                    # 同时尝试 ?id= 形式
                    qsep = "&" if "?" in full_url else "?"
                    full_url_with_qs = f"{full_url}{qsep}id={id_val}"
                    if full_url_with_qs not in seen:
                        seen.add(full_url_with_qs)
                        backfilled.append(full_url_with_qs)
                else:
                    if full_url not in seen:
                        seen.add(full_url)
                        backfilled.append(full_url)

        return backfilled

