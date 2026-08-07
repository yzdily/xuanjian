"""表单接口桥接 — 把爬虫发现但未提交的表单 action 注册为可测 API。

匿名 / fast 爬取不会真正提交表单，因此登录等表单的提交接口
（``form.action``）只被记录为 ``CrawledForm``，未进入 ``api_endpoints``，
导致 FastScanner 永远测不到它。此桥接把"发现但未提交"的表单 action
注册为 sitemap 的可测 API，让 fast 模式也能覆盖登录等高危接口。

设计要点（对齐 REDESIGN 可测性目标）：
- 纯函数 + 显式依赖（sitemap / crawl_result / target_url 全传入），零全局副作用。
- 可 100% 单测：用假 sitemap + 假 crawl_result 即可验证。
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

# 非业务 / 非 HTTP 的 action 直接跳过
_SKIP_PREFIXES = ("javascript:", "mailto:", "tel:", "data:", "blob:")


def _is_testable_action(action: str) -> bool:
    a = (action or "").strip()
    if not a:
        return False
    if a in ("#", "javascript:", "javascript:void(0)", "void(0)"):
        return False
    low = a.lower()
    if any(low.startswith(p) for p in _SKIP_PREFIXES):
        return False
    return True


def register_form_apis(
    sitemap: Any,
    crawl_result: dict,
    target_url: str = "",
    max_forms: int = 50,
) -> list[str]:
    """把"未提交"表单的 action 注册为可测 API。

    Args:
        sitemap: 目标 sitemap（需有 ``add_api`` / ``add_api_sample`` / ``apis``）。
            传 ``None`` 时只做计算、不写 side-effect（便于纯计算场景）。
        crawl_result: 爬虫结果，需含 ``forms``（可含 ``api_endpoints`` 用于去重）。
        target_url: 用于解析相对 action 的基址（通常取发现该表单的页面 URL）。
        max_forms: 单次最多补登的表单数，避免极端页面产生海量 action。

    Returns:
        新增的 ``"METHOD url"`` 列表（已去重、已过滤非业务 action）。
    """
    added: list[str] = []
    forms = crawl_result.get("forms", []) or []
    existing_apis = crawl_result.get("api_endpoints", []) or []

    exist_keys = {(a.get("method"), a.get("url")) for a in existing_apis}
    sitemap_apis = getattr(sitemap, "apis", None) or {}

    for f in forms:
        # 已提交的表单其请求已在 api_endpoints 中，跳过避免重复
        if f.get("submitted") or (f.get("requests_triggered") or 0) > 0:
            continue
        action = f.get("action") or ""
        if not _is_testable_action(action):
            continue

        page_url = f.get("page") or target_url or ""
        try:
            abs_url = urljoin(page_url, action)
        except Exception:
            continue
        if not abs_url.startswith(("http://", "https://")):
            continue

        method = (f.get("method") or "POST").upper()
        if (method, abs_url) in exist_keys:
            continue
        if any(
            getattr(e, "method", None) == method and getattr(e, "url", None) == abs_url
            for e in sitemap_apis.values()
        ):
            continue

        if sitemap is not None:
            sitemap.add_api(method, abs_url, discovered_by="form_inference")
            fields = [i for i in (f.get("fields") or []) if i]
            if fields:
                post_data = "&".join(f"{name}=" for name in fields)
                try:
                    sitemap.add_api_sample(
                        method=method,
                        url=abs_url,
                        headers={},
                        body=post_data,
                        status_code=0,
                        discovered_by="form_inference",
                        response_body="",
                        response_headers={},
                        content_type="application/x-www-form-urlencoded",
                        js_context="",
                        flow_id="",
                        trigger_context={"form_action": action, "form_page": page_url},
                    )
                except Exception:
                    pass

        added.append(f"{method} {abs_url}")
        if len(added) >= max_forms:
            break

    return added
