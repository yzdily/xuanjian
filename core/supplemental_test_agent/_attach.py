"""SupplementalTestAgent — L2 挂载层。

把新发现的 API 挂载到 sitemap：优先挂到 path 前缀最相似的现有 feature，
找不到才新建 feature。包含 attach_apis_to_sitemap 及相关辅助函数。
从原 core/supplemental_test_agent.py 抽取，行为不变。
"""

from __future__ import annotations

from urllib.parse import urlparse

from core.log import get_logger
from core.sitemap import Sitemap, Priority

from ._discovery import _DiscoveredAPI

log = get_logger("supplemental")


# ============================================================
# L2: 挂载新 API 到 sitemap（优先挂现有 feature，找不到才建新的）
# ============================================================

def attach_apis_to_sitemap(
    sitemap: Sitemap,
    apis: list[_DiscoveredAPI],
) -> tuple[list, list]:
    """把新 API 挂载到 sitemap。

    Returns:
        (new_features, attached_features)：分别是新建的 feature 列表和挂到现有 feature 上的列表。
    """
    new_features = []
    attached_features = []

    for api in apis:
        api_str = f"{api.method} {api.url.split('?')[0]}"
        attached_to = _find_best_matching_feature(sitemap, api)
        if attached_to is not None:
            # 挂到现有 feature
            if api_str not in attached_to.related_apis:
                attached_to.related_apis.append(api_str)
                attached_features.append((attached_to, api))
            # 也记录到 sitemap.apis（供 packet_merger 等模块识别）
            try:
                sitemap.add_api(api.method, api.url.split("?")[0], discovered_by="phase2_flow")
            except Exception:
                pass
            continue

        # 新建 feature
        name = _gen_feature_name(api)
        desc = _gen_feature_desc(api)
        try:
            fp = sitemap.add_feature(
                name=name,
                description=desc,
                page_url=f"{api.method} {api.host}{api.path}",
                priority=Priority.MEDIUM,
                related_apis=[api_str],
                requires_auth=True,
                module="补测发现",
            )
            if fp is not None:
                # 加 tag 便于报告区分
                try:
                    fp.findings.append("[supplemental] 由 Phase 2.55 补测 Agent 发现")
                except Exception:
                    pass
                new_features.append(fp)
                # 也记录到 sitemap.apis
                try:
                    sitemap.add_api(api.method, api.url.split("?")[0], discovered_by="phase2_flow")
                except Exception:
                    pass
        except Exception as e:
            log.warning("supplemental: 新建 feature 失败: %s（API: %s）", e, api.key)

    try:
        sitemap.save()
    except Exception:
        pass

    return new_features, attached_features


def _find_best_matching_feature(sitemap: Sitemap, api: _DiscoveredAPI):
    """找 path 前缀最相似的 feature。

    匹配规则：
      - 候选 feature 必须有 related_apis
      - 比较 api.path 和 fp.related_apis 中每个 api 的 path
      - 共同前缀段数 >= 2 即认为相似（如 /api/users/1 vs /api/users/list 共享 /api/users）
      - 取共同段最多的 feature
    """
    api_segments = [s for s in api.path.split("/") if s]
    if len(api_segments) < 2:
        return None

    best_feature = None
    best_score = 1  # 至少要有 2 段共同前缀

    for fp in (sitemap.features or {}).values():
        for related in (fp.related_apis or []):
            try:
                related_url = related.split(" ", 1)[-1] if " " in related else related
                related_path = urlparse(related_url).path or related_url
                related_segments = [s for s in related_path.split("/") if s]
                # 计算共同前缀长度
                common = 0
                for a, b in zip(api_segments, related_segments):
                    if a == b:
                        common += 1
                    else:
                        break
                if common > best_score:
                    best_score = common
                    best_feature = fp
            except Exception:
                continue

    return best_feature


def _gen_feature_name(api: _DiscoveredAPI) -> str:
    """从 API 生成功能点名称（使用完整 path 避免不同前缀路径碰撞）。

    原逻辑取 path 最后两段，导致 /.svn/entries 和 /console/.svn/entries
    生成相同名称 "GET /.svn/entries"，被 add_feature 去重逻辑错误合并。
    """
    return f"{api.method} {api.path}"


def _gen_feature_desc(api: _DiscoveredAPI) -> str:
    """从 API 生成功能点描述。"""
    parts = [
        f"补测发现的新 API（{api.method} {api.host}{api.path}）",
        f"首次响应: HTTP {api.status_code}",
    ]
    if api.content_type:
        parts.append(f"Content-Type: {api.content_type.split(';')[0]}")
    if api.response_body_preview:
        preview = api.response_body_preview[:80].replace("\n", " ")
        parts.append(f"响应预览: {preview}")
    return "；".join(parts)


def _normalize_related_api_for_scan(api_ref: str, target_url: str) -> tuple[str, str] | None:
    """把 feature.related_apis 里的条目规范成 (method, url)。

    related_apis 常见格式包括：
      - "GET https://example.com/api/user"
      - "POST /api/user"
      - "https://example.com/api/user"
      - "/api/user"

    本地补测此前只判断字符串是否以 http 开头，导致
    "GET https://..." 被拼成 "https://target/GET https://..."，
    FastScanner 实际收到非法 URL。这里统一拆出 method 和 URL。
    """
    raw = (api_ref or "").strip()
    if not raw:
        return None

    method = "GET"
    url_part = raw
    if " " in raw:
        first, rest = raw.split(" ", 1)
        if first.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = first.upper()
            url_part = rest.strip()

    if not url_part:
        return None

    parsed = urlparse(url_part)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return method, url_part

    if url_part.startswith("//"):
        scheme = urlparse(target_url).scheme or "http"
        return method, f"{scheme}:{url_part}"

    if not target_url:
        return None

    base = target_url.rstrip("/")
    if not url_part.startswith("/"):
        url_part = "/" + url_part
    return method, f"{base}{url_part}"
