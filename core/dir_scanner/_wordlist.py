"""DirectoryScanner 技术栈感知字典构建 — 从 core/dir_scanner.py 抽取，行为不变。"""

from __future__ import annotations

from ._constants import (
    DEFAULT_WORDLIST,
    UNIVERSAL_PATHS,
    JAVA_PATHS,
    PHP_PATHS,
    DOTNET_PATHS,
    NODE_PATHS,
    PYTHON_PATHS,
    STATIC_RESOURCE_PATHS,
    API_PRIORITY_KEYWORDS,
    _TECH_PATH_MAP,
)


def build_tech_aware_wordlist(
    tech_stack: str = "",
    is_spa: bool = False,
    extra_paths: list[str] | None = None,
) -> list[str]:
    """根据技术栈和 SPA 标志构建定向字典。

    策略:
    1. 始终包含 UNIVERSAL_PATHS（API 文档/配置/调试/元信息）
    2. 根据 tech_stack 字符串匹配，追加对应技术栈专属路径
    3. SPA 站点排除 STATIC_RESOURCE_PATHS（会被 catch-all 返回 index.html）
    4. 无法识别技术栈时回退到 DEFAULT_WORDLIST 全量（保持兼容）
    5. extra_paths 始终追加

    Args:
        tech_stack: 技术栈描述字符串，如 "Java/Spring, REST API"
        is_spa: 是否为 SPA 单页应用
        extra_paths: 额外追加的路径

    Returns:
        去重保序的路径列表，API 优先路径排在前面
    """
    if not tech_stack and not is_spa:
        # 无技术栈信息 → 回退到全量默认字典
        wl = list(DEFAULT_WORDLIST)
    else:
        wl = list(UNIVERSAL_PATHS)
        ts_lower = (tech_stack or "").lower()
        matched_tech = False
        for keywords, paths in _TECH_PATH_MAP:
            if any(kw in ts_lower for kw in keywords):
                wl.extend(paths)
                matched_tech = True
        # 未匹配到任何已知技术栈 → 追加所有技术栈路径（保守策略）
        if not matched_tech and tech_stack:
            wl.extend(JAVA_PATHS)
            wl.extend(PHP_PATHS)
            wl.extend(DOTNET_PATHS)
            wl.extend(NODE_PATHS)
            wl.extend(PYTHON_PATHS)

    if extra_paths:
        wl.extend(extra_paths)

    # 去重保序
    seen: set[str] = set()
    deduped: list[str] = []
    for w in wl:
        w = w.strip().lstrip("/")
        if w and w not in seen:
            seen.add(w)
            deduped.append(w)

    # SPA 站点排除静态资源路径
    if is_spa:
        deduped = [
            w for w in deduped
            if w.lower() not in STATIC_RESOURCE_PATHS
        ]

    # API 优先路径排前
    api_paths = [w for w in deduped if _is_api_priority(w)]
    other_paths = [w for w in deduped if not _is_api_priority(w)]
    return api_paths + other_paths


def _is_api_priority(word: str) -> bool:
    """判断路径是否为 API 优先（应先于静态/通用路径探测）。"""
    w_lower = word.lower()
    return any(kw in w_lower for kw in API_PRIORITY_KEYWORDS)

