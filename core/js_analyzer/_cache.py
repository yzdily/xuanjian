"""JS Analyzer 源码缓存 & API 定位 — 从 js_analyzer.py 抽取，行为不变。

供推测 API 参数构造使用：按 target（站点 base_url）分桶缓存 JS 源码，
任务结束应调用 clear_js_cache(target) 主动释放。
"""

from __future__ import annotations

from urllib.parse import urlparse

from core.log import get_logger

log = get_logger("js_analyzer")

# ★ 按 target（站点 base_url）分桶的缓存：
#   {target_key: {js_url: js_text}}
# 不同目标的 JS 完全隔离，避免跨任务串扰。
# 任务结束应调用 clear_js_cache(target) 主动释放。
_js_source_cache: dict[str, dict[str, str]] = {}

# 单 target 缓存大小上限（防止单任务的 JS 也撑爆内存 / 拖慢搜索）
_MAX_CACHE_BYTES_PER_TARGET = 50 * 1024 * 1024  # 50MB
# 全局 target 数量上限（防止长跑进程目标列表无限增长）
_MAX_TARGETS_IN_CACHE = 5


def _normalize_target_key(target: str) -> str:
    """把 target 归一化为缓存桶 key（取 scheme+host，忽略 path/query）。"""
    if not target:
        return "__default__"
    try:
        p = urlparse(target)
        if p.netloc:
            return f"{p.scheme or 'http'}://{p.netloc}".lower()
    except Exception:
        pass
    return target.lower()


def cache_js_sources(js_contents: list[tuple[str, str]], target: str = "") -> None:
    """缓存 JS 文件内容（由 analyze_page_js 调用）。

    Args:
        js_contents: [(js_url, js_text), ...]
        target: 站点 base_url，用作缓存桶 key。同一 target 的 JS 共享缓存，
                不同 target 完全隔离，避免跨任务串扰。
    """
    target_key = _normalize_target_key(target)

    # ★ LRU：限制 target 数量，超出时淘汰最早访问的
    if target_key not in _js_source_cache and len(_js_source_cache) >= _MAX_TARGETS_IN_CACHE:
        # 简化策略：丢掉第一个（dict 保持插入顺序）
        oldest = next(iter(_js_source_cache))
        log.info("JS 缓存达上限（%d 个 target），淘汰最早的: %s",
                 _MAX_TARGETS_IN_CACHE, oldest)
        _js_source_cache.pop(oldest, None)

    bucket = _js_source_cache.setdefault(target_key, {})

    # 写入新内容（同 url 覆盖，等价于刷新）
    for url, text in js_contents:
        if text and len(text) > 50:
            bucket[url] = text

    # ★ 单 target 容量超限：按"最大文件优先丢弃"策略压回上限内
    #   理由：单个超大 JS（vendor/framework）通常匹配价值低，先丢它
    total_bytes = sum(len(t) for t in bucket.values())
    if total_bytes > _MAX_CACHE_BYTES_PER_TARGET:
        # 按文件大小降序，逐个丢弃直到达标
        items_by_size = sorted(bucket.items(), key=lambda kv: -len(kv[1]))
        for url, text in items_by_size:
            if total_bytes <= _MAX_CACHE_BYTES_PER_TARGET:
                break
            bucket.pop(url, None)
            total_bytes -= len(text)
        log.info("JS 缓存超过 %dMB 上限（target=%s），已驱逐大文件至 %dKB",
                 _MAX_CACHE_BYTES_PER_TARGET // (1024 * 1024),
                 target_key, total_bytes // 1024)

    log.info("JS 源码缓存 [%s]: %d 个文件, 总 %dKB（全局 %d 个 target）",
             target_key, len(bucket),
             sum(len(t) for t in bucket.values()) // 1024,
             len(_js_source_cache))


def clear_js_cache(target: str = "") -> int:
    """清理 JS 缓存。任务结束时应主动调用以释放内存。

    Args:
        target: 指定目标则只清该 target 的缓存；留空则全清。

    Returns:
        清理掉的文件数量。
    """
    if target:
        target_key = _normalize_target_key(target)
        bucket = _js_source_cache.pop(target_key, {})
        n = len(bucket)
        if n:
            log.info("已清理 JS 缓存 [%s]: %d 个文件", target_key, n)
        return n

    n = sum(len(b) for b in _js_source_cache.values())
    _js_source_cache.clear()
    if n:
        log.info("已清理全部 JS 缓存: %d 个文件", n)
    return n


def get_js_cache_stats() -> dict:
    """返回当前缓存统计（用于诊断 / 监控）。"""
    return {
        "targets": len(_js_source_cache),
        "files_total": sum(len(b) for b in _js_source_cache.values()),
        "bytes_total": sum(len(t) for b in _js_source_cache.values() for t in b.values()),
        "by_target": {
            tk: {
                "files": len(b),
                "bytes": sum(len(t) for t in b.values()),
            }
            for tk, b in _js_source_cache.items()
        },
    }


def locate_api_in_js(api_path: str, context_lines: int = 40, target: str = "") -> str:
    """在缓存的 JS 源码中定位 API path 的调用位置，返回上下文代码。

    Args:
        api_path: API 路径，如 "/api/user/update" 或 "user/update"，
                  也可以是完整 URL（会自动从中解析 path）
        context_lines: 提取匹配位置前后各多少行
        target: 限制只在指定目标的缓存桶中搜索（强烈建议传，避免跨任务串扰）。
                留空则按以下顺序兜底：
                1. 如果 api_path 是完整 URL，用它的 host 作为 target
                2. 否则在所有桶里搜（仅兼容旧调用，不推荐）

    Returns:
        匹配到的 JS 上下文代码（带文件来源标注），未找到返回空字符串
    """
    # ★ 选择搜索的缓存桶
    if target:
        target_key = _normalize_target_key(target)
        bucket = _js_source_cache.get(target_key, {})
    elif api_path.startswith("http"):
        # 从 api_path 自身的 host 推断 target
        try:
            p = urlparse(api_path)
            target_key = f"{p.scheme}://{p.netloc}".lower()
            bucket = _js_source_cache.get(target_key, {})
        except Exception:
            bucket = {}
    else:
        # 兜底：合并所有桶（仅向后兼容；新代码请显式传 target）
        bucket = {}
        for b in _js_source_cache.values():
            bucket.update(b)

    if not bucket:
        return ""

    # 标准化搜索路径：去掉域名前缀，保留 path 部分
    search_path = api_path
    if "://" in search_path:
        search_path = urlparse(search_path).path
    # 去掉开头的 /，方便模糊匹配
    search_variants = [
        search_path,                          # /api/user/update
        search_path.lstrip("/"),              # api/user/update
    ]
    # 提取 path 的最后两段用于精确匹配
    path_parts = [p for p in search_path.split("/") if p]
    if len(path_parts) >= 2:
        search_variants.insert(1, "/".join(path_parts[-2:]))  # user/update

    # ★ 按文件质量排序：业务 chunk 优先，入口/路由配置文件最后
    sorted_cache = sorted(bucket.items(), key=lambda kv: _file_priority(kv[0]))

    # ★ 低质量上下文检测关键词
    _LOW_QUALITY_MARKERS = (
        "__vite__mapDeps", "__vite__", "mapDeps", "chunkFileNames",
        "manualChunks", "rollupOptions", "assetFileNames",
    )

    results = []

    for js_url, js_text in sorted_cache:
        # 按优先级尝试匹配
        for variant in search_variants:
            if variant not in js_text:
                continue

            # 找到所有匹配位置
            idx = js_text.find(variant)
            # ★ 性能优化：只取第一处匹配（原本 < 3 在 fuzz 场景下被调用 954 次，
            #   每次找 3 处 + while 循环 + 200 字符 nearby 检查 → 累计 CPU 耗尽）
            #   第一处匹配已足够给 LLM 提供 API 调用上下文，多处匹配价值不大
            while idx != -1 and len(results) < 1:
                # ★ 上下文质量检查：匹配位置附近是否是低质量代码
                nearby = js_text[max(0, idx - 200):idx + 200]
                is_low_quality = any(marker in nearby for marker in _LOW_QUALITY_MARKERS)

                if is_low_quality:
                    # 跳过低质量匹配，继续搜索下一个位置
                    idx = js_text.find(variant, idx + len(variant))
                    continue

                # ★ 高效提取行号 + 上下文（避免全文 split）
                start_line, end_line, code_block = _extract_lines_around(
                    js_text, idx, context_lines)

                # ★ 二次质量检查：整个代码块是否有效（含 API 调用模式或参数构造）
                has_api_pattern = any(kw in code_block for kw in
                    ("fetch", "axios", "request", "http", "$ajax", ".get(", ".post(",
                     ".put(", ".delete(", "headers", "params", "body:", "data:"))
                # 如果代码块里全是文件路径列表，判定为低质量
                if not has_api_pattern and code_block.count('"./')  > 5:
                    idx = js_text.find(variant, idx + len(variant))
                    continue

                # 限制单个代码块大小
                if len(code_block) > 4000:
                    code_block = code_block[:4000] + "\n// ... (截断)"

                source_name = js_url.split("/")[-1] if "/" in js_url else js_url
                match_type = "精确匹配" if variant == search_path else "模糊匹配"
                results.append(
                    f"// === 来源: {source_name} (行 {start_line}~{end_line}, {match_type}) ===\n"
                    f"{code_block}"
                )

                # 继续找下一处
                idx = js_text.find(variant, idx + len(variant))

            if results:
                break  # 当前优先级已找到，不再尝试更模糊的

        if results:
            break  # 已在某个文件中找到

    # ★ 已删除最后兜底分支（用 last_segment 做正则全文搜索）：
    #   - 性能：每次失败时要扫所有非框架文件（数百 KB ~ 数 MB），
    #     在 fuzz 场景下 954 次调用 × 多文件 = CPU 雪崩元凶之一
    #   - 收益低：能命中兜底的 path，业务相关性已经很弱（只匹配最后一段），
    #     生成的 JS 上下文经常误导 LLM
    #   - 真业务 API 在前两个 variant（精确/最后两段）就该命中
    return "\n\n".join(results)

# --- hoisted from locate_api_in_js (A-grade, no local capture) ---
def _file_priority(js_url: str) -> int:
    """越小越优先。"""
    name = js_url.lower().split("/")[-1] if "/" in js_url else js_url.lower()
    # 明确的业务组件文件（Vue/React 组件）优先级最高
    if any(kw in name for kw in ("service", "api.", "request", "http", "manage", "view")):
        return 0
    # 普通 chunk 文件
    if name.startswith("chunk-") or name.startswith("async-"):
        return 1
    # 内联脚本
    if name.startswith("inline_"):
        return 2
    # 框架/库文件（搜索价值低）
    if any(kw in name for kw in ("vue-", "react-", "element-plus", "echarts", "ant-design")):
        return 8
    # Vite/Webpack 入口文件（最容易产生低质量匹配）
    if name.startswith("index-") or name.startswith("app-") or name.startswith("main-"):
        return 7
    # 其他
    return 3

# --- hoisted from locate_api_in_js (A-grade, no local capture) ---
def _extract_lines_around(js_text: str, match_idx: int, ctx: int) -> tuple[int, int, str]:
    """高效提取 match_idx 附近的 ±ctx 行，返回 (start_line, end_line, code_block)。

    关键优化：避免 `js_text[:idx].split("\\n")` 这种 O(idx) 内存复制，
    用 `str.count("\\n", 0, idx)` 直接计数；用 rfind/find 定位行边界，
    只对真正需要的窗口做切片。
    """
    # 当前行号（1-based）
    line_num = js_text.count("\n", 0, match_idx) + 1
    start_line = max(1, line_num - ctx)
    end_line = line_num + ctx

    # 找 start_line 在 js_text 中的字节起点：从 match_idx 往回数 (line_num - start_line) 个 \n
    steps_back = line_num - start_line
    pos = match_idx
    for _ in range(steps_back):
        pos = js_text.rfind("\n", 0, pos)
        if pos == -1:
            pos = 0
            break
        # 跳过 '\n' 本身
    start_byte = pos + 1 if pos > 0 else 0

    # 找 end_line 末尾：从 match_idx 往后数 (end_line - line_num) 个 \n
    steps_fwd = end_line - line_num
    pos = match_idx
    for _ in range(steps_fwd):
        nxt = js_text.find("\n", pos + 1)
        if nxt == -1:
            pos = len(js_text)
            break
        pos = nxt
    end_byte = pos

    code_block = js_text[start_byte:end_byte]
    # 修正 end_line（如果遇到 EOF 提前结束）
    if end_byte == len(js_text):
        actual_end_line = start_line + code_block.count("\n")
    else:
        actual_end_line = end_line
    return start_line, actual_end_line, code_block
