"""JS Analyzer LLM 增强 — 对关键业务 JS 文件用 LLM 补充正则遗漏的 API。

从 js_analyzer.py 抽取，行为不变。
"""

from __future__ import annotations

import re

from core.log import get_logger
from core.prompts import load_prompt, load_template

from ._models import JSAnalysisResult, JSApiCall

log = get_logger("js_analyzer")

# 关键业务 JS 文件名模式（入口/主业务 bundle）
_KEY_JS_PATTERNS = re.compile(
    r'(?:^|/)'
    r'(?:'
    r'index|main|app|vendor|bundle|chunk-[^/]*'
    r')'
    r'(?:[-.][\w]+)?'  # hash 后缀，如 .e1dfb5981f / -abc123
    r'\.(?:js|mjs)$',
    re.IGNORECASE,
)

# API 相关代码关键词（用于从大文件中提取片段）
_API_CONTEXT_KEYWORDS = (
    "axios", "fetch(", ".get(", ".post(", ".put(", ".delete(", ".patch(",
    "baseURL", "BASE_URL", "apiBase", "apiPrefix", "apiUrl",
    "request(", "http(", "XMLHttpRequest",
    "interceptor", "Authorization", "Bearer",
    "router", "routes", "path:",
)


def _is_key_business_js(js_url: str, js_text: str) -> bool:
    """判断 JS 文件是否是关键业务 JS（需要 LLM 分析）。

    条件：
    1. 文件名匹配入口模式（main.js / index.js / app.js 等）
    2. 文件大小 > 50KB（排除 tracker/pixel 类小文件）
    3. 不是第三方库（排除 vue/react/echarts 等）
    """
    # 从 URL 提取文件名
    name = js_url.split("/")[-1].split("?")[0].lower()

    # 第三方库黑名单（文件名中包含这些关键词的不分析）
    _LIB_KEYWORDS = (
        "vue.", "vuex", "vue-router", "react.", "react-dom", "redux",
        "angular", "rxjs", "zone.js", "echarts", "chart", "d3.",
        "lodash", "underscore", "moment", "dayjs", "axios.js",
        "element-plus", "ant-design", "el-", "iview",
        "polyfill", "core-js", "regenerator", "babel",
        "sentry", "firebase", "amplitude", "mixpanel",
        "hotjar", "clarity", "google-analytics", "gtag",
        "recaptcha", "facebook", "beacon",
    )
    for kw in _LIB_KEYWORDS:
        if kw in name:
            return False

    # 必须匹配入口模式
    if not _KEY_JS_PATTERNS.search(js_url.split("?")[0]):
        return False

    # 大小下限
    if len(js_text) < 50_000:  # 50KB
        return False

    return True


def _extract_api_chunks(js_text: str, max_total_chars: int = 30_000) -> list[str]:
    """从大 JS 文件中提取与 API 调用相关的代码片段。

    策略：找到每个 API 关键词的位置，提取其前后 ±2KB 的代码。
    片段之间有重叠的会合并，总大小不超过 max_total_chars。
    """
    CHUNK_RADIUS = 2048  # 每个关键词前后各取 2KB

    # 找到所有关键词位置
    positions = []
    for kw in _API_CONTEXT_KEYWORDS:
        start = 0
        while True:
            idx = js_text.find(kw, start)
            if idx == -1:
                break
            positions.append(idx)
            start = idx + len(kw)
            # 每个关键词最多找 20 个位置（避免 axios 在 vendor bundle 里命中几百次）
            if len(positions) > 200:
                break
        if len(positions) > 200:
            break

    if not positions:
        # 没有找到 API 关键词 → 返回文件头 20KB（入口配置通常在文件头）
        return [js_text[:20_000]] if len(js_text) > 20_000 else [js_text]

    # 去重 + 排序
    positions = sorted(set(positions))

    # 将相邻/重叠的位置合并为区间
    intervals: list[tuple[int, int]] = []
    for pos in positions:
        start = max(0, pos - CHUNK_RADIUS)
        end = min(len(js_text), pos + CHUNK_RADIUS)
        if intervals and start <= intervals[-1][1]:
            # 合并
            intervals[-1] = (intervals[-1][0], end)
        else:
            intervals.append((start, end))

    # 提取片段，控制总大小
    chunks = []
    total = 0
    for start, end in intervals:
        chunk = js_text[start:end]
        if total + len(chunk) > max_total_chars:
            # 截断最后一个片段
            remaining = max_total_chars - total
            if remaining > 1000:
                chunks.append(chunk[:remaining] + "\n// ... (截断)")
            break
        chunks.append(chunk)
        total += len(chunk)

    return chunks if chunks else [js_text[:20_000]]


async def llm_analyze_key_js(
    js_contents: list[tuple[str, str]],
    result: JSAnalysisResult,
    base_url: str,
    llm_chat_fn,
) -> JSAnalysisResult:
    """用 LLM 分析关键业务 JS 文件，补充正则遗漏的 API。

    在 analyze_js()（纯正则）之后调用，对 main.js / index.js / app.js 等关键文件
    进行 LLM 分析。LLM 能理解 minified 代码中的 axios 实例、baseURL 拼接、
    相对路径等正则搞不定的场景。

    Args:
        js_contents: [(js_url, js_text), ...] — 与 analyze_js 相同的输入
        result: analyze_js() 的结果（会被原地增强）
        base_url: 站点基础 URL
        llm_chat_fn: async callable，签名为 async (messages, caller?) -> response
                     response 需要有 .content 属性

    Returns:
        增强后的 JSAnalysisResult（与输入是同一个对象，原地修改）
    """
    import json as _json

    # 1. 识别关键业务 JS 文件
    key_files = [(url, text) for url, text in js_contents if _is_key_business_js(url, text)]

    if not key_files:
        log.info("LLM JS 分析: 未发现关键业务 JS 文件，跳过")
        return result

    # 已有的 API 去重集合（正则结果）
    seen_keys: set[str] = set()
    for api in result.api_calls:
        seen_keys.add(f"{api.method} {api.path}")

    # ★ 2026-08-05：前置过滤——如果正则已提取到足够 API，跳过 LLM 分析节省 token
    # 此前 6 次 LLM 调用有 4 次返回 []（32892:1 的输入输出比），纯浪费
    if len(seen_keys) >= 10:
        log.info("LLM JS 分析: 正则已提取 %d 个 API，跳过 LLM 分析", len(seen_keys))
        return result

    seen_route_keys: set[str] = set()
    for route in result.routes:
        seen_route_keys.add(route.path)

    log.info("LLM JS 分析: 发现 %d 个关键业务 JS 文件，开始 LLM 分析", len(key_files))

    # 2. 逐个分析关键文件
    for js_url, js_text in key_files:
        file_name = js_url.split("/")[-1].split("?")[0]
        log.info("LLM JS 分析: 分析 %s (%dKB)", file_name, len(js_text) // 1024)

        # 提取 API 相关代码片段
        chunks = _extract_api_chunks(js_text)
        combined_code = "\n\n// --- 片段分隔 ---\n\n".join(chunks)

        if len(combined_code) > 30_000:
            combined_code = combined_code[:30_000] + "\n// ... (截断)"

        # 3. 构建 LLM prompt
        prompt = load_template("js_api_extract", file_name=file_name, combined_code=combined_code)

        try:
            from core.llm import Message
            messages = [
                Message(role="system", content=load_prompt("js_analyzer_system")),
                Message(role="user", content=prompt),
            ]
            response = await llm_chat_fn(messages, caller="js_llm_analyze")
            text = (response.content or "").strip()

            # 4. 解析 LLM 返回
            # 剥离 <think>...</think> 推理块
            text = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()
            # 提取 JSON 数组
            json_match = re.search(r'\[[\s\S]*\]', text)
            if not json_match:
                log.warning("LLM JS 分析: %s 未返回有效 JSON，跳过", file_name)
                continue

            apis = _json.loads(json_match.group())

            new_count = 0
            for item in apis:
                method = (item.get("method") or "UNKNOWN").upper()
                path = item.get("path", "").strip()
                reason = item.get("reason", "")

                if not path or len(path) < 3:
                    continue

                # 标准化路径：确保以 / 开头（除非是完整 URL）
                if not path.startswith("/") and not path.startswith("http"):
                    path = "/" + path

                # 去重
                dedup_key = f"{method} {path}"
                if dedup_key in seen_keys:
                    continue

                # 更宽松的去重：path 相同就算（忽略 method 差异，因为 LLM 可能猜错 method）
                path_only_keys = {k.split(" ", 1)[1] for k in seen_keys}
                if path in path_only_keys:
                    continue

                seen_keys.add(dedup_key)

                result.api_calls.append(JSApiCall(
                    method=method,
                    path=path,
                    source_file=js_url,
                    context=reason[:200],
                    params=[],
                ))
                new_count += 1

            if new_count > 0:
                log.info("LLM JS 分析: %s 发现 %d 个新 API（正则遗漏）", file_name, new_count)
            else:
                log.info("LLM JS 分析: %s 未发现新 API", file_name)

        except Exception as e:
            log.warning("LLM JS 分析: %s 分析出错，跳过: %s", file_name, e)
            continue

    log.info("LLM JS 分析完成: 关键文件 %d 个, 新增 API %d 个",
             len(key_files),
             len(result.api_calls) - len(seen_keys) + len(seen_keys))

    return result
