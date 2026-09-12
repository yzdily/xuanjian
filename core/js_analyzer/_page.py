"""JS Analyzer 爬虫集成高层函数 — analyze_page_js，从 js_analyzer.py 抽取，行为不变。"""

from __future__ import annotations

from core.log import get_logger

from ._models import JSAnalysisResult
from ._analyzer import analyze_js
from ._llm import llm_analyze_key_js
from ._cache import cache_js_sources

log = get_logger("js_analyzer")


async def analyze_page_js(page, base_url: str = "", llm_chat_fn=None) -> JSAnalysisResult:
    """在 Playwright page 上提取并分析所有 JS。

    包括：
    1. 内联 <script> 标签
    2. 外链 <script src> 文件
    3. 动态加载的 chunk 文件（从已加载的 JS 中找引用）
    4. （可选）对关键业务 JS 文件进行 LLM 分析，补充正则遗漏的 API

    Args:
        page: Playwright page 对象
        base_url: 站点基础 URL
        llm_chat_fn: 可选的 LLM 回调函数，签名为
            async (messages, caller?) -> response (response.content 为文本)
            传入后，对 main.js/index.js/app.js 等关键文件会自动调用 LLM 分析
    """
    js_contents: list[tuple[str, str]] = []

    try:
        # 1. 提取内联 JS
        inline_scripts = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('script:not([src])'))
                .map(s => s.textContent)
                .filter(t => t && t.length > 50);
        }""")
        for i, text in enumerate(inline_scripts or []):
            js_contents.append((f"inline_script_{i}", text))

        # 2. 提取外链 JS URL
        external_urls = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('script[src]'))
                .map(s => s.src)
                .filter(s => s && s.startsWith('http'));
        }""")

        # 3. 从 performance API 获取已加载的所有 JS 资源（包括动态 chunk）
        perf_js_urls = await page.evaluate("""() => {
            return performance.getEntriesByType('resource')
                .filter(e => e.initiatorType === 'script' || e.name.endsWith('.js'))
                .map(e => e.name);
        }""")

        # 合并去重
        all_js_urls = list(dict.fromkeys((external_urls or []) + (perf_js_urls or [])))

        # 4. 逐个下载 JS 内容（限制总量避免太慢）
        MAX_JS_FILES = 30
        MAX_SINGLE_SIZE = 2 * 1024 * 1024  # 2MB/文件
        total_size = sum(len(t) for _, t in js_contents)

        for js_url in all_js_urls[:MAX_JS_FILES]:
            if total_size > 10 * 1024 * 1024:  # 总量 10MB 上限
                log.info("JS 总量超 10MB，停止下载")
                break
            # ★ 单文件下载重试 2 次（退避 200ms / 500ms），
            # 避免网络抖动导致关键业务 JS（如 main.js/app.js）永久丢失。
            text = None
            for _js_attempt in range(3):
                try:
                    text = await page.evaluate("""async (url) => {
                        try {
                            const resp = await fetch(url);
                            if (!resp.ok) return '';
                            const ct = resp.headers.get('content-type') || '';
                            if (ct.includes('html')) return '';  // 不是 JS
                            const text = await resp.text();
                            return text.length > 2*1024*1024 ? text.slice(0, 2*1024*1024) : text;
                        } catch { return ''; }
                    }""", js_url)
                    if text and len(text) > 50:
                        break  # 成功
                except Exception as _js_e:
                    if _js_attempt < 2:
                        import asyncio as _aio
                        await _aio.sleep(0.2 * (_js_attempt + 1))
                        log.debug("JS 下载重试 %d/2 %s: %s", _js_attempt + 1, js_url[-60:], _js_e)
                    else:
                        log.debug("JS 下载最终失败 %s: %s", js_url[-60:], _js_e)
                if not text:
                    # 短暂退避后重试（避免空响应也立即重试）
                    if _js_attempt < 2:
                        import asyncio as _aio
                        await _aio.sleep(0.2 * (_js_attempt + 1))
            if text and len(text) > 50:
                js_contents.append((js_url, text))
                total_size += len(text)

    except Exception as e:
        log.warning("JS 提取失败: %s", e)

    if not js_contents:
        return JSAnalysisResult()

    log.info("提取到 %d 个 JS 文件 (%d 内联, %d 外链/chunk), 总 %dKB",
             len(js_contents),
             sum(1 for u, _ in js_contents if u.startswith("inline_")),
             sum(1 for u, _ in js_contents if not u.startswith("inline_")),
             total_size // 1024)

    # ★ 缓存 JS 源码供推测 API 参数构造使用（按 base_url 隔离不同目标）
    cache_js_sources(js_contents, target=base_url)

    result = analyze_js(js_contents, base_url)
    # ★ 记录所有外链 JS URL，供 FastScanner 动态推导 .map 探测
    result.js_file_urls = [u for u, _ in js_contents if u.startswith("http")]

    # ★ LLM 增强分析：对关键业务 JS 文件（main.js / index.js / app.js 等）
    #   用 LLM 理解代码逻辑，提取正则遗漏的 API（minified 变量名、baseURL 拼接、相对路径等）
    if llm_chat_fn and result.api_calls is not None:
        pre_count = len(result.api_calls)
        try:
            result = await llm_analyze_key_js(js_contents, result, base_url, llm_chat_fn)
            new_count = len(result.api_calls) - pre_count
            if new_count > 0:
                log.info("LLM JS 增强完成: 新增 %d 个 API（正则共 %d 个 → 合计 %d 个）",
                         new_count, pre_count, len(result.api_calls))
        except Exception as e:
            log.warning("LLM JS 增强失败，回退纯正则结果: %s", e)

    return result
