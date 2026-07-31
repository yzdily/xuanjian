"""
DOM XSS 静态扫描 — 在 JS 文件中找 source → sink 数据流。

原理：
- Source：用户可控的输入（location.hash、location.search、document.referrer 等）
- Sink：能执行/渲染的 API（innerHTML、eval、document.write 等）
- 如果 source 流向 sink，且中间没有 sanitize，就是 DOM XSS

实现策略：
1. 在 JS 文本中正则匹配所有 source 和 sink 出现位置
2. 对每个 source 出现位置，向后扫描 200 个字符内是否出现 sink
3. 标记可疑代码片段
4. 调用浏览器引擎用具体 source 通道注入 payload 实测

注意：
- 静态分析有误报（不追踪变量赋值链）
- 误报由浏览器引擎复测排除
- 不解析 AST（太重），用正则足够发现 80% 案例
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.sitemap import Sitemap


# ============================================================
# DOM XSS Source / Sink 词典
# ============================================================
DOM_SOURCES = [
    # URL 类
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.baseURI",
    "document.referrer",
    # 用户输入
    "window.name", "history.state",
    # 跨窗口通信
    "postMessage", "onmessage", "addEventListener\\(['\"]message",
    # Storage（间接用户控制）
    "localStorage", "sessionStorage",
    # cookie
    "document.cookie",
]

DOM_SINKS = [
    # innerHTML 类
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    # write 类
    "document.write", "document.writeln",
    # eval 类
    "eval\\s*\\(", "Function\\s*\\(", "setTimeout\\s*\\(\\s*['\"]",
    "setInterval\\s*\\(\\s*['\"]", "execScript",
    # 跳转
    "location.href\\s*=", "location.replace", "location.assign",
    "window.open",
    # script 创建
    "createElement\\s*\\(\\s*['\"]script", "src\\s*=",
    # jQuery
    "\\$\\(.*\\)\\.html", "\\$\\(.*\\)\\.append", "\\$\\(.*\\)\\.after",
    "\\$\\(.*\\)\\.before", "\\$\\(.*\\)\\.attr\\s*\\(\\s*['\"]on",
    # Vue / React 危险 API
    "v-html", "dangerouslySetInnerHTML",
]


@dataclass
class DomXssCandidate:
    """DOM XSS 候选 — 静态分析产出。"""
    source_type: str                      # 如 "location.hash"
    sink_type: str                        # 如 "innerHTML"
    source_offset: int = 0
    sink_offset: int = 0
    distance: int = 0                     # source 和 sink 在代码中的距离（字符）
    code_snippet: str = ""                # 完整的可疑代码片段
    js_file_url: str = ""                 # 来自哪个 JS 文件
    has_sanitizer: bool = False           # 中间是否有疑似 sanitize 调用
    sanitizer_name: str = ""              # 如 "DOMPurify.sanitize"
    confidence: float = 0.5


# 编译 source/sink 正则
_SOURCE_PATTERNS = [(re.compile(s, re.IGNORECASE), s.replace("\\", ""))
                    for s in DOM_SOURCES]
_SINK_PATTERNS = [(re.compile(s, re.IGNORECASE), s.split("\\")[0].split("(")[0].strip())
                  for s in DOM_SINKS]

# 已知的 sanitizer（出现这些就降低风险）
SANITIZER_PATTERNS = [
    re.compile(r"DOMPurify\.sanitize", re.IGNORECASE),
    re.compile(r"sanitize\s*\(", re.IGNORECASE),
    re.compile(r"escapeHtml", re.IGNORECASE),
    re.compile(r"\.replace\s*\(\s*/[<>&\"']/", re.IGNORECASE),
    re.compile(r"textContent\s*=", re.IGNORECASE),  # 用 textContent 代替 innerHTML 安全
    re.compile(r"encodeURIComponent", re.IGNORECASE),
]


def find_dom_xss_in_js(js_text: str, js_url: str = "", max_distance: int = 300) -> list[DomXssCandidate]:
    """在一段 JS 代码中找 DOM XSS 候选。"""
    candidates: list[DomXssCandidate] = []
    if not js_text or len(js_text) > 5_000_000:  # 跳过过大的 JS
        return candidates

    # 找所有 source 出现位置
    source_positions: list[tuple[int, str]] = []
    for pat, label in _SOURCE_PATTERNS:
        for m in pat.finditer(js_text):
            source_positions.append((m.start(), label))

    if not source_positions:
        return candidates

    # 找所有 sink 出现位置
    sink_positions: list[tuple[int, str]] = []
    for pat, label in _SINK_PATTERNS:
        for m in pat.finditer(js_text):
            sink_positions.append((m.start(), label))

    if not sink_positions:
        return candidates

    # 对每对 (source, sink)，如果 sink 在 source 之后且距离 < max_distance，记为候选
    for src_pos, src_label in source_positions:
        for sink_pos, sink_label in sink_positions:
            if sink_pos <= src_pos:
                continue
            dist = sink_pos - src_pos
            if dist > max_distance:
                continue

            # 截取代码片段（前 30 字符 + source 到 sink + 后 30 字符）
            start = max(0, src_pos - 30)
            end = min(len(js_text), sink_pos + 100)
            snippet = js_text[start:end]

            # 检查中间是否有 sanitizer
            between = js_text[src_pos:sink_pos]
            has_san = False
            san_name = ""
            for spat in SANITIZER_PATTERNS:
                m = spat.search(between)
                if m:
                    has_san = True
                    san_name = m.group(0)
                    break

            # 置信度：距离越近、无 sanitizer、source/sink 越危险 → 越高
            conf = 0.5
            if dist < 100:
                conf += 0.2
            if has_san:
                conf -= 0.3
            # 高危 sink 加权
            if sink_label in ("innerHTML", "outerHTML", "document.write", "eval"):
                conf += 0.2
            # 高危 source 加权
            if src_label in ("location.hash", "location.search", "postMessage"):
                conf += 0.1
            conf = max(0.0, min(1.0, conf))

            candidates.append(DomXssCandidate(
                source_type=src_label,
                sink_type=sink_label,
                source_offset=src_pos,
                sink_offset=sink_pos,
                distance=dist,
                code_snippet=snippet,
                js_file_url=js_url,
                has_sanitizer=has_san,
                sanitizer_name=san_name,
                confidence=conf,
            ))

    # 同 (source, sink, js_file) 去重，保留置信度最高的
    dedupe: dict[tuple, DomXssCandidate] = {}
    for c in candidates:
        key = (c.source_type, c.sink_type, c.js_file_url, c.source_offset // 50)
        if key not in dedupe or c.confidence > dedupe[key].confidence:
            dedupe[key] = c

    return sorted(dedupe.values(), key=lambda x: -x.confidence)


def scan_sitemap_for_dom_xss(sitemap: "Sitemap") -> list[DomXssCandidate]:
    """扫描 sitemap 中的所有 JS 文件，找 DOM XSS 候选。"""
    candidates: list[DomXssCandidate] = []
    js_analysis = getattr(sitemap, "js_analysis", None) \
                  or getattr(sitemap, "js_analyses", None) \
                  or {}

    # 从 sitemap 提取 JS 文件内容
    # sitemap 里的 js_analysis 结构因实现而异，做兼容处理
    files_to_scan: list[tuple[str, str]] = []  # (url, content)

    # 兼容多种数据来源
    if isinstance(js_analysis, dict):
        # 可能是 {url: {content, ...}} 或 {url: text}
        for url, info in js_analysis.items():
            if isinstance(info, dict):
                content = info.get("content") or info.get("text") or ""
            else:
                content = str(info)
            if content:
                files_to_scan.append((url, content))

    # 也尝试从 pages 提取（每个页面的 js_analysis 字段）
    pages = getattr(sitemap, "pages", {}) or {}
    for purl, page in pages.items():
        if isinstance(page, dict):
            js_files = page.get("js_files") or {}
        else:
            js_files = getattr(page, "js_files", {})
        if isinstance(js_files, dict):
            for jsurl, jscontent in js_files.items():
                if jscontent and isinstance(jscontent, str):
                    files_to_scan.append((jsurl, jscontent))

    # 去重
    seen_urls = set()
    unique_files = []
    for url, content in files_to_scan:
        if url not in seen_urls:
            seen_urls.add(url)
            unique_files.append((url, content))

    for url, content in unique_files:
        try:
            cands = find_dom_xss_in_js(content, js_url=url)
            candidates.extend(cands)
        except Exception:
            continue

    return candidates


def dom_candidate_to_xss_candidate(dom_cand: DomXssCandidate, target_base_url: str = ""):
    """把 DomXssCandidate 转成 XssCandidate（用于统一研判流程）。"""
    from core.xss.models import (InjectionTarget, XssCandidate, XssType,
                                  InjectionPoint, ContextType, EchoMatch)
    # 根据 source 类型决定 InjectionPoint
    if "hash" in dom_cand.source_type:
        ip = InjectionPoint.URL_FRAGMENT
    elif "search" in dom_cand.source_type:
        ip = InjectionPoint.URL_PARAM
    elif "postMessage" in dom_cand.source_type:
        ip = InjectionPoint.URL_PARAM  # 用 URL 模拟
    else:
        ip = InjectionPoint.URL_PARAM

    target = InjectionTarget(
        url=target_base_url or dom_cand.js_file_url,
        method="GET",
        injection_point=ip,
        param_name=dom_cand.source_type,
    )

    cand = XssCandidate(
        target=target,
        payload=f"[DOM XSS] {dom_cand.source_type} → {dom_cand.sink_type}",
        confidence=dom_cand.confidence,
        xss_type=XssType.DOM,
        request_packet=dom_cand.code_snippet[:1000],
        response_packet=f"JS file: {dom_cand.js_file_url}",
        scanner="xss_dom_static",
    )
    return cand
