"""
CSP / 响应头安全策略分析 — P1 关键能力。

工作：
1. 收集所有页面响应的安全相关 header：
   - Content-Security-Policy
   - X-Content-Type-Options
   - X-Frame-Options
   - X-XSS-Protection (legacy)
   - Strict-Transport-Security
   - Referrer-Policy
2. 解析 CSP 策略并识别 bypass 路径：
   - script-src 'unsafe-inline' → 任意 inline script 可执行
   - script-src 'unsafe-eval' → eval 可用
   - script-src 'self' 但允许 JSONP/AngularJS/旧版 jQuery host → 经典 bypass
   - script-src 含 *.googleapis.com / *.cloudfront.net → AngularJS sandbox escape
   - nonce 重用 / 静态 nonce
   - data: 协议允许
   - 通配符 * 允许
3. 输出"CSP 缓解强度"评分 + 具体 bypass 建议
4. 对 XSS 候选研判时作为重要上下文：
   - 即使有反射，但严格 CSP（无 unsafe-*、无白名单 CDN、有 nonce）可降级为 low

设计：
- 静态分析为主，不主动发请求验证 bypass（避免噪声）
- 输出 CspAnalysis 对象，供 LLM judge 消费
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)


# ============================================================
# 已知可被绕过的 CDN / 域名
# ============================================================
# 这些域名上托管了 AngularJS / 旧 jQuery / Flash 等可被滥用的脚本
KNOWN_BYPASS_DOMAINS = {
    # AngularJS sandbox escape (1.6 之前)
    "ajax.googleapis.com": "AngularJS sandbox escape (< 1.6)",
    "cdnjs.cloudflare.com": "AngularJS / jQuery 版本众多，易被绕过",
    "code.angularjs.org": "AngularJS sandbox escape",
    "code.jquery.com": "旧版 jQuery / jQuery.getScript bypass",
    "maxcdn.bootstrapcdn.com": "bootstrap.js / bootstrap-tour 可被滥用",
    "unpkg.com": "包含大量可被滥用的 JS 库",
    "jsdelivr.net": "包含大量可被滥用的 JS 库",
    "cdn.jsdelivr.net": "包含大量可被滥用的 JS 库",
}

# JSONP 端点高发域名（可被滥用作 CSP bypass）
JSONP_BYPASS_DOMAINS = {
    "accounts.google.com",
    "www.facebook.com",
    "graph.facebook.com",
    "api.github.com",
    "translate.google.com",
}


@dataclass
class CspDirective:
    """CSP 单条指令。"""
    name: str
    values: list[str] = field(default_factory=list)
    has_unsafe_inline: bool = False
    has_unsafe_eval: bool = False
    has_wildcard: bool = False
    has_data_uri: bool = False
    has_nonce: bool = False
    has_strict_dynamic: bool = False
    has_self: bool = False
    bypass_hosts: list[str] = field(default_factory=list)  # 已知可绕过 host


@dataclass
class CspAnalysis:
    """CSP 完整分析结果。"""
    raw_header: str = ""
    directives: dict[str, CspDirective] = field(default_factory=dict)
    # 评分（0-10，越高越安全）
    score: float = 10.0
    # 缓解程度（无/弱/中/强）
    mitigation_level: str = "strong"
    # 可利用的 bypass 路径列表
    bypass_paths: list[str] = field(default_factory=list)
    # 是否 report-only（不阻断仅上报）
    report_only: bool = False

    def to_dict(self) -> dict:
        return {
            "raw_header": self.raw_header,
            "directives": {
                k: {
                    "values": v.values,
                    "unsafe_inline": v.has_unsafe_inline,
                    "unsafe_eval": v.has_unsafe_eval,
                    "wildcard": v.has_wildcard,
                    "data_uri": v.has_data_uri,
                    "nonce": v.has_nonce,
                    "strict_dynamic": v.has_strict_dynamic,
                    "bypass_hosts": v.bypass_hosts,
                } for k, v in self.directives.items()
            },
            "score": self.score,
            "mitigation_level": self.mitigation_level,
            "bypass_paths": self.bypass_paths,
            "report_only": self.report_only,
        }


def parse_csp(header_value: str, report_only: bool = False) -> CspAnalysis:
    """解析一个 CSP header 字符串。"""
    analysis = CspAnalysis(raw_header=header_value, report_only=report_only)
    if not header_value:
        analysis.score = 0.0
        analysis.mitigation_level = "none"
        analysis.bypass_paths.append("无 CSP 头部，任意 inline/远程脚本都可执行")
        return analysis

    # 拆 directive
    for d_str in header_value.split(";"):
        d_str = d_str.strip()
        if not d_str:
            continue
        parts = d_str.split()
        name = parts[0].lower()
        values = parts[1:]
        directive = CspDirective(name=name, values=values)

        for v in values:
            vl = v.lower()
            if vl == "'unsafe-inline'":
                directive.has_unsafe_inline = True
            elif vl == "'unsafe-eval'":
                directive.has_unsafe_eval = True
            elif vl == "*":
                directive.has_wildcard = True
            elif vl == "data:" or vl.startswith("data:"):
                directive.has_data_uri = True
            elif vl.startswith("'nonce-"):
                directive.has_nonce = True
            elif vl == "'strict-dynamic'":
                directive.has_strict_dynamic = True
            elif vl == "'self'":
                directive.has_self = True
            else:
                # 检查是否在已知 bypass 域名列表
                for bd in KNOWN_BYPASS_DOMAINS:
                    if bd in v.lower():
                        directive.bypass_hosts.append(v)
                        break

        analysis.directives[name] = directive

    # ============================================================
    # 评分逻辑（最严苛的指令决定整体强度）
    # ============================================================
    score = 10.0
    bypass_paths: list[str] = []

    script_src = analysis.directives.get("script-src") or analysis.directives.get("default-src")
    if not script_src:
        score = 0.0
        bypass_paths.append("未设置 script-src / default-src，任意脚本可执行")
    else:
        if script_src.has_unsafe_inline and not script_src.has_strict_dynamic:
            score -= 6
            bypass_paths.append(
                "script-src 包含 'unsafe-inline' → 任意 inline <script> 可执行（CSP 几乎失效）"
            )
        if script_src.has_unsafe_eval:
            score -= 2
            bypass_paths.append(
                "script-src 包含 'unsafe-eval' → eval/Function 可用"
            )
        if script_src.has_wildcard:
            score -= 4
            bypass_paths.append(
                "script-src 含 * 通配符 → 可加载任意远程脚本"
            )
        if script_src.has_data_uri:
            score -= 3
            bypass_paths.append(
                "script-src 允许 data: 协议 → 可注入 data:text/javascript,..."
            )
        if script_src.bypass_hosts:
            score -= 3
            for h in script_src.bypass_hosts:
                reason = "未知"
                for bd, r in KNOWN_BYPASS_DOMAINS.items():
                    if bd in h.lower():
                        reason = r
                        break
                bypass_paths.append(f"script-src 含可绕过 host {h}: {reason}")

        # 仅 self 没有 unsafe-* 也可能被 JSONP / 文件上传绕过
        if script_src.has_self and not (
            script_src.has_unsafe_inline or script_src.has_wildcard
        ):
            bypass_paths.append(
                "script-src 仅含 'self' → 若有 JSONP/文件上传/路径遍历同源加载点，可被绕过"
            )

    # object-src 检查
    object_src = analysis.directives.get("object-src") or analysis.directives.get("default-src")
    if not object_src or "none" not in [v.lower() for v in (object_src.values or [])]:
        score -= 1
        bypass_paths.append(
            "object-src 未限制为 'none' → 可注入 <object data=...> 加载危险插件/脚本"
        )

    # base-uri 检查（重要！缺失可被 <base href> 劫持脚本加载）
    base_uri = analysis.directives.get("base-uri")
    if not base_uri:
        score -= 1
        bypass_paths.append(
            "未设置 base-uri → 攻击者可注入 <base href> 改变 <script src='relative.js'> 的解析"
        )

    # frame-ancestors 检查（影响点击劫持）
    if not analysis.directives.get("frame-ancestors"):
        bypass_paths.append("未设置 frame-ancestors → 页面可被任意网站 iframe")

    # report-only 大幅降低实际防护
    if report_only:
        score = score * 0.3
        bypass_paths.append("CSP 为 report-only 模式，不会阻断任何脚本，仅上报")

    score = max(0.0, min(10.0, score))
    analysis.score = score
    analysis.bypass_paths = bypass_paths

    if score >= 8:
        analysis.mitigation_level = "strong"
    elif score >= 5:
        analysis.mitigation_level = "medium"
    elif score >= 2:
        analysis.mitigation_level = "weak"
    else:
        analysis.mitigation_level = "none"

    return analysis


class CspAnalyzer:
    """CSP 分析器 — 从 sitemap 中收集所有页面的 CSP 并分析。"""

    def __init__(self, on_progress: Optional[callable] = None):
        self.on_progress = on_progress

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    def analyze_sitemap(self, sitemap: "Sitemap") -> dict[str, CspAnalysis]:
        """扫描 sitemap 中所有页面的响应头，分析 CSP。"""
        result: dict[str, CspAnalysis] = {}
        # 1. 从 api_samples 的 response_headers 提取
        samples = getattr(sitemap, "api_samples", {}) or {}
        for sample in samples.values():
            if not isinstance(sample, dict):
                continue
            url = sample.get("url", "")
            resp_headers = sample.get("response_headers", {}) or {}
            if not url:
                continue
            host = self._extract_host(url)
            if host in result:
                continue
            csp_header, report_only = self._extract_csp(resp_headers)
            if csp_header:
                result[host] = parse_csp(csp_header, report_only)

        # 2. 从 pages 的 metadata 提取
        pages = getattr(sitemap, "pages", {}) or {}
        for purl, page in pages.items():
            host = self._extract_host(purl)
            if host in result:
                continue
            if isinstance(page, dict):
                headers = page.get("response_headers") or page.get("headers") or {}
            else:
                headers = getattr(page, "response_headers", {}) or getattr(page, "headers", {})
            if isinstance(headers, dict):
                csp_header, report_only = self._extract_csp(headers)
                if csp_header:
                    result[host] = parse_csp(csp_header, report_only)

        if not result:
            self._report("  ⚠️ 未找到 CSP 响应头")
        else:
            for host, analysis in result.items():
                self._report(
                    f"  CSP [{host}]: 评分 {analysis.score:.1f}/10 "
                    f"({analysis.mitigation_level}), {len(analysis.bypass_paths)} 个 bypass 路径"
                )
        return result

    @staticmethod
    def _extract_host(url: str) -> str:
        from urllib.parse import urlparse
        try:
            p = urlparse(url)
            return p.netloc or url
        except Exception:
            return url

    @staticmethod
    def _extract_csp(headers: dict) -> tuple[str, bool]:
        """从 headers dict 提取 CSP（不区分大小写）。"""
        # 尝试多种大小写
        for k in headers:
            kl = k.lower()
            if kl == "content-security-policy":
                return str(headers[k]), False
            if kl == "content-security-policy-report-only":
                return str(headers[k]), True
        return "", False
