"""
参数发现层 — 从 sitemap 提取所有注入点，并主动挖掘隐藏参数。

数据来源（按优先级）：
1. sitemap.apis 已抓到的真实请求（含 query/form/json body）
2. sitemap.pages 里的 form 表单字段
3. sitemap.js_api_calls JS 中发现的 API 端点
4. sitemap.features 里的 related_apis
5. 主动 Param Miner: 用字典暴力探测隐藏参数

输出：list[InjectionTarget]，去重 + 优先级排序
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse, parse_qs, urlencode

import httpx

from core.xss.models import InjectionPoint, InjectionTarget

if TYPE_CHECKING:
    from core.sitemap import Sitemap


# ============================================================
# Param Miner 字典 — 中等力度（精选 200 个最有效的参数名）
# ============================================================
# 来源：Burp Suite Param Miner、SecLists、自经验积累
# 优先级：常见输入参数 > URL/重定向参数 > 调试参数 > 罕见参数
COMMON_PARAM_NAMES = [
    # 通用搜索/查询
    "q", "query", "search", "s", "keyword", "kw", "k", "term", "find",
    "filter", "name", "title", "subject",
    # ID 类
    "id", "uid", "user_id", "userId", "rid", "role_id", "menu_id",
    "data_id", "biz_id", "record_id", "row_id", "item_id", "key", "uuid",
    # URL / 重定向
    "url", "uri", "redirect", "redirect_uri", "redirectUri", "returnUrl",
    "return_url", "callback", "callbackUrl", "next", "target", "goto",
    "destination", "continue", "from", "ref", "referer",
    # 文件 / 路径
    "file", "filename", "path", "filepath", "dir", "page", "template",
    "view", "lang", "language", "locale",
    # 内容字段
    "content", "msg", "message", "text", "body", "description", "desc",
    "comment", "note", "remark", "memo", "bio", "intro",
    # 用户/账号
    "username", "user", "email", "phone", "mobile", "tel", "nick", "nickname",
    "real_name", "realname", "account",
    # 业务字段
    "type", "status", "category", "tag", "tags", "label", "level",
    "priority", "color", "size", "count", "limit", "offset", "page",
    "pageSize", "page_size", "sort", "order", "orderBy", "order_by",
    "dir", "direction",
    # 调试 / 隐藏
    "debug", "test", "dev", "preview", "draft", "edit", "admin",
    "internal", "_token", "csrf", "_csrf", "csrf_token", "token",
    "key", "apikey", "api_key", "secret", "code", "verify",
    # 富文本/HTML
    "html", "rich_text", "richText", "raw", "value", "data",
    # 时间
    "date", "time", "start", "end", "from_date", "to_date",
    "start_time", "end_time", "year", "month", "day",
    # 输入框名（中文系统常见）
    "input", "field", "param", "args", "data",
    # 模板/视图
    "tpl", "tmpl", "render", "format", "output", "mode",
    # JSONP / 回调
    "jsonp", "_callback", "cb",
    # SQL 类
    "where", "having", "groupBy", "limit", "offset",
    # 错误回显
    "error", "err", "errno", "error_msg",
    # OAuth/认证
    "state", "scope", "response_type", "grant_type", "client_id",
]


def extract_targets_from_sitemap(sitemap: "Sitemap") -> list[InjectionTarget]:
    """从 sitemap 中提取所有可注入目标。"""
    targets: list[InjectionTarget] = []
    seen_keys: set[str] = set()  # (method, url_path, param_name) 去重

    def _add_target(tgt: InjectionTarget):
        key = f"{tgt.method}|{tgt.url.split('?')[0]}|{tgt.injection_point.value}|{tgt.param_name}"
        if key in seen_keys:
            return
        seen_keys.add(key)
        targets.append(tgt)

    # 1. 从 api_samples 提取（有完整的 request_body 和 query）
    samples = getattr(sitemap, "api_samples", {}) or {}
    for sample_key, sample in samples.items():
        if not isinstance(sample, dict):
            continue
        url = sample.get("url", "")
        method = sample.get("method", "GET").upper()
        if not url:
            continue

        # URL query 参数
        parsed = urlparse(url)
        if parsed.query:
            qs_params = parse_qs(parsed.query, keep_blank_values=True)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for pname, pvals in qs_params.items():
                pval = pvals[0] if pvals else ""
                _add_target(InjectionTarget(
                    url=base_url,
                    method=method,
                    injection_point=InjectionPoint.URL_PARAM,
                    param_name=pname,
                    original_value=pval,
                    headers=sample.get("request_headers", {}) or {},
                    source_flow_id=sample.get("flow_id", ""),
                ))

        # POST body 参数
        body = sample.get("request_body") or sample.get("post_data") or ""
        content_type = (sample.get("request_headers", {}) or {}).get("content-type", "") or \
                       (sample.get("request_headers", {}) or {}).get("Content-Type", "")
        content_type = content_type.lower()

        if body and method in ("POST", "PUT", "PATCH", "DELETE"):
            base_url = url.split("?")[0]
            params = _parse_body_params(body, content_type)
            for pname, pval, ip in params:
                _add_target(InjectionTarget(
                    url=base_url,
                    method=method,
                    injection_point=ip,
                    param_name=pname,
                    original_value=pval,
                    headers=sample.get("request_headers", {}) or {},
                    body_template=body,
                    content_type=content_type,
                    source_flow_id=sample.get("flow_id", ""),
                ))

    # 2. 从 sitemap.apis 提取（仅有 path 和 method，无 body 详情）
    apis = getattr(sitemap, "apis", {}) or {}
    for api_key, api_info in apis.items():
        # 兼容 APIEndpoint dataclass / dict 两种
        if hasattr(api_info, "url"):
            url = getattr(api_info, "url", "")
            method = getattr(api_info, "method", "GET").upper()
        elif isinstance(api_info, dict):
            url = api_info.get("url", "")
            method = api_info.get("method", "GET").upper()
        else:
            continue
        if not url:
            # 尝试从 key 解析
            parts = api_key.split(" ", 1)
            if len(parts) == 2:
                method, url = parts
                method = method.upper()
        if not url:
            continue

        parsed = urlparse(url)
        # 已经在 samples 里覆盖过的不再处理
        if parsed.query:
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            qs_params = parse_qs(parsed.query, keep_blank_values=True)
            for pname, pvals in qs_params.items():
                pval = pvals[0] if pvals else ""
                _add_target(InjectionTarget(
                    url=base_url,
                    method=method,
                    injection_point=InjectionPoint.URL_PARAM,
                    param_name=pname,
                    original_value=pval,
                ))

    # 3. 从 sitemap.pages 的 forms 提取
    pages = getattr(sitemap, "pages", {}) or {}
    for purl, page in pages.items():
        if isinstance(page, dict):
            forms = page.get("forms", [])
        else:
            forms = getattr(page, "forms", [])
        for form in forms or []:
            action = form.get("action") if isinstance(form, dict) else getattr(form, "action", "")
            fmethod = form.get("method", "POST") if isinstance(form, dict) else getattr(form, "method", "POST")
            inputs = form.get("inputs", []) if isinstance(form, dict) else getattr(form, "inputs", [])
            if not action or action.startswith("javascript:"):
                action = purl  # 默认提交到当前页
            for inp in inputs or []:
                pname = inp.get("name", "") if isinstance(inp, dict) else getattr(inp, "name", "")
                ptype = inp.get("type", "") if isinstance(inp, dict) else getattr(inp, "type", "")
                if not pname or ptype in ("submit", "button", "image", "file"):
                    continue
                _add_target(InjectionTarget(
                    url=action,
                    method=fmethod.upper(),
                    injection_point=InjectionPoint.BODY_FORM,
                    param_name=pname,
                    original_value=inp.get("placeholder", "") if isinstance(inp, dict) else "",
                ))

    return targets


def _parse_body_params(body: str, content_type: str) -> list[tuple[str, str, InjectionPoint]]:
    """解析 request body，返回 (param_name, value, injection_point) 列表。"""
    out: list[tuple[str, str, InjectionPoint]] = []
    body = body.strip()
    if not body:
        return out

    # JSON
    if "json" in content_type or (body.startswith("{") and body.endswith("}")):
        try:
            obj = json.loads(body)
            _walk_json(obj, "", out)
            return out
        except (json.JSONDecodeError, ValueError):
            pass

    # form-urlencoded
    if "form-urlencoded" in content_type or (("=" in body) and ("\n" not in body)):
        try:
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    out.append((k, v, InjectionPoint.BODY_FORM))
            return out
        except Exception:
            pass

    # multipart 简单识别
    if "multipart" in content_type:
        name_pattern = re.compile(r'name="([^"]+)"')
        for m in name_pattern.finditer(body):
            out.append((m.group(1), "", InjectionPoint.BODY_MULTIPART))
        return out

    return out


def _walk_json(obj, prefix: str, out: list):
    """递归遍历 JSON，提取所有 leaf 字段。"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (str, int, float, bool)) or v is None:
                out.append((k, str(v) if v is not None else "", InjectionPoint.BODY_JSON))
            else:
                _walk_json(v, key_path, out)
    elif isinstance(obj, list) and obj:
        # 取第一个元素的结构
        _walk_json(obj[0], prefix + "[0]", out)


# ============================================================
# Param Miner — 隐藏参数暴力探测（bucket 算法）
# ============================================================
async def mine_hidden_params(
    base_url: str,
    method: str,
    auth_headers: dict = None,
    cookies: dict = None,
    timeout: float = 10.0,
    bucket_size: int = 30,
    proxy: str = "",
) -> list[str]:
    """对一个端点暴力探测隐藏参数（不发 XSS payload，只发探测请求）。

    算法（bucket / divide-and-conquer）：
    1. 把所有参数名分成桶（每桶 30 个），每桶塞同样的探测值
    2. 发一次请求，记录响应"baseline"（长度+状态码）
    3. 把整桶的 30 个参数当作一个请求发出去
    4. 如果响应和 baseline 显著不同（长度变化、状态码变化、新错误信息），
       说明这桶里至少有一个参数被服务端处理 → 二分定位到具体哪个
    5. 二分继续把桶切成两半，直到定位到具体参数

    Returns:
        发现的隐藏参数名列表
    """
    if not base_url:
        return []
    auth_headers = auth_headers or {}
    cookies = cookies or {}

    proxies = proxy or None

    async with httpx.AsyncClient(
        proxy=proxies, timeout=timeout, verify=False, follow_redirects=False,
        headers=auth_headers, cookies=cookies,
    ) as client:
        # 1. 获取基线
        try:
            baseline_resp = await client.request(method, base_url)
        except Exception:
            return []
        baseline_len = len(baseline_resp.content or b"")
        baseline_status = baseline_resp.status_code
        baseline_text = (baseline_resp.text or "")[:5000]

        # 2. 桶探测
        found: list[str] = []
        candidate_params = list(COMMON_PARAM_NAMES)
        marker_value = "xPmInE9"

        async def _test_bucket(params: list[str]) -> bool:
            """测试一个桶里是否有"被处理"的参数。"""
            if not params:
                return False
            payload = {p: marker_value for p in params}
            try:
                if method.upper() in ("GET", "DELETE"):
                    resp = await client.request(method, base_url, params=payload)
                else:
                    resp = await client.request(method, base_url, data=payload)
            except Exception:
                return False
            cur_len = len(resp.content or b"")
            cur_status = resp.status_code
            # 信号 1: 长度变化超过 5%
            len_changed = abs(cur_len - baseline_len) > max(50, baseline_len * 0.05)
            # 信号 2: 状态码变化
            status_changed = cur_status != baseline_status
            # 信号 3: marker 在响应中回显
            marker_echoed = marker_value in (resp.text or "")[:10000]
            # 信号 4: 新增的错误信息
            cur_text = (resp.text or "")[:5000]
            error_keywords = ["error", "exception", "invalid", "required", "缺少", "异常", "参数"]
            error_appeared = any(
                kw in cur_text.lower() and kw not in baseline_text.lower()
                for kw in error_keywords
            )
            return len_changed or status_changed or marker_echoed or error_appeared

        async def _bisect(params: list[str]):
            """二分定位。"""
            if not params:
                return
            if len(params) == 1:
                if await _test_bucket(params):
                    found.append(params[0])
                return
            # 分成两半
            mid = len(params) // 2
            left = params[:mid]
            right = params[mid:]
            left_has = await _test_bucket(left)
            right_has = await _test_bucket(right)
            if left_has:
                if len(left) <= 2:
                    for p in left:
                        if await _test_bucket([p]):
                            found.append(p)
                else:
                    await _bisect(left)
            if right_has:
                if len(right) <= 2:
                    for p in right:
                        if await _test_bucket([p]):
                            found.append(p)
                else:
                    await _bisect(right)

        # 把字典分桶，并发探测
        buckets = [candidate_params[i:i + bucket_size]
                   for i in range(0, len(candidate_params), bucket_size)]

        # 先一次性测每个桶是否值得二分
        for bucket in buckets:
            if await _test_bucket(bucket):
                await _bisect(bucket)

    # 去重
    return list(dict.fromkeys(found))


async def discover_all_targets(
    sitemap: "Sitemap",
    *,
    auth_headers: dict = None,
    cookies: dict = None,
    enable_param_mining: bool = True,
    enable_header_injection: bool = True,
    proxy: str = "",
    on_progress: callable = None,
    max_targets_for_mining: int = 30,
) -> list[InjectionTarget]:
    """完整的目标发现流程：sitemap 提取 + Header 注入 + Param Miner 增强。"""
    targets = extract_targets_from_sitemap(sitemap)
    if on_progress:
        on_progress(f"📋 从 sitemap 提取 {len(targets)} 个注入点")

    # P0: Header / Cookie / Referer / UA 注入目标
    if enable_header_injection:
        try:
            from core.xss.header_injection import generate_header_injection_targets
            header_targets = generate_header_injection_targets(sitemap)
            if header_targets:
                # 去重合并
                seen = {(t.method, t.url.split('?')[0], t.injection_point.value, t.param_name)
                        for t in targets}
                added = 0
                for ht in header_targets:
                    key = (ht.method, ht.url.split('?')[0], ht.injection_point.value, ht.param_name)
                    if key not in seen:
                        targets.append(ht)
                        seen.add(key)
                        added += 1
                if on_progress and added > 0:
                    on_progress(f"  📨 Header/Cookie 注入: 新增 {added} 个目标 "
                                f"(Referer/UA/XFF/Origin 等)")
        except Exception as e:
            if on_progress:
                on_progress(f"  ⚠️ Header 注入目标生成失败: {str(e)[:100]}")

    if not enable_param_mining or not targets:
        return targets

    # 选择需要 mine 的端点（按 URL 去重，每个 URL 只 mine 一次）
    urls_to_mine: dict[str, tuple[str, dict]] = {}
    for tgt in targets:
        key = f"{tgt.method} {tgt.url}"
        if key not in urls_to_mine and len(urls_to_mine) < max_targets_for_mining:
            urls_to_mine[key] = (tgt.method, tgt.headers)

    if on_progress:
        on_progress(f"🔍 Param Miner 启动，覆盖 {len(urls_to_mine)} 个端点...")

    new_targets = []
    completed = 0
    for key, (method, headers) in urls_to_mine.items():
        url = key.split(" ", 1)[1]
        try:
            hidden = await mine_hidden_params(
                url, method,
                auth_headers={**(auth_headers or {}), **(headers or {})},
                cookies=cookies, proxy=proxy,
            )
            completed += 1
            if hidden:
                if on_progress:
                    on_progress(f"  ✨ {url[:60]} → 发现 {len(hidden)} 个隐藏参数: {hidden[:5]}")
                for pname in hidden:
                    new_targets.append(InjectionTarget(
                        url=url,
                        method=method,
                        injection_point=InjectionPoint.URL_PARAM if method in ("GET", "DELETE") else InjectionPoint.BODY_FORM,
                        param_name=pname,
                        headers=headers or {},
                    ))
            if completed % 5 == 0 and on_progress:
                on_progress(f"  Param Miner 进度: {completed}/{len(urls_to_mine)}")
        except Exception as e:
            if on_progress:
                on_progress(f"  ⚠️ Param Miner 错误 {url[:50]}: {str(e)[:60]}")

    if on_progress:
        on_progress(f"✅ Param Miner 完成: 共发现 {len(new_targets)} 个隐藏参数注入点")

    return targets + new_targets
