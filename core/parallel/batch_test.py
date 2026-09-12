"""
batch_test — 脚本化批量检测

- META_ANALYSIS_PROMPT: 元分析 prompt 常量
- _meta_analyze_checklist: LLM 元分析，决定脚本化 vs LLM
- _execute_script_batch: 执行脚本化批量检测
- _batch_test_unauth: 批量未授权访问测试
- _batch_prelim_test: 规则化初筛
"""
# noqa: giant

from __future__ import annotations

import asyncio
import json
import re as _re
import time as _time
from typing import TYPE_CHECKING

import httpx as _httpx

from core.sitemap import TestStatus, FeaturePoint
from core.log import get_logger, metrics
from core.prompts import load_prompt
# D6 拆分：_repair_llm_json 为纯函数，独立成模块便于单测与降体积
from core.parallel._json_repair import _repair_llm_json

if TYPE_CHECKING:
    from core.session import AgentSession
    from core.llm import LLMClient

log = get_logger("parallel.batch_test")


# ============================================================
# LLM 元分析：分析 checklist 全貌，决定脚本化 vs LLM 处理
# ============================================================

META_ANALYSIS_PROMPT = load_prompt("meta_analysis", with_common=True)


async def _meta_analyze_checklist(
    features: list["FeaturePoint"],
    llm: "LLMClient",
    business_type: str = "",
    tech_stack: str = "",
) -> dict:
    """LLM 元分析：看 checklist 全貌后，决定哪些可以脚本化处理。

    Returns:
        {
            "script_batch": [{"check_type": str, "feature_ids": list, "script_method": str}],
            "llm_required": [{"check_type": str, "feature_ids": list}],
        }
    """
    from core.llm import Message
    from core.sitemap import CheckResult

    # ★ LLM 未配置或不可调用时跳过元分析（FAST 模式下 llm 为 None）
    if not callable(getattr(llm, "chat", None)):
        log.info("LLM 未配置，跳过元分析")
        return {"script_batch": [], "llm_required": []}

    # 构建 checklist 全景摘要（精简，不浪费 token）
    checklist_summary = []
    for fp in features:
        pending = [c for c in fp.checklist if c.result == CheckResult.PENDING]
        if not pending:
            continue
        apis_preview = ", ".join(fp.related_apis[:3]) if fp.related_apis else "无API"
        check_types = [c.vuln_type for c in pending]
        checklist_summary.append(
            f"- {fp.id} [{fp.name}] APIs: {apis_preview} | 待测: {', '.join(check_types)}"
        )

    if not checklist_summary:
        return {"script_batch": [], "llm_required": []}

    user_msg = (
        f"## 目标信息\n"
        f"- 业务类型: {business_type or '未知'}\n"
        f"- 技术栈: {tech_stack or '未知'}\n"
        f"- 功能点数: {len(features)}\n"
        f"- 待测 checklist 项: {sum(len([c for c in fp.checklist if c.result == CheckResult.PENDING]) for fp in features)}\n\n"
        f"## 完整 checklist 清单\n\n"
        + "\n".join(checklist_summary[:100])  # 最多100个功能点的摘要
    )

    messages = [
        Message(role="system", content=META_ANALYSIS_PROMPT),
        Message(role="user", content=user_msg),
    ]

    try:
        log.info("LLM 元分析: %d 个功能点的 checklist 分类", len(features))
        response = await asyncio.to_thread(llm.chat, messages, caller="meta_analyze")
        result_text = response.content or ""

        # 提取 JSON（多种格式兼容）
        json_str = ""
        json_match = _re.search(r'```json\s*(.*?)\s*```', result_text, _re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_match = _re.search(r'\{[\s\S]*"script_batch"[\s\S]*\}', result_text, _re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                json_match = _re.search(r'\{.*\}', result_text, _re.DOTALL)
                json_str = json_match.group(0) if json_match else ""

        if not json_str:
            # 重试一次，用更强制的指令
            log.warning("元分析: 第一次未返回有效 JSON，重试...")
            retry_msg = Message(role="user", content="请严格按要求只输出 JSON，不要其他文字。")
            messages.append(Message(role="assistant", content=result_text))
            messages.append(retry_msg)
            response = await asyncio.to_thread(llm.chat, messages, caller="meta_analyze_retry")
            result_text = response.content or ""
            json_match = _re.search(r'\{[\s\S]*"script_batch"[\s\S]*\}', result_text, _re.DOTALL)
            json_str = json_match.group(0) if json_match else ""

        if not json_str:
            log.warning("元分析: LLM 两次均未返回有效 JSON，全部交给 LLM 处理")
            return {"script_batch": [], "llm_required": []}

        # ★ JSON 容错：LLM 经常返回尾随逗号、单引号等非标准 JSON
        # 先尝试直接解析，失败后做正则修复再解析
        try:
            result = json.loads(json_str)
        except json.JSONDecodeError as je:
            log.warning("元分析: JSON 解析失败 (%s)，尝试自动修复", str(je)[:120])
            repaired = _repair_llm_json(json_str)
            if repaired:
                try:
                    result = json.loads(repaired)
                    log.info("元分析: JSON 修复后解析成功")
                except json.JSONDecodeError as je2:
                    log.warning("元分析: JSON 修复后仍失败 (%s)，全部交给 LLM", str(je2)[:120])
                    return {"script_batch": [], "llm_required": []}
            else:
                log.warning("元分析: JSON 修复失败，全部交给 LLM")
                return {"script_batch": [], "llm_required": []}
        script_batch = result.get("script_batch", [])
        llm_required = result.get("llm_required", [])

        # ★ 二次白名单校验：防止 LLM 把不该脚本化的项错误归类
        # 白名单：支持的脚本方法（必须与 _execute_script_batch 实际支持的一致）
        ALLOWED_SCRIPT_METHODS = {
            "unauth", "info_leak", "cors", "header_check",
            "method_check", "path_traversal", "error_disclosure",
        }
        # 黑名单：明确不能脚本化的 check_type 关键词（出现即移到 llm_required）
        LLM_ONLY_KEYWORDS = (
            "sql注入", "sql injection", "sqli",
            "idor", "越权", "水平越权", "垂直越权",
            "ssrf", "rce", "命令注入", "命令执行",
            "xss", "xxe", "反序列化", "ssti", "模板注入",
            "业务逻辑", "支付", "金额", "竞态", "条件竞争",
            "文件上传", "任意文件上传",
            "csrf",  # CSRF 需要业务理解（哪些是状态变更接口）
        )

        cleaned_script = []
        forced_to_llm = []
        for item in script_batch:
            if not isinstance(item, dict):
                continue
            method = (item.get("script_method") or "").strip().lower()
            check_type = (item.get("check_type") or "").strip()
            check_type_lower = check_type.lower()

            # 规则 1：script_method 不在白名单 → 移到 LLM
            if method not in ALLOWED_SCRIPT_METHODS:
                log.warning("元分析: %s 使用未知 script_method '%s'，强制改为 LLM 处理",
                            check_type, method)
                forced_to_llm.append({
                    "check_type": check_type,
                    "feature_ids": item.get("feature_ids", []),
                    "reason": f"未知脚本方法 '{method}'，转 LLM 兜底",
                })
                continue
            # 规则 2：check_type 命中黑名单关键词 → 移到 LLM
            if any(kw in check_type_lower for kw in LLM_ONLY_KEYWORDS):
                log.warning("元分析: '%s' 属于业务相关漏洞，不可脚本化，强制改为 LLM",
                            check_type)
                forced_to_llm.append({
                    "check_type": check_type,
                    "feature_ids": item.get("feature_ids", []),
                    "reason": f"漏洞类型 '{check_type}' 需要业务语义判断",
                })
                continue
            cleaned_script.append(item)

        if forced_to_llm:
            log.info("元分析二次校验: %d 项从脚本批移到 LLM 处理", len(forced_to_llm))
            llm_required.extend(forced_to_llm)
        script_batch = cleaned_script

        # 统计
        script_count = sum(len(g.get("feature_ids", [])) for g in script_batch)
        llm_count = sum(len(g.get("feature_ids", [])) for g in llm_required)
        log.info("元分析完成: 脚本可处理 %d 组 (%d 功能点), LLM 必须处理 %d 组 (%d 功能点)",
                 len(script_batch), script_count, len(llm_required), llm_count)

        return {"script_batch": script_batch, "llm_required": llm_required}

    except Exception as e:
        log.warning("元分析出错: %s，全部交给 LLM", e)
        return {"script_batch": [], "llm_required": []}


async def _execute_script_batch(session: "AgentSession", script_batch: list[dict], features: list["FeaturePoint"]) -> dict:
    """执行元分析决定的脚本化批量检测。

    预设的 script_method:
    - unauth: 未授权访问（去 Token 发请求看状态码）
    - info_leak: 信息泄露（正则扫描响应体敏感数据）
    - cors: CORS 配置检测（发 Origin 看是否回显）
    - header_check: 安全 Header 检测（X-Frame-Options/CSP/HSTS 等）
    - method_check: HTTP 方法测试（OPTIONS 探测允许的方法）
    - path_traversal: 路径穿越/任意文件读取（仅对带文件路径参数的 GET 接口）
    - error_disclosure: 错误信息泄露（畸形参数触发堆栈/SQL/调试信息）

    其他 method 暂不支持，保留给 LLM。
    """
    import httpx

    if not session.sitemap:
        return {"cleared": 0}

    feature_map = {fp.id: fp for fp in features}
    target_base = session.sitemap.target.rstrip("/")
    total_cleared = 0

    # 获取认证 headers
    auth_headers = {}
    if session.sitemap.api_samples:
        for sample in session.sitemap.api_samples.values():
            h = sample.get("headers", {})
            if h.get("Authorization") or h.get("authorization"):
                auth_headers = {k: v for k, v in h.items()
                               if k.lower() in ("authorization", "cookie", "proxy-connection")}
                break

    # 敏感数据正则（复用）
    SENSITIVE_PATTERNS = {
        "手机号": _re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)'),
        "身份证": _re.compile(r'(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)'),
        "银行卡": _re.compile(r'(?<!\d)(?:62|4\d|5[1-5])\d{14,17}(?!\d)'),
        "邮箱": _re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "内网IP": _re.compile(r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)'),
        "密码字段": _re.compile(r'"(?:password|passwd|pwd|secret|api_key|private_key)"\s*:\s*"[^"]{6,}"', _re.IGNORECASE),
    }

    async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
        for batch in script_batch:
            method = batch.get("script_method", "")
            fids = batch.get("feature_ids", [])
            check_type = batch.get("check_type", "")
            fps = [feature_map[fid] for fid in fids if fid in feature_map]

            if not fps:
                continue

            # ============ unauth: 未授权访问 ============
            if method == "unauth":
                _STATIC_EXTS2 = ('.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.map')
                for fp in fps:
                    checks = [c for c in fp.checklist if c.vuln_type == check_type and c.result == _CheckResult_PENDING]
                    if not checks or not fp.related_apis:
                        continue
                    # 取第一个非静态资源的 API 测试
                    api = None
                    for a in fp.related_apis:
                        a_path = a.split('?')[0].lower()
                        if not any(a_path.endswith(ext) for ext in _STATIC_EXTS2) and '/assets/' not in a_path:
                            api = a
                            break
                    if not api:
                        continue
                    parts = api.split(" ", 1)
                    req_method = parts[0] if len(parts) == 2 and parts[0].isupper() else "GET"
                    url = parts[-1] if parts[-1].startswith("http") else f"{target_base}{parts[-1]}"
                    try:
                        resp = await client.request(method=req_method, url=url)
                        if resp.status_code in (401, 403):
                            for c in checks:
                                c.result = _CheckResult_NOT_VULN
                                c.detail = f"元分析脚本: 无认证请求返回 {resp.status_code}，鉴权有效。"
                                c.tested_at = _time.time()
                                total_cleared += 1
                        # 200 的留给 LLM 判断
                    except (_httpx.HTTPError, _httpx.TimeoutException) as _e:
                        log.debug("unauth 脚本检测请求失败: %s", _e)

            # ============ info_leak: 信息泄露 ============
            elif method == "info_leak":
                for fp in fps:
                    checks = [c for c in fp.checklist if c.vuln_type == check_type and c.result == _CheckResult_PENDING]
                    if not checks or not fp.related_apis:
                        continue
                    api = fp.related_apis[0]
                    parts = api.split(" ", 1)
                    req_method = parts[0] if len(parts) == 2 and parts[0].isupper() else "GET"
                    url = parts[-1] if parts[-1].startswith("http") else f"{target_base}{parts[-1]}"
                    try:
                        headers = dict(auth_headers)
                        resp = await client.request(method=req_method, url=url, headers=headers)
                        if resp.status_code != 200:
                            continue
                        body = resp.text[:5000]
                        # 正则扫描
                        found = []
                        for stype, pat in SENSITIVE_PATTERNS.items():
                            if pat.search(body):
                                found.append(stype)
                        if not found:
                            for c in checks:
                                c.result = _CheckResult_NOT_VULN
                                c.detail = f"元分析脚本: 响应体({len(body)}字符)未检测到敏感数据(手机号/身份证/银行卡/邮箱/内网IP/密码)。"
                                c.tested_at = _time.time()
                                total_cleared += 1
                        # 有敏感数据的留给 LLM 判断是否属于越权
                    except (_httpx.HTTPError, _httpx.TimeoutException) as _e:
                        log.debug("info_leak 脚本检测请求失败: %s", _e)

            # ============ cors: CORS 配置 ============
            elif method == "cors":
                for fp in fps:
                    checks = [c for c in fp.checklist if check_type.upper() in c.vuln_type.upper() and c.result == _CheckResult_PENDING]
                    if not checks or not fp.related_apis:
                        continue
                    api = fp.related_apis[0]
                    parts = api.split(" ", 1)
                    url = parts[-1] if parts[-1].startswith("http") else f"{target_base}{parts[-1]}"
                    try:
                        headers = dict(auth_headers)
                        headers["Origin"] = "https://evil-attacker.com"
                        resp = await client.request(method="GET", url=url, headers=headers)
                        acao = resp.headers.get("access-control-allow-origin", "")
                        if not acao or (acao != "*" and acao != "https://evil-attacker.com"):
                            for c in checks:
                                c.result = _CheckResult_NOT_VULN
                                c.detail = f"元分析脚本: CORS 未回显攻击者 Origin (ACAO={acao or '无'})。"
                                c.tested_at = _time.time()
                                total_cleared += 1
                        # 回显了 evil Origin 或 * 的留给 LLM
                    except (_httpx.HTTPError, _httpx.TimeoutException) as _e:
                        log.debug("cors 脚本检测请求失败: %s", _e)

            # ============ header_check: 安全 Header 检测 ============
            elif method == "header_check":
                for fp in fps:
                    checks = [c for c in fp.checklist if c.result == _CheckResult_PENDING
                              and any(kw in c.vuln_type for kw in ("Header", "header", "CSP", "HSTS", "X-Frame"))]
                    if not checks or not fp.related_apis:
                        continue
                    api = fp.related_apis[0]
                    parts = api.split(" ", 1)
                    url = parts[-1] if parts[-1].startswith("http") else f"{target_base}{parts[-1]}"
                    try:
                        resp = await client.get(url, headers=auth_headers)
                        h = resp.headers
                        has_xfo = "x-frame-options" in h
                        has_csp = "content-security-policy" in h
                        has_hsts = "strict-transport-security" in h
                        if has_xfo and has_csp and has_hsts:
                            for c in checks:
                                c.result = _CheckResult_NOT_VULN
                                c.detail = f"元分析脚本: 安全 Header 齐全 (XFO={h.get('x-frame-options','')}, CSP=有, HSTS=有)。"
                                c.tested_at = _time.time()
                                total_cleared += 1
                        # 缺少的留给 LLM（可能是低危但需要确认）
                    except (_httpx.HTTPError, _httpx.TimeoutException) as _e:
                        log.debug("header_check 脚本检测请求失败: %s", _e)

            # ============ method_check: HTTP 方法探测 ============
            elif method == "method_check":
                for fp in fps:
                    checks = [c for c in fp.checklist if c.result == _CheckResult_PENDING
                              and any(kw in c.vuln_type for kw in ("HTTP方法", "method", "OPTIONS", "TRACE"))]
                    if not checks or not fp.related_apis:
                        continue
                    api = fp.related_apis[0]
                    parts = api.split(" ", 1)
                    url = parts[-1] if parts[-1].startswith("http") else f"{target_base}{parts[-1]}"
                    try:
                        resp = await client.request(method="OPTIONS", url=url)
                        allow = resp.headers.get("allow", "")
                        # TRACE/PUT/DELETE 不在允许列表 → 安全
                        dangerous = {"TRACE", "PUT", "DELETE"} & set(m.strip() for m in allow.upper().split(","))
                        if not dangerous and resp.status_code != 200:
                            for c in checks:
                                c.result = _CheckResult_NOT_VULN
                                c.detail = f"元分析脚本: OPTIONS 返回 {resp.status_code}，无危险方法开放 (Allow={allow or '无'})。"
                                c.tested_at = _time.time()
                                total_cleared += 1
                    except (_httpx.HTTPError, _httpx.TimeoutException) as _e:
                        log.debug("method_check 脚本检测请求失败: %s", _e)

            # ============ path_traversal: 路径穿越/任意文件读取（基础版） ============
            elif method == "path_traversal":
                # 只对参数值中带 = 文件名的 GET 接口做（避免误伤业务接口）
                PT_PAYLOADS = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd"]
                # 文件读取成功的特征
                LEAK_PATTERNS = [
                    _re.compile(r'root:[x*!:]:0:0:'),         # /etc/passwd
                    _re.compile(r'\[boot loader\]', _re.I),    # boot.ini
                    _re.compile(r'<\?xml.*<servlet>', _re.S | _re.I),  # web.xml
                ]
                # 只接受参数键名包含这些关键字的接口
                FILE_PARAM_KEYS = ("file", "filename", "path", "name", "doc", "image", "img", "url", "uri", "page")

                for fp in fps:
                    checks = [c for c in fp.checklist if c.vuln_type == check_type and c.result == _CheckResult_PENDING]
                    if not checks or not fp.related_apis:
                        continue
                    api = fp.related_apis[0]
                    parts = api.split(" ", 1)
                    req_method = parts[0] if len(parts) == 2 and parts[0].isupper() else "GET"
                    raw_url = parts[-1] if parts[-1].startswith("http") else f"{target_base}{parts[-1]}"

                    # 解析参数
                    if "?" not in raw_url:
                        # 无参数的 URL 不适合脚本化测试，留给 LLM
                        continue
                    base_url, qs = raw_url.split("?", 1)
                    pairs = [p.split("=", 1) for p in qs.split("&") if "=" in p]
                    target_param = None
                    for k, v in pairs:
                        if any(kw in k.lower() for kw in FILE_PARAM_KEYS):
                            target_param = k
                            break
                    if not target_param:
                        # 没有文件路径参数，留给 LLM 判断（可能 path 在 URL segment 里）
                        continue

                    leaked = False
                    try:
                        for payload in PT_PAYLOADS:
                            new_pairs = [(k, payload if k == target_param else v) for k, v in pairs]
                            new_qs = "&".join(f"{k}={v}" for k, v in new_pairs)
                            test_url = f"{base_url}?{new_qs}"
                            resp = await client.request(method=req_method, url=test_url, headers=auth_headers)
                            body_sample = resp.text[:3000] if resp.status_code == 200 else ""
                            if body_sample and any(p.search(body_sample) for p in LEAK_PATTERNS):
                                leaked = True
                                break
                        if not leaked:
                            for c in checks:
                                c.result = _CheckResult_NOT_VULN
                                c.detail = (f"元分析脚本: 对参数 {target_param} 测试 3 类路径穿越 payload，"
                                           f"未在响应中发现敏感文件内容（/etc/passwd/boot.ini/web.xml）。")
                                c.tested_at = _time.time()
                                total_cleared += 1
                        # 命中了的留给 LLM 详细验证（可能是误判，需要 LLM 看上下文）
                    except (_httpx.HTTPError, _httpx.TimeoutException) as _e:
                        # 网络异常时，保守起见不做判定
                        log.debug("path_traversal 脚本检测请求失败: %s", _e)

            # ============ error_disclosure: 错误信息泄露（基础版） ============
            elif method == "error_disclosure":
                # 错误信息特征（命中即认为有泄露风险）
                ERROR_PATTERNS = [
                    _re.compile(r'(?:Traceback \(most recent call last\)|File ".*?", line \d+)'),  # Python
                    _re.compile(r'at [\w$.]+\([\w$.]+\.java:\d+\)'),                                # Java
                    _re.compile(r'(?:#0\s+\S+\(\)\s+called at|in\s+\S+\.php(?: on line)? \d+)'),    # PHP
                    _re.compile(r'(?:SQLSTATE|sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL)', _re.I),# SQL
                    _re.compile(r'(?:Microsoft\.AspNetCore|System\.Exception|at [\w.]+\.\w+\(\) in)'),# .NET
                    _re.compile(r'(?:DEBUG\s*=\s*True|Whitelabel Error Page|Spring Framework)'),    # 框架调试
                ]
                ED_PAYLOADS = ["'", "%00", "{{7*7}}", "../"]

                for fp in fps:
                    checks = [c for c in fp.checklist if c.vuln_type == check_type and c.result == _CheckResult_PENDING]
                    if not checks or not fp.related_apis:
                        continue
                    api = fp.related_apis[0]
                    parts = api.split(" ", 1)
                    req_method = parts[0] if len(parts) == 2 and parts[0].isupper() else "GET"
                    raw_url = parts[-1] if parts[-1].startswith("http") else f"{target_base}{parts[-1]}"

                    leaked = False
                    try:
                        # 没参数也试一下：直接给 URL 末尾追加 payload
                        if "?" in raw_url:
                            base_url, qs = raw_url.split("?", 1)
                            pairs = [p.split("=", 1) for p in qs.split("&") if "=" in p]
                            if not pairs:
                                continue
                            for payload in ED_PAYLOADS:
                                # 给第一个参数追加畸形值
                                k0, v0 = pairs[0]
                                new_pairs = [(k0, v0 + payload)] + pairs[1:]
                                new_qs = "&".join(f"{k}={v}" for k, v in new_pairs)
                                test_url = f"{base_url}?{new_qs}"
                                resp = await client.request(method=req_method, url=test_url, headers=auth_headers)
                                body_sample = resp.text[:5000]
                                if any(p.search(body_sample) for p in ERROR_PATTERNS):
                                    leaked = True
                                    break
                        else:
                            # URL 段测试（path 末尾追加单引号）
                            for payload in ("%27", "%00"):
                                test_url = raw_url + payload
                                resp = await client.request(method=req_method, url=test_url, headers=auth_headers)
                                body_sample = resp.text[:5000]
                                if any(p.search(body_sample) for p in ERROR_PATTERNS):
                                    leaked = True
                                    break

                        if not leaked:
                            for c in checks:
                                c.result = _CheckResult_NOT_VULN
                                c.detail = (f"元分析脚本: 发送 4 类畸形参数 payload，"
                                           f"响应未泄露堆栈/SQL/框架调试信息。")
                                c.tested_at = _time.time()
                                total_cleared += 1
                        # 命中了的保持 pending，留给 LLM 判定严重等级
                    except (_httpx.HTTPError, _httpx.TimeoutException) as _e:
                        log.debug("error_disclosure 脚本检测请求失败: %s", _e)

            # ============ 未知方法 ============
            else:
                # ★ 持久化记录：LLM 建议了但脚本不支持的方法，用于后续能力扩充
                log.warning("元分析建议脚本方法 '%s' 暂不支持，保留给 LLM (涉及 %d 个功能点, check_type=%s)",
                           method, len(fps), check_type)
                from core.parallel.grouping import _record_unsupported_method
                _record_unsupported_method(method, check_type, fids, batch.get("reason", ""))

    # 保存结果
    if total_cleared > 0 and session.sitemap:
        session.sitemap.save()
        metrics.inc("script_cleared", total_cleared)

    return {"cleared": total_cleared}


# ---- CheckResult 常量引用（避免函数内反复 import） ----
from core.sitemap import CheckResult as _CR

_CheckResult_PENDING = _CR.PENDING
_CheckResult_NOT_VULN = _CR.NOT_VULN


async def _batch_test_unauth(session: "AgentSession", deferred_fps: list["FeaturePoint"]) -> dict:
    """批量测试 deferred 功能点的未授权访问：对每个功能点的 page_url 或 related_apis 发 HTTP 请求。

    不走 LLM，纯代码测试。返回 200/30x = 可能存在未授权访问, 401/403 = 需认证。
    """
    import httpx
    from core.sitemap import CheckResult

    target_base = session.sitemap.target.rstrip("/") if session.sitemap else ""
    tested = 0
    accessible = 0
    blocked = 0

    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=False) as client:
        for fp in deferred_fps:
            # 确定要测的 URL
            test_urls = []
            if fp.related_apis:
                for api in fp.related_apis:
                    parts = api.split(" ", 1)
                    if len(parts) == 2 and parts[0].isupper():
                        test_urls.append((parts[0], parts[1] if parts[1].startswith("http") else f"{target_base}{parts[1]}"))
                    else:
                        url = api if api.startswith("http") else f"{target_base}{api}"
                        test_urls.append(("GET", url))
            elif fp.page_url:
                # SPA 路由：前端路由全返回 200，需要推断后端 API
                from urllib.parse import urlparse
                parsed = urlparse(fp.page_url)
                path = parsed.path.rstrip("/")
                # /admin/monitor/battery → 测 /api/monitor/battery 和 /api/battery
                path_parts = [p for p in path.split("/") if p and p != "admin"]
                if path_parts:
                    # 推断 API：/api/完整路径 和 /api/最后一段
                    api_path = "/api/" + "/".join(path_parts)
                    test_urls.append(("GET", f"{target_base}{api_path}"))
                    if len(path_parts) > 1:
                        test_urls.append(("GET", f"{target_base}/api/{path_parts[-1]}"))
                # 也测前端页面本身（SPA 可能有 SSR 或 API 路由）
                url = fp.page_url if fp.page_url.startswith("http") else f"{target_base}{fp.page_url}"
                test_urls.append(("GET", url))
            else:
                # 无 URL 可测，标 skipped
                fp.checklist[0].result = CheckResult.SKIPPED
                fp.checklist[0].detail = "无可测试的 URL（功能点未关联 API 或页面地址）"
                fp.test_status = TestStatus.TESTED
                session.sitemap.save()
                continue

            # 发请求测试
            is_accessible = False
            details = []
            # ★ 过滤静态资源 URL
            _STATIC_EXTS = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                            '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp')
            filtered_urls = []
            for method, url in test_urls[:3]:
                path_lower = url.split('?')[0].lower()
                if any(path_lower.endswith(ext) for ext in _STATIC_EXTS):
                    continue  # 跳过静态资源
                if any(seg in path_lower for seg in ('/assets/', '/static/', '/dist/')):
                    continue
                filtered_urls.append((method, url))

            for method, url in filtered_urls:
                try:
                    if method.upper() == "POST":
                        resp = await client.post(url, json={})
                    elif method.upper() == "PUT":
                        resp = await client.put(url, json={})
                    elif method.upper() == "DELETE":
                        resp = await client.delete(url)
                    else:
                        resp = await client.get(url)

                    status = resp.status_code
                    body_preview = resp.text[:100] if resp.text else ""
                    details.append(f"{method} {url} → {status}")

                    if status in (200, 201, 204):
                        # SPA 前端页面返回 200 是正常的（都是 index.html），不算未授权
                        # 只有 API 端点返回 200 + 有业务数据才算
                        is_api = "/api/" in url
                        is_html = "text/html" in resp.headers.get("content-type", "")
                        ct = resp.headers.get("content-type", "").lower()
                        is_static = any(t in ct for t in ("javascript", "css", "image/", "font/"))
                        if is_api and not is_html and not is_static:
                            is_accessible = True
                            details[-1] += " ⚠️ API可未授权访问"
                        elif is_html:
                            details[-1] += " (前端页面，SPA正常返回)"
                        elif is_static:
                            details[-1] += " (静态资源，正常公开)"
                        else:
                            # 非 API 路径、非 HTML、非静态资源 → 谨慎处理，不直接标为未授权
                            body_text = resp.text[:200] if resp.text else ""
                            if any(kw in body_text for kw in ('"code"', '"data"', '"msg"', '"result"', '"total"')):
                                is_accessible = True
                                details[-1] += " ⚠️ 疑似API可未授权访问"
                            else:
                                details[-1] += " (非API，跳过)"
                    elif status in (301, 302):
                        location = resp.headers.get("location", "")
                        if "login" in location.lower():
                            details[-1] += f" (重定向到登录: {location})"
                        else:
                            details[-1] += f" (重定向: {location})"
                    elif status in (401, 403):
                        details[-1] += " (需认证)"
                    elif status == 404:
                        details[-1] += " (接口不存在)"

                except (_httpx.HTTPError, _httpx.TimeoutException) as e:
                    details.append(f"{method} {url} → 请求失败: {e}")

            # 标记结果
            # ★ 2026-05-25 改造：不再直接标 VULNERABLE，而是保留 PENDING 交给 LLM 判断
            check = fp.checklist[0]
            detail_text = "; ".join(details)
            if is_accessible:
                # 不直接标记 vulnerable！只记录线索，保持 pending 让 LLM + SKILL 做专业判断
                check.result = CheckResult.PENDING
                check.detail = (
                    f"⚡ 脚本初筛：疑似未授权访问（需 LLM 复核）: {detail_text}\n"
                    f"⚠️ 注意：仅凭 HTTP 200 + 无 cookie 不能断定为漏洞，"
                    f"需确认接口是否返回非公开的敏感数据。"
                )
                fp.test_status = TestStatus.NOT_TESTED  # 保持待测，让 LLM 后续捞到
                accessible += 1
            else:
                check.result = CheckResult.NOT_VULN
                check.detail = f"需要认证: {detail_text}"
                fp.test_status = TestStatus.TESTED
                blocked += 1

            check.tested_at = _time.time()
            fp.test_started_at = _time.time()
            fp.test_finished_at = _time.time()
            tested += 1

            session.sitemap.save()

    return {"tested": tested, "accessible": accessible, "blocked": blocked}


# ============================================================
# 脚本化初筛：规则化检测，不调 LLM，只标记确定安全的项
# ============================================================

async def _batch_prelim_test(session: "AgentSession", features: list["FeaturePoint"]) -> dict:
    """对所有功能点的 checklist 做规则化初筛。

    只标记**确定安全**的项为 not_vuln，不确定的保持 pending 留给 LLM。
    不会产生误报（宁可漏标，不会错标）。

    检测项：
    - 信息泄露：响应无敏感字段 → not_vuln
    - CORS：无 ACAO 头或值不是 * 且不回显 Origin → not_vuln
    - SQL注入初筛：参数加 ' 无 SQL 报错 → 保持 pending（不确定）
    """
    import httpx
    from core.sitemap import CheckResult

    if not session.sitemap:
        return {"tested": 0, "cleared": 0}

    target_base = session.sitemap.target.rstrip("/")

    # 收集 session_info 中的认证信息
    auth_headers = {}
    try:
        from core.mcp_bridge import _page
        if _page and not _page.is_closed():
            cookies = await _page.context.cookies()
            access_token = ""
            for c in cookies:
                if c["name"].lower() in ("access_token", "token", "authorization"):
                    access_token = c["value"]
            if access_token:
                auth_headers["Authorization"] = f"Bearer {access_token}"
                auth_headers["Cookie"] = f"access_token={access_token}"
    except (RuntimeError, ValueError) as _auth_err:
        log.warning("初筛: 从浏览器获取认证信息失败: %s", _auth_err)

    # 如果没从浏览器拿到，从 api_samples 中提取
    if not auth_headers and session.sitemap.api_samples:
        for sample in session.sitemap.api_samples.values():
            h = sample.get("headers", {})
            if h.get("Authorization") or h.get("authorization"):
                auth_headers = {k: v for k, v in h.items()
                               if k.lower() in ("authorization", "cookie", "proxy-connection")}
                break

    if not auth_headers:
        log.warning("初筛: 未获取到任何认证信息，未授权访问检测将跳过（无法做有/无认证对比）")

    tested = 0
    cleared = 0

    # 敏感数据值格式正则（匹配实际内容，不是字段名）
    SENSITIVE_VALUE_PATTERNS = {
        "手机号": _re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)'),
        "身份证": _re.compile(r'(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)'),
        "银行卡": _re.compile(r'(?<!\d)(?:62|4\d|5[1-5])\d{14,17}(?!\d)'),
        "邮箱": _re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "IPv4内网地址": _re.compile(r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)'),
        "密码/密钥": _re.compile(r'"(?:password|passwd|pwd|secret|api_key|private_key|token)"\s*:\s*"[^"]{6,}"', _re.IGNORECASE),
        "JWT Token": _re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'),
        "MD5哈希": _re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])'),
        "车牌号": _re.compile(r'[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-Z][A-HJ-NP-Z0-9]{5}'),
        "护照号": _re.compile(r'(?<![A-Z0-9])[A-Z]\d{8}(?![A-Z0-9])'),
        "社会信用代码": _re.compile(r'[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}'),
        "地址信息": _re.compile(r'(?:省|市|区|县|街道|路|号|栋|单元|室).{2,10}(?:省|市|区|县|街道|路|号|栋|单元|室)'),
    }
    # 当前用户自身数据的标识（如果响应中只有一条记录且无列表，可能是当前用户自己的）
    LIST_PATTERN = _re.compile(r'"(records|list|items|data|rows)"\s*:\s*\[')

    async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
        for fp in features:
            if not fp.related_apis:
                continue

            # 取第一个 API 做检测
            primary_api = fp.related_apis[0]
            parts = primary_api.split(" ", 1)
            if len(parts) == 2 and parts[0].isupper():
                method, url = parts[0], parts[1]
            else:
                method, url = "GET", primary_api
            if not url.startswith("http"):
                url = f"{target_base}{url}"

            # 发一个带认证的请求，拿到正常响应
            try:
                req_headers = dict(auth_headers)
                resp = await client.request(method=method, url=url, headers=req_headers)
                status = resp.status_code
                body = resp.text[:5000]
                resp_headers = dict(resp.headers)
            except (_httpx.HTTPError, _httpx.TimeoutException):
                continue

            if status not in (200, 201):
                # 接口异常，跳过初筛
                continue

            # ========== 信息泄露初筛 ==========
            info_leak_checks = [c for c in fp.checklist
                                if c.vuln_type == "信息泄露" and c.result == CheckResult.PENDING]
            if info_leak_checks:
                # 逐个正则匹配响应体中的敏感数据值
                found_types = []
                for sens_type, pattern in SENSITIVE_VALUE_PATTERNS.items():
                    matches = pattern.findall(body)
                    if matches:
                        # 过滤掉明显的误报
                        real_matches = []
                        for m in matches[:3]:
                            val = m if isinstance(m, str) else m[0] if m else ""
                            # 邮箱过滤：排除 example.com 等测试邮箱
                            if sens_type == "邮箱" and any(x in val.lower() for x in ("example", "test", "noreply", "@placeholder")):
                                continue
                            # MD5过滤：排除常见的固定 hash（如 etag、版本号）
                            if sens_type == "MD5哈希" and len(set(val)) < 6:
                                continue
                            real_matches.append(val)
                        if real_matches:
                            found_types.append(f"{sens_type}({real_matches[0][:20]}...)")

                if not found_types:
                    # 响应中没有任何真实敏感数据 → 确定安全
                    for c in info_leak_checks:
                        c.result = CheckResult.NOT_VULN
                        c.detail = (f"脚本初筛: 响应体({len(body)}字符)经正则检测，"
                                   f"未发现手机号/身份证/银行卡/邮箱/内网IP/密码/JWT等敏感数据。")
                        c.tested_at = _time.time()
                        cleared += 1
                        tested += 1
                # 如果检测到敏感数据 → 保持 pending 让 LLM 判断（可能是当前用户自己的数据）

            # ========== CORS 初筛 ==========
            cors_checks = [c for c in fp.checklist
                          if "CORS" in c.vuln_type.upper() and c.result == CheckResult.PENDING]
            if cors_checks:
                # 发一个带 Origin 的请求
                try:
                    cors_headers = dict(auth_headers)
                    cors_headers["Origin"] = "https://evil-attacker.com"
                    cors_resp = await client.request(method=method, url=url, headers=cors_headers)
                    acao = cors_resp.headers.get("access-control-allow-origin", "")

                    if not acao:
                        # 没有 ACAO 头 → 确定安全
                        for c in cors_checks:
                            c.result = CheckResult.NOT_VULN
                            c.detail = "脚本初筛: 响应中无 Access-Control-Allow-Origin 头，不存在 CORS 配置问题。"
                            c.tested_at = _time.time()
                            cleared += 1
                            tested += 1
                    elif acao == "https://evil-attacker.com":
                        # 回显了攻击者的 Origin → 疑似有问题，留给 LLM
                        pass
                    elif acao == "*":
                        # 允许所有来源，但需要判断接口是否需要认证
                        # 如果是需要认证的接口用了 *，可能有问题 → 留给 LLM
                        pass
                    else:
                        # 返回了固定的白名单 → 确定安全
                        for c in cors_checks:
                            c.result = CheckResult.NOT_VULN
                            c.detail = f"脚本初筛: CORS 配置了固定白名单 ({acao})，未回显攻击者 Origin。"
                            c.tested_at = _time.time()
                            cleared += 1
                            tested += 1
                except (_httpx.HTTPError, _httpx.TimeoutException) as _e:
                    log.debug("CORS 初筛请求失败: %s", _e)

            # ========== 未授权访问初筛（非 deferred 功能点）==========
            unauth_checks = [c for c in fp.checklist
                            if c.vuln_type == "未授权访问" and c.result == CheckResult.PENDING]
            if unauth_checks and auth_headers:
                try:
                    # 不带认证重发
                    noauth_resp = await client.request(method=method, url=url)
                    noauth_status = noauth_resp.status_code

                    if noauth_status in (401, 403):
                        for c in unauth_checks:
                            c.result = CheckResult.NOT_VULN
                            c.detail = (f"脚本初筛: 去掉认证后返回 {noauth_status}，鉴权有效。"
                                       f"(带认证={status}, 无认证={noauth_status})")
                            c.tested_at = _time.time()
                            cleared += 1
                            tested += 1
                    elif noauth_status == status:
                        # 带不带认证都返回 200 → 疑似未授权，留给 LLM 深入判断
                        pass
                except (_httpx.HTTPError, _httpx.TimeoutException) as _e:
                    log.debug("未授权访问初筛请求失败: %s", _e)

    # 保存
    if cleared > 0:
        session.sitemap.save()

    return {"tested": tested, "cleared": cleared}


# ============================================================
# FastScanner 结果转换工具
# ============================================================

def convert_findings_to_checklist_results(
    findings: list,
    features: list["FeaturePoint"],
) -> int:
    """将 FastScanner findings 回写到对应功能点的 checklist 项。

    对每个 finding，遍历 features 按 URL 匹配 related_apis，找到后调用
    fp.mark_check 标记为 VULNERABLE。

    Returns:
        命中（已标记）的功能点数。
    """
    from core.sitemap import CheckResult as _CR, TestStatus as _TS

    hit = 0
    for finding in findings:
        finding_url = (getattr(finding, "url", None) or "").lower().rstrip("/")
        if not finding_url:
            continue
        for fp in features:
            matched = False
            for api in (fp.related_apis or []):
                api_url = api.split(" ", 1)[-1].lower().rstrip("/") if " " in api else api.lower().rstrip("/")
                if finding_url == api_url or finding_url in api_url or api_url in finding_url:
                    # ★ 传递 evidence_quality 到 evidence_response 末尾（供 harm_validation 解析）
                    _eq = getattr(finding, "evidence_quality", "") or ""
                    _ev = getattr(finding, "evidence", "") or ""
                    if _eq:
                        _ev = f"{_ev}\n[evidence_quality={_eq}]"
                    marked = fp.mark_check(
                        vuln_type=finding.vuln_type,
                        result=_CR.VULNERABLE,
                        detail=getattr(finding, "detail", ""),
                        severity=getattr(finding, "severity", ""),
                        evidence_request=getattr(finding, "payload", ""),
                        evidence_response=_ev,
                        fix_suggestion=getattr(finding, "fix_suggestion", ""),
                    )
                    if marked:
                        fp.test_status = _TS.VULN_FOUND
                        hit += 1
                        matched = True
                        break
            if matched:
                break

    return hit
