"""
Test Templates — 测试执行模板生成器

⚠️ ===== 此模块已于 2026-05-19 标记为「软废弃」 =====

历史：曾被 worker_agent 调用，注入到子 Agent 的 prompt 中作为 Step 1/2/3 死板步骤模板。
问题：与 SKILL 方法论冲突，把 LLM 锁死在最浅层测试动作（如 IDOR 只会改 ID 重发）。

现状：
- worker_agent._build_group_task_message **已不再调用** generate_test_steps()
- 改为 SKILL 主导：LLM 加载 SKILL，按 SKILL 主体的 Phase 步骤 + SKILL 末尾的「最低必测自检清单」执行
- 主 Agent 的浏览器测试模板（generate_browser_test_steps）**仍然在用**，因为浏览器测试的工具调用比 HTTP 复杂，需要具体步骤指引

保留原因：
- 给 SKILL 写作者作为「常见漏洞类型的工具调用语法范例」参考
- 主 Agent 浏览器测试模板（_BROWSER_TEMPLATE_MAP）仍然有效

⛔ 不要在新的代码中调用 generate_test_steps()。如果你看到这段代码并打算调它，
   请改为引导 LLM 用 knowledge_load_skill() 加载对应 SKILL 方法论。

每个模板包含：
- 具体的 proxy_send_request / browser_* 调用参数
- 预期的判断逻辑（什么算 vulnerable，什么算 not_vuln）
- checklist_mark 调用参数
"""

from __future__ import annotations

from urllib.parse import urlparse, urlencode, parse_qs


def generate_test_steps(
    vuln_type: str,
    api: str,           # "METHOD https://target.com/api/path" 或 "METHOD /path"
    feature_id: str,
    auth_cookie: str = "",
    page_url: str = "",
    form_fields: list[str] | None = None,
) -> str:
    """根据漏洞类型和 API 生成具体测试步骤。

    返回 Markdown 格式的步骤说明，直接嵌入子 Agent 的 user prompt。
    """
    method, url = _parse_api(api)
    headers_with_auth = f'{{"Cookie": "{auth_cookie}"}}' if auth_cookie else "{}"
    headers_no_auth = "{}"

    generator = _TEMPLATE_MAP.get(vuln_type)
    if generator:
        return generator(
            method=method, url=url, feature_id=feature_id,
            headers_auth=headers_with_auth, headers_no=headers_no_auth,
            page_url=page_url, form_fields=form_fields or [],
        )

    # 未知漏洞类型 → 通用模板
    return _generic_template(
        vuln_type=vuln_type, method=method, url=url,
        feature_id=feature_id, headers_auth=headers_with_auth,
    )


def generate_browser_test_steps(
    vuln_type: str,
    page_url: str,
    feature_id: str,
    form_selector: str = "",
    input_selector: str = "",
) -> str:
    """生成浏览器测试的具体操作步骤。"""
    generator = _BROWSER_TEMPLATE_MAP.get(vuln_type)
    if generator:
        return generator(
            page_url=page_url, feature_id=feature_id,
            form_selector=form_selector, input_selector=input_selector,
        )
    return f"  用浏览器访问 {page_url}，手动测试 {vuln_type}，完成后 checklist_mark"


# ============================================================
# HTTP 测试模板
# ============================================================

def _tmpl_unauth(method, url, feature_id, headers_auth, headers_no, **kw):
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 记录正常响应的 status 和 body 长度\n"
        f"  Step 2: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_no})`\n"
        f"         → 去掉 Cookie/Token，看响应\n"
        f"  Step 3: 判断 → 如果 Step 2 也返回了数据（status=200 且 body 有业务数据）→ vulnerable\n"
        f"         → 如果 Step 2 返回 401/403/302 → not_vuln\n"
        f"  Step 4: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"未授权访问\", result=\"...\", detail=\"Step2返回status=xxx\")`"
    )


def _tmpl_idor(method, url, feature_id, headers_auth, headers_no, **kw):
    # 检测 URL 中是否有 ID 参数
    parsed = urlparse(url)
    path_parts = parsed.path.rstrip("/").split("/")
    # 找数字 ID
    id_in_path = any(p.isdigit() for p in path_parts)
    query_params = parse_qs(parsed.query)
    id_params = [k for k in query_params if "id" in k.lower()]

    if id_in_path:
        # /api/user/1001 → 改成 /api/user/1002
        modified_path = "/".join(
            ("9999" if p.isdigit() else p) for p in path_parts
        )
        modified_url = url.replace(parsed.path, modified_path)
        return (
            f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
            f"         → 正常请求，记录响应\n"
            f"  Step 2: `proxy_send_request(method=\"{method}\", url=\"{modified_url}\", headers={headers_auth})`\n"
            f"         → 改 ID 为其他用户的，看是否返回数据\n"
            f"  Step 3: `proxy_diff_responses(flow_id_a=\"Step1的flow_id\", flow_id_b=\"Step2的flow_id\")`\n"
            f"         → 对比差异\n"
            f"  Step 4: 判断 → Step 2 返回了其他用户的数据 → vulnerable\n"
            f"         → Step 2 返回 403/404 → not_vuln\n"
            f"  Step 5: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"IDOR越权\", result=\"...\", detail=\"改ID后响应...\")`"
        )
    elif id_params:
        param = id_params[0]
        return (
            f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
            f"         → 正常请求\n"
            f"  Step 2: 修改参数 `{param}` 为其他用户的值（如 +1 或 9999）\n"
            f"         `proxy_send_request(method=\"{method}\", url=\"{url.split('?')[0]}?{param}=9999\", headers={headers_auth})`\n"
            f"  Step 3: 对比两次响应 → 如果返回了不同用户的数据 → vulnerable\n"
            f"  Step 4: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"IDOR越权\", result=\"...\", detail=\"...\")`"
        )
    else:
        return (
            f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
            f"         → 观察响应中是否有 ID 字段（user_id, order_id 等）\n"
            f"  Step 2: 如果有 ID → 构造修改 ID 的请求重发\n"
            f"  Step 3: 如果没有明显 ID → `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"IDOR越权\", result=\"skipped\", detail=\"无ID参数\")`"
        )


def _tmpl_sqli(method, url, feature_id, headers_auth, headers_no, **kw):
    # 找查询参数
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    target_param = ""
    for k in params:
        if k.lower() in ("keyword", "search", "query", "q", "name", "username", "filter", "id"):
            target_param = k
            break
    if not target_param and params:
        target_param = list(params.keys())[0]

    if target_param:
        base = url.split("?")[0]
        return (
            f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{base}?{target_param}=test'\", headers={headers_auth})`\n"
            f"         → 单引号测试，看响应是否有 SQL 报错\n"
            f"  Step 2: `proxy_send_request(method=\"{method}\", url=\"{base}?{target_param}=test' OR 1=1--\", headers={headers_auth})`\n"
            f"         → 万能条件测试\n"
            f"  Step 3: `proxy_send_request(method=\"{method}\", url=\"{base}?{target_param}=test' AND SLEEP(3)--\", headers={headers_auth})`\n"
            f"         → 时间盲注（响应时间 >3 秒 = vulnerable）\n"
            f"  Step 4: 判断 → 有 SQL 报错/数据变化/延时 → vulnerable，否则 → not_vuln\n"
            f"  Step 5: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"SQL注入\", result=\"...\", detail=\"参数{target_param}测试结果...\")`"
        )
    elif method == "POST":
        return (
            f"  Step 1: `proxy_send_request(method=\"POST\", url=\"{url}\", headers={headers_auth}, body=\"...\")`\n"
            f"         → 先正常发一次，看 body 参数有哪些\n"
            f"  Step 2: 对每个文本类参数加 `'` 单引号重发，看有无 SQL 报错\n"
            f"  Step 3: 如果有报错 → 继续用 `' OR 1=1--` 和时间盲注验证\n"
            f"  Step 4: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"SQL注入\", result=\"...\", detail=\"...\")`"
        )
    else:
        return (
            f"  Step 1: 先 `proxy_send_request` 正常请求，观察有无查询参数\n"
            f"  Step 2: 如果无参数 → `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"SQL注入\", result=\"skipped\", detail=\"无可注入参数\")`"
        )


def _tmpl_csrf(method, url, feature_id, headers_auth, headers_no, **kw):
    if method in ("GET", "HEAD", "OPTIONS"):
        return (
            f"  GET 请求通常不需要 CSRF 防护\n"
            f"  `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"CSRF\", result=\"skipped\", detail=\"GET请求，不适用\")`"
        )
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 正常请求，观察请求中是否有 CSRF token（X-CSRF-Token / _token / csrf 参数）\n"
        f"  Step 2: 如果有 token → 去掉 token 重发\n"
        f"         `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})` （去掉 csrf 参数/header）\n"
        f"  Step 3: 判断 → 去掉 token 后仍然成功 → vulnerable\n"
        f"         → 返回 403/拒绝 → not_vuln\n"
        f"         → 请求中本来就没有 csrf token → vulnerable（缺少防护）\n"
        f"  Step 4: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"CSRF\", result=\"...\", detail=\"...\")`"
    )


def _tmpl_amount(method, url, feature_id, headers_auth, headers_no, **kw):
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 正常请求，观察请求体/URL 中是否有 price/amount/quantity 参数\n"
        f"  Step 2: 修改金额参数为 1（分）或 0 重发\n"
        f"  Step 3: 修改金额参数为 -1（负数）重发\n"
        f"  Step 4: 修改数量参数为 0 或 9999999 重发\n"
        f"  Step 5: 判断 → 服务端接受了篡改值 → vulnerable\n"
        f"  Step 6: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"金额篡改\", result=\"...\", detail=\"...\")`"
    )


def _tmpl_vertical_escalation(method, url, feature_id, headers_auth, headers_no, **kw):
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 用普通用户身份请求管理接口\n"
        f"  Step 2: 判断 → 返回 200 且有管理数据 → vulnerable（垂直越权）\n"
        f"         → 返回 403/401 → not_vuln\n"
        f"  Step 3: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"垂直越权\", result=\"...\", detail=\"...\")`"
    )


def _tmpl_info_leak(method, url, feature_id, headers_auth, headers_no, **kw):
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"  Step 2: `proxy_get_flow_detail(flow_id=\"Step1的flow_id\")`\n"
        f"         → 检查响应中是否有：手机号、身份证、邮箱、密码hash、内部IP、调试信息、SQL语句\n"
        f"  Step 3: 判断 → 有敏感信息泄露 → vulnerable，无 → not_vuln\n"
        f"  Step 4: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"信息泄露\", result=\"...\", detail=\"泄露了xxx字段\")`"
    )


def _tmpl_password_reset(method, url, feature_id, headers_auth, headers_no, **kw):
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 正常发起密码重置，观察流程\n"
        f"  Step 2: 检查重置 token 是否可预测（短数字验证码？连续递增？时间戳？）\n"
        f"  Step 3: 检查是否可以通过修改 Host 头进行 Host 投毒\n"
        f"         `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={{...\"Host\": \"evil.com\"}})`\n"
        f"  Step 4: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"密码重置逻辑\", result=\"...\", detail=\"...\")`"
    )


def _tmpl_file_upload(method, url, feature_id, headers_auth, headers_no, **kw):
    return (
        f"  Step 1: 用正常文件请求 `proxy_send_request(method=\"POST\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 观察上传接口的参数格式\n"
        f"  Step 2: 尝试修改文件扩展名（.php / .jsp / .aspx）重发\n"
        f"  Step 3: 尝试修改 Content-Type 绕过\n"
        f"  Step 4: 如果上传成功 → 访问上传路径确认是否可执行\n"
        f"  Step 5: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"文件上传绕过\", result=\"...\", detail=\"...\")`"
    )


def _tmpl_export_authz(method, url, feature_id, headers_auth, headers_no, **kw):
    """越权导出：不带认证 / 低权限用户能否导出全量数据。"""
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 正常请求导出接口，记录返回数据量和格式\n"
        f"  Step 2: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_no})`\n"
        f"         → 去掉认证，看是否仍能导出数据\n"
        f"  Step 3: 如果 Step 2 返回了文件/数据 → vulnerable（越权导出）\n"
        f"  Step 4: 检查导出接口有无 limit/page 参数 → 改为极大值（如 size=999999）看能否一次导出全量\n"
        f"  Step 5: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"越权导出\", result=\"...\", detail=\"...\")`"
    )


def _tmpl_batch_authz(method, url, feature_id, headers_auth, headers_no, **kw):
    """批量操作越权：batch delete/update 接口中混入其他用户的 ID。"""
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth}, body='{{\"ids\":[1]}}')`\n"
        f"         → 正常请求，观察批量操作的参数格式（ids/idList/records 等）\n"
        f"  Step 2: 在 ids 数组中混入其他角色/租户的 ID（如 [自己的ID, 9999]）\n"
        f"         `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth}, body='{{\"ids\":[自己的ID, 9999]}}')`\n"
        f"  Step 3: 如果 9999 对应的数据也被操作了（删除/修改成功）→ vulnerable\n"
        f"  Step 4: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"IDOR越权\", result=\"...\", detail=\"批量操作中越权...\")`"
    )


def _tmpl_status_tamper(method, url, feature_id, headers_auth, headers_no, **kw):
    """状态篡改：修改 status/state/role 等枚举字段绕过业务流程。"""
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 正常请求，观察请求体/响应中的 status/state/role/type 字段\n"
        f"  Step 2: 修改 status 字段值（如 pending→approved, 0→1, draft→published）重发\n"
        f"  Step 3: 修改 role 字段值（如 user→admin, 0→1）重发\n"
        f"  Step 4: 判断 → 服务端接受了篡改值且生效 → vulnerable（状态篡改/权限提升）\n"
        f"  Step 5: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"状态篡改\", result=\"...\", detail=\"...\")`"
    )


def _tmpl_mass_assignment(method, url, feature_id, headers_auth, headers_no, **kw):
    """Mass Assignment：在正常请求中附加额外字段（role/isAdmin/price）。"""
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 正常请求，记录请求体中的字段\n"
        f"  Step 2: 在请求体中额外添加敏感字段重发：\n"
        f"         `{{...原有字段..., \"role\":\"admin\", \"isAdmin\":true, \"price\":0, \"status\":\"approved\"}}`\n"
        f"  Step 3: 查看响应和后续 GET 请求 → 如果新增的字段被写入了 → vulnerable\n"
        f"  Step 4: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"Mass Assignment\", result=\"...\", detail=\"...\")`"
    )


def _generic_template(vuln_type, method, url, feature_id, headers_auth):
    return (
        f"  Step 1: `proxy_send_request(method=\"{method}\", url=\"{url}\", headers={headers_auth})`\n"
        f"         → 先正常请求，观察响应\n"
        f"  Step 2: 根据 {vuln_type} 的方法论（已注入上下文或用 knowledge_search 搜索）执行测试\n"
        f"  Step 3: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"{vuln_type}\", result=\"...\", detail=\"...\")`"
    )


# ============================================================
# 浏览器测试模板
# ============================================================

def _btmpl_xss(page_url, feature_id, form_selector="", input_selector="", **kw):
    sel = input_selector or "input[type=text], input[name=keyword], input[name=search], textarea"
    return (
        f"  Step 1: `browser_goto(url=\"{page_url}\")`\n"
        f"  Step 2: `browser_fill(selector=\"{sel}\", value=\"<img src=x onerror=alert(1)>\")`\n"
        f"  Step 3: 提交表单 `browser_click(selector=\"button[type=submit], .search-btn, .btn-primary\")`\n"
        f"  Step 4: `browser_get_content()` → 检查响应 HTML 中是否有未转义的 `<img src=x onerror=alert(1)>`\n"
        f"  Step 5: 如果 payload 原样出现在 HTML 中 → vulnerable\n"
        f"         如果被转义（&lt;img）或被过滤 → not_vuln\n"
        f"  Step 6: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"XSS\", result=\"...\", detail=\"...\")`"
    )


def _btmpl_csrf_browser(page_url, feature_id, **kw):
    return (
        f"  Step 1: `browser_goto(url=\"{page_url}\")`\n"
        f"  Step 2: `browser_get_content()` → 查找表单中是否有 csrf_token / _token 隐藏字段\n"
        f"  Step 3: 如果没有 CSRF token → vulnerable（敏感操作缺少 CSRF 防护）\n"
        f"         如果有 → not_vuln\n"
        f"  Step 4: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"CSRF\", result=\"...\", detail=\"...\")`"
    )


def _btmpl_captcha(page_url, feature_id, **kw):
    return (
        f"  Step 1: `browser_goto(url=\"{page_url}\")`\n"
        f"  Step 2: `browser_get_content()` → 查找验证码元素（img[src*=captcha], .captcha, #captcha）\n"
        f"  Step 3: 尝试不填验证码直接提交 → 如果通过 → vulnerable\n"
        f"  Step 4: 尝试重复提交同一验证码 → 如果第二次也通过 → vulnerable（验证码可重放）\n"
        f"  Step 5: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"验证码绕过\", result=\"...\", detail=\"...\")`"
    )


def _btmpl_stored_xss(page_url, feature_id, **kw):
    return (
        f"  Step 1: `browser_goto(url=\"{page_url}\")`\n"
        f"  Step 2: 找到输入框 → `browser_fill(selector=\"textarea, input[type=text]\", value=\"<script>alert('XSS')</script>\")`\n"
        f"  Step 3: 提交 → `browser_click(selector=\"button[type=submit]\")`\n"
        f"  Step 4: 刷新页面 `browser_goto(url=\"{page_url}\")`\n"
        f"  Step 5: `browser_get_content()` → 检查提交的内容是否原样展示（未转义）\n"
        f"  Step 6: `checklist_mark(feature_id=\"{feature_id}\", vuln_type=\"存储型XSS\", result=\"...\", detail=\"...\")`"
    )


# ============================================================
# 映射表
# ============================================================

_TEMPLATE_MAP = {
    "未授权访问": _tmpl_unauth,
    "IDOR越权": _tmpl_idor,
    "越权查看": _tmpl_idor,
    "越权操作": _tmpl_idor,
    "SQL注入": _tmpl_sqli,
    "CSRF": _tmpl_csrf,
    "金额篡改": _tmpl_amount,
    "数量篡改": _tmpl_amount,
    "垂直越权": _tmpl_vertical_escalation,
    "信息泄露": _tmpl_info_leak,
    "密码重置逻辑": _tmpl_password_reset,
    "文件上传绕过": _tmpl_file_upload,
    "越权导出": _tmpl_export_authz,
    "状态篡改": _tmpl_status_tamper,
    "Mass Assignment": _tmpl_mass_assignment,
}

_BROWSER_TEMPLATE_MAP = {
    "XSS": _btmpl_xss,
    "反射型XSS": _btmpl_xss,
    "存储型XSS": _btmpl_stored_xss,
    "CSRF": _btmpl_csrf_browser,
    "验证码绕过": _btmpl_captcha,
}


def _parse_api(api: str) -> tuple[str, str]:
    """解析 "METHOD url" 格式。"""
    parts = api.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return parts[0].upper(), parts[1]
    return "GET", api
