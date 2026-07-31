---
name: no-auth-quick-test
description: "无账号登录页面快速测试策略。当用户只给了一个登录页面 URL 且没有提供账号密码时使用。在没有认证凭据的情况下，能测试的范围有限，应在3分钟内快速完成外围测试。不要花大量时间在无法深入的功能上。"
priority: 9
vuln_types:
  - 未授权访问
  - 信息泄露
  - 登录绕过
  - 默认口令
  - 源码泄露
triggers:
  - 登录页
  - login
  - no-auth
  - 无账号
  - 未登录
  - Cookie缺失
  - Authorization缺失
  - Vite
  - swagger
  - actuator
synonyms:
  - unauthenticated-test
  - no-login-test
  - no-auth-check
metadata:
  tags: "登录页面,无账号,快速测试,外围,login,no-auth,unauthorized"
  category: "strategy"
  authority: "expert"
---

# 无账号登录页面快速测试策略

> **没有账号密码时，能测的东西很有限，3 分钟内完成。不要反复分析同一个页面。**

## 适用场景

- 用户给了登录页面 URL，但没有提供账号密码
- 注册功能不可用或不存在
- 无法获取有效的认证 Token

## 测试清单（按顺序，全部完成后结束）

### 1. JS 分析与 API 发现（1 分钟）
```
1. js_extract_apis → 查看所有资源文件清单
2. 选择业务 JS 调用 js_analyze_selected 深度分析
3. 关注 JS 中是否有：
   - 硬编码的 API Key / Token / 密码
   - 内部 IP / 域名
   - 管理后台路径
   - 调试接口
   - Source Map 泄露（等于前端源码泄露）
```

### 1.5 Vite/Dev Server 检测（必做！发现即高危）

> 只要目标有前端页面，就必须检测。Vite Dev Server 暴露在生产环境 = 服务器文件系统可读。

```
Step 1: 判断是否 Vite Dev Server
  proxy_send_request GET /@vite/client → 200 = Vite Dev Server
  proxy_send_request GET /src/main.ts → 200 且返回 JS 代码 = 源码泄露确认

Step 2: 如果是 Vite → 立即测 @fs 路径遍历（CVE-2023-34092 等）
  proxy_send_request GET /@fs/etc/passwd
  proxy_send_request GET /@fs/proc/self/environ
  proxy_send_request GET /@fs/app/.env
  proxy_send_request GET /@fs/app/package.json
  → 任意一个返回 200 + 文件内容 = 严重漏洞（任意文件读取）

Step 3: 如果 @fs 可用 → 深入读取敏感文件
  /@fs/app/.env                → 数据库密码、JWT_SECRET、API_KEY
  /@fs/app/.env.local          → 本地环境变量（常含真实密码）
  /@fs/app/prisma/seed.ts      → 种子数据中的硬编码用户密码
  /@fs/app/docker-compose.yml  → 数据库连接串
  /@fs/app/server/index.ts     → 后端入口代码

Step 4: 即使 @fs 被禁 → Vite Dev Server 仍可读 /src/ 下全部源码
  /src/router/index.ts         → 完整路由表（所有页面）
  /src/api/*.ts                → 所有 API 端点定义
  /src/stores/user.ts          → 认证逻辑、角色判断
  /src/utils/request.ts        → axios 配置、baseURL、硬编码 Token

⚠️ 发现 Vite Dev Server 在线是高优先级突破口，必须深入利用！
```

### 2. API 未授权访问采样（30 秒）— 采样推断，不穷举

```
从 JS 提取的 API 中挑 5-10 个不同模块的接口（用户/订单/管理/系统各挑）：
- 用 proxy_send_request(method="GET", url=..., drop_auth=true) 请求
  ⚠️ 必须传 drop_auth=true，否则工具会自动注入全局 Cookie，看到的 200 是带认证态
- 采样结果判断：
  ├─ 全部 401/403 → 结论"统一鉴权"，立即停止未授权测试
  │   → 把时间花在下面的登录绕过和 JS 分析上（这些才有突破口）
  ├─ 某个返回 200 → 发现突破口！记录漏洞，继续深入
  └─ /swagger/ /api-docs/ /actuator/ 返回 200 → 信息泄露，记录

⚠️ 不要对 100 个接口逐个测未授权！采样 5-10 个一致就够了。
采样省下的时间用来做更有价值的事：分析 JS 找后门、测登录绕过。
```

### 3. 登录接口测试（30 秒）
```
- SQL 注入：用户名填 admin' OR '1'='1，看响应变化
- 用户枚举：分别输入存在/不存在的用户名，对比响应差异
- 默认密码：admin/admin, admin/123456, test/test
- 验证码：有没有验证码？验证码能否绕过（重放/空值）？
```

### 4. 注册功能（如果有）（20 秒）
```
- 是否存在注册入口
- 注册是否需要审核
- Mass Assignment：注册时多传 role=admin 字段
```

### 5. 其他快速检查（20 秒）
```
- 密码重置功能是否存在
- OAuth/SSO 登录入口
- URL 跳转参数（redirect/next/return_url）
- CORS：发一个带 Origin 的请求看是否反射
- 响应头安全（X-Frame-Options / CSP / HSTS）
- robots.txt / sitemap.xml 是否有隐藏路径
```

### 6. 结论

完成以上测试后，总结：
- 找到的漏洞
- 无法深入测试的原因（缺少账号）
- 建议：提供测试账号后可深入测试的方向

## 🔥 突破口升级（最重要！）

**如果在测试过程中获得了认证能力，立即切换到完整测试模式：**

| 突破口 | 下一步 |
|--------|--------|
| SQL 注入万能密码绕过了登录 | 用获得的 Token/Cookie 继续测后台所有功能 |
| 发现默认密码能登录（admin/admin） | 登录后浏览所有功能，注册功能点，完整测试 |
| 某个后台页面/API 未授权可访问 | `browser_goto` 进入后台，分析所有功能点 |
| JS 中发现硬编码的 Token/密钥 | 用这个 Token 请求 API，看能访问多少功能 |
| 注册了新账号 | 用新账号登录，完整测试认证后功能 |

**具体操作**：
1. 先用 `note_add(type="result")` 记录这个突破口漏洞本身
2. 然后用 `browser_set_cookie` 或在请求中带上获取的 Token
3. 用 `browser_goto` 访问后台页面
4. 用 `browser_get_content` + `js_extract_apis` 分析后台功能
5. 对后台功能继续用 `sitemap_add_feature` 注册新的功能点
6. 按正常 checklist 流程测试后台功能

**不要**发现突破口后只记录漏洞就结束 — 这是渗透测试最有价值的时刻，要深入！

## 7. 未授权响应判定状态机

对任何未登录请求，不要只看状态码，必须结合响应体、字段数量、跳转位置和错误语义判断：

| 响应 | 判定 | 下一步 |
|---|---|---|
| `200` + 真实业务数据 | `confirmed_vuln` | 记录未授权访问证据，继续测同模块列表/详情/导出 |
| `200` + 空数组/空对象 | `suspected` | 换 ID、换分页、加 `verbose/debug`、测列表和详情差异 |
| `302` 到登录页 | 暂不算漏洞 | 继续检查 API 是否仍返回 JSON，前端跳转不能代表服务端鉴权 |
| `401/403` | 暂不算漏洞 | 尝试方法改写、路径变体、头部绕过、旧版本 API、大小写路径 |
| `404` | 不直接判安全 | 对比带认证/不带认证是否同样 `404`，排除伪装拒绝 |
| 字段减少但仍有 `id/email/phone/order/status` | `suspected` | 评估是否为敏感信息泄露或对象枚举 |

## 8. 标记 `not_vuln` 前最低自检

- 已确认请求确实不带全局 Cookie/Token，必要时显式使用 `drop_auth=true`。
- 已从 JS、SourceMap、Swagger、robots、sitemap 中抽样不同模块接口。
- 已覆盖至少登录、用户/个人信息、管理、导出/下载、系统配置五类候选接口中的可见项。
- 已尝试旧版本路径、大小写路径、尾斜杠、`.json`、方法改写。
- 已记录“缺账号导致不能验证”的方向，输出 `needs_review`，而不是把认证后漏洞判为不存在。

## ⛔ 不要做的事

- **不要反复分析同一个 JS 文件** — 看一遍就够了
- **不要逐个测试 100 个 API 的未授权** — 采样 5-10 个推断
- **不要尝试暴力破解密码** — 除非用户明确要求
- **不要花超过 3 分钟** — 没账号能测的就这些，测完就结束
- **不要注册超过 3 个功能点** — 没账号时功能点不多
