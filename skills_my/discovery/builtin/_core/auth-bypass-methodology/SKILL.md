---
name: auth-bypass-methodology
description: "认证绕过完整方法论 — 基于 300+ HackerOne/Bugcrowd 真实报告提炼。覆盖未授权访问、登录逻辑缺陷、MFA 绕过、Session 管理攻击、认证降级、默认/泄露凭据、注册逻辑漏洞、API 认证缺失、Response 篡改、Race Condition 认证绕过。任何出现 login/session/token/cookie/Authorization/MFA/2FA/验证码/注册验证/受保护 API 的场景都必须使用此 skill。"
priority: 9
vuln_types:
  - 认证绕过
  - 未授权访问
  - MFA绕过
  - Session管理缺陷
  - 认证降级
  - 登录逻辑缺陷
  - 账户接管
triggers:
  - login
  - signin
  - auth
  - session
  - cookie
  - Authorization
  - Bearer
  - token
  - mfa
  - 2fa
  - otp
  - captcha
  - register
  - verify
  - logout
  - refresh_token
  - /api/v1/
  - /internal/
synonyms:
  - authentication bypass
  - auth bypass
  - login bypass
  - unauthenticated access
  - mfa bypass
  - 2fa bypass
  - session fixation
  - session bypass
  - 认证缺失
  - 登录绕过
metadata:
  tags: "auth bypass,authentication,login bypass,mfa bypass,2fa bypass,session,认证绕过,登录绕过,双因素,多因素,OTP,验证码,session fixation,session hijack,default credentials,凭据泄露,注册漏洞,认证降级,response manipulation,race condition,account takeover,未授权访问,api key"
  category: discovery
  authority: "expert"
---

# 认证绕过完整方法论

> **关于本 Skill 的使用边界**
>
> 本 Skill 提供的是认证绕过挖掘的**通用思路与常见场景清单**，不是执行脚本，更不是必须严格按顺序走完的流程。
>
> - 如果在某个 Phase 已经获得了清晰证据（例如删 Cookie 后仍返回业务数据、或 MFA 临时 token 已可调用业务 API），不必再机械执行后续 Phase。
> - 当目标的真实表现与本 Skill 描述不符（例如认证架构是自研、Session 机制不常见、MFA 流程走的不是主流模式）时，**以现场观察为准**，本 Skill 仅作参考。
> - 如果你判断当前场景需要一个本 Skill 未覆盖的攻击路径（例如某个 SDK 的 token 交换逻辑、某个中间件的身份头传递、某个微服务间的隐式信任、某个开源组件的认证默认配置问题），请**直接按你的推理执行**，不要因为不在清单里就放弃。
> - "最低必测自检"用于防止漏测，不是用于压制你的判断。如果某项确实不适用，标记原因即可，不要为凑数而硬测。


## 🤖 Agent 工具映射

| 操作 | Agent 工具 |
|------|-----------|
| 记录完整登录/注册/MFA/注销流程 | `browser_*` + `proxy_get_traffic` |
| 删除认证、空 token、随机 token、旧 token 对照 | `proxy_send_request(..., drop_auth=True)` |
| 重放并修改 Cookie、Authorization、Session、MFA 参数 | `proxy_replay` / `proxy_send_request` |
| 直接访问最后一步页面/API 验证跳步 | `browser_goto` + `proxy_send_request` |
| 对比认证前后、MFA 前后、注销前后响应 | `proxy_diff_responses` |
| 查看 Set-Cookie、重定向、权限字段和错误详情 | `proxy_get_flow_detail` |
| 抓取 LocalStorage/SessionStorage/JWT/MFA 页面状态 | `browser_evaluate` + `browser_get_cookies` |
| 固化认证绕过证据与后续影响补充 | `checklist_mark` + `note_add` |
| JWT/OAuth/密码重置/403 绕过等专项 | `knowledge_load_skill` |

**执行约束**：认证绕过必须证明“未经完整认证却获得受保护资源或敏感操作能力”；页面跳转不是证据，必须直接请求后端 API 做二次校验。

---

## 0. 立即执行摘要：认证绕过先测“删除/替换/降级/跳步”

看到登录、注册、MFA、验证码、`Authorization`、`Cookie`、`session`、`token`、`refresh_token`、`/api/v1/`、移动端 API、内部 API、受保护资源时，必须进入本 skill。认证绕过的第一目标不是爆破密码，而是证明 **服务端是否在每条受保护路径、每个步骤、每种客户端、每个旧版本接口上都执行了认证检查**。

优先顺序：

1. 对所有受保护 API 做删除认证、空 token、随机 token、过期 token、低权限 token 对照。
2. 登录/MFA/注册/找回流程必须尝试直接访问最后一步或业务 API，检查是否可跳步。
3. 测旧版本、移动端、小程序、内部、GraphQL、WebSocket、导出下载接口是否少认证。
4. 测注销、改密、角色变化后旧 Session/Token 是否仍有效。
5. 如果前端根据响应字段决定登录态，必须验证后端 API 是否二次校验。

## 1. 认证响应判定状态机

| 响应现象 | 不要立刻下结论 | 下一步 |
|---|---|---|
| 删除认证后 `200 + 业务数据` | 高危信号 | 与正常登录响应对照，确认是否受保护数据 |
| 删除认证后 `200 + 空对象` | 可能软拒绝或数据为空 | 换对象 ID、分页、导出接口、移动端接口 |
| `302` 到登录页 | 页面拒绝不代表 API 拒绝 | 直接请求 JSON API，看是否仍返回数据 |
| `401/403` | 有认证检查但可能不完整 | 方法切换、路径变体、Header 伪造、旧版本 API |
| `404` | 可能权限伪装 | 用高权限/合法对象确认资源存在 |
| MFA 未完成但有临时 token | 高危信号 | 用临时 token 调业务 API |
| 注销后页面跳登录 | 不足以证明失效 | 用旧 Cookie/Token 直接请求 API |

## ⚠️ 关键认知

认证绕过 ≠ 密码爆破。**90% 的认证绕过来自逻辑缺陷**，而非密码学弱点。开发者实现了认证，但在某些路径上忘了检查、检查不完整、或检查可被绕过。

**五大根因**（HackerOne 数据）：
1. **不一致的认证执行**（41%）— 主入口有认证，但旁路/内部/v1 接口没有
2. **可预测/可操纵的认证状态**（23%）— Session/Token/Cookie 可伪造或重用
3. **多步骤流程中的逻辑跳跃**（18%）— 直接请求最后一步跳过验证
4. **客户端验证依赖**（12%）— 前端检查但后端不检查
5. **默认/弱/泄露凭据**（6%）— 听起来简单但仍然是最快的入口

## ⛔ 安全边界（真实渗透测试必读）

1. **禁止影响真实用户**：账户锁定/OTP 爆破测试只对自己的测试账号执行，不要锁定真实用户
2. **并发测试需谨慎**：Race Condition 测试可能导致数据不一致，仅在测试环境或获得明确授权后执行
3. **禁止使用窃取的凭据**：发现泄露的 API Key/密码后截图报告即可，不要实际使用
4. **Session 测试用自己的账号**：Session 固定/劫持测试仅在自己的两个测试账号间进行
5. **注册测试及时清理**：重复注册/Unicode 绕过等测试创建的账号要及时删除
6. **MFA 绕过验证即停**：确认可跳过 MFA 后立即记录，不要继续操作业务功能

---

---

## Phase 1: 认证机制侦察

### 1.1 识别认证类型

```
检查目标使用的认证方式（常多种并存）：
├── Session-based（Set-Cookie: PHPSESSID/JSESSIONID/connect.sid）
├── Token-based（Authorization: Bearer eyJ...）→ 转 jwt-attack-methodology
├── API Key（X-API-Key / ?api_key= / Authorization: ApiKey）
├── Basic Auth（Authorization: Basic base64(user:pass)）
├── OAuth/SSO（redirect_uri + code）→ 转 oauth-sso-attack
├── SAML（SAMLResponse）
├── mTLS/客户端证书
└── 自定义（Cookie 中的自定义字段）→ 转 cookie-analysis
```

### 1.2 认证端点枚举

```
必查端点（不管爬虫有没有发现）：
/login, /signin, /auth, /authenticate, /api/login, /api/auth
/register, /signup, /api/register, /api/users (POST)
/logout, /signout, /api/logout
/forgot-password, /reset-password → 转 password-reset-attack
/verify, /confirm, /activate
/api/token, /api/refresh, /oauth/token
/admin, /admin/login, /manage, /dashboard
/.well-known/openid-configuration
/api/v1/*, /api/v2/* (版本差异)
/internal/*, /debug/*, /test/*
```

### 1.3 认证流程全记录

**先正常走一遍完整登录流程**，用 proxy 记录每一个请求：

```
记录项：
1. 登录请求格式（POST body 字段名、是否加密）
2. 登录成功响应（Set-Cookie? Token? redirect?）
3. 后续请求如何携带认证（Cookie? Header?）
4. 认证失败的响应特征（状态码、错误消息、响应体差异）
5. 是否有 MFA/2FA 第二步
6. 是否有"记住我"功能
7. 是否有验证码（CAPTCHA）
```

---

## Phase 2: 未授权访问（最快路径）

**在测试任何绕过之前，先检查是否有端点根本就没加认证。**

### 2.1 去除认证头直接访问

```
对每个已知的 API 端点：
1. 正常请求（带 Cookie/Token）→ 200
2. 去掉 Cookie/Authorization 头 → 还是 200？→ 未授权访问！
3. 用空 Token → Authorization: Bearer  → 200？
4. 用无效 Token → Authorization: Bearer invalid → 200？
```

### 2.2 高概率未授权端点

| 端点模式 | 原因 | 优先级 |
|----------|------|--------|
| `/api/v1/*`（旧版本） | 新版加了认证，旧版忘了 | 🔴 高 |
| `/internal/*`, `/debug/*` | 内部接口假设不会被外部访问 | 🔴 高 |
| `/api/public/*` 之外的 public 路由 | 开发者标记错误 | 🔴 高 |
| `/health`, `/status`, `/metrics` | 运维端点信息泄露 | 🟡 中 |
| `/graphql`（Introspection） | Schema 暴露所有 API | 🔴 高 |
| `/api/docs`, `/swagger.json` | API 文档暴露 | 🟡 中 |
| `WebSocket ws://` | WS 连接常缺认证 | 🟡 中 |
| 静态资源路径（`/uploads/`） | 文件直接可访问 | 🟡 中 |
| `/api/*/export`, `/api/*/download` | 导出接口常被遗漏 | 🔴 高 |

### 2.3 HTTP 方法差异

```
GET /api/admin/users → 401
POST /api/admin/users → 200？（不同方法不同的认证中间件）
OPTIONS /api/admin/users → 200 + 敏感 Header 泄露？
PUT /api/admin/users → 200？
```

---

## Phase 3: 登录逻辑缺陷

### 3.1 SQL 注入登录绕过

```
用户名字段测试（经典但仍有效）：
admin' --
admin' OR '1'='1' --
admin'/*
' OR 1=1 --
" OR 1=1 --
admin') OR ('1'='1
```

**发现信号**：登录失败消息不同（"用户不存在" vs "密码错误"）→ 用户名枚举 + SQL 注入可能。

### 3.2 响应操纵（前端依赖）

```
抓取登录失败的响应：
POST /api/login → {"success": false, "role": "none"}

用 proxy_replay 修改响应：
{"success": true, "role": "admin"}

如果前端据此跳转 → 认证仅在前端执行
```

**HackerOne 真实案例**：多个 SPA 应用（React/Vue）在登录响应中返回 `{"authenticated": true}`，前端直接据此显示管理面板，后续 API 调用也不再验证。

### 3.3 参数操纵

```
正常登录：POST /login {"username":"user","password":"pass"}

测试：
1. 删除 password 字段 → {"username":"admin"}
2. 空密码 → {"username":"admin","password":""}
3. null 值 → {"username":"admin","password":null}
4. 数组 → {"username":"admin","password":[]}
5. 对象 → {"username":"admin","password":{}}
6. 布尔 → {"username":"admin","password":true}
7. 添加字段 → {"username":"admin","password":"x","admin":true}
8. 添加字段 → {"username":"admin","password":"x","verified":true}
```

### 3.4 认证降级

```
如果正常登录需要 MFA：
1. 找旧版 API → /api/v1/login（可能没有 MFA）
2. 找移动端 API → /mobile/api/login（可能简化认证）
3. 找第三方集成 → /integrations/auth（可能绕过 MFA）
4. Basic Auth 降级 → Authorization: Basic base64(admin:password)
5. API Key 降级 → 找泄露的 API Key 直接使用
```

### 3.5 默认凭据（仍然有效）

```
高频默认凭据：
admin:admin, admin:password, admin:123456, admin:admin123
root:root, root:toor, root:password
test:test, guest:guest, demo:demo
operator:operator, support:support

框架默认：
Spring Boot Actuator: /actuator（常无认证）
Tomcat Manager: tomcat:tomcat, admin:admin
Jenkins: 无初始密码或 admin:admin
Grafana: admin:admin
phpMyAdmin: root:（空）
```

---

## Phase 4: MFA/2FA 绕过

### 4.1 直接跳过 MFA 步骤

```
正常流程：
Step 1: POST /login → 200 {"mfa_required": true, "temp_token": "xxx"}
Step 2: POST /mfa/verify → {"code": "123456", "temp_token": "xxx"}
Step 3: 获得完整 session

绕过测试：
1. Step 1 后直接访问 /dashboard → 如果 200 → MFA 可跳过
2. Step 1 后直接调用业务 API → 如果 200 → MFA 仅限前端
3. Step 1 的 temp_token 直接当正式 token 用 → 权限相同？
```

### 4.2 OTP 验证码绕过

```
1. 空验证码 → {"code": ""} 或 {"code": null}
2. 通用码 → {"code": "000000"} / {"code": "123456"}
3. 负数 → {"code": -1}
4. 超长值 → {"code": "000000000000"}
5. 响应中泄露 → 检查 Step 1 响应体/Header 是否包含 OTP
6. 无速率限制 → 6 位数字 = 100 万种，无限制可爆破
7. 前一个 OTP 仍有效 → 请求新 OTP 后旧的没失效
8. OTP 未绑定 session → A 的 OTP 用在 B 的 session 上
```

### 4.3 备用验证方式绕过

```
1. "记住此设备"Cookie → 复制 remember_device Cookie 到新浏览器
2. 备用码（Recovery Code）→ 检查是否可预测或可枚举
3. 短信/邮件回退 → 用 Host 头投毒劫持验证链接
4. 安全问题回退 → 答案可能被猜测或在其他泄露中
```

### 4.4 MFA 配置阶段攻击

```
1. MFA 绑定时替换 user_id → 给受害者绑定攻击者的 2FA 设备
2. MFA 解绑请求无二次认证 → 直接 DELETE /mfa 解除保护
3. TOTP Secret 泄露 → 检查 /mfa/setup 响应中的 otpauth:// URI
```

**HackerOne 真实案例**：
- Shopify #629892 — $4,000 — 通过 GraphQL 禁用任意用户的 2FA
- GitLab #743096 — $3,000 — MFA 验证码不过期，可无限重试

---

## Phase 5: Session 管理攻击

### 5.1 Session 固定（Session Fixation）

```
1. 访问目标获取 Session ID（未登录状态）
2. 将此 Session ID 传给受害者（通过 URL/Cookie 注入）
3. 受害者用此 Session ID 登录
4. 攻击者用同一 Session ID 获得受害者权限

检测：登录前后 Session ID 是否改变？
→ browser_get_cookies 对比登录前后的 session cookie
→ 如果相同 → Session Fixation 可能存在
```

### 5.2 Session 不过期/过长有效期

```
1. 登录获取 session
2. 退出登录
3. 用旧 session 继续请求 → 如果仍有效 → Session 未正确注销

4. 长时间不活动后 session 仍有效？
5. 密码修改后旧 session 仍有效？
6. 角色变更后旧 session 权限未更新？
```

### 5.3 并发 Session 控制

```
1. 设备 A 登录
2. 设备 B 登录同一账户
3. 设备 A 的 session 是否失效？
→ 如果不失效：攻击者一旦获得凭据，受害者改密码也踢不掉
```

### 5.4 Session Token 可预测

```
收集 5-10 个 session token，分析：
1. 是否包含可识别的模式（时间戳、递增数字）
2. 熵是否足够（短 token 可爆破）
3. 是否包含 Base64 编码的用户信息 → 解码检查
4. 是否使用已知弱算法（MD5(username+timestamp) 等）
```

---

## Phase 6: 注册逻辑漏洞

### 6.1 重复注册覆盖

```
1. 注册 admin@target.com（如果允许）
2. 如果"邮箱已存在"→ 测试大小写绕过：Admin@target.com
3. 测试 Unicode 绕过：ɑdmin@target.com（拉丁字母 ɑ）
4. 测试空格注入：" admin@target.com" / "admin@target.com "
5. 测试加号技巧：admin+anything@target.com
```

### 6.2 邮箱验证绕过

```
1. 注册后不验证邮箱直接登录 → 能访问功能？
2. 修改注册响应中的 verified 字段 → {"verified": true}
3. 验证链接中的 token 可预测？
4. 验证请求中修改邮箱 → POST /verify {"token":"xxx","email":"other@x.com"}
```

### 6.3 邀请码/注册码绕过

```
1. 删除邀请码字段 → 注册成功？
2. 空邀请码 → {"invite_code": ""}
3. 常见弱码 → 000000, 123456, default
4. 其他用户的邀请码重复使用 → 未绑定一次性？
```

---

## Phase 7: API 认证缺失模式

### 7.1 微服务间信任

```
微服务架构中，服务间通信常假设"内网可信"：
1. 添加 Header → X-Internal-Request: true
2. 添加 Header → X-Service-Name: auth-service
3. 内网 IP 伪造 → X-Forwarded-For: 10.0.0.1
4. 直接访问内部端口 → 目标:8080/internal/api

真实案例：Uber #1090871 — $6,500 — 内部 API 通过 X-Uber-Source header 信任请求
```

### 7.2 GraphQL 认证盲点

```
1. Introspection 查询 → {__schema{types{name,fields{name}}}} → 无需认证
2. 找到 mutation 后直接调用 → 部分 mutation 忘加认证
3. 不同 operation 不同认证 → query 需要认证，mutation 不需要
4. Batch query 绕过速率限制 → [{"query":"..."}, {"query":"..."}]
```

### 7.3 API Key 管理漏洞

```
API Key 泄露来源：
1. 前端 JS 源码中硬编码
2. GitHub/GitLab 公开仓库
3. 移动端 APK 反编译
4. HTTP Referer 头泄露（Key 在 URL 中）
5. 错误响应中泄露有效 Key
6. .env/.config 文件直接可访问

API Key 权限测试：
- Key 是否区分读/写权限？
- Key 吊销后是否立即失效？
- Key 是否绑定 IP/域名？
```

---

## Phase 8: Race Condition 认证绕过

### 8.1 并发登录绕过锁定（⚠️ 仅对自己的测试账号）

```
账户锁定策略：5 次失败后锁定

验证方式（使用自己的测试账号）：
1. 同时发送 10 个登录请求（不同密码）
2. 如果锁定计数器非原子操作 → 实际可尝试 10+ 个密码
3. 记录现象即可证明漏洞

⛔ 禁止：对真实用户账号执行此测试（会导致账号被锁定）
```

### 8.2 并发 OTP 验证

```
OTP 验证后应失效，但如果非原子操作：
1. 获取有效 OTP
2. 同时发送 5 个验证请求（相同 OTP）
3. 如果多个返回成功 → OTP 验证非原子，可重用
```

### 8.3 并发注册同一用户名

```
1. 同时发送 10 个注册请求（相同用户名/邮箱，不同密码）
2. 如果多个成功 → 竞态条件
3. 用不同密码尝试登录 → 确定哪个密码生效
4. 真实案例：HackerOne #1131204 — 通过竞态条件绕过邮箱唯一性约束
```

---

## Phase 9: 认证绕过决策树

> 💡 **决策树警告**：下面的 Step 1–6 是**最常见的 6 个排查方向**，**不是穷尽列举**，更**不是"6 步走完就能下结论"**。
> 特别注意：
> - **"全部失败 → 转向其他攻击面"是误导性描述**——很多认证缺陷恰恰在这棵树**之外**：BFF/网关身份透传（`X-User-Id`、`X-Real-User`、内部 JWT）、SSO backchannel logout 未生效、CDN/反代缓存了带身份的响应（不同用户读到同一份缓存）、负载均衡粘性会话错位、Service Worker / PWA / Electron IPC / WebView jsBridge 提供的高权限通道、运维端点（`/_internal`、`/__debug`、`/actuator/*`）走业务端口对外暴露、反向代理后的原始服务可被直达（origin bypass）、gRPC/Dubbo/RPC 内部调用默认信任。
> - **"登录端点测了 = 认证机制测过了"是错觉**——主登录可能很硬，但 `/api/v1/`、移动端 `/m/api/`、小程序 `/mp/`、合作方 `/partner/`、Webhook、消息队列消费者 HTTP 入口、定时任务触发接口的鉴权可能完全不一样。
> - **"Session 测试通过 = 会话管理无缺陷"也是错觉**——多租户 `X-Tenant-Id` 切换、JWT 与 Session 双轨制下的就低原则、刷新令牌与访问令牌的不对等失效、设备绑定逻辑漏洞，这些都不在 Step 4 的常规清单里。
> - **以现场实际响应为准**：决策树是**思考起点**，不是**判断终点**。一旦发现任一 Step 已构成证据（哪怕只走到 Step 1），**先 `checklist_mark vulnerable` 再继续深挖**，不要等树跑完。

```
目标有认证机制？
│
├── Step 1: 未授权访问检测
│   ├── 去掉认证头访问所有 API → 有 200？→ 漏洞！
│   ├── 旧版本 API（/v1/, /v2/） → 认证缺失？→ 漏洞！
│   └── 内部/调试端点 → /internal/, /debug/ → 可访问？→ 漏洞！
│
├── Step 2: 登录逻辑测试
│   ├── SQL 注入 → admin' -- → 登录成功？
│   ├── 参数操纵 → 删除/空/null 密码 → 登录成功？
│   ├── 默认凭据 → admin:admin → 登录成功？
│   └── 响应操纵 → 改 false→true → 前端绕过？
│
├── Step 3: MFA 绕过（如果有 MFA）
│   ├── 直接跳过 → Step 1 后直接访问业务页 → 可用？
│   ├── OTP 绕过 → 空码/通用码/爆破/响应泄露
│   └── 备用方式 → 记住设备 Cookie/备用码/短信回退
│
├── Step 4: Session 测试
│   ├── 固定 → 登录前后 Session ID 不变？
│   ├── 不过期 → 注销/改密码后旧 Session 仍有效？
│   └── 可预测 → Token 熵不足/包含用户信息？
│
├── Step 5: 注册逻辑
│   ├── 重复注册 → 大小写/Unicode/空格 绕过唯一性
│   ├── 验证绕过 → 不验证邮箱直接使用？
│   └── Mass Assignment → 注册时注入 role=admin？→ 转 privilege-escalation-web
│
├── Step 6: 高级绕过
│   ├── Race Condition → 并发绕过锁定/OTP/注册
│   ├── 认证降级 → 旧 API/移动端/Basic Auth
│   └── 微服务信任 → X-Internal-Request/X-Forwarded-For
│
└── 全部失败 → 转向其他攻击面
    ├── JWT 攻击 → jwt-attack-methodology
    ├── OAuth 攻击 → oauth-sso-attack
    ├── 密码重置 → password-reset-attack
    ├── 403 绕过 → 401-403-bypass
    └── 权限提升 → privilege-escalation-web
```

---

## Phase 10: 真实案例速查表

| 目标 | 漏洞 | 赏金 | 关键发现技巧 |
|------|------|------|-------------|
| Uber | 内部 API 通过 Header 信任请求 | $6,500 | X-Uber-Source header 伪造 |
| Shopify | GraphQL 禁用任意用户 2FA | $4,000 | mutation 未检查当前用户 |
| Starbucks | API v1 认证缺失 | $4,000 | /api/v1/ 完全无认证 |
| Airbnb | MFA 跳过（直接访问仪表盘） | $3,500 | Step 1 后 session 已完全认证 |
| Microsoft | 并发注册覆盖账户 | $5,000 | 竞态条件绕过唯一性约束 |

---

## 🚨 证据级响应与记录时机

**认证绕过一旦出现“未经完整认证却获得受保护权限”的证据，立即 `checklist_mark(... result="vulnerable")`。** 不要为了继续挖账户接管链路而延迟记录；后续影响力用 `note_add(type="result")` 追加。

### 认证绕过证据级响应（任一即可）

- ✅ `drop_auth=True` 或删除 `Cookie/Authorization` 后，仍能访问原本需要登录的 API 数据
- ✅ 登录流程失败响应被前端信任，修改响应后可进入受保护页面，且后续 API 没有二次校验
- ✅ MFA 流程未完成时，临时 token/session 已能访问业务 API 或仪表盘
- ✅ 注销、改密、角色变更后，旧 Session/Token 仍可执行敏感操作
- ✅ 注册/验证/邀请流程可跳步，未完成验证即可获得已验证用户能力
- ✅ 旧版本、移动端、内部端点比主流程少认证步骤，返回同等权限数据

### 结果分级

- `vulnerable`：可复现地绕过认证前置条件，并访问受保护资源或完成敏感动作
- `needs_review`：发现登录态异常、响应差异、临时 token 权限过大等线索，但还不能证明权限获得
- `not_vuln`：完成最低必测自检，未授权、MFA、Session、注册、降级路径均无绕过证据
- `skipped`：缺少账号、MFA、注册权限、测试环境或授权范围导致无法验证，必须写明缺失条件

### 输出格式

```text
[认证绕过检查]
入口/流程：登录/API/MFA/注册/找回/Session/旧版本/内部接口/其他
认证方式：Cookie/Bearer/JWT/APIKey/Basic/OAuth/自定义/未知
测试动作：删认证/空token/错token/低权限/跳步/MFA未完成/旧session/降级路径/响应操纵
响应差异：状态码/业务字段/跳转/错误消息/权限结果
结论：confirmed_vuln | suspected_vuln | needs_review | not_vuln
未测原因：缺账号/缺MFA/缺注册权限/缺旧接口样本/其他
```

---

## 证据收集规范

**认证绕过漏洞的核心证据 = 证明"未经合法认证获得了已认证用户的权限"。**

### 有效 PoC 必须包含

1. **正常认证流程截图**：展示正常需要的认证步骤
2. **绕过过程的完整请求/响应**：每一步的 HTTP 请求（含 Header）+ 响应
3. **绕过后的权限证明**：证明确实获得了受保护资源/功能的访问权
4. **影响范围**：是否影响所有用户？管理员？特定角色？

### 升级影响力

```
✅ 好的证据:
"目标应用 /api/v2/users 端点需要 Bearer Token 认证，
但 /api/v1/users 端点未添加认证中间件。
直接 GET /api/v1/users 返回所有用户列表（含邮箱、手机号）。
进一步测试 POST /api/v1/users/{id}/reset-password 同样无需认证，
可重置任意用户密码实现账户接管。
影响：全部 50,000+ 用户的个人信息泄露 + 任意账户接管。"

❌ 差的证据:
"不带 Cookie 访问 /api/users 返回了 200"
（没有对比正常流程、没有说明影响）
```

**每确认一个认证绕过立即 `vuln_verify` + `note_add(type="result")` 记录。**

---

## ⛔ 「最低必测自检」— 标 not_vuln/skipped 前必答

任何认证绕过项准备标 `not_vuln` 或 `skipped` 前，必须逐条回答下面问题。**只测了正常登录失败，不等于测过认证绕过。**

| # | 必测项 | 跳过的合法理由 |
|---|--------|---------------|
| 1 | **无认证基线**：对目标受保护 API 使用 `drop_auth=True` 或删除 `Cookie/Authorization` 重发，确认是否仍返回业务数据 | 目标功能本身公开，无认证要求 |
| 2 | **无效认证对照**：使用空 token、随机 token、过期 token、其他测试账号 token 访问同一接口，看是否被正确拒绝 | 目标只使用 Session Cookie 且无法构造 token |
| 3 | **登录流程跳步**：记录完整登录流程后，直接访问最后一步页面/API；如果有 MFA，必须测试 MFA 未完成时访问业务 API | 目标没有多步骤认证/MFA |
| 4 | **响应操纵检查**：如果前端根据登录响应字段跳转，尝试把 `success:false`、`authenticated:false`、`role:user` 改成成功/管理员值，确认后端 API 是否二次校验 | 非 SPA/前端不依赖响应字段控制权限 |
| 5 | **Session 生命周期**：注销、改密、角色变更后，旧 Session/Token 是否仍能访问敏感 API | 无法执行注销/改密/角色变更操作 |
| 6 | **认证降级路径**：测试 `/api/v1/`、移动端 API、内部 API、Basic Auth、API Key、旧 OAuth 回调等是否比主流程少认证步骤 | 已确认不存在旧版本/移动端/内部路径 |
| 7 | **注册/验证绕过**：注册后不验证邮箱/手机号能否使用核心功能？邀请/注册码能否删除、复用、置空、替换？ | 目标无注册/邀请/验证流程 |
| 8 | **默认/泄露凭据只读验证**：如果发现默认凭据或泄露 Key，只做登录成功/权限范围截图，不继续操作业务数据 | 无凭据线索 |

### 跳过的"非法"理由

- ❌ "登录接口不能爆破，所以没有认证绕过" → 认证绕过重点是流程和状态，不是爆破
- ❌ "前端跳不过去，所以后端安全" → 必须直接请求后端 API 验证
- ❌ "MFA 页面拦住了" → 必须验证 MFA 前的临时 session/token 是否能调用业务 API
- ❌ "注销后页面跳登录" → 必须用旧 Cookie/Token 直接请求 API，而不是只看页面跳转

---

## ⚠️ Skill 边界与逃逸

本 Skill 是**辅助参考**，不是束缚你的脚手架。在以下情况下，请**主动跳出本 Skill 的清单**，按你自己的判断行动：

1. **现场证据与本 Skill 矛盾时**
   - 例如本 Skill 说"删除认证头后 200 = 未授权"，但你看到目标返回 200 却只是公开默认响应体，真正的鉴权可能在 Header、在渲染阶段、在下一跳接口才生效 —— 以现场为准，重新定义你的证据门槛。
   - 反过来，本 Skill 说"401/403 = 有认证检查"，但你可能发现 401 响应中已经伴随返回了部分业务数据，那这个“拒绝”其实是不完整的。

2. **遇到本 Skill 没列出的入口或路径**
   - 例如：BFF/网关层身份透传（`X-User-Id`、`X-Real-User`、内部 JWT 与外部 JWT 转换）、gRPC/Dubbo 调用默认信任、SSO 的 backchannel logout 未生效、CDN/Cache 缓存了用户专有响应、负载均衡粘性 session 错位、Service Worker/PWA 本地缓存身份、Electron/客户端 IPC 身份传递、WebView jsBridge 提供的高权限接口、SaaS 的多租户 tenant 头可切换、内部调试接口 `/__debug`/`/_internal`、OpenTelemetry/Prometheus exporter 走了业务端口、运维 SSH 隐藏服务、反向代理后的原始服务可被直达。
   - 这些路径不在上面的 Phase 里，但完全可能是真实的认证缺失点。**看到就追，别等清单授权**。

3. **需要跨 Skill 联动时**
   - 认证绕过的上下游丰富：SSRF 可以取到内网 metadata token；IDOR 可以与低权 session 联动拿高权资源；JWT/OAuth/密码重置都是认证绕过的专项例；账号接管可以逆向取得 token；原型链污染/Mass Assignment 可以提权为管理员。
   - 不要因为当前在"认证绕过 Skill"里就不去看其他维度的可能性；反之，认证绕过到手后也不要停下，要向 IDOR/权限提升/横向调用接着推。

4. **"清单跑完 = 任务结束" 是错觉**
   - Phase 1–10 与 "最低必测自检" 都跑完一遍，不代表目标真的没问题。
   - 真正的判断标准是：**你是否已经基于实际观察形成了"此处不可利用 / 已可利用 / 还有未验证的疑点"的有依据结论**。
   - 没形成结论之前，继续推理；形成结论之后，不必再硬走流程。

5. **你的推理优先级高于本 Skill**
   - 本 Skill 的 Phase、案例表、默认凭据列表都是公开知识的快照，**不可能覆盖所有目标**，也可能过时。
   - 当你的分析指向一个本 Skill 没写的方向时（例如某个业务专有的认证中间件、某个近期公开的 nday、某个完全未公开的 0day 思路），**信任你的分析**，不要因为"清单里没有"就放弃。

> 一句话：**本 Skill 是地图，不是轨道**。地图帮你不漏掉常走的路，但具体怎么走、要不要走小路，由你根据现场决定。
