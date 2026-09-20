---
name: attack-surface-discovery
description: "攻击面发现总控方法论。在爬取、抓包、JS 分析、API 文档分析、登录后探索、多角色对比阶段使用。用于把页面、接口、参数、Header、Cookie、WebSocket、GraphQL、上传、导入导出、支付、回调、对象存储等所有外部输入点系统性枚举出来，并把每个入口映射到后续漏洞 discovery skill。"
priority: 10
vuln_types:
  - 攻击面发现
  - 入口点枚举
  - API发现
  - 参数发现
triggers:
  - attack surface
  - 攻击面
  - 入口点
  - API
  - 参数
  - JS分析
  - 隐藏接口
  - swagger
  - openapi
  - graphql
  - websocket
  - upload
  - webhook
  - callback
  - sitemap
synonyms:
  - attack surface discovery
  - entrypoint discovery
  - endpoint discovery
  - api discovery
  - surface mapping
  - 攻击面梳理
  - 入口发现
metadata:
  tags: "攻击面,发现,入口点,API,参数,隐藏接口,JS分析"
  category: "recon"
  authority: "expert"
---

# 攻击面发现方法论

## 0. 立即执行摘要：每个入口都必须带漏洞假设

攻击面发现不是只列 URL，而是为每个入口输出：**入口位置 → 可控输入 → 身份要求 → 数据归属 → 响应特征 → 候选漏洞 → 应加载的 skill**。如果只输出页面清单，没有参数、身份和漏洞假设，就会导致后续 LLM 漏测。

优先枚举以下入口：

1. 页面路由、SPA 前端路由、隐藏菜单、按钮、表单。
2. XHR/Fetch/API、Swagger/OpenAPI、GraphQL、WebSocket、RPC。
3. URL path/query/body/Header/Cookie/LocalStorage/SessionStorage 中的所有可控字段。
4. 上传、导入、导出、下载、预览、回调、Webhook、支付、优惠券、审批、邀请、分享。
5. 移动端、小程序、旧版本 API、管理端、内部端点、调试端点。

## 1. 入口 → 后续 skill 路由矩阵

| 入口/特征 | 候选漏洞 | 后续 skill |
|---|---|---|
| `/api/`、JSON、Swagger | 未授权、IDOR、Mass Assignment、注入 | `api-fuzz`、`auth-bypass-methodology`、`idor-methodology` |
| `id/user_id/order_id/file_id/org_id` | IDOR/BOLA、多租户越权 | `idor-methodology`、`privilege-escalation-web` |
| `role/is_admin/permission/scope` | 权限提升、Mass Assignment | `privilege-escalation-web` |
| `upload/import/multipart/filename` | 文件上传、XXE、ZIP Slip、上传后越权 | `file-upload-methodology` |
| `q/search/filter/sort/orderBy` | SQLi、NoSQL、XSS、排序注入 | `sql-injection-methodology`、`nosql-injection`、`xss-methodology` |
| `url/redirect/callback/webhook/proxy` | SSRF、开放重定向、Host Header | `ssrf-methodology`、`open-redirect`、`http-host-header-attacks` |
| `callback/jsonp/cb` | JSONP/XSSI 数据泄露 | `jsonp-data-leak` |
| `ws/wss/socket.io` | WebSocket 越权、CSWSH | `websocket-attack` |
| 支付/优惠券/积分/库存/审批 | 业务逻辑漏洞 | `business-logic-attack` |
| `Host/X-Forwarded-*`、缓存头 | Host 攻击、缓存投毒、请求走私 | `http-host-header-attacks`、`cache-and-smuggling` |
| 第三方登录/SSO | OAuth/OIDC/SAML 漏洞 | `oauth-sso-attack` |

## 核心：攻击面 = 所有能被外部输入影响的点

## Checklist 1: 从流量中发现

对代理抓到的每一条请求，逐项检查：

### 请求层面
- [ ] URL 路径中有没有 ID/参数？(`/user/123` `/order/ORD001`)
- [ ] Query 参数有哪些？哪些是用户可控的？
- [ ] Request Body 的字段和类型？
- [ ] 有没有文件上传字段？(`multipart/form-data`)
- [ ] Content-Type 是什么？(`json` / `xml` / `form-urlencoded`)

### Header 层面
- [ ] Cookie 中有没有明文身份信息？(`uid=1001` `role=user`)
- [ ] Authorization Header 用什么格式？(Bearer JWT / Basic / API Key)
- [ ] 有没有自定义 Header？(`X-User-Id` `X-Forwarded-For`)
- [ ] Referer/Origin 是否被校验？

### 响应层面
- [ ] 响应中有没有敏感字段？(手机号/身份证/邮箱/内部 ID)
- [ ] 错误响应有没有泄露信息？(SQL 语句/堆栈/文件路径)
- [ ] Set-Cookie 的属性？(HttpOnly? Secure? SameSite?)
- [ ] CORS Header？(`Access-Control-Allow-Origin`)
- [ ] 有没有 debug/trace 相关的 Header？

## Checklist 2: 从页面 DOM 中发现

- [ ] 隐藏表单字段 (`<input type="hidden">`) — 经常包含 user_id、token、price
- [ ] 禁用的输入框 (`disabled`) — 可以在 DevTools 中启用
- [ ] HTML 注释中的内容 — 有时包含测试 URL、API 地址
- [ ] `data-*` 属性 — 可能包含 API 端点或配置信息
- [ ] `<meta>` 标签 — 可能包含 CSRF token、API base URL

## Checklist 3: 从 JS 文件中发现

### API 端点
搜索以下模式：
```
/api/        /v1/        /v2/
/graphql     /rest/      /rpc/
/admin/      /internal/  /management/
```

### 密钥和凭据
搜索以下模式：
```
apiKey       api_key      API_KEY
secret       SECRET       token
password     passwd       aws_access
AKID         ak=          sk=
```

### 配置信息
搜索以下模式：
```
baseURL      base_url     endpoint
debug        DEBUG        isDev
config       CONFIG       settings
```

### 注释中的宝藏
```
// TODO       // FIXME      // HACK
// temp       // test       // admin
```

## Checklist 4: 从响应对比中发现

### 同一接口不同参数
```
GET /api/user/1001  → 200, 自己的数据
GET /api/user/1002  → 200, 他人的数据 → IDOR!
GET /api/user/1002  → 403, 拒绝       → 有权限控制
GET /api/user/9999  → 500, 报错       → 可能有注入
```

### 同一接口不同身份
```
带 Token 请求    → 200, 正常
不带 Token 请求  → 200, 还是正常  → 未授权访问!
不带 Token 请求  → 401, 拒绝      → 有认证
用户 A 的 Token  → 200, 用户 B 的数据 → 越权!
```

### 同一接口不同方法
```
GET  /api/user/1001 → 200
POST /api/user/1001 → 405 Method Not Allowed
PUT  /api/user/1001 → 200, 修改成功 → 写操作越权!
DELETE /api/user/1001 → 200, 删除成功 → 危险!
```

## 输出：攻击面清单

发现的每个攻击面应记录为：

```
攻击面: POST /api/order/create
可控参数: product_id, quantity, price, coupon_code
身份要求: 需要登录（Bearer Token）
发现方式: 流量分析
风险判断: price 参数由前端传递，服务端可能未校验 → 金额篡改
建议测试: business-logic-attack, idor-methodology
```

## 最低必测自检

标记攻击面枚举完成前，必须确认：

1. 已覆盖未登录、登录后、至少两个普通账号；有管理/VIP/商户角色时必须纳入。
2. 已记录 path、query、body、Header、Cookie、WebSocket message、GraphQL variables 七类输入。
3. 已分析 JS bundle、source map、HTML 注释、LocalStorage、API 文档和错误响应。
4. 已单独标记上传、导入、导出、下载、回调、支付、审批、批量、异步任务等高价值功能。
5. 每个入口都必须给出候选漏洞和建议加载的 skill；缺少业务上下文时标 `needs_review`。

## 输出格式

```text
[攻击面发现]
入口：方法 + URL/协议
来源：流量/DOM/JS/Swagger/GraphQL/WebSocket/爬虫/猜测
身份要求：未登录/普通用户/管理员/多租户/未知
可控输入：path/query/body/header/cookie/ws/graphql/file
对象归属字段：id/user_id/order_id/file_id/org_id/tenant_id/无
响应特征：状态码/敏感字段/错误/缓存头/CORS/Set-Cookie
候选漏洞：
建议 skill：
优先级：P0/P1/P2/P3
```
