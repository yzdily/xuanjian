---
name: crawl-strategy
description: "站点爬取/功能发现策略方法论。在 Phase 0 站点探索阶段使用。定义如何系统性发现网站页面、SPA 路由、按钮、表单、XHR/Fetch、API 端点、JS 隐藏路径、登录后功能、多角色差异、WebSocket、GraphQL、上传/导入/导出/支付等入口，并为每个入口生成漏洞假设。"
priority: 8
vuln_types:
  - 站点爬取
  - 功能发现
  - API发现
  - 入口点枚举
triggers:
  - crawl
  - spider
  - sitemap
  - robots.txt
  - 站点地图
  - 爬取
  - 页面发现
  - 功能发现
  - XHR
  - Fetch
  - JS路由
  - SPA
  - 表单
synonyms:
  - crawling strategy
  - site crawl
  - spidering
  - sitemap discovery
  - function discovery
  - 站点探索
  - 爬虫策略
metadata:
  tags: "crawl,爬取,探索,发现,sitemap,站点地图,功能发现,API发现"
  category: "recon"
  authority: "expert"
---

# 站点爬取策略方法论

## 0. 立即执行摘要：爬虫输出必须变成测试入口，而不是 URL 列表

爬取阶段的目标是发现所有可交互入口，并为每个入口标记候选漏洞。每个页面/接口至少要记录：**身份、触发动作、请求、参数、响应、对象归属字段、候选 skill**。如果只保存 URL，不记录参数和触发动作，后续 LLM 会漏测。

三遍爬取之外，必须额外覆盖：

1. JS bundle/source map 中隐藏 API。
2. Swagger/OpenAPI/GraphQL schema。
3. WebSocket/Socket.IO 端点。
4. 上传、导入、导出、下载、预览、支付、优惠券、审批、邀请、分享、Webhook。
5. 移动端/小程序/旧版本 API 与 Web API 差异。

## 核心原则：三遍爬取法

一个网站至少要爬三遍才算完整：

| 轮次 | 身份 | 目的 |
|------|------|------|
| 第一遍 | 未登录 | 发现公开页面、登录/注册入口、公开 API |
| 第二遍 | 普通用户 | 发现登录后功能、用户专属页面、业务 API |
| 第三遍 | 管理员（如有） | 发现管理功能、对比与普通用户的差异 |

**对比不同角色看到的差异本身就是越权检测的第一步。**

## Phase 0.1: 未登录爬取

### 页面发现
1. 从首页开始，递归跟踪所有 `<a href>` 链接
2. 检查 `robots.txt` — 它告诉你网站不想被看到的路径
3. 检查 `sitemap.xml` — 网站主动暴露的全部路径
4. 检查常见路径：`/admin` `/login` `/register` `/api` `/docs` `/swagger`

### 元素发现
每个页面上，提取并点击：
- 所有 `<a>` 链接
- 所有 `<button>` 按钮
- 所有 `<form>` 表单（先不提交）
- 所有 `[onclick]` 元素
- 所有 `[role=button]` 元素
- 导航栏/侧边栏的所有菜单项（包括需要 hover 展开的）

### 请求记录
通过代理抓包记录：
- 页面加载时的所有 XHR/Fetch 请求（很多 SPA 应用的 API 在这里）
- 点击元素后触发的请求
- 每个请求的方法、URL、参数、响应格式

## Phase 0.2: 登录后爬取

### 登录方式
1. 用用户提供的账号密码登录
2. 如果没提供账号，尝试注册一个
3. 登录后保存 Cookie/Token

### 登录后发现
登录后会出现大量新内容：
- 用户中心/个人设置
- 订单/交易记录
- 充值/提现/钱包
- 消息/通知
- 收藏/关注

### 对比未登录
记录登录前后的差异：
- 新出现了哪些页面？
- 新出现了哪些 API？
- 同一个 API，登录前后返回的数据有什么不同？

## Phase 0.3: 隐藏端点发现

### JS 文件分析
1. 收集页面加载的所有 `.js` 文件
2. 在 JS 中搜索 API 路径模式：`/api/` `/v1/` `/v2/` 
3. 搜索关键词：`fetch(` `axios.` `$.ajax` `XMLHttpRequest`
4. 提取出的路径可能包含未在页面上暴露的管理 API

### 响应分析
1. 检查每个 API 响应中是否有其他 API 的 URL
2. 检查 HTML 注释中是否有隐藏链接
3. 检查 `<script>` 标签中的配置变量（常含 API 地址）

### 路径推测
发现 `/api/user/info` 后，推测可能存在：
- `/api/user/list` `/api/user/delete` `/api/user/update`
- `/api/admin/user/list`（管理端）
- `/api/v2/user/info`（新版本）

## Phase 0.4: 表单智能填写

### 字段识别
对每个表单的输入框，根据 name/type/placeholder 判断含义：
- `username` `email` `phone` → 身份信息
- `password` `passwd` `pwd` → 密码
- `amount` `price` `money` → 金额（高优先级！）
- `code` `captcha` `verify` → 验证码
- `id` `user_id` `order_id` → 对象标识符（高优先级！）

### 填写策略
- 文本框：填合理的测试数据
- 下拉框：选第一个非空选项
- 单选框：选第一个
- 文件上传：暂时跳过（Phase 2 再测）
- 验证码：如果是图片验证码，标记为"需要人工介入"

### 提交并跟踪
提交表单后：
- 记录提交的请求（方法、URL、参数）
- 记录响应（成功/失败/跳转）
- 如果跳转到新页面，继续爬取新页面

## Phase 0.5: 爬取结果到漏洞假设映射

| 爬取发现 | 候选漏洞 | 后续 skill |
|---|---|---|
| 登录后新增 API | 未授权、认证绕过 | `no-auth-quick-test`、`auth-bypass-methodology` |
| URL/参数含对象 ID | IDOR/BOLA | `idor-methodology` |
| 表单含金额/数量/价格/优惠券 | 业务逻辑漏洞 | `business-logic-attack` |
| 表单含 `role/is_admin/status` | 权限提升/Mass Assignment | `privilege-escalation-web` |
| 搜索/筛选/排序 | SQLi/XSS/NoSQL | `sql-injection-methodology`、`xss-methodology`、`nosql-injection` |
| 文件上传/导入 | 上传漏洞/XXE/ZIP Slip | `file-upload-methodology`、`xxe-injection-methodology` |
| 下载/导出/预览 | IDOR/LFI/SSRF | `idor-methodology`、`lfi-rfi-methodology`、`ssrf-methodology` |
| 第三方登录/回调 | OAuth/SSO/Open Redirect | `oauth-sso-attack`、`open-redirect` |
| WebSocket | CSWSH/消息越权 | `websocket-attack` |
| GraphQL | BOLA/批量/Introspection | `graphql-methodology` |

## 最低必测自检

标记爬取完成前必须确认：

1. 已完成未登录、普通用户、管理/高权限角色（如有）的三遍爬取。
2. 已点击按钮、菜单、hover 展开项、分页、筛选、导出、上传、弹窗、表单提交。
3. 已提取 JS 中 API、配置、source map、隐藏路由和注释。
4. 已记录每个请求的参数、身份要求、响应类型和候选漏洞。
5. 已对登录前后、多角色之间的新增页面/API 做差异清单。

## 输出格式

```text
[爬取入口]
页面/功能：
触发动作：访问/点击/提交/上传/导出/筛选/分页/hover/自动加载
身份：未登录/普通用户/管理员/租户/未知
请求：METHOD URL
参数：path/query/body/header/cookie/file/ws/graphql
响应：HTML/JSON/文件/跳转/错误/WebSocket/未知
对象字段：id/user_id/order_id/file_id/tenant_id/无
候选漏洞：
建议 skill：
优先级：P0/P1/P2/P3
```
