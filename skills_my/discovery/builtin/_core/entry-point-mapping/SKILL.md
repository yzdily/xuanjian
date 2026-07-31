---
name: entry-point-mapping
description: "入口点 → 漏洞类型 → SKILL 映射表。Agent 在 Phase 2 测试功能点时，根据此表判断该入口点最可能存在什么漏洞，精准加载对应 SKILL。这是 Agent 渗透决策的核心路由表 — 定义'至少测什么'，但不限制你的推理。"
priority: 10
vuln_types:
  - 攻击面路由
  - 入口点映射
  - 漏洞发现
triggers:
  - API
  - 接口
  - 数据包
  - 功能点
  - 参数
  - 登录
  - 注册
  - 订单
  - 用户
  - 上传
  - 导出
  - 回调
  - webhook
  - 管理后台
synonyms:
  - entrypoint
  - route-to-skill
  - feature-routing
  - attack-surface-routing
metadata:
  tags: "mapping,路由,决策,入口点,功能点,漏洞类型,SKILL选择"
  category: "strategy"
  authority: "expert"
---

# 入口点 → 漏洞类型 → SKILL 映射表

## 0. 强制路由闸门：看到数据包后先做这一步

在任何具体漏洞测试前，先把当前请求按下面 4 层打标签；一个请求可以命中多个标签，**命中即加载对应 SKILL，不要二选一**。

| 数据包/功能特征 | 必须加载 | 不能遗漏的原因 |
|---|---|---|
| `id`、`uid`、`user_id`、`order_id`、`tenant_id`、`org_id`、资源路径数字/UUID | `idor-methodology` + `privilege-escalation-web` | 任何对象引用都可能是水平/垂直/租户越权 |
| `url`、`uri`、`link`、`src`、`callback`、`webhook`、`redirect`、`next`、`returnUrl` | `ssrf-methodology` + `open-redirect` | URL 参数常同时具备服务端请求和浏览器跳转语义 |
| `file`、`path`、`dir`、`template`、`page`、`lang`、`download`、`export` | `lfi-rfi-methodology` + `file-upload-methodology` + `information-disclosure-methodology` | 文件读写/模板/导出通常能升级为信息泄露或执行链 |
| `q`、`query`、`search`、`filter`、`sort`、`orderBy`、`where`、JSON 条件对象 | `sql-injection-methodology` + `nosql-injection` + `xss-methodology` | 查询语义同时可能进入数据库、搜索引擎和页面回显 |
| `role`、`is_admin`、`permission`、`scope`、`status`、`price`、`amount`、`discount` | `business-logic-attack` + `privilege-escalation-web` | 业务状态和权限字段不能只当普通参数处理 |
| `Authorization`、`Cookie`、`Set-Cookie`、`token`、`access_token`、`jwt` | `cookie-analysis` + `jwt-attack-methodology` + `auth-bypass-methodology` | 认证材料既要测伪造，也要测降级、混用、过期和服务端校验 |

**最低执行要求**：每个数据包至少输出 `命中特征 → 候选漏洞 → 已加载/应加载 skill → 未测原因`。如果缺账号、缺第二用户、缺样本，只能标 `needs_review`，不能标 `not_vuln`。

## ⚠️ 核心原则：这是下限，不是上限

> **此映射表告诉你"至少要测什么"，而不是"只能测这些"。**
>
> - 映射表命中的 → 加载对应 SKILL，按方法论执行
> - 映射表没列的，但你根据推理觉得可疑的 → **鼓励你自主探索**
> - 通用检查层 → 每个入口点都必须做，不需要查表
>
> 你是渗透测试专家，不是查表机器。映射表帮你不遗漏，推理能力帮你发现新攻击面。

---

## 零、通用检查层（每个入口点必做，无需加载 SKILL）

**不管看到什么功能，以下检查直接做，不需要查表：**

| 检查项 | 做法 | 工具 |
|--------|------|------|
| 未授权访问 | 去掉 Token/Cookie 重发请求，看是否仍返回数据 | `proxy_replay` 删 Cookie |
| IDOR 越权 | 有 ID 参数就改成别人的 ID | `proxy_replay` 改 ID |
| CSRF | 敏感 POST 操作（修改/删除/转账）是否有 CSRF token | 观察请求参数 |
| CORS | 检查响应中 Access-Control-Allow-Origin 是否反射 Origin | `proxy_get_flow_detail` |
| 响应信息泄露 | 响应中是否多返回了不该有的字段（密码hash/内部ID/调试信息） | `proxy_get_flow_detail` |
| 输入回显 XSS | 任何输入被回显到页面的地方，试 `<img src=x onerror=alert(1)>` | `browser_fill` |
| HTTP 方法测试 | 403 的路径试 PUT/DELETE/PATCH，GET 的接口试 POST | `proxy_send_request` |

**这些是"渗透测试直觉"，不需要方法论指导，直接做。**

---

## 一、认证相关入口点

### 登录页面
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 用户名/密码表单 | 用户枚举（不同用户名返回不同提示） | `user-enum-data-leak` |
| 用户名/密码表单 | SQL 注入（万能密码） | `sql-injection-methodology` |
| 有验证码 | 验证码绕过后暴力破解 | `captcha-bypass` |
| 登录后有 Cookie/Token | Cookie 伪造 / JWT 攻击 | `cookie-analysis` / `jwt-attack-methodology` |
| 有"记住我"功能 | Cookie 可预测/伪造 | `cookie-analysis` |
| 响应中有 token | Token 泄露 | `information-disclosure-methodology` |

### 注册页面
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 注册表单 | 用户枚举（"该用户已存在"） | `user-enum-data-leak` |
| 注册表单有角色/类型字段 | Mass Assignment（注册时传 role=admin） | `privilege-escalation-web` |
| 手机号/邮箱注册 | 短信轰炸 | `captcha-bypass` |
| 邀请码注册 | 邀请码可遍历/绕过 | `business-logic-attack` |

### 密码重置/找回密码
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 输入邮箱/手机号 | Host 头投毒、Token 泄露 | `password-reset-attack` |
| 短信验证码 | 验证码爆破/重放 | `captcha-bypass` |
| 多步骤流程 | 跳步绕过 | `password-reset-attack` |
| 重置链接含 token | Token 可预测 | `password-reset-attack` |

### OAuth/SSO 登录
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| redirect_uri 参数 | 重定向劫持 → token 窃取 | `oauth-sso-attack` + `open-redirect` |
| state 参数 | CSRF 绑定攻击 | `oauth-sso-attack` |
| 第三方登录按钮 | 配置错误 | `oauth-sso-attack` |

---

## 二、数据操作入口点

### 带 ID 参数的 API（/user/1001, /order/10086）
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| URL 或 body 中有数字 ID | IDOR 水平越权 | `idor-methodology` |
| 有多个角色（管理员/普通用户） | 垂直越权 | `privilege-escalation-web` |
| 去掉 Token 仍可访问 | 未授权访问 | `401-403-bypass` |
| ID 是自增数字 | ID 遍历泄露数据 | `user-enum-data-leak` |

### 搜索/查询功能
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 搜索框 + 结果回显 | XSS（反射型） | `xss-methodology` |
| 搜索参数传到后端查询 | SQL 注入 | `sql-injection-methodology` |
| JSON body 查询 | NoSQL 注入 | `nosql-injection` |
| 搜索结果有分页 | 批量数据导出 | `user-enum-data-leak` |

### 个人资料/设置页
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 修改个人信息接口 | CSRF（敏感操作无 token） | `csrf-methodology` |
| 修改邮箱/手机号 | 账户接管链 | `password-reset-attack` |
| 修改请求有隐藏字段 | Mass Assignment | `privilege-escalation-web` |
| 头像上传 | 文件上传漏洞 | `file-upload-methodology` |

### 评论/留言/反馈/站内信
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 用户输入存储后展示给其他用户 | 存储型 XSS | `xss-methodology` |
| 消息/站内信有 ID | IDOR（读取他人消息） | `idor-methodology` |
| 富文本/HTML 内容 | XSS + 文件上传 | `xss-methodology` + `file-upload-methodology` |

### 收货地址/配送管理
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 地址增删改接口 | IDOR（改别人地址） + CSRF | `idor-methodology` + `csrf-methodology` |

---

## 三、业务流程入口点

### 支付/订单/购物车
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 金额/价格参数 | 金额篡改 | `business-logic-attack` |
| 数量参数 | 负数/0/溢出 | `business-logic-attack` |
| 优惠券/折扣码 | 重复使用/篡改面额 | `business-logic-attack` |
| 多步骤支付流程 | 订单替换/跳步 | `business-logic-attack` |
| 余额/积分操作 | 竞态条件（并发双花） | `race-condition-exploit` |
| 支付回调接口 | 回调伪造 | `business-logic-attack` |

### 优惠券/红包/邀请码/积分
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 领取/兑换接口 | 并发重复领取 | `race-condition-exploit` |
| 码有规律（纯数字/短字符串） | 枚举/遍历 | `user-enum-data-leak` |
| 使用后可转赠/分享 | 逻辑绕过 | `business-logic-attack` |

### 文件上传
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 图片/头像上传 | 文件上传（后缀/MIME 绕过） | `file-upload-methodology` |
| 文档导入（Excel/CSV/XML） | XXE / SSRF | `xxe-injection-methodology` + `ssrf-methodology` |
| 富文本编辑器 | 存储型 XSS / 文件上传 | `xss-methodology` + `file-upload-methodology` |
| 实名认证/KYC（证件照） | 文件上传 + 信息泄露 | `file-upload-methodology` + `idor-methodology` |

### 导入/导出/PDF生成
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 导出 CSV/Excel | 批量数据泄露 | `user-enum-data-leak` |
| 导入 XML/XLSX | XXE | `xxe-injection-methodology` |
| 导出无权限校验 | 越权导出 | `idor-methodology` |
| 导出/生成 PDF | HTML 注入 → SSRF/LFI | `pdf-generation-attack` |

### 邮件/短信发送功能
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 联系表单/反馈/分享给朋友 | 邮件头注入 | `email-header-injection` |
| 短信验证码发送接口 | 短信轰炸 | `captcha-bypass` |
| 邀请/通知邮件 | SSRF（邮件中的 URL 预览） | `ssrf-methodology` |

### 二维码/短链接生成
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 输入 URL 生成二维码/短链 | SSRF（服务端请求该 URL） | `ssrf-methodology` |

---

## 四、URL/请求参数入口点

### 含 URL 的参数（url=, src=, callback=, next=, redirect=）
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 参数值是 URL | SSRF | `ssrf-methodology` |
| 登录后跳转参数 | 开放重定向 | `open-redirect` |
| 图片/文件预览 URL 参数 | SSRF | `ssrf-methodology` |
| Webhook/回调 URL | SSRF | `ssrf-methodology` |
| JSONP callback 参数 | 数据窃取 | `jsonp-data-leak` |

### 含文件路径的参数（file=, page=, include=, lang=, template=）
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 参数值像文件路径 | LFI/任意文件读取 | `lfi-rfi-methodology` |
| PHP 应用 | PHP 伪协议利用 | `lfi-rfi-methodology` |
| lang=/locale= 参数 | LFI（`?lang=../../../../etc/passwd`） | `lfi-rfi-methodology` |

### 含模板/表达式的参数（name=, greeting=, template=, msg=）
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 输入被回显且非 HTML 上下文 | SSTI | `ssti-methodology` |
| Flask/Jinja2/Twig 应用 | SSTI | `ssti-methodology` |

### 含命令/系统操作的参数（ip=, host=, cmd=, ping=, domain=）
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 网络诊断工具（Ping/Traceroute/DNS） | 命令注入 | `command-injection-methodology` |
| 任何直接执行系统操作的功能 | 命令注入 | `command-injection-methodology` |

### 同名参数重复出现
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 前后端架构、有 WAF/代理 | HTTP 参数污染 | `http-parameter-pollution` |

---

## 五、API/协议入口点

### REST API
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| Swagger/OpenAPI 文档泄露 | 信息泄露 + API 枚举 | `information-disclosure-methodology` + `api-fuzz` |
| API 版本号（/v1/, /v2/） | 旧版本未下线 | `api-fuzz` |
| /admin/ /manage/ /internal/ | 未授权访问 | `401-403-bypass` |
| 批量操作接口（/batch, /bulk） | 绕过单条记录权限校验 | `idor-methodology` + `api-fuzz` |

### GraphQL
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| /graphql 端点 | Introspection 泄露 + 注入 + 批量查询 | `graphql-methodology` |

### WebSocket
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| ws:// 或 wss:// 连接 | CSWSH + 消息注入 | `websocket-attack` |

---

## 六、HTTP 层入口点

### 响应头
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| Access-Control-Allow-Origin 反射 | CORS 配置错误 | `cors-misconfiguration` |
| 自定义 Host 头被反射 | Host Header 攻击 | `http-host-header-attacks` |
| JSONP 响应（callback 参数） | 跨域数据窃取 | `jsonp-data-leak` |

### CDN/代理/缓存层
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| CDN 缓存响应（Cache-Control/X-Cache） | 缓存投毒 | `cache-and-smuggling` |
| 前后端代理架构 | HTTP 走私 | `cache-and-smuggling` |

### 子域名
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| 子域名返回云服务默认错误页 | 子域名接管 | `subdomain-takeover` |

---

## 七、信息收集阶段入口点

### JS 文件
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| SPA 应用的 JS bundle | 隐藏 API 端点 / API Key 泄露 | `js-api-extract` |
| Source Map 可访问 | 源码泄露 | `js-api-extract` + `information-disclosure-methodology` |

### 敏感路径
| 观察到的特征 | 最可能的漏洞 | 加载 SKILL |
|-------------|-------------|-----------|
| /.git/, /.svn/, /.env, /backup | 源码/配置泄露 | `information-disclosure-methodology` |
| /actuator, /debug, /phpinfo, /trace | 调试信息泄露 | `information-disclosure-methodology` |
| /robots.txt, /sitemap.xml | 隐藏路径发现 | `attack-surface-discovery` |

---

## 八、技术栈特征 → 额外关注方向

**识别出技术栈后，额外关注该技术栈的高频漏洞：**

| 技术栈特征 | 怎么识别 | 额外关注 |
|-----------|---------|---------|
| PHP | URL 含 .php / 响应头 X-Powered-By: PHP | LFI（php://filter）、反序列化、文件上传解析漏洞 |
| Java/Spring | /actuator、JSESSIONID Cookie、.do/.action URL | SpEL 注入、反序列化、Actuator 未授权 |
| Node.js/Express | connect.sid Cookie、JSON API 为主 | 原型链污染、NoSQL 注入 |
| Python/Flask | Flask 签名 Cookie（含.的 base64）、Werkzeug 调试 | SSTI (Jinja2)、pickle 反序列化 |
| Python/Django | csrfmiddlewaretoken、/admin/ 后台 | Django admin 弱密码、ORM 注入 |
| .NET/ASP | .aspx URL、__VIEWSTATE 参数 | ViewState 反序列化、路径穿越 |
| WordPress | /wp-admin/、/wp-content/、/wp-json/ | 已知插件漏洞、XML-RPC 攻击 |
| Nginx | Server: nginx | 路径穿越（/..;/）、CGI 解析漏洞 |
| Apache | Server: Apache | .htaccess 上传、路径解析（shell.php.xxx） |

**注意：技术栈识别不需要加载 SKILL，用 `proxy_get_flow_detail` 看响应头即可判断。**

---

## 使用指南

**Agent 的决策流程：**

```
Phase 1 识别功能点
    ↓
对每个功能点，执行"通用检查层"（不需要加载 SKILL）
    ↓
查此映射表，匹配特征 → 精准加载 1-3 个 SKILL
    ↓
有 SKILL → 按 SKILL 方法论执行（注意 authority 等级）
无 SKILL → 根据你的推理自主测试
    ↓
测试 → vuln_verify → note_add(type="result")
    ↓
⚠️ 完成映射表命中的测试后，问自己：
"这个功能点还有没有映射表没列出来的攻击面？"
如果你的推理告诉你有 → 继续测试。
映射表确保你不遗漏，但你的思考才是发现 0day 的关键。
```

**三条原则：**
1. **映射表是下限** — "至少测这些"，不是"只测这些"
2. **通用检查不需要查表** — 去 Token、改 ID、看回显，直接做
3. **推理优先于映射** — 如果你觉得某个地方可疑但映射表没列，测它
