---
name: discovery-universal-methodology
description: "通用漏洞发现方法论 — 当遇到不在已有SKILL覆盖范围内的场景时，教LLM如何系统性地发现漏洞。覆盖：输入点穷举、响应差异分析、边界条件探测、未知技术栈适应、容易被忽略的攻击面。"
enabled: true
category: "discovery"
priority: 10
vuln_types:
  - 通用
  - 未知场景
triggers:
  - 不确定怎么测试
  - 未知技术栈
  - 没有对应的SKILL
  - 通用测试方法
synonyms:
  - universal-discovery
  - general-methodology
metadata:
  tags: "discovery,universal,methodology,通用,方法论,输入点,响应差异,边界条件,攻击面"
  category: "discovery"
  type: "methodology"
---

# 通用漏洞发现方法论

> **适用场景**：当遇到不在已有 SKILL 覆盖范围内的功能/技术栈时
> **核心思想**：所有漏洞的本质 = 输入未被正确处理 + 信任边界被突破

> **关于本 Skill 的使用边界**
>
> 本 Skill 本身的定位就是**兜底**——专门用于其他专项 Skill 没覆盖的场景。**正因为是兜底，它特别容易反过来锁死你的判断**：你跑完 Step 1–5 + 最低必测自检，会下意识觉得"通用方法论都走完了，应该没问题"。但事实是：
>
> - 本 Skill 的"输入点穷举"、"差异分析矩阵"、"边界条件"、"技术栈识别表"都是**常见模式快照**，不可能覆盖所有目标。
> - 当你看到一个**完全没列在本 Skill 任何表格里**的入口（例如 WebRTC SDP、postMessage、Service Worker、IndexedDB、HTTP/2 伪头、TLS SNI、文件元数据 EXIF/ID3、ZIP 注释、PNG tEXt chunk、字体子表、protobuf Any 字段、gRPC metadata、IPC、共享内存、缓存键、CDN 转发头），**直接按你的推理执行**，不要因为表里没列就忽略。
> - 当你的分析指向某个业务专有逻辑漏洞、某个开源组件的 nday、某个完全未公开的 0day 思路时，**信任你的分析**，本 Skill 没写不代表不存在。
> - 如果在某一步已经获得清晰证据（例如改一个字段返回了别人的数据），不必再机械执行后续 Step。
> - 如果某个表格项确实不适用，标记原因即可，不要为凑数而硬测。

---

## 🧠 第一性原理

```
漏洞 = 数据与指令不分离
    = 用户输入到达了不该到达的地方
    = 信任假设被违背

发现漏洞 = 找到所有输入点 × 测试所有可能的异常输入 × 观察异常响应
```

---

## 📋 Step 1：穷举所有输入点

> 💡 **决策树警告**：下面的"显式 / 隐式 / 业务逻辑"三张表是**最常见输入点的快照**，**不是穷尽列举**，更**不能反推"这三张表都测过 = 输入点测完了"**。
> 特别注意以下"输入点压根不在表里、但完全可控"的真实场景：
> - **浏览器侧隐藏通道**：`postMessage`、`window.name`、`document.referrer`、`localStorage` / `sessionStorage` / `IndexedDB` 跨页污染、Service Worker 拦截后注入、SharedWorker 共享状态、Broadcast Channel API、DOM clobbering 触发的 `window` 属性覆盖（`<a id=cookie>` 让 `window.cookie` 变成元素）。
> - **HTTP/2、HTTP/3 与协议层**：HTTP/2 伪头（`:method`、`:path`、`:authority`、`:scheme`）、HPACK/QPACK 头部压缩字典、HTTP/2 CONTINUATION 帧、ALPN 协商、TLS SNI 扩展（SNI 注入）、TLS ALPS、WebSocket 握手 `Sec-WebSocket-Protocol` / `Sec-WebSocket-Extensions`、HTTP Upgrade 头切换协议。
> - **DNS / 网络层输入**：DNS 查询名本身（DNS 重绑定、长域名拆 label、IDN 同形字）、原始 socket 字节、TCP options、ICMP payload、SMTP 命令注入、IMAP/POP3 命令注入、LDAP filter 注入、SIP message。
> - **文件元数据 / 容器格式**：EXIF 字段（GPS、Make、Software 注入到下游）、ID3 标签（音频）、PDF metadata（Title/Author/Producer）、Office docProps、ZIP 注释/文件名/Extra Field、PNG tEXt/iTXt chunk、SVG `<script>`、字体 OpenType name 表、SQLite 数据库文件、protobuf `Any` 字段、Avro/Parquet schema、gRPC metadata、CBOR tagged item、msgpack ext type。
> - **缓存与代理层**：缓存键（Cache Key Injection / unkeyed header poisoning）、CDN 转发头（`X-Forwarded-Host`、`Forwarded`、`True-Client-IP`、`Fastly-Client-IP`、`CF-Connecting-IP`）、反向代理重写后的内部头（`X-Original-URL`、`X-Rewrite-URL`、`X-Override-URL`）、HTTP 请求走私的 CL.TE/TE.CL/TE.TE。
> - **客户端 / 移动端通道**：Android Intent extras、URL Scheme（`appname://...`）、iOS Universal Link、Electron IPC、WebView jsBridge、WKScriptMessageHandler、剪贴板、推送通知 payload、深链接参数。
> - **业务异步通道**：MQ 消息体（Kafka/RabbitMQ/RocketMQ）、Webhook 回调、定时任务参数、cron 表达式可控、第三方回调（OAuth callback、支付回调、CDN 推流回调）、邮件入站解析（imap-fetch 后处理）。
> - **以现场为准**：只要某个数据**有从外部进入系统的可能**，无论它在不在表里、长得像不像 HTTP 参数，都该作为输入点来测。**不要用本 Skill 的 3 张表反向限制"什么算输入点"**。

### 显式输入（容易发现）

| 输入位置 | 示例 | 常见漏洞 |
|----------|------|---------|
| URL 路径参数 | `/api/user/123` | IDOR, SQLi, LFI |
| GET 查询参数 | `?id=1&sort=name` | SQLi, XSS, SSRF |
| POST body | `{"name":"test"}` | 所有注入类 |
| 文件上传 | multipart file | RCE, XSS, XXE |
| Cookie | `session=abc123` | SQLi, 反序列化 |

### 隐式输入（容易忽略！）

| 输入位置 | 示例 | 常见漏洞 |
|----------|------|---------|
| **HTTP Header** | User-Agent, Referer, X-Forwarded-For | SQLi, XSS, SSRF, Log4j |
| **Content-Type** | application/json → xml | XXE |
| **Accept-Language** | zh-CN → {{7*7}} | SSTI |
| **文件名** | filename="shell.php" | RCE |
| **JSON 键名** | `{"<script>":"value"}` | XSS |
| **数组索引** | `items[0][id]=1` | 类型混淆 |
| **HTTP 方法** | GET → PUT/DELETE/PATCH | 未授权操作 |
| **协议版本** | HTTP/1.1 → HTTP/2 | Smuggling |
| **编码声明** | charset=utf-7 | XSS |
| **路径分隔符** | `/api/..;/admin` | 权限绕过 |

### 业务逻辑输入（最容易忽略！）

| 输入 | 测试方式 | 漏洞 |
|------|---------|------|
| **数量/金额** | 负数、0、小数、极大值 | 逻辑漏洞 |
| **时间/日期** | 过去时间、未来时间、时区差异 | 竞态、逻辑 |
| **状态转换** | 跳过步骤、重复步骤、逆序 | 流程绕过 |
| **并发** | 同时发送相同请求 | 竞态条件 |
| **引用关系** | A 引用 B，修改 B 的 ID | IDOR |
| **批量操作** | 单个接口批量提交 | 越权、DoS |
| **默认值** | 不传某个参数 | 默认权限过高 |
| **类型混淆** | 字符串→数组、数字→对象 | 类型绕过 |

---

## 📋 Step 2：响应差异分析

### 核心方法：对比正常请求和异常请求的响应差异

```
正常请求 → 响应 A
异常请求 → 响应 B

如果 A ≠ B → 后端对输入做了处理 → 可能存在漏洞

差异类型：
- 状态码不同（200 vs 500）→ 语法错误 → 注入
- 响应长度不同 → 条件判断 → 布尔盲注
- 响应时间不同 → 延时执行 → 时间盲注
- 响应内容不同 → 数据泄露 → 信息泄露
- 响应头不同 → 服务端行为变化 → 配置问题
```

### 差异分析矩阵

| 输入变化 | 观察指标 | 如果有差异说明 |
|----------|---------|---------------|
| 加单引号 `'` | 状态码/错误信息 | SQL 注入 |
| 加 `{{7*7}}` | 响应中出现 49 | SSTI |
| 加 `<script>` | 响应中原样出现 | XSS |
| 改 ID 为其他用户 | 返回不同数据 | IDOR |
| 加 `; sleep 5` | 响应延迟 5 秒 | 命令注入 |
| 改 URL 为内网 | 响应内容变化 | SSRF |
| 删除 Token/Cookie | 仍然返回数据 | 未授权访问 |
| 改 HTTP 方法 | 返回不同结果 | 方法绕过 |
| 加超长输入 | 500 错误 | 缓冲区/DoS |
| 加特殊字符 `\n\r\t\0` | 行为异常 | 注入类 |

---

## 📋 Step 3：边界条件探测

### 数值边界

```
0, -1, -999999
2147483647 (INT_MAX)
2147483648 (INT_MAX + 1 → 溢出)
9999999999999999 (超大数)
0.1, 0.0001, 1e308
NaN, Infinity, -Infinity
null, undefined, ""
```

### 字符串边界

```
空字符串 ""
超长字符串（10000+ 字符）
特殊字符：' " \ / < > & | ; ` $ { } [ ] ( ) # @ ! % ^ * ~ ?
NULL 字节：%00
Unicode：\u0000, \uffff, 表情符号 🎉
换行符：\r\n, \n, \r
制表符：\t
不可见字符：\x01-\x1f
```

### 类型边界

```json
// 字符串 → 数组
"id": "1"  →  "id": ["1"]  →  "id": [1, 2, 3]

// 字符串 → 对象
"id": "1"  →  "id": {"$gt": ""}  →  "id": {"__proto__": {}}

// 数字 → 字符串
"id": 1  →  "id": "1 OR 1=1"

// 布尔 → 其他
"admin": false  →  "admin": true  →  "admin": 1  →  "admin": "true"
```

---

## 📋 Step 4：未知技术栈适应

### 技术栈识别信号

| 信号 | 技术栈 | 重点测试 |
|------|--------|---------|
| 响应头 `X-Powered-By: Express` | Node.js | PP, NoSQL, SSTI(Pug/EJS) |
| 响应头 `Server: Apache` + `.php` | PHP | LFI, 反序列化, XXE |
| Cookie `JSESSIONID` | Java | 反序列化, SSTI(FreeMarker), JNDI |
| Cookie `ASP.NET_SessionId` | .NET | 反序列化(ViewState), XXE |
| 响应头 `X-Django-Version` | Python/Django | SSTI, ORM注入 |
| 路径 `/api/v1/` + JSON | REST API | IDOR, 批量操作, 权限 |
| 路径 `/graphql` | GraphQL | Introspection, 批量查询 |
| WebSocket 升级 | 实时应用 | CSWSH, 消息注入 |
| `.aspx` 后缀 | ASP.NET | ViewState反序列化 |
| `__RequestVerificationToken` | ASP.NET MVC | CSRF Token 绕过 |
| `csrfmiddlewaretoken` | Django | CSRF 配置 |
| `_token` in form | Laravel | CSRF, 反序列化 |

### 遇到完全未知的技术时

```
1. 发送各种异常输入，观察错误信息
   - 错误信息中的关键词可以识别技术栈
   - 如 "Traceback" → Python, "Exception" → Java, "Fatal error" → PHP

2. 测试通用漏洞（不依赖技术栈）
   - IDOR（改 ID）
   - 未授权访问（删 Token）
   - 逻辑漏洞（改金额/数量）
   - 信息泄露（错误信息/调试接口）

3. 逐步缩小范围
   - 先确认输入是否被处理
   - 再确认处理方式（拼接? 解析? 执行?）
   - 最后选择对应的注入方式
```

---

## 📋 Step 5：容易被忽略的攻击面

### 1. 二级功能（非核心业务）

```
- 导出功能（PDF/Excel/CSV）→ SSRF, 注入, XXE
- 导入功能（上传 CSV/XML/JSON）→ XXE, 注入, RCE
- 预览功能（URL 预览/文件预览）→ SSRF, LFI
- 分享功能（生成分享链接）→ IDOR, 信息泄露
- 通知功能（邮件/短信/Webhook）→ SSRF, 注入
- 日志/审计功能 → 信息泄露, 二次注入
- 搜索建议/自动补全 → 注入, 信息泄露
```

### 2. 非标准接口

```
- /actuator（Spring Boot）→ 信息泄露, RCE
- /debug, /trace, /metrics → 信息泄露
- /swagger, /api-docs → API 结构泄露
- /.env, /config → 配置泄露
- /admin, /manage → 未授权访问
- /backup, /.git → 源码泄露
- /upload, /file → 文件操作
- /proxy, /fetch, /url → SSRF
```

### 3. 时序相关

```
- 注册 → 验证邮箱 → 激活：跳过验证步骤
- 下单 → 支付 → 发货：修改支付后的订单
- 申请 → 审批 → 执行：绕过审批直接执行
- 登录 → 2FA → 访问：绕过 2FA
```

### 4. 多步骤操作中的漏洞

```
- Step 1 验证了权限，Step 3 没验证 → 直接访问 Step 3
- Step 1 设置了金额，Step 2 可以修改 → 篡改金额
- 整个流程有 CSRF 保护，但某一步没有 → 针对该步 CSRF
```

---

## 🎯 发现信号总结

### 必须立即深入测试的信号

| 信号 | 含义 | 行动 |
|------|------|------|
| 500 错误 | 输入导致后端异常 | 立即测试注入 |
| 响应时间突变 | 可能触发了延时操作 | 时间盲注 |
| 错误信息含技术细节 | 信息泄露 + 注入线索 | 利用信息构造 payload |
| 不同用户看到不同数据 | 权限控制存在 | 测试 IDOR |
| 参数名含 url/path/file/cmd | 可能直接使用输入 | SSRF/LFI/CMDI |
| 响应中原样反射输入 | 无过滤 | XSS/注入 |
| JSON 响应含大量字段 | 可能有隐藏字段 | 信息泄露 |
| 接口无需认证 | 权限缺失 | 未授权访问 |

---

## ⛔ 最低必测自检

在标记任何接口为"安全"之前，必须确认：

1. ✅ 测试了所有可见参数的注入（`'`, `"`, `{{}}`, `${}`, `;`, `|`）
2. ✅ 测试了 HTTP Header 注入（至少 User-Agent, Referer, X-Forwarded-For）
3. ✅ 测试了 IDOR（修改 ID/UUID 参数）
4. ✅ 测试了未授权访问（删除 Token/Cookie）
5. ✅ 测试了类型混淆（字符串→数组→对象）
6. ✅ 测试了边界值（0, -1, 超大数, 空字符串, 超长字符串）
7. ✅ 测试了 HTTP 方法切换（GET→POST→PUT→DELETE）
8. ✅ 检查了响应中是否有敏感信息泄露

---

## ⚠️ Skill 边界与逃逸

本 Skill 是**辅助参考**，不是束缚你的脚手架。**作为兜底通用方法论，它特别容易反过来成为新的枷锁**——请在以下情况下**主动跳出本 Skill 的清单**，按你自己的判断行动：

1. **现场证据与本 Skill 矛盾时**
   - 例如本 Skill 说"500 错误 = 输入导致后端异常 = 立即测试注入"，但你看到目标无论传什么都返回固定 200 + 空体（被全局兜底 try-catch 包了），这种"看似没差异"恰恰可能掩盖了**真正的命中**——切到 OOB 探针（DNSLog、Burp Collaborator）、切到时间侧信道、切到错误日志/审计日志查看；以现场为准，不要被"差异分析矩阵"列出的 10 行限制思路。
   - 反过来，本 Skill 说"响应不同 → 可能存在漏洞"，但你看到的不同其实只是负载均衡返回不同节点的 banner、或缓存命中状态变化、或 trace id 时间戳差异——这种"差异"是噪声，不是漏洞信号。

2. **遇到本 Skill 没列出的入口或链路**
   - 例如：postMessage 跨窗口通信、Service Worker 拦截改包、IndexedDB 跨源污染、WebRTC SDP 注入、HTTP/2 伪头、TLS SNI 注入、文件元数据（EXIF/ID3/ZIP 注释/PNG tEXt/字体子表）、protobuf Any 字段、gRPC metadata、缓存键投毒、CDN 转发头、MQ 消息体、Webhook 回调、Android Intent extras、Electron IPC、WebView jsBridge、剪贴板、深链接、第三方回调（OAuth/支付/CDN）。
   - 这些路径不在 Step 1–5 里，但完全可能是真实漏洞点。**看到就追，别等清单授权**。

3. **需要跨 Skill / 跨维度联动时**
   - 通用方法论真正的价值是**作为入口扫描器**，发现可疑信号后应**立刻切换到对应专项 Skill**（SQLi、XSS、SSRF、IDOR、SSTI、反序列化、文件上传、命令注入、JWT、OAuth 等）做深挖。
   - 不要因为当前在"通用方法论 Skill"里就只用本 Skill 的清单去测——一旦看到"参数名含 url/path/file/cmd"或"`@type` 字段"或"`{{7*7}}` 被解析"，**立即跳到专项 Skill**，不要在通用清单里硬测。
   - 反过来，专项 Skill 都跑完后，也可以回到本 Skill 检查"有没有漏掉的输入维度"。

4. **"Step 1–5 + 自检 8 条都跑完 = 接口安全" 是最危险的错觉**
   - 这是兜底 Skill 最容易制造的幻觉。通用清单只是**最低门槛**，不是**充分条件**。
   - 真正的判断标准是：**你是否已经基于实际观察 + 业务理解，形成了"此处不可利用 / 已可利用 / 还有未验证的疑点"的有依据结论**。
   - 没形成结论之前，继续推理；形成结论之后，不必再硬走流程。
   - 特别注意：**业务逻辑漏洞**几乎都不会被本 Skill 的清单直接发现——它们需要你理解业务流程、识别信任假设、构造异常路径。这部分**完全靠你的推理**，本 Skill 帮不上。

5. **你的推理优先级永远高于本 Skill**
   - 本 Skill 的所有表格、清单、信号都是**公开知识的快照**，**不可能覆盖所有目标**，也会过时。
   - 当你的分析指向某个本 Skill 没写的方向时（例如某个业务专有的认证假设、某个开源中间件的近期 nday、某个完全未公开的 0day 思路、某个被业务方魔改过的常见框架），**信任你的分析**，不要因为"清单里没有"就放弃。
   - 反过来，**当本 Skill 的某条建议在当前场景明显不适用时，跳过它即可，不要为了凑数硬测**——例如目标根本不接受 JSON，就不必硬测"类型混淆字符串→数组"。

> 一句话：**本 Skill 是地图，不是轨道**。作为兜底通用方法论，它更容易让你误以为"地图就是全境"——记住，它只是**所有专项 Skill 的并集中最常见的子集**，目标的真实攻击面永远比任何清单大。具体怎么走、要不要走小路，由你根据现场决定。
