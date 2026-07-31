---
name: information-disclosure-methodology
description: "Web 应用敏感信息泄露检测与利用。当发现 .git/.svn 目录、备份文件路径(.bak/.zip/.tar.gz)、.env 配置文件、Swagger/OpenAPI 文档、debug 页面等信息泄露点时使用。也适用于发现源码泄露后的深入利用：git 历史审计（git log -p -S 搜索已删除的密码和 flag）、svn wc.db 文件列表提取、.DS_Store 目录枚举。优先于漏洞利用——信息泄露可直接提供凭据和攻击路径，往往比直接挖漏洞更快进入系统"
priority: 10
vuln_types:
  - 信息泄露
  - 源码泄露
  - 凭据泄露
  - API文档泄露
  - 调试信息泄露
  - 敏感数据泄露
triggers:
  - .git
  - .env
  - swagger
  - openapi
  - debug
  - backup
  - source map
  - sourcemap
  - stack trace
  - token
  - secret
  - password
  - api_key
synonyms:
  - info-leak
  - information-disclosure
  - sensitive-data-exposure
  - source-code-leak
metadata:
  tags: "information_disclosure,information disclosure,source-code,backup,debug,credentials,ssh,.git,.svn,.env,git-dumper,svn-extractor,源码泄露"
  category: discovery
  authority: "expert"
---

# 信息泄露方法论

> **关于本 Skill 的使用边界（读 Phase 之前必读）**
>
> 本 Skill 是「**敏感信息泄露的发现 → 验证 → 升级链**」手册，**不是**「凡是返回任何内容都算泄露」的判定器，**也不是**「数据/源码安全的全集」。
>
> - **不要**把「`/.git/HEAD` 返回 200」直接等同「源码泄露已确认」——必须验证返回的是 git 真文件而非 Web 通配 200/SPA fallback；同理 `.env`、`.DS_Store`、`/swagger.json` 都要验内容而非仅状态码。
> - **不要**把「响应里有几个用户名/邮箱」直接等同「P0 PII 泄露」——必须区分**当前账号自己的数据**、**当前账号该看的同业务数据**、**当前账号不该看的他人数据**；后者请走 `idor-methodology` 闭环。
> - **不要**把本 Skill 当成「源码审计工具」——拿到源码后的鉴权/SQL/反序列化/模板 sink 排查请联动 `code-security-audit` + 各漏洞主 Skill；本 Skill 只负责把源码挖出来并提示**该往哪个 Skill 走**。
> - **不要**把「Server header 暴露版本号」「robots.txt 列了几个路径」单独判高危——这是**辅助证据**，必须叠加可利用结论才能升级。
> - **不要**把「stack trace / debug 页 / actuator 暴露」直接当 RCE——它通常是入口，需进一步联动 `lfi-rfi-methodology`、`ssrf-methodology`、`deserialization-methodology`、`ssti-methodology`、`auth-bypass-methodology` 验证可达 sink。
> - 看到 `.git` / `.svn` / `.env` / `swagger` / `actuator` / `phpinfo` / `.DS_Store` / `sourcemap` / `backup.zip` / 备份后缀 / 调试参数 / stack trace / 暴露的 token，**都应把本 Skill 当作必查项**跳 Phase 1。

## 0. 立即执行摘要：信息泄露要转化为攻击路径

发现信息泄露后不要只记录文件名，必须判断它能否升级：

| 泄露内容 | 风险等级 | 下一步 |
|---|---|---|
| 密钥、Token、Cookie、JWT_SECRET、数据库连接串、云凭证 | P0 | 在安全边界内验证凭据是否有效，转 `auth-bypass`/`jwt`/云资源风险 |
| 源码、`.git`、SourceMap、备份包 | P0/P1 | 搜索鉴权逻辑、隐藏接口、密钥、SQL/SSRF/文件操作 sink |
| Swagger/OpenAPI/GraphQL schema | P1 | 转 `api-fuzz`、`idor-methodology`、`graphql-methodology` |
| Stack trace、debug、actuator、phpinfo | P1/P2 | 提取路径、版本、环境变量、内部接口，寻找已知漏洞或未授权端点 |
| 用户手机号、邮箱、订单、地址、身份证局部字段 | P1/P2 | 判断是否越权、批量、可枚举，转 IDOR/用户枚举 |
| 版本号、Server header、内部路径 | P3 | 作为辅助证据，不能单独夸大 |

能验证有效性的泄露才是高质量报告；只有无敏感内容的路径存在或通用版本号，不应直接判高危。

## ⛔ 深入参考（必读）

> 💡 **决策树警告**：上表 6 类风险归类是**最常见情况**，**不是穷尽列举**。
> 特别注意以下「**看似低危实则 P0**」与「**看似 P0 实则无害**」的反直觉场景，遇到必须升级或降级判断：
>
> - **空目录索引 / `Index of /`** 看似无内容，但 `/uploads/`、`/backup/`、`/.well-known/` 下可能列出**他人上传的发票、合同、人脸照片** → 等价 **批量 IDOR + PII 泄露**，按 P0 处理
> - **SourceMap（`.js.map`）** 表面只是调试便利，但解开后 = **完整前端源码 + 隐藏 API 路径 + 后端字段名 + 注释里的 TODO/密钥** → 必须 `unwebpack-sourcemap` 还原后再判级
> - **JS bundle / chunk-vendor.js** 内嵌的 `apiKey`、`bucket`、`accessKeyId`、`AppID/SecretKey`（小程序）、企业微信 corpid + secret → **绝大多数 P0 都是从前端文件抠出来的**，不要只看后端
> - **CDN / 对象存储（OSS/S3/COS）公开桶**：根域 200 不代表无风险，需测 `?list-type=2`、`?delimiter=/`、`?prefix=` 列举对象；**桶可写**（PUT 200）等于站点级劫持，比读高一档
> - **`.well-known/security.txt` / `.well-known/openid-configuration` / `.well-known/assetlinks.json`** 不是泄露，是**指路牌**——常含内部 IDP、备用域名、Android 包名签名，配合 `oauth-sso-attack` / 子域接管使用
> - **mPaaS / Sentry / Bugsnag / 阿里云 ARMS / 腾讯 RUM 上报域** 在前端 JS 里暴露的 DSN/Project Token 可能允许伪造错误事件、读取他人崩溃堆栈（含 PII）
> - **GraphQL introspection 关闭 ≠ 安全**：可试 `__type(name:"User")`、字段差错回显、persisted query id 枚举、Apollo Studio 公开 schema、`/graphql.json`、`/graphiql.html` 旧路径
> - **`/actuator/*` 即使 401**：`/actuator/health` 常常无认证可探出依赖（DB/Redis/Kafka 主机名）；`/actuator/heapdump` 返回 200 = **直接拿到内存中的所有 token/密码**（P0）
> - **Stack trace 显示绝对路径**（`/home/admin/app/...` / `C:\Users\xxx\...`）单独低危，但与 LFI/任意文件读联动后即可定位 webroot/conf 提权
> - **`robots.txt` / `sitemap.xml`** 不直接泄露，但 disallow 列出的 `/admin-tmp/`、`/internal-api/`、`/backup-2024/` 是**最高效率的入口源**，必须当 entry-point 跑
> - **「200 但内容是 SPA index.html」是最常见误报**：`.git/HEAD`、`.env`、`/swagger.json` 都可能返回 SPA fallback，必须比对 `Content-Type`、内容长度、首行特征（`ref: refs/heads/`、`{`、`<!DOCTYPE`）
>
> 看到任意上述场景，**回到 Phase 1-6 重新走对应路径**，并按需联动 `js-api-extract` / `attack-surface-discovery` / `subdomain-takeover` / `oauth-sso-attack`。


## Phase 1: 源码和配置文件
直接请求常见敏感路径（逐一测试或批量扫描）：
```
/.git/HEAD          /.env              /config.py         /Dockerfile
/.svn/entries       /.svn/wc.db        /.DS_Store         /robots.txt
/WEB-INF/web.xml    /package.json      /app.py            /backup.sql
/.dockerenv         /composer.json     /Gemfile           /requirements.txt
```
1. 使用 `curl -s -o /dev/null -w '%{http_code}' http://TARGET/<path>` 批量检测状态码
2. 对 200 响应进一步检查内容是否为真实文件（排除自定义 404 页面）
3. `.git/HEAD` 返回 200 → git-dumper 整体 dump → git log 审计历史提交找密码/flag！
4. `.svn/entries` 或 `.svn/wc.db` 返回 200 → svn-extractor dump → 提取文件列表和内容
5. `.env` 返回 200 → 直接读取数据库连接串、API Key、SECRET_KEY 等敏感配置

## Phase 2: 调试信息
1. 发送畸形请求触发 500 错误页面（缺少参数、类型不匹配、非法字符）
2. Flask `debug=True` 显示完整源码和交互式 debugger（可能直接 RCE）
3. Django DEBUG=True 显示 settings、URL 路由、SQL 查询
4. Stack Trace 中提取：文件绝对路径、框架版本、数据库类型、变量值
5. 检查响应 Header：`Server`、`X-Powered-By`、`X-Debug-Token`、`X-Request-Id`
6. 尝试访问 `/debug`、`/trace`、`/actuator`（Spring Boot）、`/elmah.axd`（.NET）

## Phase 3: API 文档泄露
1. 逐一请求文档端点：`/docs`、`/swagger`、`/swagger.json`、`/swagger-ui.html`
2. 补充路径：`/openapi.json`、`/redoc`、`/api-docs`、`/graphql`、`/graphiql`
3. 检查 `/v1/docs`、`/v2/docs` 等带版本前缀的路径
4. API 文档中提取：所有端点列表、参数类型和示例值、认证方式、数据模型定义
5. 重点关注管理接口（`/admin/*`）、用户管理（`/users`）、文件操作（`/upload`、`/download`）
6. GraphQL introspection 查询：`{__schema{types{name,fields{name}}}}`

## Phase 4: 备份和日志
1. 扫描备份文件：`/backup.zip`、`/backup.tar.gz`、`/app.py.bak`、`/web.config.old`
2. 文件名变体：`index.php.bak`、`index.php~`、`index.php.swp`、`.index.php.swp`
3. 日志文件：`/access.log`、`/error.log`、`/debug.log`、`/app.log`
4. 使用 `spray` 或 `ffuf` 配合备份字典扫描更多路径
5. 数据库备份：`/dump.sql`、`/db.sql`、`/database.sql`、`/backup.sql`
6. 版本控制残留：`/.hg/`（Mercurial）、`/.bzr/`（Bazaar）

## Phase 5: API 参数操控
1. 发现 API 接口后，对查询参数做四种操控：置空、`%` 通配符、null、删除参数
2. `pageSize=9999` 放大分页，获取更多数据
3. `info` → `list` 端点变换，寻找列表接口
4. 空数组 `[]` → 删除 Token，测试认证绕过
5. 添加 `verbose=true`、`debug=1` 参数，检查是否返回额外信息

## Phase 6: 凭据搜索
1. 在已获取的源码/配置中搜索：`password`、`secret`、`api_key`、`token`、`mysql://`
2. 检查 `.env` 文件中的数据库连接串和第三方 API 密钥
3. 搜索 SSH 私钥：`/.ssh/id_rsa`、`/home/*/.ssh/id_rsa`
4. Base64 编码的凭据：解码所有 Base64 字符串检查内容
5. **找到凭据后立即在安全边界内验证**：例如用测试账号、只读接口、`whoami/profile` 类接口确认有效性；不要读取真实用户隐私或执行破坏性操作
6. Git 历史中搜索已删除的密码：`git log -p -S 'password'`

## Phase 7: 最低必测自检

标记 `not_vuln` 前必须确认：

- 已区分真实文件和自定义 404/统一错误页。
- 已检查响应内容是否包含有效密钥、源码、配置、PII、接口定义或调试栈，而不是只看 `200`。
- 源码泄露已搜索鉴权、上传、下载、SSRF、SQL、模板、反序列化等 sink。
- API 文档泄露已转入 `api-fuzz` 做未授权、IDOR、字段权限、批量接口验证。
- 凭据类泄露已用最小无害动作验证有效性；不能验证时标 `suspected`。
- 所有证据已脱敏，报告中不要贴完整密钥、完整身份证、完整手机号或真实用户隐私。

---

## ⚠️ Skill 边界与逃逸

本 Skill 覆盖的是「**信息泄露的发现 + 内容验证 + 升级路径分流**」，**以下场景必须从本 Skill 主动逃逸到联动 Skill**：

| 现场信号 | 应跳转/联动的 Skill 或方向 |
|---|---|
| 拿到 **`.git` / `.svn` / SourceMap / 备份包** 后要审源码 | `code-security-audit` + 对应漏洞主 Skill（SQLi/XSS/SSRF/反序列化/SSTI…） |
| 暴露的 **Swagger/OpenAPI/GraphQL schema** 要打接口 | `api-fuzz` + `idor-methodology` + `graphql-methodology` |
| 拿到 **JWT_SECRET / signing key / RS256 公钥** | `jwt-attack-methodology`（伪造/降级/混淆算法） |
| 拿到 **OAuth client_id+secret / IDP metadata / `.well-known/openid`** | `oauth-sso-attack` |
| **AccessKey / SecretKey / 云控制台凭据** | 走云资产风险评估，**不在本 Skill 范围内**直接打云 API |
| **数据库直连串 / Redis / MQ 凭据** 暴露 | 在合规边界内验证可连通即停，禁止脱库；进入后续合规上报流程 |
| **`.well-known/assetlinks.json` / 移动端配置** 暴露 | `mobile-backend` + 子域接管/深链劫持评估 |
| **CDN/OSS 公开桶 + 可写** | `subdomain-takeover` 思路（站点级劫持）+ 数据归属验证 |
| **stack trace / debug / actuator** 暴露内部接口 | `attack-surface-discovery` 收集后转主 Skill；heapdump → 凭据回流本 Skill |
| 暴露的是 **PII（手机号/邮箱/订单/身份证）** | 先判归属：自己数据 = 不算；他人数据 = 走 `idor-methodology` + `user-enum-data-leak` |
| **前端 JS 抠出的隐藏 API / 隐藏字段** | `js-api-extract` + `js-hidden-api-verify` |
| **多个域名/历史快照/Wayback 找到的旧路径** | `passive-recon` + `attack-surface-discovery` |
| 调试参数（`debug=1` / `verbose=true`）能切出 SQL/模板回显 | `sql-injection-methodology` / `ssti-methodology` |

> **一句话**：本 Skill 是「把别人不该露的东西挖出来 → 证明它真的露了 → 指出它能换成什么攻击」的转换层，不是「源码安全总论」也不是「PII 合规总论」。任何「200 + 看似有内容」都必须先做**真实性验证**（不是 SPA fallback / 不是统一错误页 / 内容能落地为攻击素材），然后**按上表分流**到主 Skill 闭环；没有可落地下一步的「泄露」只能算 `informational`，不能直接判 P0。
