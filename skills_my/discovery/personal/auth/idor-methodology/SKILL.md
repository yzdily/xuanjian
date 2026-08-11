---
name: idor-methodology
enabled: true
description: "IDOR/BOLA 越权漏洞完整方法论 — 基于 250+ HackerOne 真实报告 + Intigriti/CN-SEC 实战技巧提炼。覆盖水平越权、垂直越权、盲 IDOR、GraphQL IDOR、二阶 IDOR、多租户越权、API 版本降级、文件资源 IDOR、批量操作越权、403 绕过。任何出现 user_id/order_id/file_id/org_id/tenant_id/uuid/资源 ID/批量 ids/导出任务/对象归属的场景都必须使用此 skill。"
priority: 10
vuln_types:
  - IDOR越权
  - BOLA
  - 水平越权
  - 垂直越权
  - 多租户越权
  - 文件越权
  - 批量越权
  - 二阶IDOR
  - Mass Assignment
triggers:
  - id
  - ids
  - uuid
  - user_id
  - uid
  - account_id
  - member_id
  - order_id
  - invoice_id
  - file_id
  - attachment_id
  - org_id
  - tenant_id
  - workspace_id
  - project_id
  - batch
  - bulk
  - export
  - owner_id
synonyms:
  - idor
  - bola
  - broken object level authorization
  - insecure direct object reference
  - horizontal privilege escalation
  - object authorization bypass
  - 越权访问
  - 水平越权
  - 对象越权
metadata:
  tags: "idor,insecure direct object reference,privilege_escalation,authorization,access-control,bola,越权,水平越权,垂直越权,权限绕过,对象引用,绕过,hpp,文件越权,批量操作,api,permission,role,admin,user_id,account,权限,token,session,jwt,接口越权,未授权访问,graphql,blind-idor,二阶idor"
  category: discovery
  authority: "expert"
---

# IDOR 越权漏洞完整方法论

> **数据来源**：250 份 HackerOne 公开报告（2017-2025）分析 + Intigriti/CN-SEC 实战技巧
> **核心数据**：36.4% 为 High/Critical，平均赏金 $2,941，最高 $20,000

> **关于本 Skill 的使用边界（读 Phase 之前必读）**
>
> 本 Skill 是「**对象级授权缺失（BOLA/IDOR）的发现与证据闭环手册**」，**不是**「所有『能拿到别人数据』场景的判定器」，**也不是**「权限越界的全集」。
>
> - **不要**把「403/404 撒屏」等同于「不存在 IDOR」——Phase 6 的九类绕过中 **任一未试完**都不能标 `not_vuln`。
> - **不要**把「只看到同账号返回 200」等同于「无越界」——IDOR 证据是「**不同归属主体（A/B 用户、两租户、两角色、两工作区）下响应出现各自唯一字段」，必须闭环。
> - **不要**把本 Skill 当成「身份认证绕过」或「权限提升」的主路——账号接管需 `password-reset-attack`/`oauth-sso-attack`，未认证访问需 `no-auth-quick-test`，JWT 伪造需 `jwt-attack-methodology`；本 Skill **假设你已拿到合法身份**，只是考验「合法身份能不能摸别人的东西」。
> - **不要**把「业务就是该让代理/客服看所有工单」等同于「该接口本来就不该查权限」——不同 **跨越边界（跨工作组/跨租户/跨项目/跨区域）** 还是业务正常吗？必须验证。
> - 看到任何 `id` / `uuid` / `*_id` / `ids[]` / `node(id:)` / WebSocket 房间号 / 导出任务 / 批量接口 / 文件下载路径，**都应把本 Skill 当作必查项**跳 Phase 1。

## 🤖 Agent 工具映射

| 操作 | Agent 工具 |
|------|-----------|
| 建立 A/B 账号、角色、租户资源归属基线 | `browser_*` + `proxy_get_traffic` |
| 替换 path/query/body/Header/Cookie/WebSocket 中的对象 ID | `proxy_replay` / `proxy_send_request` |
| 去认证、低权限、跨账号、跨租户访问对照 | `proxy_send_request(..., drop_auth=True)` |
| 对比 A 自己资源、B 资源、非法 ID、403 绕过响应 | `proxy_diff_responses` |
| 查看完整响应字段、归属证据、错误差异和状态变化 | `proxy_get_flow_detail` |
| 批量 ids、导出任务、GraphQL node 和异步任务验证 | `proxy_send_request` + `proxy_diff_responses` |
| 固化三点闭环证据：当前身份、对象归属、越权结果 | `checklist_mark` + `note_add` |
| GraphQL/WebSocket/文件上传/403 绕过等专项 | `knowledge_load_skill` |

**执行约束**：没有第二账号/第二角色/第二租户归属闭环时不能标 `not_vuln`；只需用测试资源证明越权，不批量遍历真实用户，不执行不可恢复写操作。

---

## 0. 立即执行摘要：没有 A/B 归属闭环，不能判安全

看到任何 `id`、`uuid`、`user_id`、`account_id`、`member_id`、`order_id`、`invoice_id`、`file_id`、`org_id`、`tenant_id`、`workspace_id`、`project_id`、`owner_id`、`ids[]`、批量操作、导出任务、文件下载、GraphQL node、WebSocket room/channel 时，必须进入本 skill。IDOR 的核心证据是 **当前身份是谁、被访问对象属于谁、服务端返回/执行了什么**。

优先顺序：

1. 用 A/B 两个测试账号建立资源归属基线；没有第二账号不能标 `not_vuln`，只能 `needs_review`。
2. 覆盖 path、query、body、nested JSON、array、Header、Cookie、WebSocket message 中的对象 ID。
3. 读操作、写操作、批量操作、导出/下载、异步任务、旧版本/移动端接口分别验证，不能互相代替。
4. `403/404` 后继续测试方法切换、Content-Type、路径变体、Header 覆盖、HPP、批量接口。
5. `200` 后必须确认响应是否属于 B 账号/其他租户，不能只看状态码。

## 1. 对象类型触发矩阵

| 对象/参数 | 漏洞假设 | 立即测试 |
|---|---|---|
| `user_id/uid/account_id/member_id` | 用户资料 IDOR | A token 请求 B 用户资料 |
| `order_id/invoice_id/payment_id` | 订单/财务越权 | A 请求 B 测试订单/发票 |
| `file_id/attachment_id/media_id/key` | 文件越权 | A 下载 B 文件，未登录下载 URL |
| `org_id/tenant_id/workspace_id/project_id` | 多租户越权 | A 租户 token + B 租户 ID |
| `ids[]/batch/bulk/list` | 批量越权 | 数组混入 B 的测试资源 ID |
| `export_id/task_id/job_id` | 异步/二阶 IDOR | 创建任务时替换归属 ID，取结果验证 |
| GraphQL `node/id` | GraphQL BOLA | 查询/mutation 替换 global id |
| WebSocket `room_id/channel` | 实时通道越权 | 订阅 B 房间/项目频道 |

## ⚠️ 关键认知

IDOR 不是"低危小漏洞"——它是**SRC 出洞率最高的漏洞类型**。开发者检查了"你是否登录"但没检查"你是否有权访问这条数据"。

**四大根因**（HackerOne 数据）：
1. 缺少所有权验证（78% 的案例）
2. 可预测的对象标识符（65%）
3. 端点间授权不一致（45%）— 部分端点安全，新功能/内部 API 被遗漏
4. 仅客户端安全（23%）— 前端隐藏 ≠ 后端保护

## ⛔ 安全边界（真实渗透测试必读）

1. **使用自己的测试账号**：必须用自己注册的 2 个测试账号互相测试，**严禁读取/修改真实用户数据**
2. **禁止批量遍历**：证明 IDOR 只需用 2 个 ID 对比即可（自己的 vs 另一个测试账号的），**禁止遍历所有用户 ID**
3. **禁止写操作利用**：确认读越权后，在报告中说明"理论上 PUT/DELETE 也可能越权"即可，**不要实际修改/删除他人数据**
4. **禁止账户接管**：不要修改其他账号的邮箱/密码，即使技术上可以
5. **敏感数据脱敏**：如果看到了其他测试账号的数据，截图时脱敏处理

---

## Phase 1: 发现 IDOR 入口

### 高价值参数名（必查清单）

```
# 用户相关
user_id, id, uid, user, profile_id, account_id, member_id

# 交易相关
booking_id, order_id, transaction_id, payment_id, invoice_id

# 文件相关
document_id, file_id, attachment_id, media_id, asset_id

# 组织相关
project_id, org_id, team_id, workspace_id, tenant_id

# 内容相关
report_id, ticket_id, case_id, issue_id, request_id
comment_id, note_id, message_id, thread_id, conversation_id
```

### 入口位置（按优先级）

| 位置 | 示例 | 优先级 |
|------|------|--------|
| URL 路径 | `/api/users/1001` | 🔴 高 |
| Query 参数 | `?user_id=1001&order_id=5003` | 🔴 高 |
| POST/PUT Body | `{"user_id": 1001}` | 🔴 高 |
| GraphQL 变量 | `query { user(id: 1001) {...} }` | 🔴 高 |
| Cookie/Header | `uid=1001` / `X-User-Id: 1001` | 🟡 中 |
| 文件路径 | `/uploads/user_1001/avatar.jpg` | 🟡 中 |
| WebSocket 消息 | `{"action":"getProfile","uid":1001}` | 🟡 中 |

### ID 泄露猎杀清单

| 来源 | 说明 |
|------|------|
| 其他 API 响应 | 请求 A 接口，响应中泄露其他用户的 ID |
| 公开资料页 | 头像 URL、分享链接中包含 UUID |
| 登录/注册响应 | 响应中可能包含 user_id |
| 分享/邀请链接 | 链接中暴露资源 GUID |
| 前端 JS 文件 | 搜索 `userId`、`accountId` 等关键词 |
| API 文档/Swagger | 暴露端点结构和参数名 |
| Google Dorks | `site:target.com "userId"` |
| Wayback Machine | 历史快照中可能记录 ID |
| LocalStorage/Cookie | 客户端存储中的 ID |

---

## Phase 2: 水平越权测试（读操作）

**前提**：至少需要 2 个账户（A=攻击者，B=受害者）

```
账户 A (uid=1001) 的 Token:
GET /api/users/1001/profile → 200（自己的数据，记录作为基线）
GET /api/users/1002/profile → 200 + 不同数据？→ IDOR！
GET /api/users/1/profile    → 管理员数据？→ 垂直越权！
GET /api/users/0/profile    → 500 错误泄露？→ 边界测试
GET /api/users/-1/profile   → 触发异常？
```

### 响应判断矩阵

| 响应 | 判断 | 下一步 |
|------|------|--------|
| 200 + 不同用户数据 | ✅ IDOR 确认 | 保存证据，测写操作 |
| 200 + 相同数据 | 后端忽略了 ID 参数 | 换其他端点 |
| 200 + 空数据 | 用户不存在或数据为空 | 换 ID 范围 |
| 403/401 | 有权限检查 | → Phase 6 绕过技巧 |
| 404 | ID 不存在 | 换 ID 范围或枚举 |
| 500 | 后端报错 | 分析错误信息（SQL泄露？堆栈？） |

---

## Phase 3: 写操作越权（⚠️ 谨慎验证）

确认读越权后，**在报告中说明写操作风险即可**，大多数情况下无需实际执行写操作：

```
⚠️ 安全的验证方式（使用自己的两个测试账号）：
PUT    /api/users/TEST_ACCOUNT_B  {"email":"test-b-new@test.com"}  → 能改？→ 记录+立即恢复
PATCH  /api/users/TEST_ACCOUNT_B  {"bio":"idor_test"}             → 能改？→ 立即恢复原值

⛔ 禁止的操作：
DELETE /api/orders/5003                    → 不可逆，禁止
POST   /api/users/1/reset-pwd              → 影响真实账户，禁止
PUT    /api/users/1002/role {"role":"admin"}  → 提权操作，禁止
```

**关键发现**：很多应用 GET 有权限检查但 POST/PUT/DELETE 忘了——在报告中指出这一点即可，无需实际执行破坏性操作。

---

## Phase 4: 垂直越权

> **实战教训**：AOMS priv_esc.py 只测了 getallFtpInfo.do，其余7个敏感接口未做矩阵，漏了垂直越权系统性结论。禁止只测1个接口就下"有角色控制"结论。

### 4.0 垂直越权矩阵 (MUST)

**强制项**：所有"敏感数据接口"必须跑三角色垂直越权矩阵

```
三角色矩阵：
├─ 高权限角色 (adminsafe) — 管理员/超级用户/系统管理员
├─ 普通用户角色 (co_jianghaichao) — 普通用户/已认证用户
└─ 低权限角色 (aiTest) — 游客/只读用户/受限用户
```

**测试流程**：

```python
async def vertical_privilege_matrix_test(task):
    """
    垂直越权矩阵测试
    """
    results = {}
    
    # 高权限角色测试
    admin_resp = await send_request_as_admin(task)
    results["admin"] = admin_resp
    
    # 普通用户角色测试
    user_resp = await send_request_as_user(task)
    results["user"] = user_resp
    
    # 低权限角色测试
    low_resp = await send_request_as_low_priv(task)
    results["low_priv"] = low_resp
    
    # 判定逻辑
    if admin_resp.status_code == 200 and has_sensitive_data(admin_resp):
        if user_resp.status_code in [403, 401] or not has_sensitive_data(user_resp):
            if low_resp.status_code in [403, 401] or not has_sensitive_data(low_resp):
                return "垂直越权漏洞确认", results
    
    return "无垂直越权漏洞", results
```

**判定标准**：

| 响应组合 | 判定 | 结论 |
|---------|------|------|
| 仅高权限返回200 + 敏感数据 | ✅ 垂直越权漏洞确认 | **High** |
| 高权限+普通用户都返回200 | 需进一步验证数据差异 | **需Review** |
| 三角色都返回200 + 相同数据 | 无角色控制 | **需Review** |
| 三角色都返回403/401 | 有权限控制 | **Not Vuln** |

**禁止行为**：

- ❌ 禁止只测1个接口就下"有角色控制"结论
- ❌ 禁止只用1个角色测试就标"安全"
- ❌ 禁止跳过低权限角色测试

### 4.1 敏感数据接口识别

```python
SENSITIVE_API_PATTERNS = [
    # 用户管理
    r"/admin/.*",
    r"/manage/.*",
    r"/system/.*",
    r"/config/.*",
    r"/user/.*",
    
    # 数据操作
    r"/export/.*",
    r"/download/.*",
    r"/backup/.*",
    r"/log/.*",
    
    # 审批流程
    r"/approval/.*",
    r"/approve/.*",
    r"/review/.*",
    
    # 财务相关
    r"/payment/.*",
    r"/order/.*",
    r"/invoice/.*",
    r"/refund/.*",
]
```

### 4.2 敏感数据识别

```python
SENSITIVE_DATA_PATTERNS = [
    # 个人信息
    r"email",
    r"phone",
    r"mobile",
    r"id_card",
    r"身份证",
    r"手机号",
    r"邮箱",
    
    # 财务信息
    r"balance",
    r"余额",
    r"payment",
    r"支付",
    r"银行卡",
    
    # 权限信息
    r"role",
    r"权限",
    r"admin",
    r"管理员",
    
    # 系统信息
    r"config",
    r"配置",
    r"password",
    r"密码",
    r"secret",
    r"密钥",
]
```

### 4.3 垂直越权测试清单

```markdown
## 垂直越权测试清单 (MUST)

### 敏感数据接口
- [ ] GET /api/admin/users — 管理员用户列表
- [ ] GET /api/admin/config — 系统配置
- [ ] GET /api/admin/logs — 系统日志
- [ ] POST /api/admin/create-user — 创建用户
- [ ] PUT /api/admin/update-user/:id — 更新用户
- [ ] DELETE /api/admin/delete-user/:id — 删除用户

### 审批流程接口
- [ ] POST /api/approval/approve — 审批操作
- [ ] PUT /api/approval/reject — 拒绝操作
- [ ] GET /api/approval/pending — 待审批列表

### 财务相关接口
- [ ] GET /api/payment/list — 支付列表
- [ ] POST /api/payment/refund — 退款操作
- [ ] GET /api/invoice/list — 发票列表

### 数据导出接口
- [ ] GET /api/export/users — 导出用户数据
- [ ] GET /api/export/orders — 导出订单数据
- [ ] POST /api/backup/create — 创建备份
```

### 4.4 垂直越权证据收集

```python
def collect_vertical_privilege_evidence(admin_resp, user_resp, low_resp):
    """
    收集垂直越权证据
    """
    evidence = {
        "admin_response": {
            "status_code": admin_resp.status_code,
            "has_sensitive_data": has_sensitive_data(admin_resp),
            "data_summary": summarize_data(admin_resp.body),
        },
        "user_response": {
            "status_code": user_resp.status_code,
            "has_sensitive_data": has_sensitive_data(user_resp),
            "data_summary": summarize_data(user_resp.body),
        },
        "low_priv_response": {
            "status_code": low_resp.status_code,
            "has_sensitive_data": has_sensitive_data(low_resp),
            "data_summary": summarize_data(low_resp.body),
        },
        "conclusion": "垂直越权漏洞确认" if admin_resp.status_code == 200 and has_sensitive_data(admin_resp) else "无垂直越权漏洞",
    }
    return evidence
```

### 真实案例：审批/Workflow 系统

OA、合同审批、工单系统中，"审批"操作是最典型的垂直越权目标：
```
POST   /contracts/1/approve
PATCH  /contracts/1  {"status":"approved"}
POST   /api/admin/approval  {"id":1,"action":"approve"}
```

### 提权技巧

- **JWT Claims 篡改**：解码 → 改 `"role":"user"` 为 `"role":"admin"` → `alg:none` 或弱密钥可伪造
- **Mass Assignment**：注册/更新时注入 `{"role":"admin","is_admin":true}`
- **伪造内部请求头**：`X-User-ID: admin_id`、`X-Forwarded-For: 127.0.0.1`

---

## Phase 5: 高级 IDOR 模式

### 5.1 GraphQL IDOR（增长 140%）

```graphql
# 枚举用户
query { user(id: 1) { email phone ssn } }
query { user(id: 2) { email phone ssn } }

# 写操作越权
mutation { deletePost(id: "VICTIM_POST_ID") }
mutation { updateUser(id: "VICTIM_ID", input: { email: "evil@x.com" }) }

# 批量查询
[
  {"query": "{ user(id:1) { email } }"},
  {"query": "{ user(id:2) { email } }"}
]
```

**真实案例**：Snapchat #1819832 — $15,000 — 通过 GraphQL mutation 删除任何人的 Spotlight 内容

### 5.2 二阶 IDOR（Blind IDOR）

漏洞组件**间接引用**数据对象，操作结果不在当前响应中体现：

| 场景 | 利用方式 |
|------|---------|
| 定时导出 | 创建导出任务时篡改 user_id → 定时任务导出受害者数据 |
| 通知触发 | 修改他人通知设置 → 对方收到邮件则操作成功 |
| 计时攻击 | 合法 ID 200ms vs 非法 ID 50ms → 通过响应时间判断 |
| 异步处理 | Webhook 回调中的 ID 被异步处理，无即时响应 |

### 5.3 多步骤 IDOR 链

```
1. GET /api/comments → 评论中泄露 user_id: 1002
2. GET /api/users/1002/profile → 用泄露的 ID 读取个人资料
3. GET /api/users/1002/orders → 进一步读取订单数据
```

**真实案例**：Uber #1145428 — $5,750 — 3 漏洞链实现任意扣款：
```
IDOR #1 → 枚举优惠券 ID
IDOR #2 → 修改优惠券目标
Auth bypass → 应用到任意账户
```

### 5.4 API 版本降级

```
/api/v3/user/1001 → v3 已修复
/api/v2/user/1001 → v2 仍然存在 IDOR！
/api/v1/user/1001 → v1 更老，更可能存在
```

### 5.5 静态关键字替换

开发者用 `me`/`current`/`self` 引用当前用户，但 API 通常也支持数字 ID：
```
/api/users/me/profile → 正常
/api/users/1002/profile → IDOR！
```

### 5.6 文件/媒体资源 IDOR

```
/uploads/user_1001/avatar.jpg   → 改 1001 为 1002
/attachments/report-001.pdf     → 遍历编号
/export/data-20260101.csv       → 改日期遍历
```

**S3/OSS 直链**：`https://bucket.s3.amazonaws.com/users/1001/doc.pdf` 直接改路径可能绕过应用层权限

### 5.7 批量操作越权（⚠️ 仅验证可行性）

```json
// ⚠️ 仅用自己的测试账号 ID 验证，不要用真实用户 ID
POST /api/users/bulk {"ids": [MY_ID, TEST_ACCOUNT_B_ID]}
POST /api/orders/export {"order_ids": [MY_ORDER, TEST_ACCOUNT_B_ORDER]}

// ⛔ 禁止：批量枚举或批量删除
// POST /batch-delete {"ids": ["my_item_1", "victim_item_1"]}
```

### 5.8 多租户越权

```
/api/tenant/{my_org_id}/user/1001 → 换 org_id
/api/workspace/{my_ws}/data → 换 workspace
```

---

## Phase 6: IDOR 绕过技巧（当返回 403 时）

> 💡 **决策树警告**：下面 9 类绕过是**最常见的 403/404 撒屏反制**，**不是穷尽列举**。
> 特别注意：「9 类都试过还是 403」**不能**直接判定为「不存在 IDOR」——
> 以下状況上面表格不覆盖，遇到必须补测：
> - **业务层「软拒」**：返回 200 但 body 为「无权限」提示——该场景是「隐性 403」，需用上面 9 类变体重试
> - **后绯错误不一致**：`{"code":403}` vs `{"code":404}` vs `{"code":-1}` 常反映「对象存在与否」泄露，能打出枚举变越界
> - **跨服务授权不一致**：主服务 403、外包服务（统计/导出/通知/审计/搜索备份）可能还是 200
> - **GraphQL 背包、批量、别名**：`@include` / `@skip` / fragment / batch query / persisted query 常可绕过单点 403
> - **WebSocket / SSE / gRPC-Web 同业务另一道口**：同一资源的 HTTP 接口 403，但长连接/推送通道未检查归属
> - **缓存/CDN 表现**：`If-None-Match` / `If-Modified-Since` / `Range` / 负数字节 可让边缘 CDN 返回别人的 304/206
> 看到任一上述现象，**返回本 Phase 手动构造变体**，不要仅凭「9 类都试过」就标 not_vuln。

### 6.1 参数变形

| 绕过手法 | 示例 |
|----------|------|
| ID 数组包装 | `id=1002` → `id[]=1002` |
| JSON 对象包装 | `id=1002` → `{"id":{"$eq":1002}}` |
| JSON Globbing | `id=1002` → `id=[1002,1003]` / `id=*` / `id=null` |
| 负数/零 | `id=-1` / `id=0` / `id=undefined` |
| 小数/前导零 | `id=1002.0` / `id=00001002` |
| 布尔值 | `id=true` |
| 带分隔符 | `id="1001,1002"` |

### 6.2 编码绕过

| 方式 | 示例 |
|------|------|
| URL 编码 | `/user/1002` → `/user/%31%30%30%32` |
| 双重编码 | `/user/%2531%2530%2530%2532` |
| Base64 | 解码 → 改 ID → 重新编码 |
| 十六进制 | `/user/123` → `/user/0x7B` |
| Unicode | `/admin` → `/a%u0064min` |

### 6.3 HTTP 方法切换

```
GET /api/user/1002 → 403
PUT /api/user/1002 → 200（写操作反而没权限检查！）
PATCH /api/user/1002 → 200
DELETE /api/user/1002 → 200
```

### 6.4 Content-Type 切换

```
Content-Type: application/json → application/x-www-form-urlencoded
Body: {"id":1002} → id=1002
```

### 6.5 路径技巧

```
/api/users/victim_id → 403
/api/users/victim_id/ → 200（末尾斜杠）
/api/users/victim_id.json → 200（添加后缀）
/api/users/my_id/../../users/victim_id/profile → 200（路径穿越）
```

### 6.6 伪造请求头

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin/users/victim_id
X-Rewrite-URL: /admin/users/victim_id
X-User-ID: victim_id（微服务架构常见）
```

### 6.7 HPP 参数污染

```
?id=my_id&id=victim_id（后端可能取最后一个）
?user_id=my_id&user_id=victim_id
```

### 6.8 403 但操作已执行

```
DELETE /file/victim_id → 403 Forbidden
但刷新文件列表后文件确实被删除！（盲 IDOR）
```

### 6.9 403 响应差异分析

```
403 + "Permission denied" → ID 有效但无权限
403 + "Resource not found" → ID 无效
（不同错误消息暗示 ID 是否存在）
```

---

## Phase 7: 框架特征 IDOR

| 框架 | 高发点 | 原因 |
|------|--------|------|
| Spring Data REST | `/{entity}/{id}` 全暴露 | 自动生成 CRUD，默认无权限 |
| Django REST Framework | `/api/{model}/{pk}/` | ViewSet 忘加 permission_classes |
| Express + Mongoose | `/api/users/:id` | 中间件顺序错误 |
| Laravel | `/api/{model}/{id}` | 忘加 Policy |
| GraphQL (任何) | `query { node(id:"...") }` | Relay Global ID 暴露任意对象 |
| gRPC/Protobuf | 二进制请求中的 ID 字段 | 需解码修改重编码 |
| REST + HATEOAS | 响应 `_links` 中的 URL | 直接修改 href 访问 |

---

## Phase 8: IDOR 组合攻击

| 组合 | 效果 | 案例 |
|------|------|------|
| IDOR + XSS | 注入 XSS 到他人账户 | Self-XSS 升级为 Stored-XSS |
| IDOR + CSRF | 诱导受害者触发越权操作 | 无 token 的 PUT 请求 |
| IDOR + 文件上传 | 覆盖他人文件/上传恶意文件到他人目录 | 头像覆盖 |
| IDOR + 信息泄露 | 一步泄露 ID → 二步越权读数据 | 评论泄露 user_id → 读 profile |
| IDOR + 竞态条件 | 并发请求绕过单次权限检查 | 批量 API 竞态 |

---

## 🚨 证据级响应与记录时机

**只要拿到证据级响应，立即 `checklist_mark(... result="vulnerable")`，不要等把所有越权链测完。** IDOR 的证据来自"三点闭环"：**当前身份是谁、访问的对象属于谁、响应/状态变化证明了什么**。

### IDOR 证据级响应（任一即可）

- ✅ A 账号 Token 请求 B 账号资源，响应中出现 B 的唯一字段（邮箱、手机号、订单号、文件名、租户名等）
- ✅ 普通用户访问管理员/其他角色资源，返回管理数据或执行了管理动作
- ✅ 批量接口混入其他用户 ID 后，响应一并返回或处理了其他用户对象
- ✅ 写操作使用自己的两个测试账号验证，A 能修改/绑定/删除 B 的测试资源，且可立即恢复
- ✅ 403/404 绕过后，同一资源从拒绝访问变为返回真实业务数据

### 结果分级

- `vulnerable`：有明确两账号/两角色/两租户对照，能证明越权读或安全可恢复的越权写
- `needs_review`：存在响应差异、ID 泄露、错误信息或可疑状态变化，但缺少第二账号/第二角色闭环
- `not_vuln`：完成最低必测自检，所有对象替换、Body ID、批量、写操作和 403 绕过均无越权证据
- `skipped`：缺少必要条件导致无法测试，例如没有第二账号、没有可替换对象 ID、没有授权测试写操作；必须说明缺失条件

### 输出格式

```text
[IDOR/BOLA检查]
入口/接口：
对象类型：用户/订单/发票/文件/项目/组织/租户/批量/导出任务/GraphQL/WebSocket/其他
测试身份：A账号/B账号/低权限/高权限/A租户/B租户/未登录
测试位置：path/query/body/nested-json/array/header/cookie/ws-message
测试动作：ID替换/批量混入/写操作/导出任务/旧版本/403绕过/多租户
归属证据：B唯一字段/租户名/文件名/订单号/状态变化/无
结论：confirmed_vuln | suspected_vuln | needs_review | not_vuln
未测原因：缺第二账号/缺对象ID/缺租户/禁止写操作/其他
```

### 记录格式

```text
checklist_mark(vuln_type="IDOR/越权", result="vulnerable",
  detail="A账号(<角色/租户>) 使用自己的认证访问 B账号资源 <endpoint/id>，响应包含 B 的 <唯一字段>；已用 B账号确认资源归属。")
note_add(type="result", content="补充请求/响应对、账号归属证明、影响范围、是否存在写操作风险。")
```

---

## Phase 9: 证据收集规范

**$500 与 $20,000 报告的区别在于你展示的影响力。**

### 有效 PoC 必须包含

1. **请求/响应对**：完整 HTTP 请求（含认证头）+ 完整响应
2. **两账号对比**：A 账号访问 B 的数据，B 账号确认数据属于 B
3. **关键字段标注**：高亮响应中的敏感字段（姓名/邮箱/手机号）
4. **影响力说明**：写操作能力、爆炸半径（影响多少用户）、链式攻击可能

### 升级影响力的技巧（报告中说明，不实际执行）

- 不要止步于"能看到用户#2的资料"
- 在报告中说明**写操作可能性**（如 PUT/DELETE 端点也无授权检查）
- 在报告中说明**批量影响**（ID 可遍历 → 影响所有用户）
- 在报告中说明**链式攻击可能**（IDOR → 读取邮箱 → 密码重置 → 账户接管）
- 在报告中说明**敏感数据类型**（PII/金融/医疗）

**⛔ 禁止**：实际遍历所有用户、实际修改/删除数据、实际接管账户

```
✅ 好的证据:
"用 A 账号(uid=1001) 的 token 请求 /api/users/1002/profile，
返回了 B 账号的姓名(张三)、邮箱(zhangsan@test.com)、手机号(138xxxx)。
进一步测试 PUT /api/users/1002 可修改邮箱，实现账户接管。
影响：任意用户数据泄露+账户接管，影响全部 10 万+ 注册用户。"

❌ 差的证据:
"请求 /api/users/1002 返回了 200"
```

**每确认一个 IDOR 立即 `vuln_verify` + `note_add(type="result")` 记录。**

---

## 真实案例速查表

| 目标 | 漏洞 | 赏金 | 关键发现技巧 |
|------|------|------|-------------|
| GitLab | 通过项目导入窃取私有对象 | $20,000 | 导入文件中注入外部 issue_id |
| Snapchat | 删除任何人的 Spotlight 内容 | $15,000 | GraphQL mutation 无授权 |
| PayPal | 向商户添加未授权用户 | $10,500 | 多步流程第二步缺检查 |
| Uber | 3漏洞链任意扣款 | $5,750 | 优惠券 ID 枚举 + 目标篡改 |
| Shopify | 跨店铺计费访问 | $5,000 | 多租户 ID 替换 |

---

## ⛔ 「最低必测自检」— 标 not_vuln/skipped 前必答

任何 IDOR 项准备标 `not_vuln` 或 `skipped` 前，**逐条对照下面 7 个问题**回答你做了什么。
**任何一项答"未尝试"且没有合理跳过理由 → 不能 not_vuln，必须补测**。

把答案写进 `checklist_mark` 的 `detail` 字段（精简版即可），`note_add` 中可以详写：

| # | 必测项 | 跳过的合法理由（任一即可） |
|---|--------|---------------------------|
| 1 | **路径/Query ID 替换**：把 path 中的数字 ID（或 `?xxx_id=`、`?uid=`）改成至少 2 个其他值（自己另一个测试账号、+1、随机大数 9999），观察响应是否返回他人数据？ | 接口路径和参数中**完全没有**数字/UUID 类标识 |
| 2 | **响应中泄露的 ID 反向利用**：测过该接口前，先看响应里有没有泄露其他用户的 `*_id`、`uuid`、关联实体 ID？拿这些 ID 反过来去请求当前接口或同模块其他接口？ | 响应中确实没有任何 ID 字段 |
| 3 | **Body 中的 ID 字段**（POST/PUT/PATCH/DELETE）：请求体中如果有 `id`/`xxx_id`/`uuid` 类字段，必须改成其他值重发对比 | 该接口是 GET 且 URL 无 ID 参数 |
| 4 | **Mass Assignment 形态**（POST/PUT 创建/修改类）：在请求体中**追加**敏感字段（`role`、`is_admin`、`account_id`、`workspace_id`、`responder_id`、`creator_id`、`owner_id`、`status`、`approved`），看服务端是否接受？ | 该接口是只读 GET |
| 5 | **批量/邻接接口**：如果有 `/batch`、`/bulk`、`/list?ids=...`、`/adjacent_*`、`/related/*` 这类接口，必须在 ids 列表中**混入其他用户的 ID**，看是否一并操作了？ | 该模块确实没有批量/邻接类接口 |
| 6 | **写操作越权探测**：如果有同一资源的 PUT/PATCH/DELETE，至少对 1 个改 ID 试一次（**不需要真的改坏数据**，看是否返回 200/204 即可推断） | 该资源完全只读 |
| 7 | **403/404 撞墙时 → 5 种绕过技巧**（来自本 SKILL Phase 6）：HTTP Verb 切换（GET ↔ POST）、添加 `X-Original-URL`/`X-Forwarded-For`/`X-Custom-IP-Authorization`、双 URL 编码、加 `..;/` 路径混淆、改 Accept 类型为 XML/JSON 看是否绕过 | 接口正常返回 200 没有撞墙 |

### 跳过的"非法"理由（这些**不算**合理跳过，看到要驳回）

- ❌ "代理/管理员本就能看所有工单，业务正常" → 可能是**真**正常，但你必须证明：换了**另一个不同工作组/角色/租户**的资源 ID 也能看到？跨工作组也算正常？
- ❌ "RESTful 接口不接受自定义参数" → 你试过 `?include=*`、`?fields=password`、`?expand=related` 这种**框架性的隐式参数**吗？
- ❌ "受 CSRF 保护无法 PUT" → 那你**从浏览器 DOM 抓 CSRF token**带上 token 重发了吗？
- ❌ "需要 JWT 当前只有 Cookie" → 你试过从 `localStorage`、`sessionStorage`、网络流量样本中提取已有 JWT 重用吗？
- ❌ "无该资源的其他 ID 可测" → 你试过从其他 API 响应、JS bundle、URL 历史中收集 ID 吗（参考 Phase 1 ID 泄露猎杀清单）？

---

## 📚 知识库（按需加载）

| 知识库 | 内容 | 加载方式 |
|--------|------|----------|
| **IDOR 真实案例库** | 7 个 H1 真实案例 + 绕过技巧 + 思维链模板 | `knowledge_load_skill("idor-methodology/cases")` |
| **国产组件指纹** | 国产中间件默认路径 + 默认凭据 | `knowledge_load_skill("china-specific/fingerprints")` |

---

## ⚠️ Skill 边界与逃逸

本 Skill 覆盖的是「**合法身份下的对象级越界**（BOLA）+ 403/404 绕过 + Mass Assignment + 二阶/多租户/批量/GraphQL/WebSocket 变体」，**以下场景必须从本 Skill 主动逃逸到联动 Skill**：

| 现场信号 | 应跳转/联动的 Skill 或方向 |
|---|---|
| 接口 **未认证就能调**（未登录拿到他人数据） | `no-auth-quick-test`（不是 IDOR，是完全漏授权） |
| **密码重置/邮箱绑定/手机号修改** 可越界 | `password-reset-attack`（定性为账号接管而非 IDOR） |
| 越界携带 **JWT/SAML/OAuth token** | `jwt-attack-methodology` / `oauth-sso-attack` |
| **全局越界**（普通用户能调管理后台/内部 API） | `auth-bypass-methodology` + `privilege-escalation-web` |
| 越界读取的是 **SSRF/LFI/XXE/SSTI 带出的外部资源** | 对应 Skill 主线，**不是 IDOR** |
| 越界携带 **交易/订单/价格/优惠券 业务逻辑** | `business-logic-attack` |
| **GraphQL 介绍/复杂查询交互** 占主导 | `graphql-methodology`（以本 Skill 5.1 为补充，不取代） |
| **多账号原始会话导入** | `setup-browser-cookies` / 浏览器会话导入 Skill |
| **只拿到路径/Cookie/Header 没拿到会话** | `entry-point-mapping` + `js-api-extract`，先补身份再进本 Skill |
| **需要判定是否为「业务本身该权限」** | `multi-role-recon`（多角色/多租户探查）先画出权限边界不会拍脑袋 |

> **一句话**：本 Skill 是「拿到身份后能不能摸别人东西」的动作手册，不是「身份从哪里来」也不是「什么都能摸」的判决书。任何接口只要有对象标识符（数字 ID / UUID / global id / room\_id / 任务 id / 文件 key / 资源 路径）且能看到跨归属主体的差异响应，都要进本 Skill；但如果你是在「越界可接管账号/可提权/可改价格/可绕认证」路上，**请以上表中的主 Skill 为主路，本 Skill 只作为「资源归属闭环」补证**。
