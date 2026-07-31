---
name: user-enum-data-leak
description: "用户枚举与敏感数据遍历方法论。当目标有注册、登录、找回密码、搜索用户等功能时使用。覆盖用户名/手机号/邮箱枚举（通过注册/登录/密码重置接口的差异响应）、批量数据导出越权、订单号/发票号等业务ID遍历。SRC 常见中危漏洞。"
priority: 10
vuln_types:
  - 用户枚举
  - 信息泄露
  - 敏感数据泄露
  - 数据遍历
  - 批量导出越权
  - ID遍历
triggers:
  - register
  - registration
  - login
  - forgot
  - reset
  - username
  - user_id
  - phone
  - email
  - exists
  - check
  - search
  - export
  - page_size
  - limit
  - order_id
  - invoice
  - password_hash
  - api_token
  - 用户枚举
  - 信息泄露
synonyms:
  - user enumeration
  - account enumeration
  - data leak
  - information disclosure
  - sensitive data exposure
  - id enumeration
metadata:
  tags: "user enumeration,用户枚举,手机号遍历,邮箱枚举,信息泄露,批量导出,数据遍历,订单遍历,ID遍历,registration,注册检测"
  category: discovery
  authority: "reference"
---

# 用户枚举与数据遍历方法论

## 🤖 Agent 工具映射

| 场景 | 优先使用的 Agent 工具 |
|------|------------------------|
| 对注册、登录、找回密码、检查账号、搜索用户接口发送存在/不存在账号对照样本 | `proxy_send_request` |
| 比较状态码、响应体长度、错误码、Cookie/Header、字段数量和响应时间差异 | `proxy_diff_responses` + `proxy_get_flow_detail` |
| 修改 `username/email/phone/user_id/order_id/invoice/limit/page_size` 验证枚举、遍历和批量返回 | `proxy_replay` / `proxy_send_request` |
| 用低权限、匿名、普通用户和更高权限账号对同一接口做字段和数据边界对比 | `browser_get_cookies` + `proxy_send_request` |
| 对列表、搜索、导出、GraphQL 接口测试空关键词、大分页、超大 limit 和过滤条件缺失 | `proxy_send_request` |
| 故意发送畸形参数，检查错误响应是否泄露堆栈、SQL、内部 IP、文件路径或追踪头 | `proxy_send_request` + `proxy_get_flow_detail` |
| 批量生成少量安全样本 ID、订单号、发票号和手机号/邮箱格式变体，避免大规模遍历真实数据 | `python3` |
| 命中后记录至少两个枚举差异证据，或记录越权字段/导出数据、角色边界和影响范围 | `checklist_mark` + `note_add` |

**执行要点**：手机号/邮箱等字段是否构成泄露取决于当前角色是否业务必要；不要用“业务正常”泛化跳过，必须说明角色边界和字段必要性，且禁止大规模遍历真实用户。

---

## Phase 1: 用户枚举

### 1.1 注册接口枚举
```
注册时输入已存在的用户名/手机号/邮箱：
- 已存在: "该手机号已注册" / "用户名已被占用"
- 不存在: "注册成功" 或进入下一步

→ 差异响应 = 可枚举用户是否存在
→ proxy_send_request 分别提交存在和不存在的用户，对比响应
```

### 1.2 登录接口枚举
```
- 存在的用户 + 错误密码: "密码错误"
- 不存在的用户 + 任意密码: "用户不存在" / "账号或密码错误"

即使提示相同，也检查：
1. 响应时间差异（存在的用户需要查库比对密码，更慢）
2. 响应长度差异（多几个字节也是差异）
3. HTTP 状态码差异
4. Cookie/Header 差异
```

### 1.3 密码重置枚举
```
- 存在的手机号: "验证码已发送"
- 不存在的手机号: "该手机号未注册"

→ 密码重置接口是用户枚举的最常见入口
```

### 1.4 API 接口枚举
```
搜索用户接口:
GET /api/user/search?phone=13800138000
→ 返回用户信息 = 可通过手机号查任意用户

检查用户是否存在:
GET /api/user/check?username=admin
→ 返回 {"exists": true}
```

## Phase 2: 业务 ID 遍历

### 2.1 订单号遍历
```
自己的订单: GET /api/order/10086
改 ID: GET /api/order/10087, 10088, 10089...

如果返回其他用户的订单 → IDOR + 数据泄露
如果返回 404/403 但响应不同 → 可判断订单是否存在
```

### 2.2 发票/合同号遍历
```
发票下载: GET /api/invoice/INV-2024-0001
遍历: INV-2024-0002, INV-2024-0003...
→ 泄露其他用户/公司的发票信息
```

### 2.3 用户 ID 遍历
```
个人资料: GET /api/user/profile/1001
遍历: 1002, 1003, 1004...
→ 批量获取用户个人信息

注意遍历策略：
- 数字 ID: 1, 2, 3... 或 1001, 1002, 1003...
- UUID: 不可遍历，但可能从其他接口泄露
- 自增序列: 试 ID ± 1, ± 10, ± 100 判断规律
```

## Phase 3: 批量数据导出

```
检查以下接口：
1. 导出功能: GET /api/export/users?format=csv
   → 不传过滤条件 = 导出全量数据？
   → 修改分页参数: page_size=999999

2. 搜索接口: GET /api/search?keyword=&page_size=1000
   → 空关键词 + 大分页 = 全量查询

3. 列表接口: GET /api/users?limit=999999&offset=0
   → 直接拉全量

4. GraphQL: { users(first: 99999) { id, name, email, phone } }
   → 批量查询
```

## Phase 4: 敏感信息泄露

```
检查 API 响应是否包含不该返回的字段：

用户接口:
- 密码 hash（password_hash, encrypted_password）
- 身份证号（id_card, identity）
- 完整手机号（phone 未脱敏）
- 完整邮箱
- 家庭住址
- 银行卡号

订单接口:
- 其他用户的收货信息
- 支付流水号
- 第三方账户信息

系统接口:
- 数据库连接信息
- 内部 IP
- API Key/Secret
```

## Phase 5: 响应差异分析技巧

```
微妙的枚举指标（肉眼不易察觉）：
1. 响应时间: 存在用户 200ms vs 不存在 50ms
2. 响应大小: 差 10-20 字节
3. Cookie 数量: 存在用户多设置一个 Cookie
4. 错误码: 同样 400 但 error_code 不同
5. JSON 字段: 存在用户多返回一个 user_id 字段

→ proxy_diff_responses 自动发现差异
```

## 验证与记录

```
1. 证明可以判断用户是否存在（至少 2 个差异证据）
2. 或证明可以获取其他用户的数据
3. 评估影响范围（可遍历多少用户/订单）
4. vuln_verify + note_add(type="result")
```

---

## ⛔ 「最低必测自检」— 标 not_vuln/skipped 前必答

⚠️ **关键**：响应中含手机号/邮箱不一定是漏洞——必须判断"该角色应不应该看到这些字段"。

| # | 必测项 | 跳过的合法理由 |
|---|--------|---------------|
| 1 | **响应字段普查**：列出该接口响应中所有字段名，标注哪些是"业务必要"（用户主动展示），哪些是"敏感字段"（IP、internal_note、private_field、creator_email、phone、id_number、salt、hash） | - |
| 2 | **角色边界判断**：当前角色（代理/普通用户/匿名）正常业务流程**应该看到**哪些字段？响应中是否含有"超出当前角色应见范围"的字段？ | - |
| 3 | **跨角色对比**：如果有多个测试账号，用低权限账号请求同一接口，看是否仍返回敏感字段？低权限能看到 → 越权信息泄露 | 仅一个账号 |
| 4 | **错误响应泄露**：故意发畸形请求（无效参数、`'`、`'A'*1000`），看错误响应是否含堆栈、SQL 语句、内部 IP、文件路径？ | 该接口响应稳定，错误处理统一 |
| 5 | **响应头泄露**：检查 `Server`、`X-Powered-By`、`X-Backend`、`X-Aspnet-Version`、`X-Runtime`、`X-Trace-Id`、内部 host 名是否泄露 | 已检查响应头无内部信息 |
| 6 | **批量返回放大**：接口支持分页/limit 吗？试 `?page_size=10000`、`?limit=99999` 看能否一次性拉取超大量数据 | 接口非列表型 |
| 7 | **管理类敏感字段**：`/users` 类接口返回的字段中是否包含 `password_hash`、`salt`、`secret_key`、`api_token`、`session_token`、`reset_token`、`mfa_secret`？ | 接口非用户/账户类 |

### 跳过的"非法"理由

- ❌ "返回了邮箱/手机但是业务正常" → 你必须给出"为什么业务必要"的具体理由，例如"代理需要联系工单创建者所以需要邮箱"。如果只是"业务正常"四个字，等于没判断
- ❌ "响应是工单详情，含联系方式正常" → 那么**普通用户**对**别的工单**调相同接口能不能看到这些字段？跨工单/跨工作组测过吗？
- ❌ "X-Request-Id 等是标准追踪头" → 那 `X-Backend-Server: prod-db-3.internal.lan` 也是标准吗？要看具体值

---

