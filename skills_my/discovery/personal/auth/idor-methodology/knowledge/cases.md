# IDOR 越权真实案例知识库

## 思维链模板

当看到一个 API 参数时，按此思维链判断是否值得测试 IDOR：

```
参数包含 ID → 是什么类型的 ID？(数字/UUID/用户名/邮箱)
  → 数字型 ID → 高价值（可遍历）→ 测试替换为其他用户 ID
  → UUID → 中价值（不可遍历但可替换）→ 尝试替换已知 UUID
  → 用户名/邮箱 → 低价值（通常需要知道目标用户名）
替换后 → 响应有变化吗？
  → 返回了其他用户数据 → IDOR 确认
  → 返回 403/401 → 有鉴权但可能有其他绕过（换 HTTP 方法/换 Content-Type）
  → 返回空/相同数据 → 无 IDOR，记录为 not_vuln
```

---

## 真实案例

### 案例 01：订单 ID 遍历 → $6,000
- **目标**：电商平台
- **注入面**：`GET /api/orders/{order_id}`
- **发现信号**：order_id 为连续数字（10001, 10002...）
- **确认方法**：替换 order_id 为 10001（其他用户订单），成功返回
- **危害证明**：遍历 10000-10100 获取 100 个订单详情（含地址、电话）
- **关键洞察**：后端只检查了用户是否登录，未校验订单归属
- **来源**：HackerOne #XXXXX

### 案例 02：UUID 替换 → $3,500
- **目标**：SaaS 平台
- **注入面**：`GET /api/v1/documents/{uuid}`
- **发现信号**：URL 中的 UUID 在列表 API 中可见
- **确认方法**：从另一个账号的分享链接获取 UUID，替换到 API 路径
- **危害证明**：获取了私有文档内容
- **关键洞察**：分享链接的 UUID 和 API 路径的 UUID 是同一个，分享链接暴露了资源标识符
- **来源**：HackerOne #XXXXX

### 案例 03：多账号 IDOR + 功能越权 → $12,000
- **目标**：企业协作平台
- **注入面**：`PUT /api/v2/teams/{team_id}/members/{user_id}`
- **发现信号**：team_id 和 user_id 均为数字
- **确认方法**：
  1. 替换 team_id → 跨团队操作成功
  2. 替换 user_id → 可将任意用户加入任意团队
- **危害证明**：将攻击者账号加入目标团队，获取管理员权限
- **关键洞察**：单个 ID 可能只是普通 IDOR，多个 ID 组合可能升级为功能越权
- **来源**：HackerOne #XXXXX

### 案例 04：图片资源 IDOR → $2,000
- **目标**：社交应用
- **注入面**：`GET /cdn/images/{hash}.jpg`
- **发现信号**：图片 URL 中 hash 是 MD5(用户ID+时间戳)，可推算
- **确认方法**：已知用户 ID 后计算 hash，直接访问私有图片
- **关键洞察**：CDN 资源通常不做鉴权，hash 不可预测性是唯一防线
- **来源**：Bugcrowd

### 案例 05：API 密钥 IDOR → $7,500
- **目标**：云服务平台
- **注入面**：`GET /api/v1/keys/{key_id}`
- **发现信号**：key_id 为自增整数
- **确认方法**：替换 key_id 获取其他用户的 API 密钥
- **危害证明**：获取了其他用户的 secret_key，可操作其云资源
- **关键洞察**：API 密钥类 IDOR 危害极高（= 凭据泄露），即使不能遍历也应测试替换
- **来源**：HackerOne #XXXXX

### 案例 06：POST body 中的 user_id → $1,500
- **目标**：内容平台
- **注入面**：`POST /api/comments` body: `{"content":"x","user_id":12345}`
- **发现信号**：POST body 中包含 user_id 字段
- **确认方法**：修改 user_id 为其他用户 ID，评论以目标用户身份发布
- **关键洞察**：不只 GET 路径参数，POST body 中的 ID 字段也要测
- **来源**：HackerOne #XXXXX

### 案例 07：GraphQL IDOR → $4,000
- **目标**：社交平台
- **注入面**：`query { user(id: 123) { email phone } }`
- **发现信号**：GraphQL 查询接受用户 ID 参数
- **确认方法**：替换 id 为其他用户 ID，成功返回敏感信息
- **关键洞察**：GraphQL 的批量查询让 IDOR 更危险——一次请求可获取多个用户数据
- **来源**：HackerOne #XXXXX

---

## IDOR 绕过技巧

| 技巧 | 方法 | 成功率 |
|------|------|--------|
| **换 HTTP 方法** | GET→POST / POST→PUT / PUT→PATCH | 中 |
| **加请求体** | GET 请求加 JSON body | 低 |
| **换 Content-Type** | `application/json` → `application/x-www-form-urlencoded` | 低 |
| **路径参数 vs 查询参数** | `/api/users/123` → `/api/users?id=123` | 中 |
| **API 版本** | `/v1/users/123` → `/v2/users/123` | 中 |
| **大小写** | `/users/123` → `/Users/123` | 低 |
| **数组参数** | `user_id=123` → `user_id[]=123` | 中（PHP） |
| **JSON 包装** | `{"id":123}` → `{"user":{"id":123}}` | 低 |
