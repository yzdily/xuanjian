# SRC 漏洞报告

> 每个漏洞独立一份，可直接提交到 SRC 平台。

---

## 基本信息

- **报告时间**: {{TIMESTAMP}}
- **任务 ID**: {{TASK_ID}}
- **测试人员**: PentestAgent (人工审核)
- **数据来源**: {{DATA_SOURCE}}

---

## 资产信息

{{ASSET_INFO}}

---

## 漏洞列表

{{VULNERABILITIES}}

---

## 漏洞统计

- 严重: {{CRITICAL_COUNT}} 个
- 高危: {{HIGH_COUNT}} 个
- 中危: {{MEDIUM_COUNT}} 个
- 低危: {{LOW_COUNT}} 个
- **合计**: {{TOTAL_COUNT}} 个

**测试覆盖率**: {{COVERAGE_PERCENT}}（已测 {{TESTED_COUNT}} / 跳过 {{SKIPPED_COUNT}} / 待测 {{PENDING_COUNT}}）

---

> 以下是每个漏洞的标准格式模板，Agent 记录 result 笔记时应遵循此结构：

### [漏洞模板]

**漏洞标题**: [漏洞类型] 简要描述（如：[IDOR] 通过修改 user_id 可查看任意用户订单）

**漏洞等级**: 严重 / 高危 / 中危 / 低危

**漏洞类型**: IDOR / SQLi / XSS / SSRF / CSRF / 信息泄露 / 业务逻辑 / JWT / 越权 / 未授权访问 / ...

**漏洞 URL**: `https://target.com/api/xxx`

**影响范围**: 描述受影响的功能/用户/数据范围

**复现步骤**:

1. 登录账号 A（普通用户），获取 Cookie/Token
2. 访问 `GET /api/order/detail?order_id=10001`，返回自己的订单
3. 修改参数 `order_id=10002`，重新发送请求
4. 返回了其他用户的订单详情，包含姓名、手机号、地址

**请求包**:
```http
GET /api/order/detail?order_id=10002 HTTP/1.1
Host: target.com
Cookie: session=xxx
```

**正常响应 (自己的数据)**:
```json
{"code": 200, "data": {"order_id": 10001, "user": "张三", ...}}
```

**漏洞响应 (他人的数据)**:
```json
{"code": 200, "data": {"order_id": 10002, "user": "李四", "phone": "138xxxx", ...}}
```

**影响说明**: 攻击者可通过遍历 order_id 参数获取平台所有用户的订单信息，包含姓名、手机号、收货地址等敏感数据，存在大规模数据泄露风险。

**修复建议**:
1. 服务端校验当前用户是否有权访问该 order_id 对应的订单
2. 使用不可预测的订单标识符（UUID）替代连续整数 ID
3. 在 API 网关层增加基于用户身份的访问控制

{{SKIPPED_SECTION}}

{{FALLBACK_SECTION}}

---

*本报告由 PentestAgent 辅助生成，漏洞已验证，请人工审核后提交 SRC 平台。*
