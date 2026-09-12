---
name: pre-launch-pt
description: "上线前渗透测试场景剧本。测试环境，可激进测试。有源码/账号/文档支持，目标是发现尽可能多的安全问题。"
metadata:
  tags: "pentest,渗透测试,上线前,测试环境"
  category: "playbook"
---

# 上线前渗透测试 Playbook

## 场景特点

- **测试环境**：可以做破坏性测试，不影响真实用户
- **有完整支持**：可能有源码、多角色账号、API 文档
- **目标全面**：尽可能多地发现安全问题
- **时间充裕**：可以深入测试每个功能

## 测试范围（比 SRC 更宽）

### 允许的操作
- 任意参数 fuzz（不限速率）
- 使用多账号测试越权（管理员/普通用户/未登录）
- 文件上传测试（各种格式和绕过）
- SQL 注入深度测试（手动构造 payload）
- 竞态条件测试（并发请求）
- 会话管理测试（token 过期、重放、并发登录）

### 仍然禁止
- 自动化扫描器（保持人工渗透思维）
- 攻击非测试环境的目标

## 测试清单（全覆盖）

### 认证与会话
- [ ] 弱密码策略测试
- [ ] 密码重置流程是否可劫持
- [ ] 会话 Token 是否可预测
- [ ] 登出后 Token 是否仍有效
- [ ] 并发登录限制
- [ ] JWT/Cookie 安全性（→ jwt-attack-methodology, cookie-analysis）

### 授权与访问控制
- [ ] 水平越权：用户 A 能否访问用户 B 的数据（→ idor-methodology）
- [ ] 垂直越权：普通用户能否访问管理功能（→ privilege-escalation-web）
- [ ] 未授权访问：去掉认证后能否访问（→ 401-403-bypass）
- [ ] 功能级授权：各 API 的权限校验

### 输入验证
- [ ] SQL 注入（→ sql-injection-methodology）
- [ ] XSS（→ xss-methodology）
- [ ] 命令注入（→ command-injection-methodology）
- [ ] SSRF（→ ssrf-methodology）
- [ ] 文件上传（→ file-upload-methodology）
- [ ] XXE（→ xxe-injection-methodology）

### 业务逻辑
- [ ] 支付/金额篡改（→ business-logic-attack）
- [ ] 流程跳转/状态篡改
- [ ] 竞态条件/并发（→ race-condition-exploit）
- [ ] 验证码绕过

### 信息泄露
- [ ] 敏感路径泄露（→ information-disclosure-methodology）
- [ ] API 文档泄露（Swagger/GraphQL introspection）
- [ ] 错误信息泄露（Stack Trace）
- [ ] JS 中的敏感信息

### API 安全
- [ ] GraphQL 安全（→ graphql-methodology）
- [ ] WebSocket 安全（→ websocket-attack）
- [ ] CORS 配置（→ cors-misconfiguration）
- [ ] HTTP Header 安全

## 报告格式

使用完整渗透测试报告模板，包含：执行摘要、测试范围、方法论、详细发现、风险评级、修复建议、附录。
