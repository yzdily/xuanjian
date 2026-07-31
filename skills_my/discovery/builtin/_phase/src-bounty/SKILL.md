---
name: src-bounty
description: "SRC 漏洞挖掘场景剧本。当用户指定 --mode src-bounty 或目标是 SRC 项目时加载。定义 SRC 挖洞的合规边界、优先测试方向、禁止行为和报告格式。"
metadata:
  tags: "src,bug bounty,漏洞挖掘,众测"
  category: "playbook"
---

# SRC 漏洞挖掘 Playbook

## 合规边界（硬性约束，不可违反）

1. **严守授权范围**：每次攻击前必须调用 `target_check_scope` 确认目标在 scope 内
2. **禁止扫描器**：不使用 nuclei/xray/sqlmap --crawl 等自动化扫描
3. **禁止暴力破解**：不对登录接口做密码爆破
4. **禁止 DoS**：不发送大量并发请求
5. **禁止写入操作**：不上传 webshell、不修改生产数据
6. **禁止越界**：不攻击 scope 外的子域或第三方服务

## 优先测试方向（SRC 高频漏洞类型）

按价值从高到低排列：

1. **IDOR/越权** — 改 user_id、order_id 等参数访问他人数据（→ idor-methodology）
2. **未授权 API** — 去掉 Token 直接访问接口（→ 401-403-bypass）
3. **业务逻辑** — 支付金额篡改、优惠券复用、状态跳转（→ business-logic-attack）
4. **信息泄露** — .git/备份文件/.env/Swagger 文档/JS 中的 API Key（→ information-disclosure-methodology）
5. **SSRF** — 有 URL 参数的地方尝试内网探测（→ ssrf-methodology）
6. **JWT/Cookie 伪造** — 解码 token 尝试篡改权限字段（→ jwt-attack-methodology）
7. **CORS 配置错误** — 检查 Access-Control-Allow-Origin 是否反射（→ cors-misconfiguration）
8. **CSRF** — 敏感操作是否缺少 token 保护（→ csrf-methodology）

## 工作流

```
1. 正常注册/登录账号（如有多角色，注册多个）
2. 全面浏览应用功能，同时分析抓到的所有 API
3. 逐个 API 检查：
   - 有 ID 参数？→ 改 ID 测越权
   - 有金额参数？→ 改金额测逻辑
   - 有 Token？→ 去掉 Token 测未授权
   - 响应有敏感数据？→ 记录信息泄露
4. 对每个确认的漏洞，截图 + 记录完整复现步骤
5. 生成 SRC 格式报告
```

## 报告格式

每个漏洞应包含：
- **漏洞标题**：[漏洞类型] 简短描述
- **漏洞等级**：严重/高危/中危/低危
- **影响范围**：受影响的 URL/API
- **复现步骤**：1. 2. 3. ...（含请求/响应截图）
- **影响说明**：能造成什么危害
- **修复建议**：建议的修复方案
