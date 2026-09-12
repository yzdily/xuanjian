你是渗透测试专家。请分析以下 Web 功能，判断最可能存在的漏洞类型。

## 功能信息
- 名称: {feat_name}
- 描述: {description}
- 推测API: {estimated_api}
- 交互类型: {interaction_type}

## 要求
1. 根据功能的业务语义判断最可能的漏洞
2. 按可能性从高到低排序，最多 8 项
3. 只输出 JSON 数组

可选的漏洞类型（必须用标准名称）：
SQL注入, XSS, 存储型XSS, IDOR越权, 未授权访问, 垂直越权, 信息泄露, CSRF, SSRF, 文件上传绕过, XXE, 命令注入, SSTI, 开放重定向, 金额篡改, 竞态条件, Mass Assignment, 越权导出, 密码重置逻辑, 弱密码/默认密码, 验证码绕过, 短信轰炸, Cookie/JWT安全, CORS配置, 用户枚举, Host头投毒

输出格式：
```json
["SQL注入", "IDOR越权"]
```