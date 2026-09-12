---
name: target-profiling
description: "目标全景画像与攻击面优先级分析。当需要系统性整理目标资产、技术栈、认证体系、API 风格、权限/租户模型、业务高价值功能、WAF/CDN/中间件、移动端/小程序入口，并推断最该优先测试的漏洞类型时使用。适合在 recon-full 或 crawl 后生成结构化目标档案。"
priority: 7
vuln_types:
  - 目标画像
  - 攻击路径规划
  - 技术栈指纹
  - 攻击面优先级
triggers:
  - profiling
  - fingerprint
  - 指纹
  - 画像
  - 技术栈
  - 资产分析
  - 攻击路径
  - 优先级
  - WAF
  - CDN
  - tenant
  - RBAC
  - API风格
synonyms:
  - target profiling
  - target profile
  - asset profiling
  - technology profiling
  - attack path planning
  - 目标画像
  - 资产画像
metadata:
  tags: "recon,profiling,fingerprint,port,画像,档案,资产分析,攻击面评估"
  category: "recon"
  authority: "reference"
---

# 目标全景画像方法论

## 0. 立即执行摘要：画像必须转化为漏洞优先级

目标画像不是资产列表，而是要回答：**这是什么系统、信任边界在哪里、最可能出什么漏洞、先测哪些入口**。画像完成后必须给出漏洞优先级，而不是只列域名/IP/端口。

必须识别：

1. 技术栈：前端框架、后端语言、框架、中间件、数据库、对象存储、消息队列。
2. 认证体系：Cookie/JWT/OAuth/SSO/API Key/MFA/移动端签名。
3. API 风格：REST/GraphQL/RPC/WebSocket/文件直传。
4. 权限模型：普通用户、管理员、商户、租户、子账号、审批角色。
5. 高价值业务：支付、优惠券、订单、导出、上传、审批、邀请、文件、消息、回调。
6. 防护与架构：WAF/CDN/反向代理/缓存/多域名/移动端/小程序。

## 1. 技术栈 → 漏洞优先级矩阵

| 画像信号 | 优先漏洞 | 建议 skill |
|---|---|---|
| REST/JSON API | 未授权、IDOR、Mass Assignment | `api-fuzz`、`idor-methodology`、`privilege-escalation-web` |
| GraphQL | BOLA、批量查询、Introspection | `graphql-methodology`、`idor-methodology` |
| WebSocket/Socket.IO | CSWSH、消息级越权 | `websocket-attack` |
| Spring Boot/Java | Actuator、反序列化、SSTI、路径权限 | `information-disclosure-methodology`、`deserialization-methodology` |
| PHP/Laravel/WordPress | LFI、文件上传、反序列化、SQLi | `lfi-rfi-methodology`、`file-upload-methodology`、`sql-injection-methodology` |
| Node/Express | 原型污染、NoSQL、SSRF | `prototype-pollution`、`nosql-injection`、`ssrf-methodology` |
| CDN/反代/缓存 | Host 攻击、缓存投毒、请求走私 | `http-host-header-attacks`、`cache-and-smuggling` |
| 对象存储/直传 | ACL、上传后越权、Content-Type XSS | `file-upload-methodology`、`idor-methodology` |
| OAuth/SSO | redirect_uri、state、账号绑定 | `oauth-sso-attack` |
| 多租户/RBAC | IDOR、垂直越权、租户越权 | `idor-methodology`、`privilege-escalation-web` |

## Phase 1: 数据汇总
用 `evidence_list`（按类型筛选资产记录）和 `list_vulns` 获取已有的侦察数据。如果数据不足，补充执行：
- `subfinder -d domain` / `ksubdomain -d domain` — 子域名
- `naabu -host target` — 端口（nmap 作为备选）
- `httpx -u target -tech-detect` / `curl -sI target` — 指纹

## Phase 2: 攻击面分析

### 2.1 技术栈分布
统计目标使用的技术栈，识别统一管理的和独立部署的系统：
- 统一框架（如全站 Spring Boot）→ 一个漏洞可能影响所有系统
- 混合技术栈 → 各系统独立评估

### 2.2 暴露面评估
按风险等级分类已发现的服务：

**极高风险**（应优先攻击）：
- 管理后台（admin/manager/console）
- 开发/测试环境（dev/staging/test）
- 暴露的数据库端口（3306/5432/6379/27017）
- CI/CD 系统（Jenkins/GitLab/Harbor）

**高风险**：
- 带已知漏洞的组件（旧版 Spring/Struts/Log4j）
- 认证页面（可能存在弱密码/默认凭据）
- API 端点（可能缺少认证）

**中风险**：
- 标准 Web 应用（需要进一步手动测试）
- 邮件/VPN 入口（社工攻击入口）

**低风险**：
- CDN/静态资源
- 纯展示型网站

### 2.3 网络拓扑推断
从子域名和 IP 分布推断网络结构：
- 同一 IP 段 → 可能同一机房/VPC
- CDN 后的真实 IP → 可能绕过 WAF
- 内外网混部 → 横向移动的潜在路径

## Phase 3: 输出目标档案

生成结构化报告，包含：
1. **资产清单**：域名/IP/端口/服务/版本
2. **技术栈总览**：框架/中间件/CMS 分布
3. **攻击优先级**：按风险等级排序的攻击目标列表
4. **推荐攻击路径**：基于发现的信息，建议 2-3 条最有可能成功的攻击路径
5. **信息缺口**：还需要进一步侦察的方面

## 网络拓扑推断
- 子网分析：10.0.1.x 可能是 Web 段（同一子网的 Web 服务器），10.0.2.x 可能是数据库段（不同子网，有网络隔离）

## 信息缺口识别
- 子域名来源单一：缺 OSINT、缺爬虫，覆盖不足
- 端口不全：默认 Top 1000 端口不够，需要全端口（65535）扫描
- 非标准端口（30000+）高端口可能隐藏服务

## 输出格式

```text
[目标画像]
资产范围：主域/子域/IP/端口/服务
技术栈：前端/后端/数据库/中间件/对象存储/CDN/WAF
认证体系：Cookie/JWT/OAuth/SSO/APIKey/MFA/移动签名/未知
API风格：REST/GraphQL/RPC/WebSocket/文件直传/未知
权限模型：游客/普通用户/VIP/商户/管理员/租户/子账号/未知
高价值业务：支付/订单/优惠券/上传/导出/审批/邀请/回调/消息/文件
优先漏洞：按 P0/P1/P2 排列
建议路径：先测哪些入口、加载哪些 skill
信息缺口：缺账号/缺角色/缺移动端/缺API文档/缺端口/缺样本
```

## 最低必测自检

完成画像前必须确认：

1. 已将资产按业务系统聚类，而不是只按域名罗列。
2. 已识别认证体系、权限模型和是否多租户；无法识别则列为信息缺口。
3. 已给出每类技术栈对应的漏洞优先级和后续 skill。
4. 已标记高价值业务入口和缺失样本。
