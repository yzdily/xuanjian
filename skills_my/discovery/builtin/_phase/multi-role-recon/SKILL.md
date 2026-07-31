---
name: multi-role-recon
description: "多角色/多账号/多租户对比分析方法论。当有游客、普通用户 A/B、VIP、商户、子账号、管理员、审核员、客服、租户 A/B 等测试身份时使用。通过对比不同角色看到的页面、API、数据、按钮、菜单、响应字段和操作结果来发现未授权、IDOR、垂直越权、租户越权、Mass Assignment。"
priority: 8
vuln_types:
  - 多角色侦察
  - 权限边界发现
  - IDOR越权
  - 垂直越权
  - 多租户越权
  - 未授权访问
triggers:
  - role
  - RBAC
  - 权限
  - 多角色
  - 普通用户
  - 管理员
  - 商户
  - 租户
  - 子账号
  - A/B账号
  - VIP
  - auditor
  - 客服
synonyms:
  - multi role recon
  - role comparison
  - rbac recon
  - permission mapping
  - tenant comparison
  - 多账号对比
  - 权限对比
metadata:
  tags: "多角色,对比,越权,权限,RBAC,水平越权,垂直越权,角色"
  category: "recon"
  authority: "expert"
---

# 多角色对比分析方法论

## 0. 立即执行摘要：角色差异就是越权测试地图

多角色侦察的目标不是简单截图菜单，而是输出：**角色 → 可见页面 → 可调用 API → 可见数据范围 → 可操作动作 → 对应越权测试点**。任何没有 A/B 普通账号和跨角色对照的 IDOR/权限结论都不完整。

优先对比：

1. 未登录 vs 普通用户：发现未授权访问。
2. 普通用户 A vs 普通用户 B：发现水平越权/IDOR。
3. 普通用户 vs VIP/商户/管理员：发现垂直越权。
4. 租户 A vs 租户 B：发现多租户越权。
5. 主账号 vs 子账号/审核员/客服：发现委托权限和流程越权。

## 核心思路

> 最高效的越权发现方式不是"猜"，而是"对比"。

## Step 1: 角色梳理

列出所有可用的测试角色：

| 角色 | 账号 | 预期权限 |
|------|------|----------|
| 未登录 | - | 只能看公开内容 |
| 普通用户 A | user_a / pass | 看自己的数据 |
| 普通用户 B | user_b / pass | 看自己的数据 |
| VIP 用户 | vip / pass | 多一些功能 |
| 管理员 | admin / pass | 管理所有数据 |

## Step 2: 三维对比

### 维度一：页面差异（垂直越权线索）
```
用普通用户登录 → 记录能看到的所有页面 URL
用管理员登录   → 记录能看到的所有页面 URL
差异 = 管理员多出来的页面
测试：用普通用户的 Token 访问这些管理员页面 → 能访问就是垂直越权
```

### 维度二：API 差异（垂直越权线索）
```
用普通用户操作 → 抓包记录所有 API
用管理员操作   → 抓包记录所有 API
差异 = 管理员多出来的 API
测试：用普通用户的 Token 调用这些管理 API → 能调用就是垂直越权
```

### 维度三：数据差异（水平越权线索）
```
用用户 A 请求 GET /api/order/list → 返回 A 的订单
用用户 B 的 Token 请求同一个接口 → 返回 B 的订单
用用户 A 的 Token 请求 GET /api/order/detail?id=B的订单ID
  → 如果返回了 B 的订单详情 → 水平越权!
```

## Step 3: 系统性对比方法

对爬取到的每一个 API：

1. **用角色 A 的 Token 请求** → 记录响应 `resp_A`
2. **用角色 B 的 Token 请求同一个 API** → 记录响应 `resp_B`
3. **不带 Token 请求** → 记录响应 `resp_none`
4. 对比：
   - `resp_A == resp_B` 且包含 A 的数据 → 没问题
   - `resp_A == resp_B` 且 A 能看到 B 的数据 → **水平越权**
   - `resp_none` 状态码 200 → **未授权访问**
   - 普通用户能访问管理 API → **垂直越权**

## 自动化对比脚本思路

```
for api in all_discovered_apis:
    resp_a = request(api, token=user_a_token)
    resp_b = request(api, token=user_b_token)
    resp_no = request(api, token=None)
    
    if resp_no.status == 200:
        report("未授权访问", api)
    if resp_a.status == 200 and contains_other_user_data(resp_a, user_b):
        report("水平越权", api)
```

这种方法论在 Phase 2 测试阶段可以批量执行，效率极高。

## 角色差异 → 后续测试矩阵

| 对比结果 | 漏洞假设 | 后续 skill |
|---|---|---|
| 未登录能访问登录后 API | 未授权访问 | `no-auth-quick-test`、`auth-bypass-methodology` |
| A 能看到 B 唯一字段 | IDOR/BOLA | `idor-methodology` |
| 普通用户能调管理 API | 垂直越权 | `privilege-escalation-web` |
| A 租户能读 B 租户数据 | 多租户越权 | `idor-methodology`、`privilege-escalation-web` |
| 子账号能执行主账号动作 | 委托权限缺陷 | `business-logic-attack`、`privilege-escalation-web` |
| 角色只在前端隐藏菜单 | 前端鉴权缺陷 | `auth-bypass-methodology`、`api-fuzz` |
| 响应字段比页面多 | 敏感信息泄露/Mass Assignment | `information-disclosure-methodology`、`privilege-escalation-web` |

## 最低必测自检

标记多角色侦察完成前必须确认：

1. 至少有未登录、普通用户 A、普通用户 B 三类样本；缺少则标信息缺口。
2. 如果系统存在组织/租户/商户/管理员/子账号，必须做跨角色或跨租户对比。
3. 对页面、API、菜单、按钮、响应字段、操作结果分别做差异记录。
4. 对每个差异项给出候选漏洞和后续 skill，而不是只写"权限不同"。
5. 发现 `403/404` 差异时，记录资源是否存在、谁能访问、谁不能访问。

## 输出格式

```text
[多角色侦察]
角色矩阵：未登录/普通A/普通B/VIP/商户/管理员/租户A/租户B/子账号
入口/API：
可见性差异：谁可见/谁不可见
数据边界：本人/他人/本租户/跨租户/全部/未知
操作权限：读/写/删除/审批/导出/邀请/管理
候选漏洞：未授权/IDOR/垂直越权/租户越权/MassAssignment/信息泄露
建议 skill：
信息缺口：缺角色/缺账号/缺租户/缺高权限样本
```
