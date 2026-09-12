---
name: business-logic-analysis
description: "业务逻辑分析方法论。在 Phase 1 功能分析阶段使用。用于理解 Web 应用业务模型、关键流程、状态流转、金额/数量/优惠券/订单/审批/邀请/积分/库存/支付回调等高价值逻辑入口，并把每个流程转化为可测试的业务漏洞假设。"
priority: 8
vuln_types:
  - 业务逻辑漏洞
  - 流程绕过
  - 状态机绕过
  - 优惠券滥用
triggers:
  - price
  - amount
  - quantity
  - coupon
  - discount
  - order
  - pay
  - payment
  - refund
  - balance
  - points
  - inventory
  - status
  - state
  - approve
  - invite
  - workflow
synonyms:
  - business logic
  - logic flaw
  - workflow bypass
  - price tampering
  - payment logic
  - coupon abuse
  - 逻辑漏洞
  - 业务漏洞
metadata:
  tags: "业务逻辑,分析,理解,业务流程,攻击面,功能点,优先级"
  category: "recon"
  authority: "expert"
---

# 业务逻辑分析方法论

## 0. 立即执行摘要：所有金额、状态、次数、归属、流程顺序都要建漏洞假设

看到 `price`、`amount`、`quantity`、`coupon`、`balance`、`points`、`status`、`state`、`step`、`approve`、`refund`、`invite`、`inventory`、`pay`、`callback` 时，必须进入本 skill。业务逻辑漏洞不是靠 payload，而是靠打破开发者默认假设：**用户会按顺序操作、不会改金额、不会重复提交、不会跨账号使用资源、不会伪造回调**。

优先顺序：

1. 梳理正常流程和状态机，标出每一步由前端传还是后端算。
2. 找金额、数量、折扣、积分、库存、状态、归属、审批、回调等可信边界。
3. 对每一步测试跳步、逆序、重复、并发、过期重放、跨账号、跨租户。
4. 用无害测试资源验证，不破坏真实支付、提现、订单、库存。

## 1. 业务入口触发矩阵

| 入口/参数 | 漏洞假设 | 立即测试 |
|---|---|---|
| `price/amount/total` | 金额篡改 | 0、1、负数、小数、超大值、前后端金额不一致 |
| `quantity/count/num` | 数量边界 | 0、负数、超库存、并发扣减 |
| `coupon/discount/promo` | 优惠券滥用 | 重复使用、跨账号、叠加、过期仍可用 |
| `status/state/step` | 状态机绕过 | 直接提交终态、跳过审批/支付/验证 |
| `order_id/pay_id/refund_id` | 订单越权/重复支付 | A/B 账号、重复回调、退款重放 |
| `invite/referral` | 邀请奖励滥用 | 自邀请、重复领取、批量注册 |
| `balance/points/credit` | 资产篡改 | 并发领取、负数扣减、重复兑换 |
| `callback/webhook/notify` | 回调伪造 | 签名弱、状态跳转、重放旧回调 |

## 核心：先理解再攻击

> 逻辑漏洞的本质是"开发者认为用户不会这么做，但攻击者偏要这么做"。
> 你不理解正常流程，就不知道哪里可以"不正常"。

## Step 1: 应用类型识别

拿到爬取结果后，先判断这是什么类型的应用：

| 类型 | 特征 | 核心攻击面 |
|------|------|-----------|
| 电商/商城 | 商品列表、购物车、下单、支付 | 金额篡改、订单状态跳转、优惠券滥用 |
| 社交/社区 | 用户主页、关注、消息、动态 | 越权查看私信、身份冒用、隐私泄露 |
| 管理后台 | 用户管理、角色权限、数据看板 | 垂直越权、未授权访问、批量导出 |
| SaaS 平台 | 多租户、工作空间、API Key | 租户隔离突破、API Key 泄露 |
| 金融/支付 | 充值、提现、转账、钱包 | 竞态条件双花、金额溢出、提现逻辑 |
| 内容平台 | 文章、评论、上传、搜索 | XSS、SSRF（图片加载）、文件上传 |
| API 服务 | RESTful/GraphQL、文档、SDK | 未授权端点、批量查询、注入 |

## Step 2: 关键业务流程梳理

对每种应用类型，梳理核心业务流程：

### 用户生命周期
```
注册 → 登录 → 使用功能 → 修改信息 → 注销
每一步都要问：
- 注册时有没有邀请码/角色选择？能不能注册成管理员？
- 登录后 Token 怎么发的？有没有过期？
- 修改信息时服务端校验了什么？
- 注销后 Token 还能用吗？
```

### 交易流程（电商/支付类最关键）
```
浏览商品 → 加购物车 → 填地址 → 选支付 → 确认下单 → 支付 → 完成
每一步都要问：
- 价格在哪一步确定？是前端传的还是后端算的？
- 数量有没有上限/下限？负数呢？
- 优惠券在哪一步生效？能叠加吗？
- 订单状态流转是否可以跳步？
- 支付回调是否可以伪造？
```

### 权限模型
```
普通用户 → VIP → 管理员 → 超级管理员
问：
- 不同角色能访问哪些 API？有没有遗漏的权限校验？
- 角色信息存在哪里？Cookie/JWT/Session？能改吗？
- 有没有隐藏的管理端点？
```

## Step 3: 功能点分类与优先级

### 优先级判断标准

**Critical（必测）**：
- 涉及钱的操作：支付、充值、提现、转账、退款
- 涉及权限的操作：角色切换、权限分配、管理功能
- 涉及大量用户数据：用户列表、订单导出、数据查询

**High（重点测）**：
- 参数中有 ID 的 API：user_id、order_id、file_id → IDOR
- 参数中有金额的 API：price、amount、quantity → 篡改
- 有 JWT/Token 的功能：认证绕过、Claims 篡改
- 文件上传/下载：上传绕过、任意文件读取

**Medium（常规测）**：
- 搜索功能 → 注入
- 个人信息修改 → CSRF、越权
- 评论/消息 → XSS
- 密码重置 → 逻辑绕过

**Low（快速过）**：
- 静态页面（关于我们、帮助文档）
- 纯展示功能（无交互）

## Step 4: API 参数分析

对每个发现的 API，分析其参数的安全含义：

| 参数模式 | 含义 | 测试方向 |
|----------|------|----------|
| `user_id=1001` | 用户标识，连续整数 | IDOR：改成 1002 |
| `order_id=ORD20240001` | 订单号，有规律 | IDOR：遍历 |
| `price=9900` | 金额（分） | 改为 1、0、-1 |
| `role=user` | 角色字段 | 改为 admin |
| `is_admin=false` | 权限标志 | 改为 true |
| `redirect=https://a.com` | 跳转地址 | SSRF/Open Redirect |
| `file=report.pdf` | 文件名 | 路径穿越 `../../etc/passwd` |
| `token=eyJhb...` | JWT | 解码 → 篡改 → 重放 |
| `callback=handleData` | JSONP 回调 | XSS |
| `xml=<root>...` | XML 输入 | XXE |

## Step 5: 输出测试计划

分析完成后，输出结构化的测试计划：

```
功能点: 下单支付
优先级: critical
相关 API:
  - POST /api/order/create (参数: product_id, quantity, price, coupon_code)
  - POST /api/order/pay (参数: order_id, amount, payment_method)
  - GET /api/order/detail?order_id=xxx
测试方向:
  1. 金额篡改：修改 create 请求中的 price 参数
  2. 数量篡改：quantity 设为 0 或负数
  3. 优惠券复用：同一 coupon_code 多次使用
  4. 订单越权：改 order_id 查看他人订单 (→ idor-methodology)
  5. 竞态条件：并发支付请求 (→ race-condition-exploit)
  6. 支付状态跳转：直接调用已支付接口
```

## 最低必测自检

标记业务分析完成前必须确认：

1. 已识别核心业务流程、状态流转和每一步的服务端校验点。
2. 已标记所有金额、数量、优惠、积分、库存、订单、审批、回调、邀请类参数。
3. 已为每个高价值流程给出跳步、逆序、重复、并发、跨账号、过期重放测试方向。
4. 已说明哪些测试因安全边界只能做无害验证或需要授权。

## 输出格式

```text
[业务逻辑分析]
功能/流程：
正常状态流：
高价值参数：price/amount/quantity/coupon/status/order_id/user_id/callback/其他
信任边界：前端传入/服务端计算/第三方回调/异步任务/未知
候选漏洞：金额篡改/流程绕过/重复提交/竞态/越权/回调伪造/优惠滥用
建议测试：
安全边界：测试账号/测试订单/禁止真实支付/其他
优先级：Critical/High/Medium/Low
```
