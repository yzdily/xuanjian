# 玄鉴 XuanJian v2.0 架构文档

> **封板声明**：自 v2.0 起，玄鉴进入封板维护态。功能冻结，仅接纳 bugfix 与安全补丁。
> AI-native 安全模块（LLM/Agent/RAG 安全）归入 [鉴微 JianWei](https://github.com/yzdily/jianwei) 平台层。

---

## 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     Web UI (index.html SPA)                     │
│   对话终端 · 目标管理 · 扫描控制 · 漏洞报告 · 设置 · 高级工具     │
├─────────────────────────────────────────────────────────────────┤
│                  Web API Layer (FastAPI, 19 routers)             │
│  sessions · reports · dashboard · skills · memory · packet      │
│  credential_injection · crypto · diff · replay · oob · triggers │
│  presets · templates · models · auth · system                   │
├─────────────────────────────────────────────────────────────────┤
│                    Session State Machine                         │
│   Phase 0 → 0.5 → 1 → 1.5 → 2a/2b → 2.55 → 2.6 → 3          │
│   (chat_loop.py: 爬虫→业务理解→功能分析→对账→漏洞测试→补测→验证→报告)│
├─────────────────────────────────────────────────────────────────┤
│                      Core Engine Layer                           │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ Crawler  │ │  Parallel │ │   XSS    │ │ FastScanner      │  │
│  │ (Auto)   │ │ Orchestr. │ │ 13-step  │ │ (YAML规则引擎)   │  │
│  └──────────┘ └───────────┘ └──────────┘ └──────────────────┘  │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │   LLM    │ │   Harm    │ │   Fuzz   │ │ JS Analyzer      │  │
│  │ Client   │ │ Validator │ │ Engine   │ │ (深度分析)        │  │
│  └──────────┘ └───────────┘ └──────────┘ └──────────────────┘  │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ Browse   │ │ Dir       │ │ Supplement│ │ Crypto Replay    │  │
│  │ Worker   │ │ Scanner   │ │ Test Agent│ │ (加密回放)       │  │
│  └──────────┘ └───────────┘ └──────────┘ └──────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                   Knowledge & Rules Layer                        │
│  skills_my/ (方法论 SKILL)  ·  rules/ (YAML 检测规则)           │
│  prompts/ (LLM 提示词模板)  ·  templates/ (报告模板)             │
├─────────────────────────────────────────────────────────────────┤
│                   External Integration Layer                     │
│  MCP Servers (浏览器/代理)  ·  Burp Suite Plugin  ·  REST API   │
│  Playwright (浏览器自动化)  ·  mitmproxy (流量拦截)              │
└─────────────────────────────────────────────────────────────────┘
```

## 核心模块说明

### 会话状态机 (`core/session/`)

8 阶段自动流转，由 `chat_loop.py` (ChatLoopMixin) 驱动：

| 阶段 | 职责 | 执行者 |
|------|------|--------|
| Phase 0 | 站点探索（爬虫 + JS 分析 + 流量 + SPA 降级） | AutoCrawler |
| Phase 0.5 | 业务理解（语义分析 → 攻击假设） | BusinessUnderstanding |
| Phase 1 | 功能分析（识别功能点 → Checklist） | AnalyzeWorker |
| Phase 1.5 | 业务对账（Checklist × 业务理解交叉验证） | 主 Agent |
| Phase 2a | HTTP 漏洞测试（SQLi/IDOR/未授权…） | 3 子 Agent 并行 |
| Phase 2b | 浏览器漏洞测试（XSS/CSRF…） | 主 Agent |
| Phase 2.55 | 补测（扫描遗漏 API） | SupplementalTestAgent |
| Phase 2.6 | 危害验证（检测层铁律 + LLM 审核员双重去误报） | HarmValidator |
| Phase 3 | 汇总报告（覆盖矩阵 + 漏洞详情 + PoC） | 主 Agent |

### 爬虫引擎 (`core/crawler/`)

AutoCrawler（3547 行，已拆分为包），支持：
- Playwright 有头/无头模式自动浏览
- SPA 智能降级（Vue/React/Angular 检测 → 手动浏览 + 流量录制）
- 表单自动填充、登录凭证注入、验证码 OCR 识别
- 黑名单过滤、路径去重、站点地图构建

### 快速扫描引擎 (`core/fast_scanner/`)

YAML 规则引擎，11 子模块：
- `_engine.py` — 超时熔断/心跳/调度核心
- `_fp_filters.py` — 检测层假阳性硬规则过滤（铁律）
- `_checks_*` — 15 类漏洞检测（sql_injection, xss, idor, ssrf, csrf…）
- 规则通过 `rules/*.yaml` 声明式配置，`getattr(f"_check_{rule}")` 分发

### 危害验证 (`core/harm_validation/`)

独立 LLM 审核员 + 检测层硬规则双重去误报：
- `validator.py` — 危害验证主逻辑
- `render.py` + `_render_helpers.py` — 证据渲染
- `context.py` — 上下文管理
- `exploit.py` — 利用验证

### XSS 专项引擎 (`core/xss/`)

13-step 完整检测流程：
- 反射/存储/DOM XSS
- OOB 带外验证、上传型 XSS、CSP 绕过
- `llm_judge.py` — LLM 辅助判定（判定范式被鉴微复用）

### Fuzz 引擎 (`core/fuzz/`)

- `sqli.py` — SQL 注入 Fuzz（含布尔盲注三层校验 + 时间盲注二次复现）
- `race_condition.py` — 竞态条件检测
- `waf_bypass.py` — WAF 绕过 Payload 生成

### LLM 客户端 (`core/llm/`)

10 子模块，支持 10+ 模型热切换：
- `_client.py` — 统一 LLM 调用接口
- `_pool.py` — 连接池管理
- `_response_cache.py` — 响应缓存
- `_tokens.py` — Token 计数与费用追踪

### 并行调度 (`core/parallel/`)

- `orchestrator.py` — 并行任务编排（1499 行）
- `_orchestrator_helpers.py` — 辅助函数
- `batch_test.py` — 批量测试执行

### Web API (`web/api/`)

19 个 FastAPI Router：

| Router | 职责 |
|--------|------|
| `sessions_api` | 会话管理（创建/删除/列表） |
| `reports_api` | 漏洞报告（批量下载/删除） |
| `dashboard_api` | 仪表盘数据 |
| `skills_api` | SKILL 方法论管理 |
| `memory_api` | 经验记忆管理 |
| `packet_api` | 数据包管理 |
| `credential_injection_api` | 凭证注入 |
| `crypto_api` | 加密回放 |
| `diff_api` | 差异对比 |
| `replay_api` | 流量重放 |
| `oob_api` | OOB 带外验证 |
| `triggers_api` | 触发器管理 |
| `presets_api` | 预设配置 |
| `templates_api` | 报告模板 |
| `models_api` | 模型管理 |
| `auth_api` | 认证管理 |
| `system_api` | 系统信息 |
| `dashboard_api` | LLM 用量监控 |

## 扫描模式（双轴正交）

**维度一 · 扫描深度**（`ScanMode`）：

| 深度 | LLM | 场景 |
|------|-----|------|
| FAST | 否 | 快速全量规则扫描 |
| STANDARD | 部分 | 日常渗透 |
| DEEP | 完整 | 全量 LLM 分析 |
| SMART | 自动 | 先分析再选深度 |

**维度二 · 编排方式**：

| 编排 | 流程 | 场景 |
|------|------|------|
| Batch | 爬虫→分析→并行测试→报告 | 全站渗透 |
| Realtime | 发现即测 | 快速验证 |
| Packet | 单数据包跑 Checklist | Burp 联动 |

## 封板边界

**封板含（冻结范围）：**
- Web/App 渗透 Agent 全能力
- 19 Router Web API
- 爬虫/编排/并行/上下文/危害验证全模块
- FastScanner YAML 规则引擎 + 假阳性防护体系
- XSS 13-step 专项引擎
- SQLi/Race/WAF Bypass Fuzz 引擎
- 自定义 SKILL 方法论体系
- 合规报告 + 免责声明
- Burp Suite 插件 + MCP 工具服务

**封板不含（不再添加）：**
- LLM/Agent/RAG 等 AI-native 安全模块
- 护栏（sec_shield）
- 评测度量（ASR/拒答率/泄露率）
- 以上全部归入 [鉴微 JianWei](https://github.com/yzdily/jianwei) 平台层

## 维护策略

- `main` 分支归档，保持封板状态
- `maintain` 分支仅接纳 bugfix 与安全补丁
- 社区 PR 欢迎，但不新增 feature
- 许可证：MIT
