# Changelog

本文件记录玄鉴 XuanJian 的所有重要变更。

> 自 v2.0 起进入封板维护态，仅接纳 bugfix 与安全补丁。

---

## [v2.0] — 2026-08-18 · 封板版

**封板声明**：功能冻结，仅维护。AI-native 安全模块归入 [鉴微 JianWei](https://github.com/yzdily/jianwei) 平台层。

### 架构与工程

- 大规模包化拆分：`fast_scanner.py` → 11 子模块、`crawler_core.py` → 包化、`js_analyzer` → 9 子模块、`browse_worker` → 5 子模块、`dir_scanner` → 5 子模块、`supplemental_test_agent` → 5 子模块、`worker_agent` → 3 子模块
- DI（依赖注入）收敛：`core/di.py` resetter 模式，全局态 `global` 从 54 处大幅收敛
- Prompts 抽取：LLM 提示词模板从业务代码分离至 `core/prompts/`
- 上下文预算硬阻断（D14）：防止 sample injection 溢出

### 扫描引擎

- FastScanner YAML 规则引擎：检测规则从硬编码迁移至 `rules/*.yaml` 声明式配置
- 检测层假阳性防护铁律：业务错误码解析、空 data 检查、WAF 拦截页识别、响应归一化、布尔盲注三层校验、时间盲注二次复现、XSS 可执行上下文、命令注入/SSRF 特征收紧、登录接口白名单、CSRF Token 名扩展
- LLM 重试优化
- HarmValidator 增强

### 漏洞检测

- 新增 CSRF 检测技能（SKILL 方法论）
- 新增 SQLi 检测技能
- 优化 IDOR 方法论
- SQLi Fuzz 模块增强
- WAF 封禁状态持久化 + WAF 智能降级
- DirScan 路径过滤优化
- 敏感发现上报为漏洞
- 二次验证多因素判定优化，减少响应头误报

### 功能新增

- 配置运行时、CWE 映射、表单 API 桥接
- 误报跟踪管理（`false_positive_manager.py`）
- 严重性规则
- 技能路由（`skill_router`）
- 资产映射模块
- 合规报告模块
- PoC 生成模块（`poc_generator.py`）
- 端口扫描模块（`port_scanner.py`）
- 报告批量下载/删除
- SSE 解析优化 + FAST 模式优化

### 爬虫与前端

- SPA 爬虫智能降级（Vue/React/Angular 检测 → 手动浏览 + 流量录制）
- 凭证注入登录（Cookie/JWT/Header 绕过登录）
- JS 分析增强
- README 优化与截图修复

### 补测 Agent

- 补测 Agent 重构（5 子模块：`_discovery` + `_attach` + `_runner`）
- 路径过滤器统一
- 报告渲染优化
- 补测 Agent 增强

### 工程治理

- hollowing-optimization-plan 从仓库移除并加入 .gitignore
- 本地 docs/ 目录 untrack + gitignore
- 扫描稳定性与报告质量优化
- 日志输出优化

---

## [v1.0] — 初始版本

### 核心能力

- 全自动渗透测试 Agent（8 阶段状态机）
- URL 全流程渗透（输入目标 URL → 自动完成爬虫/分析/测试/报告）
- 账号密码登录渗透
- 凭证注入渗透（Cookie/JWT/Header）
- 手动登录凭证捕获（Playwright 有头模式）
- 验证码自动识别（OCR）
- 自定义 SKILL 方法论

### 引擎模块

- AutoCrawler（Playwright 爬虫）
- ChatLoop（对话式任务编排）
- Parallel Orchestrator（并行任务调度）
- FastScanner（快速检测）
- HarmValidator（危害验证）
- XSS 13-step 专项引擎
- Fuzz 引擎（SQLi/Race/WAF Bypass）
- LLM Client（10+ 模型支持）
- JS Analyzer
- Browse Worker

### Web 与集成

- Web UI（单体 SPA，原生 JS）
- 18 Router FastAPI REST API
- Burp Suite 插件
- MCP 工具服务（浏览器/代理）
- Frida 前端加密拦截（crypto_hook）
- Wooyun 历史漏洞知识库
