# Changelog

本文件记录玄鉴 XuanJian 的所有重要变更。

> 自 v2.0 起进入封板维护态，仅接纳 bugfix 与安全补丁。

---

## [Unreleased] — 2026-09-23 · 0923 方案全量修复（任务生命周期 + 结果可信度）

> 主题：**扫得完、接得上、说得清、骗不了人**。
> 依据：`hollowing-optimization-plan/plan/923/0923_技术方案.md` 与
> `0923_评审报告_三角色_v2.md`（三角色评审 + 逐行核对后的修订版补丁）。
> 全部改动为 bugfix / 接线级：不新增扫描能力、不改 Phase 结构。

### 任务生命周期（修 D5 / B1 / B1b / A1-A5）

- **T16 · 终态落库 + 存量回填**
  - `core/scan_store.py`：幂等 `ALTER TABLE` 迁移 `phase_status` / `fail_reason` /
    `resumable` / `resume_phase` 四列；新增 `set_terminal_state()` 与
    `mark_stale_running()`；`upsert_scan` 增加列白名单（未知 kwarg 不再抛 SQL 错）。
  - 保持 `finish_scan(task_id, metrics)` 签名不变（已被报告阶段与 `task_queue` 调用）。
  - `web/server.py` 启动钩子回填：实测 `scan_store.db` 中 **31 条** `running` 残留
    （最早 2026-07-31）→ 回填为 `failed`。修正前失败任务永久停在 `running`，
    导致仪表盘统计、「删除会话」护栏、续跑判定全部失去依据。
- **B1 · P3 熔断不再炸任务**：`core/browse_worker/_worker.py` 把
  `raise BrowseStuckError` 从 while 顶部（`try` 之外）移入 `try` 内，
  由既有 `except` 统一产出 `browse_worker_stuck`。修正前单组子 Agent 卡死
  = 整个任务 `task_failed(uncaught_exception)`。
- **B1b · 子 Agent 异常收敛**：`core/session/chat_loop.py` 消费端补
  `browse_worker_stuck` 分支 + 对 `worker.run()` 加 try/except（`CancelledError`
  原样上抛）。单组失败只标记 stuck，其余组与主流程继续。
- **T6' · 「继续」语义归一**：新增模块级 `_match_resume()`（前缀匹配 + 礼貌前缀剥离），
  统一原先**两套**互不一致的判定（idle 精确等值 / 非 idle 子串模糊）。
  实测「继续测试跑完这个流程」原先前后端都判不中 → 落 LLM intent → 任务 FAIL。
- **T6' · 断点续跑**：新增 `_infer_resume_stage()`（按 sitemap 已抓产物推断阶段）与
  幂等 `AdvancePhaseMixin._enter_phase(stage)`。修正前「继续」恒从 Phase 0 重爬，
  已抓的 94 API / 493 功能点被丢弃。
- **T5' · 暂停/停止两态**：`/api/stop` 支持 `mode=pause|stop`。`pause` 保留
  `session.phase` 并写 `resumable=1`（可续跑）；`stop` 置 `_resume_blocked`
  （不可续）。前端「继续」改绑 `resumeCurrentTask()`（续跑当前任务），
  不再调 `startScanFromHeader()`（那会新建会话、从 36 个目标里挑错目标）。
- **T7' · 状态接口补齐**：`/api/sessions/{id}/status` 返回五态 `status` /
  `resumable` / `resume_phase`（原先只有 `running: bool`，前端读 `status` 恒为
  `undefined`，逻辑穿透）。

### 结果可信度（修 D1 / D2 / D3 / D4 / D8 / T14）

- **T8 · 敏感发现内容校验**：`dir_scanner` 复用 `fast_scanner` 既有的
  `SENSITIVE_PATH_FINGERPRINTS` + `_verify_sensitive_path_content`（禁止造第三套）。
  验证器明确否定 → 丢弃（与 `_checks_server.py` 语义对齐）；仅 `content_match`
  记为 `confirmed`，弱证据降为 `medium + needs_review`。补 `.git/index` /
  `.svn/wc.db` / `WEB-INF/classes` 等缺失指纹 key。
- **T15 · 多簇兜底页判定**：`compute_catch_all_clusters()` 用 body_hash 簇证据
  （总数 ≥5、单簇 ≥3、占比 ≥60%）替代不可用的 `wildcard_detected` ——
  后者只要基线探测返回非 404 就为 True，拿它否决会对 SPA/WAF 目标造成大面积漏报。
  命中簇时目录类发现**整体降级**（不丢数据，可复核）。
- **T1 · 台账唯一写入入口**：新增 `core/session/dir_finding_store.py`。修正前
  正常 Phase 0 路径只 `yield` 到终端、从不写台账 → 终端 5 条 HIGH / 报告 0 漏洞。
  同时修掉原 `explore_mixin` 里 `try` 包住属性访问导致的**静默丢数据**。
  默认值改为 fail-safe（缺 `review_status` → `needs_review`）。
- **T8b · 报告第二消费点**：`core/sitemap/coverage.py::get_coverage_matrix()`
  原先零状态过滤直接把台账渲染成「🔴 DirScan 敏感发现」表格 → 即使
  `get_coverage()` 已过滤，报告矩阵仍会印误报。两个消费点统一走
  `core/sitemap/dir_findings.py::is_confirmed`。
- **T14 · 事件可审计**：`core/session/base.py::_event` 增加
  `data/logs/events.jsonl` 镜像（白名单，排除 message/thinking 等高频流式事件）。
  修正前终端"看得见"的发现服务端日志 0 命中，事后无法审计。
- **T9 · 终态语义分流**：`_normalize_terminal_event()` 把 `done` 收窄为
  五态事件；目标不可达 → `task_unreachable`（不再与"扫完确实没漏洞"同形）；
  有组未完成 → `task_partial`。`terminal_events` 集合同步登记新事件名。
- **T11 · 子 Agent 不再静默"完成"**：按 group 维度核算净产出，
  "有错误 + 零新增 API"判为未完成，不再伪装成 `✅ 完成（1 轮）`。

### LLM 韧性与前置检查（修 C1-C4 / B2 / B3 / B5）

- **T10 · 令牌桶限速**：`core/llm/_client.py` 新增进程级 `_TokenBucket`，
  按 `XUANJIAN_LLM_RPM` 强制最小调用间隔（3 RPM → 20s）；退避下限改为
  `max(Retry-After, 指数退避, 60/RPM)`。修正前退避下限仅 1s，对 3 RPM 的 key 形同虚设。
- **T12 · 开跑前模型健康检查**：新增 `core/llm/_preflight.py` +
  `POST /api/models/preflight`，并在 Phase 0 之前自动执行。阻断型
  （模型名 404 / 余额不足 / Key 失效）直接拦下且**不提示"可重试"**，
  避免爬完 95 个 JS 文件、493 个功能点后才炸。
- **B5 · 错误文案分型**：新增 `core/llm/_failure.py`（FOUNDATION 层）。
  修正前所有 LLM 失败统一提示「发送消息可重试」，而实测四次失败里三次是
  **配置性错误**（模型名 404 / 余额不足 39 次 / 组织 RPM 上限）。
- **B2 · 上下文超限文案自洽**：`ContextLimitError` 增 `available` 参数，
  打印真实可用输入预算。修正前打印 `context_window`，日志出现
  「估算 15832 tokens > 可用 32768」（15832 < 32768，报错本身不成立）。

### 安全与合规

- **新增 `core/redaction.py` 去标识化工具**：机构别名表 + 内网 IP / 凭据 /
  JWT / 邮箱 / 手机号正则，幂等；`redact_file` 对 `*.json` 强制"脱敏后仍须
  合法 JSON"，否则放弃写入。
- 实测修复既有违规：`data/notes/task_1790149459_b5c238-info.md` 含真实客户名
  「中信百信银行」→ 已脱敏；同批处理 93 个 notes / reports / sitemap 产物。
  `mcp_servers/note_mcp.py` 落盘前脱敏（这是违规的直接入口）。
- **`Sitemap.load()` 容错**：坏缓存不再抛异常穿透会话恢复链路（缓存是可丢弃派生物）。
- 已隔离 14 个在本次脱敏过程中被破坏的 sitemap 缓存
  （`*.corrupt-20260923`，保留可追溯），并修复 2 个本机目标的 `target` 字段。

### 工程门禁

- 新增 4 个测试文件（`tests/unit/test_sensitive_path_verify.py` /
  `test_resume_and_ledger_0923.py` / `test_scan_store_terminal_state.py` /
  `test_redaction_0923.py`），把「离线夹具复现 ics.aibank.com 双兜底页误报」
  变成可 CI 的断言；验收项 V15 从"重放真实站点"改为**不依赖网络**。
- 抽取 `core/dir_scanner/_finding_policy.py`：`_scanner.py` 953 → 789 行，
  满足仓库 800 行门槛（未使用豁免）。
- 分层契约（`scripts/layer_lint.py`）0 硬违反：共享纯逻辑下沉 FOUNDATION
  （`core/llm/_failure.py`、`core/sitemap/dir_findings.py`）。
- 全量回归：**2517 passed**；剩余 11 项失败均为环境所致（6 项需本地 HTTP 服务、
  3 项需 `fastapi`、1 项既有计时 flake），与本批改动无关。

---

## [Unreleased] — 2026-08-28 · 跨平台启动增强 (bugfix only)

> 仅工程性增强，**不影响** v2.0 封板承诺（无新功能、无 API 变更）。

### 跨平台启动

- 新增 `Makefile` — 跨平台等价命令 (`make install / run / doctor / scan / test / docker-up / clean`)
- 新增 `start.sh` — macOS / Linux 一键启动 (等价 `python start.py`)
- 新增 `start.command` — macOS Finder 双击启动 (拉起 Terminal 并执行)
- 新增 `start.ps1` — Windows PowerShell 启动器 (与 `launch.bat` 行为对齐)
- `start.py` 修正在非 Windows 上误报 `set PROXY_PORT=...` 提示的问题

### 文档

- README 重写为英文版 (面向国际开源贡献者)
- 保留原中文内容为 `README.zh.md`

---

## [v2.0] — 2026-08-18 · 封板版

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
