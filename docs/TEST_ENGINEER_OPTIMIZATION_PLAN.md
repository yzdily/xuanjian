# 玄鉴 XuanJian 全系统功能优化方案（测试工程师视角 · v3 全量复读）

> **视角**：以测试工程师身份，重读 `core/`（196 py，68,621 行）、`web/`（22 py，5,947 行，含 `web/api/` 18 文件）、`mcp_servers/`，并交叉分析运行日志 `data/logs/agent.log`、`coverage.xml`、`docs/zhenduan.txt`。
> **边界**：本文件为**新增交付物，只出方案、不改动任何现有代码**。所有问题均附代码/日志证据（file:line）。
> **依据快照**：2026-08-13 第三次全量复读（v2 之后，重点补齐 Web/API/认证/报告/持久化盲区，并订正 v2 路径与认证论断）。
> 与 `XUANJIAN_AI_OPTIMIZATION_PROMPT.md`、`docs/REDESIGN_AND_TESTING_PLAN.md`、`DEVELOPMENT_PLAN_AND_OPTIMIZATION.md` 互补，本文聚焦**功能正确性、安全合规、扫描有效性、测试可信度、可观测性**。

---

## 一、结论速览（健康度评分 · v3 修订）

| 维度 | 评分 | 一句话结论（相对 v2 的变化） |
|------|:---:|------|
| 功能正确性 | 🟡 B- | 日志 5 类崩溃多数已修复（带 `★ 修复`）；仅 `_client.py:385` 仍裸取值。均无回归守护 |
| **安全合规** | 🔴 D | **v3 新深挖盲区**：`save_report` 路径穿越、默认口令明文落日志、token 走 URL、未配 API_KEY 全免认证、开放注册——均已落地但零测试守护 |
| 扫描有效性 | 🟡 B | 空心扫描三连基本已修；`scan_store` 兜底补同步验证了"54 漏洞未同步 DB"的沉默丢失 |
| 测试可信度 | 🔴 D→C | `tests.yml` 已建但 `--cov-fail-under=70` 与实测 8.2% 脱节；**`web/api/` 全 18 文件 0% 覆盖**（v2 误写为 `core/web/api/`） |
| 系统健壮性 | 🟢 B | `producer()` 已防御式包裹；WAF 熔断、SSE 降级、LLM 重试齐备；但 `system_api/sessions_api/dashboard_api` 相对路径与全量重扫 sitemap 埋隐患 |
| 可维护性 | 🟢 B+ | 持续拆分；仍 2 个 >2000 行上帝文件（crawler_core 3521 / chat_loop 2201）+ 多模块全局态 |
| 可观测性 | 🟡 B- | **v3 修正**：仪表盘/漏洞聚合竟每次请求全量重扫 `data/tasks/*-sitemap.json`（O(n)、无缓存），与已建的 SQLite `scan_store` 目的相悖；`llm_usage.jsonl` 计量地基就绪 |

**总体判断（不变且更精确）**：团队大量投入" reactive 修 bug"（满屏 `★ 修复`），但**"修完不写测试"导致同类缺陷反复出现**；v3 进一步暴露——**Web/API 层是 0% 覆盖的安全黑盒**，且认证与路径处理存在数个可一次性利用的 concrete 漏洞。测试工程师的首要任务从"找 bug"转为**"把已修的固化、把没修的钉死、把 0% 覆盖的安全边界补上"**。

---

## 二、v3 复读关键修正（推翻/订正 v2 的旧论断）

| v2 方案中的论断 | v3 复读结论 | 证据 |
|------|------|------|
| "全部 17 个 `core/web/api/*.py` 是 0% 覆盖" | **路径写错**：真实路径是根级 `web/api/`（18 个 .py，含 `__init__.py`），coverage.xml 实锤 17 个 router 0% 覆盖 | `web/api/` 目录清单；`coverage.xml` `0 api/` 17 文件 |
| "默认 `admin/admin` 弱口令" | **已作废（#16 加固）**：默认密码改为"环境变量 > 持久化文件 > 启动随机 12 位"（`core/auth.py:85,358`）；仅当显式设 `PENTEST_DEFAULT_PASSWORD=admin` 才弱 | `core/auth.py:358-387,390-423` |
| "WAF/LLM 等是主要未知风险" | 这些已有兜底；**真正 0% 覆盖且带 concrete 漏洞的是 Web/API 层**（路径穿越、认证绕过、token 泄漏） | 见 §3.6 / §四.P0-4 |
| "可观测性地基就绪，升级 compare_runs 即可" | **修正**：仪表盘/漏洞列表每次请求都重扫全部 sitemap 文件（O(n)、无缓存），与已建 `scan_store`（SQLite 索引）目的相悖，规模化会劣化 | `web/api/dashboard_api.py:40`、`core/scan_store.py:246` |
| "全局态 18 文件/32 处" | 维持（grep 复核一致）；**新增 Web 层全局态**：`web/_state.STATE/_sessions/_pool`、`server._sse_connection_count`、`system_api._TARGETS_CACHE/_TARGETS_LOCK`、`auth._CACHE/_login_failures` | grep `^\s*global\s+` + 各文件 |

> 教训：v2 基于"静态快照+日志"推断，Web 层与认证实现未被真正精读，导致路径写错、认证论断过时。本方案所有状态均经 v3 源码实地逐文件复核。

---

## 三、证据基线（先看数据，再谈优化）

### 3.1 代码规模与巨型文件（可测性阻碍）

`core/`：196 个 .py，68,621 行；`web/`：22 个 .py，5,947 行（其中 `web/api/` 18 文件全部 0% 覆盖）；`tests/`：51 文件 / 15,617 行。

| 文件 | 行数 | 覆盖 | 说明 |
|------|:---:|:---:|------|
| `core/crawler/crawler_core.py` | 3521 | 0% | 6 个 mixin 巨型类，最该拆 |
| `core/session/chat_loop.py` | 2201 | 0% | 主循环 `chat`，按稳定性铁律保留但需抽纯函数 |
| `core/parallel/orchestrator.py` | 1498 | 0% | 抽了 `_orchestrator_helpers.py`(503) |
| `core/sitemap/feature_gen.py` | 1388 | 0% | sitemap/API 推测 |
| `core/fuzz/sqli.py` | 1271 | 0% | SQL 注入 |
| `core/parallel/batch_test.py` | 1033 | 0% | 并行测试执行 |
| ✅ `core/llm/`、`core/fast_scanner/`、`core/dir_scanner/`、`core/js_analyzer/`、`core/browse_worker/`、`core/supplemental_test_agent/`、`core/harm_validation/` | 已包化 | 部分高 | mixin 模式，可测性提升样板 |
| ⚠️ `web/server.py` + `web/api/*`（18 文件） | 539 + ~3500 | **0%** | **安全黑盒**：认证/路径/导出全在盲区 |

### 3.2 覆盖率分布：幻觉缩小但未消失（8.2%）

`coverage.xml`：`lines-valid=37406`，`lines-covered=3074` → **行覆盖 8.2%**；`branches-covered=13/15284` → **分支覆盖 0.085%**。

| 高/中覆盖（可作门禁锚点） | line-rate | 零覆盖（系统主干） | line-rate |
|------|:---:|------|:---:|
| `xss/models.py` | 96.5% | **`web/api/*`（17 router）** | **0%** |
| `dir_scanner/_models.py` | 94.2% | `analyze_worker.py` / `auto_crawler.py` | 0% |
| `diff/models.py` | 94.0% | `browse_worker/*`（4 文件） | 0% |
| `fast_scanner/_models.py` | 93.5% | `business_understanding.py` / `vision.py` | 0% |
| `tools.py` | 83.3% | `crawler_core / chat_loop / orchestrator / sqli` | 0% |
| `config.py` | 66.3% | `server.py` / `web/_state.py` | 0% |
| `log.py` | 69.0% | `replay/*` / `crypto_replay/*` / `poc_generator.py` / `port_scanner.py` | 0% |

> 诊断：编排层、会话主循环、爬虫、**全部 Web API（17 router）+ 认证/导出 + 新增生存工具（poc_generator/port_scanner/credential_injector/crypto_engine）**——即"能不能挖到洞 + 能不能安全运行 + 能不能防住别人打这台工具"——全是 0%。分支覆盖 0.085% 尤其危险：`except` 分支（含已"修复"的崩溃分支）几乎没被测。

### 3.3 日志实锤缺陷的**当前真实状态**（核心交付）

重读源码逐一核对 `agent.log` 的 5 类崩溃 + 空心扫描：

| # | 缺陷（日志证据） | 当前源码状态 | 结论 | 回归测试缺口 |
|---|------|------|:---:|------|
| 1 | `server.producer`：`cannot access local variable 'os'` | `web/server.py:417` 的 `producer()` 已用 `try/except` 包裹 `session.chat()`，异常转 `task_failed` 事件，**不再裸崩**；`crawler_core.py:1418` 条件内 `import os` 仍是潜伏根因 | 止血✅ / 根因⚠️ | 条件内 import 失败路径测试 |
| 2 | `_advance_phase() missing 'summary'` | 两处调用都传 `summary`：`advance_mixin.py:82`、`chat_loop.py:879/2155`（带 `★ 修复`） | **已修复✅** | 无签名契约测试 |
| 3 | `ScanStrategyConfig` 缺 `crawl_timeout` | `scan_strategies.py:454` 已补（带 `★ 修复`） | **已修复✅** | 无字段完备性测试 |
| 4 | `_effective_max_workers` 未定义 | `orchestrator.py:139` 已实例化为属性，使用点均在其后 | **已修复✅** | 无并发冒烟测试 |
| 5 | `'str' object has no attribute 'choices'` | `_client.py:385` 仍 `resp.choices[0]` **无类型守卫**；日志 48 次"降级为空"印证仍会崩 | **部分修复⚠️** | 注入 str/空响应防御式测试 |
| 6 | 空心扫描：mitmproxy 挂→API=0 被 ✅ 伪装 | FAST SKIPPED 已被静态资源过滤修复；dirsearch 已包化并接入补测；✅ 误导已修正为 ⚠️ | 基本修复✅ | 空心扫描端到端断言 |
| 7 | 表单接口从不进 Phase 2 | `form_api_bridge` **已接入** `chat_loop.py:1167-1168` | **已修复✅** | 仅函数级测试，缺链路级 |

**关键洞察**：4/5 崩溃已修、1/5 部分修；空心扫描基本闭环。但**零回归测试**——下次重构随时回退。这是测试工程师最该补的"信任底座"。

### 3.4 运行日志画像（`agent.log`，WARNING 占比仍 ~19%）

高频 WARNING（归一化）：WAF 降速 2680 次、replay 超 100MB 静默丢 655 次、LLM 非标准 SSE 降级 535 次（为空 48）、连接重试 44、模型名纠正 ~76、tool_router 异常 28×3、未授权检测跳过 21、Token 超限 13。

### 3.5 全局可变状态审计（可测性头号敌人）

`grep "^\s*global "`：**18 个文件 / 32 处全局声明**。最危险：`core/skill_registry.py:5`、`core/task_queue.py:4`、`core/captcha_solver.py:3`、`core/replay/register.py:2`、`core/memory.py:2`、`core/fuzz/registry.py:2`、`core/crypto_replay/register.py:2`、`core/auth.py:2`、`core/scan_store.py:39`。**Web 层新增**：`web/_state.STATE/_sessions/_pool`、`web/server.py:_sse_connection_count`、`web/api/system_api.py:_TARGETS_CACHE/_TARGETS_LOCK`、`core/auth.py:_CACHE/_login_failures`——并发任务下存在跨任务串扰与写竞争，且让单元测试无法隔离。

### 3.6 ⚠️ v3 新增：Web/API 安全与持久化审查（0% 覆盖黑盒）

v3 首次逐文件精读 `web/` 与 `core/auth.py` / `core/scan_store.py`，发现以下 concrete 问题（均 0% 覆盖、无测试守护）：

| # | 问题 | 证据（file:line） | 严重度 | 状态 |
|---|------|------|:---:|------|
| S1 | **路径穿越写文件**：`save_report` 取 `task_id` 后**未校验**，直接 `_save_report_file(task_id, ext, content)` → `REPORTS_DIR / f"{task_id}_report.{ext}"`；`task_id="../x"` 可逃逸 `data/reports/`。同文件 `delete_report:382` 反而校验了 `_validate_task_id`，不一致 | `web/api/reports_api.py:394-408, 692-697` | **高** | 待修+测试 |
| S2 | **未配 API_KEY 时全 `/api/*` 免认证**：`server.py:260-267` 当 `XUANJIAN_API_KEY` 为空，仅"有 token 则校验"，无 token 直接放行——部署若漏配即全接口裸奔 | `web/server.py:220,260-267` | **高** | 待修+测试 |
| S3 | **Token 泄漏到 URL/日志**：`_extract_token` 优先读 `query.token`（`auth_api.py:42`）；token 经 URL 进入访问日志，与 zhenduan"明文打印敏感字段"同源 | `web/api/auth_api.py:42` | 中 | 待修+测试 |
| S4 | **默认管理员密码明文落日志/终端**：`init_default_user` 把随机生成的默认密码 `print(banner)` 且 `log.warning(...)`（`auth.py:413-423`）；凭证进入日志违反合规 | `core/auth.py:413-423` | 中 | 待修（仅提示查文件，不打印密码） |
| S5 | **开放注册无默认门禁**：`register` 仅在 `XUANJIAN_DISABLE_REGISTER=1` 时关闭（`auth.py:268`）；未设则该安全工具任何人可自建账号 | `core/auth.py:252,268` | 中 | 配置建议+测试 |
| S6 | **相对路径依赖 CWD（与绝对路径实现不一致）**：`system_api.py:231/270/294/298/330`、`sessions_api.py:96/148/156`、`dashboard_api.py:31` 用 `Path("data/...")`；而 `reports_api.py:26-28`、`scan_store.py:22-23`、`auth.py:39-40` 用项目根绝对路径。服务从非根目录启动 → 目标/会话/仪表盘读写错位，且测试 fixture 难固定 | 多文件 | 中 | 待修（统一绝对路径）+测试 |
| S7 | **仪表盘/漏洞聚合每次 O(n) 全量重扫 sitemap**：`dashboard_api.py:40` `for f in tasks_dir.glob("*-sitemap.json")` 每次请求遍历并 JSON 解析全部任务文件；`scan_store.list_all_vulns:246` 同样兜底全扫。与已建 SQLite `scan_store`（索引层）目的相悖，无缓存，任务数增长后劣化 | `web/api/dashboard_api.py:40`、`core/scan_store.py:246` | 中 | 待修（走 DB+缓存）+测试 |
| S8 | **batch task_id 用 `hash(url)` 非确定**：`scan_all_targets` 用 `f"batch_{time}_{hash(url)%10000}"`（`system_api.py:308`），`hash()` 受 PYTHONHASHSEED 影响跨进程不确定，且易碰撞 | `web/api/system_api.py:308` | 低 | 待修（用 uuid）+测试 |
| S9 | **上传无大小上限**：`csv_upload_targets` `await file.read()` 一次性读全量（`system_api.py:452`），超大文件打爆内存 | `web/api/system_api.py:439-464` | 低 | 待修（限流/流式）+测试 |

> 认证层已做的不错（PBKDF2+per-user salt、HS256 持久化密钥、`hmac.compare_digest` 常量比较、登录 5 次/5 分限速、默认密码随机化、注册可关闭）——**缺陷在"边界处理与配置默认值"，不在算法**。这正是测试应重点覆盖处。

---

## 四、P0 · 必须先做（固化已修 + 钉死安全黑盒 + 真门禁）

> 原则：**先红后绿**——每条先写会失败的 pin 测试，再确认修复成立。测试收拢至新建 `tests/regression/`（pin 防回归）与 `tests/integration/test_web_security.py`（Web 安全）。以下所有 file:line 均经 v3 源码实地复核。

### P0-1　为"已修复的缺陷"补"红→绿"回归测试（最高 ROI）
逐项对照 §3.3，为每个 `★ 修复` 点补一条永久防回归 pin 测试：

| 已修缺陷 | 证据（file:line，已复核） | pin 测试断言 |
|---|---|---|
| `_advance_phase(summary)` 签名 | `core/session/advance_mixin.py:85`（+ `chat_loop.py:879/2155`） | 调用 `_advance_phase(summary="")` 不抛 `missing 'summary'`；签名契约测试锁死必传 `summary` |
| `ScanStrategyConfig.crawl_timeout` 字段 | `core/scan_strategies.py:454`（FAST=180 / `:103,:130`；默认 300） | `ScanStrategyConfig().crawl_timeout` 存在且为 int；FAST 实例 `==180` |
| `_effective_max_workers` 实例化 | `core/parallel/orchestrator.py:139` | 编排器构造后属性存在且 ≤ `MAX_WORKERS`；并发冒烟不抛 NameError |
| `form_api_bridge` 接入 Phase 2 | `core/session/chat_loop.py:1167`（`register_form_apis`） | **链路级**：表单接口站点扫描后 Phase 2 被触发（非仅函数级） |
| `'str'.choices` 部分修复 | `core/llm/_client.py:385`（仍裸取 `resp.choices[0]`） | 见 **P1-2**：注入 str/空响应不崩，降级 + `is_error=True` |

**落地**：新建 `tests/regression/`，将散落的 `test_advance_mixin` / `test_scan_strategies` / `test_hollowing_completion_fix` / `test_login_route_regression` / `test_log_driven_optimizations` / `test_resume_after_stuck` / `test_race_condition` 收拢于此；每个日志 ERROR / 每个 `★ 修复` 对应一条"先红后绿"。

### P0-2　让 CI 门禁"真实生效"
**现状**：`.github/workflows/tests.yml:42` 设 `--cov-fail-under=70`，`pyproject.toml:100` `fail_under=0`，实测 8.2% → 每次 CI 必红、被绕过。

**改法（分层门禁，替换单一 70% 地板）**：
1. **目录级门禁 ≥90%**——已达标的高覆盖包（`xss/models.py` 96.5%、`dir_scanner/_models.py` 94.2%、`diff/models.py` 94.0%、`fast_scanner/_models.py` 93.5%）锁死不回退；按包设分阈值。
2. **diff-coverage ≥80%**——接入 `diff-cover`：`pytest --cov --cov-report=json:coverage.json` 后 `diff-cover coverage.json --compare-branch=origin/main --fail-under=80`，只卡 PR 新增/改动行，杜绝"改了不测"。
3. **全局地板 ratchet**——`fail_under` 从实测基线 8 起步，阶梯 8→20→40→70，每轮提一档而非一步到位。
4. **source 相对路径**——`coverage.xml` 的 `source` 改相对路径，CI 与本地一致。

### P0-3　钉死"空心扫描"剩余风险
**已落地 ✅**：dirsearch 接入补测、`✅`→`⚠️` 误导修正、mitmproxy 不可用时 Playwright 兜底。
**补**：端到端断言——"代理不可用 → 兜底仍产流量且告警 ⚠️"锁死；断言 `DirectoryScanner` 在补测流程被调用（grep 调用点存在）。

### P0-4 ⚠️ v3 新增　Web/API 安全加固（0% 覆盖黑盒，concrete 漏洞）
按 §3.6 优先级，每项"修 + 测试"配对，全部纳入新建 `tests/integration/test_web_security.py`（FastAPI `TestClient` + 临时 `data/` 目录，绕过全局态）：

| # | 问题 | 证据（已复核） | 改法 | 测试断言 |
|---|---|---|---|---|
| S1 | 路径穿越写文件 | `web/api/reports_api.py:394-410`（`save_report` 未校验 task_id）、`:692-697`（`_save_report_file` 直拼路径）；对照 `delete_report:382` 已校验 | `save_report` 接入已有 `_validate_task_id`（`:35`，正则 `^[a-zA-Z0-9_\-]+$`） | `task_id="../../../etc/x"` 返回 400 且文件未写出 `data/reports/` 之外 |
| S2 | 未配 API_KEY 时全 `/api/*` 免认证 | `web/server.py:260-267`（`else` 分支无 token 直接放行） | 未配 `XUANJIAN_API_KEY` 时默认拒绝业务接口；或至少启动醒目告警 + 文档强制 | 无 Key 调用 `/api/scans` 返回 401 |
| S3 | token 走 URL/日志 | `web/api/auth_api.py:42`（`query.token`） | 移除 `query.token` 提取，仅保留 Authorization 头 + cookie | 请求 `?token=x` 不被 `_extract_token` 采纳 |
| S4 | 默认密码明文落终端 | `core/auth.py:413-423`：`print(banner)` 含明文 `password`（⚠️ `log.warning:423` 仅记用户名、不泄密——改 `print` 即可） | `init_default_user` 不再 `print` 明文密码，改为提示"密码见 `data/.default_password`" | 捕获 stdout/日志，断言不含明文密码串 |
| S5 | 开放注册无默认门禁 | `core/auth.py:268`（默认 `"0"`=开放；密码最低 8 位 `:265` 已加固） | 文档默认 `XUANJIAN_DISABLE_REGISTER=1`；可选启动告警 | 未设开关时可注册、设 `1` 时拒（双态测试） |

**验收**：`tests/integration/test_web_security.py` 全绿；S1 路径穿越、S2 免认证、S3 token 泄漏三类高危被锁死。

---

## 五、P1 · 稳健性、一致性、可扩展性

### P1-1　WAF 对抗策略化 + 指标化（日志第一噪声源 2680 次）
**现状 ✅**：绕过能力已具备（`core/fuzz/waf_bypass.py` `WAFBypassFuzzer`）。
**改法**：命中率 / 降速时长 / 封禁中止纳入结构化任务级指标；命中后按目标维度动态收敛 payload。
**测试**：稳定拦截 mock 目标，断言 N 次内收敛。

### P1-2　LLM 层健壮性（重点修 `_client.py:385`）
**证据（已复核）**：`core/llm/_client.py:385` `choice = resp.choices[0]` 仍无类型守卫；日志 48 次"降级为空"印证非标准 SSE 会崩。
**改法**：
- `_parse_sse_chat_payload` 返回非对象 / 空时降级为安全空响应 + `is_error=True`，而非裸取 `.choices[0]`；
- 录制各供应商真实 SSE 为 golden fixtures（`tests/fixtures/llm_sse/*.txt`）；
- 模型名纠正启动时 prominent 打印 wrong→correct 映射。
**测试**：注入 str / 空 SSE → 不抛 AttributeError，返回 `is_error` 响应。

### P1-3　决策回放数据丢失（replay 超 100MB 静默丢 655 次）
**证据（已复核）**：`core/replay/store.py:29` `MAX_SCRIPT_SIZE=100MB` 单文件硬截断，无分片。⚠️ per-run_id 重复告警去重**已完成**（`:37` `_size_warned_runs`），但截断本身仍丢数据。
**改法**：分片 / 滚动写入（`script_001.jsonl`…）+ 关键帧采样压缩。
**测试**：构造超大任务回放，断言首尾关键帧不丢。

### P1-4 ⚠️ v3 新增　路径一致性 + 仪表盘可扩展性

| # | 问题 | 证据（已复核） | 改法 | 测试 |
|---|---|---|---|---|
| S6 | 相对路径依赖 CWD | `system_api.py:230/255/293`、`sessions_api.py:96/148/156`、`dashboard_api.py:31`、`scan_store.py:237` 用 `Path("data/...")`；而 `reports_api.py:26`、`scan_store.py:22`、`auth.py:39` 用项目根绝对路径 | 统一为共享 `_PROJECT_ROOT`（`Path(__file__).resolve().parents[...]`），消除 CWD 依赖 | 非根目录启动 fixture，断言读写落对位置 |
| S7 | 仪表盘 O(n) 全量重扫 sitemap | `dashboard_api.py:40`（每次请求遍历 `*-sitemap.json` 并 JSON 解析；⚠️ 已从 3x 合并为 1x 但仍无缓存）；`scan_store.list_all_vulns:246` 同样兜底全扫 | 优先读 SQLite `scan_store`（索引层已建），仅对"未同步 DB 的 sitemap"兜底；结果加 30s TTL 缓存 | "1000 任务下 `/api/dashboard/stats` 延迟 < X"性能测试 |
| S8 | batch task_id 用 `hash(url)` 非确定 | `system_api.py:307`（`hash(url)%10000`，受 PYTHONHASHSEED 影响、跨进程不定且易碰撞） | 改 `uuid4().hex[:8]` 或确定性 `sha1(url)[:8]` | 跨进程同 url 生成同 task_id |
| S9 | 上传无大小上限 | `system_api.py:452`（`await file.read()` 一次性读全量） | 加 `Content-Length ≤ 10MB` 校验 + 流式解析 | 超限上传返回 413 |

### P1-5　巨型文件按"出错路径"优先拆分
剩 2 个 >2000 行：`crawler_core.py` 3521、`chat_loop.py` 2201。先抽"出过 bug 的纯函数"（阶段判断、模式选择、预算计算、响应解析）下沉为可单测单元；遵守稳定性铁律——`chat_loop` 主循环保留，仅抽周边纯函数。

---

## 六、P2 · 可观测性、全局态、合规收尾

| # | 项 | 锚点 / 说明 |
|---|------|------|
| 1 | 全局可变状态收敛（18 文件/32 处 + Web 层 `_sessions`/`STATE`/`_sse_connection_count`/`_TARGETS_CACHE`） | `core/di.py` 已建 `register_resetter`/`reset_singletons`；剩余单例逐个迁移为注入/容器，解锁并行测试 |
| 2 | 生产/测试日志分离 | `agent.log` 混入 pytest 噪声；测试用独立 logger |
| 3 | 结构化任务级指标看板 | 复用 `core/log.py` metrics + `scripts/compare_runs.py` 升级为回归护栏（新版 vs 基线 API/漏洞数不得显著回退）|
| 4 | 计量地基复用 | `llm_usage.jsonl`（caller 级 token 成本）补租户隔离与结构化导出 |
| 5 | 安全合规（脱敏 + 加固收尾） | S3/S4 已入 P0-4；补充：日志默认脱敏 OAuth state / 内网域名 / 密码；`web/_state` 多 session 隔离需验证无串扰 |
| 6 | 文档与代码对齐 | README 批处理/实时/包测 与 `ScanMode` 正交维度矩阵已同步，补"入口"第三维 |

> P2-1（全局态）是单元测试隔离与并行化最大障碍，高价值；P2-3/4 是 Cloud 化前置，可优先于 P2-2/5。

---

## 七、测试体系升级（核心交付）

### 7.1 目标测试金字塔
| 层 | 目标占比 | 覆盖对象 | 关键技术 |
|----|:---:|------|------|
| 单元 70% | FP 铁律、归一化、时间盲注二次复现、XSS 上下文、配置推导、去重/优先级、`_advance_phase` 契约、`ScanMode` 序列化 | pytest+参数化+hypothesis；冻结 clock/random |
| 集成 20% | FastScanner 对 mock HTTP 靶标、**Web 安全（P0-4 的 S1-S5）**、表单桥接链路、dirsearch 补测、LLM 适配器对录制 SSE、代理兜底、全局态注入隔离 | `FastAPI TestClient` + 临时 `data/` + golden fixtures |
| 端到端 10% | 完整链路对漏洞靶场（DVWA/Juice Shop/Docker）+ "已知干净"目标零严重误报 | Docker Compose + Golden Report 比对 |

### 7.2 日志驱动回归语料库（放大 `tests/test_log_driven_optimizations.py`）
原则：**"日志里出现过的每一个失败，都必须有一个测试守着它不再出现。"** 当前散落 `test_advance_mixin`/`test_scan_strategies`/`test_hollowing_completion_fix`/`test_login_route_regression`/`test_log_driven_optimizations`/`test_resume_after_stuck`/`test_race_condition` → 收拢至 `tests/regression/`；**新增 `tests/integration/test_web_security.py` 覆盖 §3.6 全部 S1-S5**。

### 7.3 DoD（可量化）
- 任一 `★ 修复` 注释点 → 必补回归测试锁死（**P0-1 表 + P0-4 的 S1-S5 即首要清单**）。
- 任一 PR：ruff 通过、快测全绿、**diff-coverage ≥ 80%**、高覆盖 domain 目录级 ≥ 90%、不新增全局可变运行时状态、Web 安全测试全绿。
- 任一线上 ERROR/空心扫描/路径穿越 → 先补 pin 测试（红），再修（绿）。

---

## 八、优先级 × 工作量矩阵

| 优化项 | 优先级 | 工作量 | 风险 | ROI |
|------|:---:|:---:|:---:|:---:|
| **P0-4 Web/API 安全加固（S1 路径穿越/S2 免认证/S3 token/S4 密码日志/S5 注册）** | **P0** | 中 | 低 | ⭐⭐⭐⭐⭐ |
| P0-1 为已修缺陷补回归测试 | P0 | 小-中 | 低 | ⭐⭐⭐⭐⭐ |
| P0-2 CI 门禁真实生效 | P0 | 小 | 低 | ⭐⭐⭐⭐⭐ |
| P0-3 空心扫描端到端断言 | P0 | 中 | 中 | ⭐⭐⭐⭐ |
| P1-1 WAF 策略化+指标化 | P1 | 中 | 中 | ⭐⭐⭐⭐ |
| P1-2 LLM `_client.py:385` 防御 + SSE golden | P1 | 中 | 低 | ⭐⭐⭐⭐ |
| P1-3 Replay 分片写入 | P1 | 中 | 低 | ⭐⭐⭐ |
| P1-4 路径一致性(S6)+仪表盘 DB/缓存(S7)+task_id(S8)+上传限流(S9) | P1 | 中 | 低 | ⭐⭐⭐⭐ |
| P1-5 巨型文件按出错路径拆分 | P1 | 大 | 中 | ⭐⭐⭐ |
| P2 全局态收敛 + 日志分离 + 指标看板 + 计量复用 + 合规 | P2 | 中-大 | 低 | ⭐⭐⭐⭐ |

---

## 九、分阶段路线图

- **Sprint 1（安全黑盒 + 真门禁）**：P0-4（S1-S5 修复+测试）、P0-2（目录级≥90% + diff-cov≥80% + ratchet）、P0-1（4 类已修崩溃 + ScanMode + 表单桥接 pin 测试）。产出：Web 层 concrete 漏洞封死，CI 红灯可拦截。
- **Sprint 2（救剩余空心 + 路径/可扩展）**：P0-3 端到端断言；P1-4（S6 绝对路径统一、S7 仪表盘走 DB+缓存、S8/S9）。
- **Sprint 3（提稳健）**：P1-1/1-2/1-3。产出：WARNING 占比下降，回放完整，LLM 不再裸崩。
- **Sprint 4（固可测 + 全局态）**：P1-5 拆 crawler_core/chat_loop；P2 全局态收敛 + 指标看板 + 合规脱敏。产出：主干覆盖爬升，测试可隔离。

---

## 十、可量化验收标准

- [ ] §3.3 的 4 类已修崩溃 + ScanMode + 表单桥接，各有 pin 回归测试（先红后绿）。
- [ ] `tests.yml` 生效且**不每次必红**：目录级 ≥90% 通过、diff-coverage ≥80% 通过、ratchet 可见。
- [ ] **`tests/integration/test_web_security.py` 全绿**：S1 路径穿越被拒、S2 无 Key 调用业务接口返回 401、S3 无 query.token 提取、S4 日志不含明文默认密码、S5 注册门禁双态。
- [ ] 单登录页/SPA 站点：登录/表单接口进 Phase 2；`DirectoryScanner` 在补测流程被调用（grep 调用点存在）。
- [ ] `agent.log` 中 `'str'.choices` 不再出现；非标准 SSE 降级为空有明确告警。
- [ ] WAF/replay/SSE 三类 WARNING 纳入结构化指标并可对比；**1000 任务下 `/api/dashboard/stats` 延迟有上限（走 DB+缓存）**。
- [ ] 靶场端到端：漏洞检出率 ≥ 基线；"已知干净"目标零严重误报。
- [ ] 生产日志与测试日志物理分离；全局可变状态收敛至 <10 处（或注入/单例容器），解锁并行单测。

---

## 附：证据索引

| 证据 | 位置 / 数据 |
|------|------|
| 覆盖率 | `coverage.xml`：line-rate 8.2%（3074/37406），branch 0.085%（13/15284） |
| **Web API 路径（v3 订正）** | 真实为根级 `web/api/`（18 .py，17 router 0% 覆盖）；**非** v2 写的 `core/web/api/` |
| CI 门禁 | `.github/workflows/tests.yml:42` `--cov-fail-under=70`；`pyproject.toml` `fail_under=0` |
| 已修崩溃 | `_advance_phase` `chat_loop.py:879`/`advance_mixin.py:82`；`crawl_timeout` `scan_strategies.py:454`；`_effective_max_workers` `orchestrator.py:139` |
| 部分修复 | `'str'.choices` `core/llm/_client.py:385` 无守卫 |
| **S1 路径穿越** | `web/api/reports_api.py:394-408`（save_report 未校验）、`692-697`（`_save_report_file` 拼路径）；对照 `delete_report:382` 已校验 |
| **S2 免认证** | `web/server.py:220,260-267`（无 API_KEY 时 `/api/*` 放行） |
| **S3 token 泄漏** | `web/api/auth_api.py:42`（`query.token`） |
| **S4 密码日志** | `core/auth.py:413-423`（`print(banner)` + `log.warning` 明文密码） |
| **S5 开放注册** | `core/auth.py:252,268`（`XUANJIAN_DISABLE_REGISTER`） |
| **S6 路径不一致** | 相对：`system_api.py:231/270/294/298/330`、`sessions_api.py:96/148/156`、`dashboard_api.py:31`；绝对：`reports_api.py:26-28`、`scan_store.py:22-23`、`auth.py:39-40` |
| **S7 仪表盘 O(n)** | `web/api/dashboard_api.py:40`、`core/scan_store.py:246` |
| **S8 task_id** | `web/api/system_api.py:308`（`hash(url)%10000`） |
| **S9 上传不限** | `web/api/system_api.py:439-464` |
| 默认口令（v3 订正） | 已随机化：`core/auth.py:85,358-387`，**非** v2 的 admin/admin |
| 全局态 | 18 文件 / 32 处 `global`（grep `^\s*global\s+`）+ Web 层 `_sessions`/`STATE`/`_sse_connection_count`/`_TARGETS_CACHE` |
| 巨型文件 | crawler_core 3521 / chat_loop 2201 / orchestrator 1498 / feature_gen 1388 / sqli 1271 / batch_test 1033 |
| 日志噪声 | WAF 2680 / replay 655 / SSE 降级 535（空 48）/ 重试 44 / 模型名 76 |
| 计量地基 | `llm_usage.jsonl`（caller 级 token 成本） |
| 可复用资产 | `tests/test_log_driven_optimizations.py`、`tests/unit/test_form_api_bridge.py`、`scripts/compare_runs.py`、`core/llm/`、`core/fast_scanner/`（已包化） |
