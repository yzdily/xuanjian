# 玄鉴 XuanJian · 开发方案与优化建议（v4.1）

> 版本：v4.1 ｜ 日期：2026-08-14 ｜ 状态：基于**第四次通读全部源码 + 日志 + 诊断文档**实证（**未改动任何源码**）；v4.1 按工作区实测校准上帝文件行数与文件锚点
> 阅读对象：产品/技术负责人、开发团队
> 演进：v1（初版）→ v2（复读修正 6 处）→ v3（重构落地后重读）→ **v4（本轮 P0 基本清零后的收口）** → v4.1（度量校准）。每一次均重读度量，不凭记忆。
> 一句话结论：**工程治理类 P0 已全部落地，产品正确性（空心化）已实质性修复；剩余风险从"缺能力"转为"没接线 / 没提交 / 没验证"——这是 v4 与之前最大的不同。**

---

## §0 v4 相对 v3 的关键变化（本轮实测）

| 维度 | v3 结论 | v4 实测 | 判定 |
|---|---|---|---|
| CI 测试门禁 | `tests.yml` 缺失、`fail_under=0` 假门禁 | **`.github/workflows/tests.yml` 已建，`pytest -m "not slow and not e2e and not llm" --cov-fail-under=70`** | ✅ 已落地（但见 §4 新风险） |
| 提示词单源 `_common.md` | 缺失 | **已建**（`core/prompts/_common.md`，含 5 条铁律）；`load_prompt(name, with_common=)` 机制就绪 | ⚠️ 已建**未采纳**（0 调用方传 `with_common=True`，11 处仍内联） |
| `ScanMode` 云序列化 bug | 普通 `Enum`，`== "fast"` 恒 False | **已改为 `class ScanMode(str, Enum)`**，含兼容性说明 | ✅ 已修复 |
| 产品正确性（空心化·表单桥接） | `register_form_apis` 草稿未接线 | **已接入 `chat_loop.py:1167`**，并加 SEC-3 守卫防"✅ 伪装" | ✅ 已修复 |
| 空心化检测/报告告警 | 仅 FAST SKIPPED bug 降级 | `core/session/report_mixin.py` 新增 `_compute_real_completion` / `_detect_hollowing` / 告警 markdown；`core/report_templates.py` 加空心化告警段 | ✅ 已落地（未提交） |
| 安全降级开关散落 | "散落未修" | 仅 `auth.py:268` 一处 `XUANJIAN_DISABLE_REGISTER` 环境变量 | ✅ 已收敛为单点 |
| 上帝文件 | 2 个（crawler_core 3521 / chat_loop 2201） | 仍是 2 个；**工作区实测 crawler_core 3,265 / chat_loop 2,038**（chat_loop 较 HEAD 1,873 反增 +165） | ⚠️ 拆分停滞 |
| 全局可变状态 | 31 处 / 18 文件 | **32 处 / 18 文件**（不降反升 1） | ❌ 未治理 |
| 测试用例数 | 1,092 | **1,145**（+53） | ✅ 增长 |
| 工作区提交状态 | 大量未提交在途重构 | **145 个文件未提交**（含全部好改动） | ❌ 高风险（见 §4） |

> 最大转折：v1→v3 我们在"补能力"（拆文件、建门禁、修 bug）；v4 起能力已具备，**瓶颈变成"接好线、提交掉、验证过"**。

---

## §1 项目量级（精确度量，v4）

| 模块 | 文件数 | 总行数 | 备注 |
|---|---:|---:|---|
| core | 196 | 68,626 | 较 v3 微降（68,910→68,626） |
| web | 22 | 5,947 | — |
| mcp_servers | 9 | 3,946 | — |
| tests | 51 | 15,617 | 用例 1,145 |
| **合计（含测试）** | **278** | **94,136** | — |

**上帝文件（>1500 行）仅剩 2 个**（演进：v1 文档称 7 → v2 实测 6 → v3 2 → v4 仍 2）：

| 文件 | 行数 | 结构特征 |
|---|---:|---|
| `core/crawler/crawler_core.py` | 3,265 | `AutoCrawler(LoginMixin, ScopeMixin, UrlFilterMixin, FormMixin, ResultBuilderMixin, SPAMixin)` —— 已 mixin 化，主类仍是巨石 |
| `core/session/chat_loop.py` | 2,038 | `ChatLoopMixin` 单一大类，Agent 主循环全在此；**未提交改动使其较 HEAD(1,873) 反增 +165** |

> 注：行数为**工作区实测**（含 145 个未提交文件）；v3 沿用值（3,521 / 2,201）已偏移，v4.1 校准。

**全局可变状态**：18 个文件 **32 处 `global` 声明**（v2 31 → v4 32，未减）。分布：`auth / skill_registry / false_positive_manager / scan_store / task_queue / memory / fuzz(base/concurrent/registry) / replay(recorder/register) / crypto_replay/register / diff/register / poc_generator / compliance_report / captcha_solver / asset_mapping / xss/oob`。

**内联 prompt**：11 个 `.py` 仍含 `你是一个/你是一名/system_prompt=`（`business_understanding / harm_validation/exploit / harm_validation/validator / parallel/grouping / prompts/phases / realtime_worker / reconcile / vision / worker_agent/_helpers / xss/llm_judge / xss/waf_bypass`）。其中 `exploit.py`、`vision.py`、`xss/llm_judge.py` 属安全分析类，**应外置并前置铁律**。

---

## §2 架构现状与问题（代码实证）

### 2.1 上帝文件：拆分基本完成 ✅（剩 2 个停滞）
`fast_scanner.py / llm.py / js_analyzer.py / browse_worker.py / supplemental_test_agent.py / worker_agent.py` 已全部删除并包化。`orchestrator` 已 trimmed 至 <1500 行。剩 `crawler_core`(3,265) 与 `chat_loop`(2,038) 未拆分 —— 二者拆分缝已就绪（crawler_core 已是 mixin 组合；chat_loop 可按 phase 拆 handler），属"临门一脚"。

### 2.2 全局可变状态（未去，32 处）❌
仍是**最深的结构性欠债**。每次"改核心逻辑无回归守护"的带病上线风险都源于此（`hollowing-optimization-plan/优化.txt` 即教训）。`metrics` 单例也已封入 `core/llm/__init__.py`（导入即创建），结构好了全局态没去。

### 2.3 模式术语不一致（云序列化 bug）✅ 已修
`ScanMode` 改 `str, Enum`，`ScanMode.FAST == "fast"` 现为真、可原生 JSON 序列化。云多进程/计量场景的静默比较失效已消除。

### 2.4 提示词散落（机制就绪，采纳为 0）⚠️
`core/prompts/` 已建单源加载器 + `_common.md` 铁律。但：
- `load_prompt(name, with_common=False)` **默认不前置铁律**，且**0 个调用方传 `with_common=True`**；
- 11 处 prompt 仍内联（含安全分析类）。
→ 铁律目前**形同虚设**，未真正接管任何提示词。这是"建好没用上"的典型。

### 2.5 测试门禁：真门禁已建 ✅（但见 §4 风险）
`tests.yml` 覆盖 `push/PR → main`，排除 `slow/e2e/llm` 标记，`--cov-fail-under=70`。`pyproject` 的 `fail_under=0` 现为**刻意本地宽松默认**，由 CI 强制 70 —— 这是合理模式，v2/v3 的"假门禁矛盾"已消解。

### 2.6 日志 / 可观测性（地基好，缺口明确）⚠️
`llm_usage.jsonl`（5,539 条）已含 **caller 级 token 成本**（`call_id/model/input_output_tokens/elapsed/caller/is_error`），是 Cloud 计量的现成地基。缺口仍是：**明文 OAuth `state` token / 内网域名未脱敏、无租户隔离、未聚合暴露**。

### 2.7 安全降级开关（已收敛为单点）✅
仅 `auth.py:268` 的 `XUANJIAN_DISABLE_REGISTER` 环境变量，行为清晰、可审计。不再"散落"。

---

## §3 产品级"空心"根因（来自 `docs/zhenduan.txt`，已逐条验证代码锚点）

v3 诊断的三层根因，本轮**实质性修复**：

1. **mitmproxy 未运行 → 流量为空**：`core/crawler/*` 已多处引用 mitmproxy/health 逻辑（结构性兜底存在）。
2. **登录表单 POST 从未进入测试队列**：`register_form_apis()` 已接入 `chat_loop.py:1167`，把"发现未提交"的表单 action 注册为可测 API（纯函数、显式依赖、零全局副作用、去重、过滤非业务 action），fast 模式也能覆盖登录等高危接口。✅ **Plan A 落地且质量高**。
3. **`✅` 把空心扫描伪装成正常**：`core/session/chat_loop.py` 加 **SEC-3 守卫**——fast 模式 + 登录页目标但桥接 0 产出 → 明确告警；`core/session/report_mixin.py` 新增 `_compute_real_completion` / `_detect_hollowing` / 告警 markdown，`core/report_templates.py` 加"空心化告警"段。✅ **伪装问题已堵**（注：report_mixin / report_templates 仍处未提交 staged 状态）。

> 结论：v3 列为最高优先级的"产品正确性"项，本轮已闭环。剩余为工程治理与 Cloud-ready（§5）。

---

## §4 v4 新浮现的两大风险（比老问题更紧迫）

### 4.1 ❌ 145 个文件未提交——多数好改动仍悬在工作区
`git status` 显示约 145 个文件未提交，包含本次多数关键落地：`tests.yml`（未跟踪）、`_common.md`（未跟踪）、`ScanMode` StrEnum、`core/session/report_mixin.py` 空心化检测、`core/llm/` 包、`orchestrator` 拆分等（`form_api_bridge` 模块本身已在 `43e5b9a` 提交，仅 `chat_loop.py:1167` 接线所在文件有未提交改动）。风险：
- **工作区一旦丢失/误删，数月重构归零**；
- 若某次"整体提交 + 直接 push main"，无中间 review，重演 `优化.txt` 的"带病上线"（改核心安全逻辑无守护）；
- 与"小 PR 分批合入 + 配测试"的既往教训相悖；
- **未提交改动正让 `chat_loop` 变大**（HEAD 1,873 → 工作区 2,038，+165），与 P1"拆分瘦身"目标背道而驰，越拖越难拆。

**建议**：立即按"已带测试、可独立验收"的边界**拆小 PR**（至少：① LLM 包 + tests ② 空心化 fix + form_api_bridge ③ ScanMode/CI/提示词机制 ④ crawler_core/chat_loop 拆分各自成 PR），每 PR 过 CI 后再合。

### 4.2 ⚠️ CI 门禁已变"真"，但从未被验证——可能一 push 就挂
`--cov-fail-under=70` 是硬门槛，但：
- 该门禁对应的代码**从未提交、从未在 CI 跑过**；
- 当前覆盖率是否 ≥70% **未知**（1,145 用例但 core 6.8 万行，且大量 `slow/e2e/llm` 被排除，有效覆盖可能偏低）；
- 一旦首次 push/PR，若覆盖率 <70%，**所有提交被卡**，反而阻塞 4.1 的合入节奏。

**建议**：在首个 PR 前，本地先跑一次 `pytest -m "not slow and not e2e and not llm" --cov-fail-under=70` 摸底；若未达标，**先把 `tests.yml` 的阈值临时设为 `--cov-fail-under=`（现状值）或先放宽到 40–50% 作为基线**，随覆盖率提升再收紧，避免门禁反成阻塞。

---

## §5 开发方案（v4 优先级重排）

> 原则变化：**从"补能力"转向"接线 / 提交 / 验证 / 收口"**。P0 治理项已清零，新 P0 是"交付安全"。

### P0 · 交付安全（最高优先级，今明可做，零代码风险）
1. **拆小 PR 提交在途重构**（§4.1）——防丢失、防带病上线。
   - 验收：145 → 0 个未提交文件；每个 PR 过 CI 绿。
   - 首步：`git diff --stat HEAD` 逐文件归类，按"已带测试"边界先开第 1 个 PR（建议 LLM 包 + tests）。
2. **本地摸底 CI 覆盖率**，校准 `tests.yml` 阈值（§4.2）——防门禁反阻塞。
   - 验收：得到当前覆盖率数值；`tests.yml` 阈值先设为现状值并留收紧计划。
   - 首步：`pytest -m "not slow and not e2e and not llm" --cov --cov-report=term`（先看数，再决定 70 是否可行）。
3. **`_common.md` 采纳接入**（§2.4）：把所有**安全分析类** `load_prompt(...)` 改为 `with_common=True`，并把 11 处内联 prompt 外置为 `.md`。让铁律真正生效（当前 0 采纳）。
   - 验收：安全类 `with_common=True` 全覆盖；内联 `你是一个/你是一名/system_prompt=` 降至 0。
   - 首步：先改 `harm_validation/exploit.py`、`vision.py`、`xss/llm_judge.py` 三处安全类，跑 `tests/unit/test_prompts_single_source.py`。

### P1 · 根深治本（2–6 周）
4. **拆 `crawler_core`(3,265)**：mixin（Login/Scope/UrlFilter/Form/ResultBuilder/SPA）已就位，抽成独立模块文件。
5. **拆 `chat_loop`(2,038)**：按 phase 抽 handler（explore/focused_test/report/idle 等 mixin 已存在）。
6. **收敛 32 处全局可变状态**：`metrics`/配置/注册表改依赖注入或模块级不可变 + 显式 setter；优先 `auth/skill_registry/false_positive_manager/scan_store/task_queue`。

### P2 · Cloud-ready（4–8 周，建在已落地地基上）
7. **成本遥测 API 化**：复用 `llm_usage.jsonl` 的 caller 级成本，做聚合暴露 + 计量计费。
8. **日志脱敏 + 租户隔离**：OAuth `state`/内网域名脱敏，按 tenant 分桶。
9. **多租户隔离 + KYC + 授权证明 + 审计日志**：商业化前置条件。

---

## §6 按 ROI 排序的优化建议 v4（带文件锚点）

| 优先级 | 建议 | 锚点 | 状态 |
|---|---|---|---|
| 🔴 P0 | 拆小 PR 提交 145 个在途文件 | git 工作区 | ❌ 未做 |
| 🔴 P0 | 本地摸覆盖率、校准 CI 阈值防反阻塞 | `.github/workflows/tests.yml` | ❌ 未验证 |
| 🔴 P0 | `_common.md` 采纳：安全类 prompt 加 `with_common=True` + 外置 11 处 | `core/prompts/__init__.py:40`、`harm_validation/exploit.py:96`、`vision.py`、`xss/llm_judge.py` | ⚠️ 已建未用 |
| 🟠 P1 | 拆 `crawler_core` 3,265 行 | `core/crawler/crawler_core.py:238` | ⚠️ 停滞 |
| 🟠 P1 | 拆 `chat_loop` 2,038 行 | `core/session/chat_loop.py:42` | ⚠️ 停滞（未提交改动反增） |
| 🟠 P1 | 收敛 32 处 `global` 为注入/不可变 | `core/auth.py`、`skill_registry.py`、`scan_store.py` 等 18 文件 | ❌ 未减 |
| 🟡 P2 | 成本遥测 API 化 | `data/logs/llm_usage.jsonl` | ⚠️ 地基在 |
| 🟡 P2 | 日志脱敏 + 租户隔离 | `core/log.py`、`llm_usage.jsonl` | ❌ 未做 |
| 🟢 已完 | CI 真门禁 / `ScanMode` StrEnum / 表单桥接 / 空心化检测 | `.github/workflows/tests.yml`、`core/scan_strategies.py:31`、`core/session/chat_loop.py:1167`、`core/session/report_mixin.py:190` | ⚠️ 代码就绪/未提交 |

---

## §7 成功度量（v4）

- [ ] 在途重构 145 → 0 个未提交文件，CI 全绿（覆盖率达标后）
- [ ] `with_common=True` 安全类覆盖 0 → 全量；内联 prompt 11 → 0
- [ ] `global` 声明数 32 → <10
- [ ] 上帝文件 2 → 0（crawler_core 3,265 / chat_loop 2,038 拆分完成）
- [ ] 日志脱敏 + 租户隔离上线
- [ ] 覆盖率门槛从基线逐步收紧至 70% 不阻塞（基线待首次摸底）

## §8 本周可立即推进的 3 件事

1. **提交在途重构**（按 §4.1 拆 4 个 PR），先合"已带测试"的部分。
2. **本地跑一次 `pytest -m "not slow and not e2e and not llm" --cov-fail-under=70`** 摸底，据结果校准 `tests.yml` 阈值。
3. **让 `_common.md` 生效**：给 `exploit/vision/xss_llm_judge` 等安全类 `load_prompt` 加 `with_common=True`，并外置 11 处内联 prompt——半天内可完成、零行为风险。

---

### 附：与三份战略文档 + 诊断文档的对账（v4）

- **PRODUCT_STRATEGY / COMPETITIVE / REDESIGN**：仍基于早期快照，多次"待办"在代码中已落地（测试基座、fast_scanner 包化、LLM 重试/预算、WAF 感知、空心化修复）。**建议按现状修订三份文档**，否则规划与代码持续脱节。
- **REDESIGN 可测性目标**：`form_api_bridge` 纯函数 + 100% 单测，正是对齐该目标的样板，已落地。
- **zhenduan.txt 三层根因**：① mitmproxy 兜底（结构性存在）② 表单桥接（✅ 已接线）③ ✅ 伪装（✅ SEC-3 + 报告告警已堵）——**全部闭环**。
- **hollowing-optimization-plan/优化.txt 教训**："改核心安全逻辑须有回归守护"——本轮所有修复均配测试（空心化 fix、form_api_bridge test），方向正确；但**未提交**仍是最薄弱一环。
