# 玄鉴 XuanJian 代码优化 AI 提示词（工程 Brief）

> 本文档是一份**可直接喂给 AI（或交给研发）使用的优化提示词 / 工程任务书**。  
> 由产品经理基于 D:\xuanjian-main 全量代码审计编写，所有问题均附代码证据。  
> **本文件为新增交付物，未改动项目任何现有代码。**

---

## 0. 角色与总任务

你是一名**资深 Python 安全工具架构师 + AI 提示词工程师**。你的任务是优化「玄鉴 XuanJian」智能安全扫描器的代码库，目标是：

1. **可维护性**：消除上帝文件、收敛重复的安全规则（单源化，不建提示词中心基础设施）、消除重复规则。
2. **稳定性**：在不改变外部行为、不破坏假阳性防护的前提下做重构。
3. **提示词质量**：让驱动扫描的 LLM 提示词更结构化、更一致、更少漂移。

**铁律：优化 = 重构与治理，不是重写业务逻辑，不是削弱安全能力。**

---

## 1. 项目背景（必读上下文，来自代码事实）

- **定位**：LLM 驱动 + 本地规则双引擎的自动化渗透测试 Agent（`pyproject.toml` 描述）。
- **运行形态**：主 Agent 状态机（`core/session/`）+ 并行子 Agent（`core/parallel/`）+ 危害验证审核员（`core/harm_validation/`）+ 浏览器爬虫（`core/crawler/`）。
- **三档扫描模式（代码已实现）**：`ScanMode.FAST / STANDARD / DEEP`（`core/parallel/orchestrator.py`）。FAST 模式 `enable_llm = not _fast_mode`，即 FAST = 纯本地规则、不调 LLM；STANDARD/DEEP = LLM 驱动。`_fast_mode = scan_cfg.mode == ScanMode.FAST`（`orchestrator.py:669,702`）。
- **假阳性防护（核心资产，绝不可破坏）**：检测层硬规则（`core/fast_scanner.py` 的 `_is_business_deny / _is_waf_block_page / _normalize_body / _bodies_similar` 等）+ LLM 审核员双重过滤（`core/prompts/harm_validation.md` + `core/harm_validation/validator.py`）。
- **提示词载体**：`core/prompts/`（`phases.py` 481 行、`harm_validation.md`、多个 `.md`）+ 分散在 15 个业务文件里的 `SYSTEM_PROMPT` 常量。
- **知识库**：`skills_my/` 含 111 个 `.md` 方法论（discovery/exploit/wooyun-legacy-main）。
- **工程亮点（要保留）**：`core/llm.py` 的 caller 级并发池 + 响应缓存（LLRU+TTL）、`CONFIG_UNIFICATION_REPORT.md` 已完成的 14 个常量集中化。

---

## 2. 已确认的硬约束（绝不可破坏）

| 约束                                        | 原因                                | 代码位置                                                                  |
| ----------------------------------------- | --------------------------------- | --------------------------------------------------------------------- |
| 检测层假阳性硬规则                                 | 即使 FAST 跳过危害验证也靠它去误报              | `core/fast_scanner.py:410-748`                                        |
| LLM 审核员 `accepted/borderline/rejected` 裁决 | 按 SRC 标准去误报                       | `core/harm_validation/validator.py`、`core/prompts/harm_validation.md` |
| 三档模式语义（FAST 无 LLM）                        | 产品三档架构契约                          | `core/parallel/orchestrator.py:669-808`                               |
| `drop_auth=true` 认证剥离机制                   | 未授权访问测试的正确姿势                      | `core/tools.py`、`core/prompts/phases.py`                              |
| 测试门禁                                      | CI 中 `pytest --cov-fail-under=70` | `pyproject.toml`                                                      |
| 法律声明                                      | 合规底线                              | `DISCLAIMER.md`、`README.md`                                           |

> 任何重构都必须保证：现有 `tests/` 用例全绿、假阳性规则行为与重构前一致、模式语义不变。

---

## 3. 通过代码审计发现的具体问题（附证据）

### P0 · 架构级（必须治理）

**问题 1：上帝文件（单文件超长、单类跨数千行）**

| 文件                              | 行数       | 风险点                                                                                                          |
| ------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------ |
| `core/fast_scanner.py`          | **4266** | `FastScanner` 单类横跨 794→4043 行，方法间距极远，难以 review                                                               |
| `core/crawler/crawler_core.py`  | **3704** | `AutoCrawler(LoginMixin, ScopeMixin, UrlFilterMixin, FormMixin, ResultBuilderMixin, SPAMixin)` 6 个 mixin 巨型类 |
| `core/session/chat_loop.py`     | 2147     | 主循环职责过多                                                                                                      |
| `core/llm.py`                   | 2048     | 客户端/池/缓存/重试全塞一个文件                                                                                            |
| `core/browse_worker.py`         | 2028     |                                                                                                              |
| `core/parallel/orchestrator.py` | 2013     |                                                                                                              |
| `core/js_analyzer.py`           | 1937     |                                                                                                              |

**问题 2：提示词散落 + 同一规则多处重复（最高漂移风险）**

- 系统提示词常量分散在 **15 个文件**：`business_understanding.py`、`context.py`、`harm_validation/exploit.py`、`harm_validation/validator.py`、`lesson_extractor.py`、`parallel/batch_test.py`、`parallel/grouping.py`、`prompts/phases.py`、`realtime_worker.py`、`reconcile.py`、`session/idle_mixin.py`、`vision.py`、`worker_agent.py`、`xss/llm_judge.py`、`xss/waf_bypass.py`。
- **同一套规则被复制多份**：`drop_auth=true` 的指导同时存在于 `core/prompts/phases.py`、`core/prompts/solver.md`、`core/harm_validation/validator.py`、`core/tools.py`；CORS 误报规则同时存在于 `core/fast_scanner.py`（代码）、`core/harm_validation/render.py`、`core/harm_validation/validator.py`、`core/prompts/harm_validation.md`、`core/config.py`。
- **后果**：改一处忘改另一处 → 代码与提示词对安全判定结论不一致 → 误报/漏报。

**问题 3：扫描模式术语对外不一致**

- 代码：`ScanMode.FAST / STANDARD / DEEP`（`scan_strategies.py:473` 还把 `"batch": ScanMode.STANDARD` 标为「兼容旧模式名」）。
- README：主推「批处理(Batch)/实时(Realtime)/包测(Packet)」三模式。
- 这是**两个正交维度**（入口/编排方式 vs 智能深度）被混用，对外文档与代码语义冲突，易误导用户与接手研发。

### P1 · 提示词工程级（非阻塞，不建框架）

- **格式不统一（已知现状，暂不改）**：提示词一部分是 `.py` 常量（带 f-string 插值，如 `phases.py` 的 `GROUPING_USER_TEMPLATE`），一部分是纯 `.md` 原文（如 `harm_validation.md`、`browse_sop.md`）。两类无统一加载/校验/版本机制——**对此不新建 `load_prompt` 等基础设施**（过度工程），仅通过"安全铁律单源化"（Phase A）收敛最关键的重复。
- **无提示词回归测试**：提示词改动没有断言/快照测试，靠人工肉眼 review（先用代码侧假阳性回归测试兜底，见 Phase D）。
- **证据固化规则需单源化**：`WORKER_SYSTEM_PROMPT` 里的「漏洞证据强制固化铁律」写得很好，但只在子 Agent 提示词里——归入 Phase A 第 1 条的 `_common.md` 单源。

### P2 · 质量与可观测性

- **测试结构**：`tests/` 行数很大但多为 `unit`；`integration/e2e/llm` 标记为慢测试默认不跑（`pyproject.toml` markers）。端到端行为缺乏保障。
- **日志/用量**：`core/llm.py` 有调用统计，但 token/费用归因到 caller 维度的看板仍依赖 Web UI，缺结构化日志。
- **文档与代码不同步**：README 的模式表、目录结构与代码实际存在偏差（见问题 3）。

---

## 4. 优化工作流（分阶段，按 ROI 排序）

### Phase A · 安全规则单源化（最高 ROI，先做；**不建提示词基础设施**）

> **范围约束**：本项目是扫描系统，不是提示词平台。**不新建** `load_prompt` 加载器、版本管理、插值校验框架等"提示词中心"类基础设施（属过度工程，ROI 低）。本阶段只做最小、必要的"安全铁律单源化"——修的是规则漂移 bug，不是搭框架。

1. **抽取公共安全铁律为单源**：把 `drop_auth` 认证机制说明、CORS 误报黑白名单、漏洞证据固化铁律、等级定级标准收拢到**一处**（建议 `core/prompts/_common.md`）。代码注释与分散在 `phases.py` / `worker_agent.py` / `harm_validation` 的提示词片段，统一指向它作为唯一出处，消除当前 15 处 + 多份重复。**include 方式用现有字符串拼接 / 模块 import 即可，不引入新机制。**
2. **代码侧假阳性规则与提示词规则对齐**：以 `core/fast_scanner.py` 的检测层硬规则为唯一事实源，提示词只引用、不另写判定逻辑，避免双份维护。

### Phase B · 上帝文件拆分（P0）

- `fast_scanner.py`：按职责拆出 `rules_loader / fp_filters / scanner_engine / csrf_probe / param_discovery`，保留 `FastScanner` 门面。
- `crawler_core.py`：6 个 mixin 各自独立成模块文件，主类只做编排。
- `llm.py`：拆出 `client / caller_pool / response_cache / retry`。
- **拆分原则**：每文件 < 600 行；保持公开 API 签名不变；配套测试。

### Phase C · 模式语义统一（P0）

- 代码侧：明确 `ScanMode` 枚举只有 FAST/STANDARD/DEEP，删除 batch/realtime/packet 的旧别名或显式映射到新维度。
- 文档侧：README 用「智能深度（FAST/STANDARD/DEEP）× 入口方式（Web/Burp/API）」二维矩阵重写，消除冲突。

### Phase D · 测试与可观测性（P1）

- 为 Phase A 的提示词收敛加**提示词快照/断言测试**（变量完整性、关键铁律片段存在）。
- 补 `integration` 级假阳性回归用例（构造已知误报样本，断言被过滤）。

### Phase E · 文档同步（P2）

- 根据代码实际补齐 ARCHITECTURE 文档、模式说明、提示词维护约定。

---

## 5. 执行规范（每条工作的硬性要求）

- **无行为变更**：重构前后 `tests/` 全绿；FAST 模式假阳性过滤输出逐条一致（可加差分断言）。
- **保留公共 API**：拆分不破坏 `core/parallel/orchestrator.py`、`core/session/chat_loop.py` 对模块的 import 路径（可用兼容 re-export）。
- **提示词优化手法**：
  - 结构化（用标题/列表/表格，而非大段散文）；
  - 去重（公共铁律单源 include）；
  - 证据固化（要求模型「看到证据立即 `checklist_mark`，不换 payload 继续试探」——沿用现有优秀写法）；
  - 给出禁止项（⛔）与示例（✅/❌），降低模型违规率。
- **不引入新依赖**除非必要；改动需在 PR 描述里标注影响的提示词/模式/测试。

---

## 6. 验收标准

- [ ] `drop_auth` / CORS / 证据固化等安全铁律各只有**单源**（指向 `core/prompts/_common.md`），不要求所有提示词物理收拢到单一目录。
- [ ] 单文件行数 ≤ 800（原 7 个上帝文件全部达标）。
- [ ] 扫描模式对外术语（代码 + README）一致，无 batch/realtime/packet 与 FAST/STANDARD/DEEP 混用。
- [ ] `pytest` 全绿且覆盖率不低于当前基线。
- [ ] 新增假阳性回归测试（构造已知误报样本，断言被过滤）。
- [ ] 假阳性率（已知样本集）不高于重构前。

---

## 7. 可直接复用的「启动提示词」（复制给 AI 执行 Phase A）

```
你是玄鉴 XuanJian 的提示词治理工程师。当前问题：系统提示词常量散落在 15 个文件，
且 drop_auth 认证说明、CORS 误报规则、漏洞证据固化铁律被复制多份，存在安全判定漂移风险。

请执行（只读分析后给出方案，再在确认后改代码）：
1. 用 grep 全量列出 core/ 下所有 SYSTEM_PROMPT / *_PROMPT 常量与其所在文件行号；
2. 把重复的安全铁律抽成 core/prompts/_common.md（含 drop_auth、CORS 黑白名单、等级定级、
   证据固化铁律），由 phases.py / worker_agent.py / harm_validation 统一 include；
3. （不做）不设计新的 load_prompt 统一加载框架，仅用现有字符串拼接 / include 引用 _common.md。
4. 输出一份「提示词治理方案」：列出每个待合并文件、抽取片段、include 方式、回归测试点。
约束：不得改变任何安全判定结论；不得删除未确认使用的提示词；先给方案待确认。
```



---

> 编写依据：D:\xuanjian-main 全量代码审计（README、pyproject、core/ 151 个 py、core/prompts/、  
> core/llm.py、core/fast_scanner.py、core/parallel/orchestrator.py、CONFIG_UNIFICATION_REPORT.md 等）。  
> 本文件为新增交付物，未修改项目任何现有代码。
