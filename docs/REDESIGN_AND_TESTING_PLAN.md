# 玄鉴 XuanJian 生产级重构 + 全测试覆盖方案

> 角色：资深安全开发工程师
> 目标：在**不重写业务价值**的前提下，对现有代码做工程化重构，使其达到**生产级可维护性**与**全测试覆盖**（单元 / 集成 / 端到端三层），并把"假阳性铁律"这类核心安全逻辑变成**可被证明正确**的确定性代码。

---

## 0. 现状评估（基于实际代码，非泛泛而谈）

通读 `core/`（145 个 py）、`tests/`（29 个 py）、`web/`、`mcp_servers/` 后，工程层面的核心问题如下：

| # | 问题 | 证据 | 对"生产级 + 全测试"的阻碍 |
|---|------|------|---------------------------|
| 1 | **全局可变配置** | `core/config.py` 中 `FEATURE_VULN_MAPPING`/`VULN_SYNONYMS`/`VULN_TO_SKILL` 是模块级 `list`/`dict`；`apply_skill_registry()` **原地 `clear()+update()`** 修改全局 | 测试间相互污染；无法注入自定义配置验证边界；热重载依赖"原地改全局"这一反模式 |
| 2 | **全局单例 + 构造即 I/O** | `FalsePositiveManager.__init__` 直接 `Path(db_path).mkdir()` 并读 `data/false_positives.json`；`get_fp_manager()` 是模块级单例；`core.log.metrics` 也是全局单例 | 单测必触发文件系统副作用；无法在无盘/沙箱环境确定性验证持久化与命中计数 |
| 3 | **构造函数做重活、无可测试接缝** | 测试中大量 `FastScanner.__new__(FastScanner)` 绕过 `__init__`，用 `MagicMock()` 伪造响应 | 说明 `FastScanner.__init__` 耦合 LLM/网络；无法干净实例化，集成测试只能"黑 MagicMock" |
| 4 | **测试基座缺失** | 无 `conftest.py`、无 `[tool.coverage.*]` 配置、无测试 CI（仅有 `docker.yml`） | 29 个测试文件"裸奔"：无 fixtures 复用、无覆盖率门槛、无门禁，无法保证"全覆盖" |
| 5 | **外部依赖未抽象成端口** | LLM（`core/llm.py`）、HTTP（`httpx`）、浏览器（Playwright）、抓包（mitmproxy）均为具体实现、顶层 import | 无法用 Fake 替代；LLM/浏览器测试只能真跑或全 skip，确定性为 0 |
| 6 | **导入耦合重** | `import core.fast_scanner` 即拉入 `httpx` + `core.xss.oob`；许多模块顶层 import 重依赖 | 单测需装齐所有重依赖才能 import，CI 慢且脆 |
| 7 | **确定性逻辑与概率性 LLM 混住** | "假阳性铁律"（业务码/空 data/WAF/归一化/时间盲注二次复现）与 LLM 审核员在同一链路 | 去误报的硬规则本应 100% 可测，却因混在 Agent 里难以独立验证 |

**结论**：业务价值（SKILL 方法论、8 阶段流程、假阳性铁律）是好的，工程骨架是"能跑的原型"级别。重构方向是**分层 + 端口/适配器 + 依赖注入**，把确定性核心抽出来吃满测试，把不确定的 LLM/浏览器收敛到可替换的端口后。

---

## 1. 设计目标与原则

1. **确定性核心 100% 单测覆盖**：所有"假阳性铁律"、配置推导、去重、优先级、危害规则判定必须是纯函数，无网络/无盘/无时钟依赖。
2. **一切 IO 走端口（Protocol）**：LLM、HTTP、Browser、TrafficCapture、RuleStore 全部定义接口，生产用真实适配器，测试用 Fake。
3. **依赖注入，零运行时全局可变状态**：`ScanConfig`、`clock`、`random`、`uuid`、各端口均通过构造参数注入；热重载返回**新对象**而非改全局。
4. **测试金字塔 + 覆盖率门禁**：单元 70%+，集成 20%，e2e 10%；CI 强制 `fail_under`。
5. **渐进式迁移，不 big-bang**：每一阶段都可独立合入、可回滚、不破坏现有扫描能力。
6. **安全回归即活文档**：每个修过的误报 / 每个新漏洞类型，都对应一个 pin 住的红/绿测试。

---

## 2. 目标架构（分层 + 端口/适配器 + DI）

```
┌──────────────────────────────────────────────────────────────┐
│                        Composition Root (infra/)              │
│   启动时装配：真实适配器 + ScanConfig + 单例容器（仅此处可有单例）│
└──────────────────────────────────────────────────────────────┘
          │ 注入端口与配置                │ 注入端口与配置
          ▼                               ▼
┌─────────────────────┐        ┌─────────────────────────────────┐
│   application/       │        │   adapters/  (具体实现，可替换) │
│   用例 / 编排         │──────▶ │  OpenAIAdapter / PlaywrightAdapter│
│   - ScanSession(状态机)│ 依赖  │  HttpxAdapter / MitmproxyAdapter │
│   - ParallelScheduler │ ports │  JsonFileRuleStore / Fake*       │
└─────────────────────┘        └─────────────────────────────────┘
          │ 调用纯逻辑                    ▲ 实现
          ▼                               │
┌──────────────────────────────────────────────────────────────┐
│   domain/  (纯、确定性、零 IO)   ← 测试 coverage 最高优先级      │
│   - rules: 假阳性铁律 / WAF / 归一化 / 时间盲注二次复现 / XSS上下文│
│   - config: ScanConfig(可注入) + dedup/priority/checklist 推导   │
│   - fp: FalsePositiveManager(端口化存储 + 可控时钟)              │
│   - harm: 危害判定硬规则（确定性部分）                          │
│   - model: VulnFinding / ScanResult / Skill 等领域对象          │
└──────────────────────────────────────────────────────────────┘

   ports/ (typing.Protocol 接口，无实现):
     LLMClient │ HttpClient │ BrowserDriver │ TrafficCapture │ RuleStore │ Clock
```

**关键不变量**：`domain/` 只允许 import 标准库与自身；任何对 LLM/网络/文件的调用都必须通过 `ports/` 注入。这样 `domain/` 可在无第三方依赖环境下被完整单测。

---

## 3. 关键重构点（逐项对应第 0 节问题）

### 3.1 配置对象化（解决 #1）
- 新增 `core/config_runtime.py:ScanConfig`（dataclass），默认**拷贝** `core.config` 的当前生产值（已落地 PoC）。
- 引擎通过 `ScanConfig` 取配置，不再 `from core.config import X` 散弹引用。
- `apply_skill_registry()` 改为返回**新的 `ScanConfig`**，不再原地改全局；热重载=替换容器里的引用。
- 测试可注入裁剪过的 `ScanConfig`（如把 `max_checklist_per_fp` 设为 3 验证裁剪）。

### 3.2 FP 管理器端口化（解决 #2）
- `RuleStore` Protocol：`MemoryRuleStore`（测试）/ `JsonFileRuleStore`（生产，向后兼容 `data/false_positives.json`）。
- 构造函数注入 `store` 与 `clock`；`clock` 默认 `datetime.now`（已落地 PoC，`FakeClock` 可控）。
- 删除模块级 `_fp_manager` 单例对测试的侵入——通过组合根持有单例，测试用全新实例。

### 3.3 FastScanner / AnalyzeWorker / HarmValidator 注入化（解决 #3、#5）
- 抽离 `HttpClient` / `LLMClient` / `BrowserDriver` 端口。
- `FastScanner.__init__(config, http: HttpClient, clock, rng)`——不再顶层 import 重依赖；重依赖延迟到适配层。
- 测试用 `MockHttpClient`（录制/回放真实 `httpx.Response`）替代 `MagicMock`，避免序列化回归。

### 3.4 端口与 Fake 体系（解决 #5、#6）
- `ports/` 定义 6 个 Protocol；`adapters/` 放真实实现。
- `tests/fakes/`：`FakeLLM`（脚本化响应 + 调用记录 + 限流模拟）、`FakeBrowser`、`InMemoryRuleStore`、`MockHttpClient`（基于本地 `http.server` 的 `http_target` 固件，已落地 PoC）。
- 顶层 import 重依赖下沉到 `adapters/`，`domain/` 与单测零重依赖。

### 3.5 确定性来源可注入（贯穿）
- `clock`、`random.Random`、`uuid` 提供注入点；时间盲注二次复现、溯源 trace_id、规则 id 均依赖注入值，测试冻结后完全确定性。

### 3.6 可观测性去全局（解决 #2 连带）
- `metrics` 改为可注入的 `MetricsSink` 端口；全局仅组合根持有一个默认实现，测试可注入内存 sink 断言计数。

---

### 3.7 fast 模式的确定性 skill 路由（已落地，设计哲学实证）
- **背景**：产品要求 fast 模式也获得「skill 引导」，但 fast 的核心卖点是速度，不能退化为半个 standard。
- **方案**：新增 `core/skill_router.py`，纯函数 + 可注入 `registry`，**不调用 LLM**：
  - `route_vuln_types_to_skills()`：按 `VULN_TO_SKILL` 确定性查表 → 按 `priority` 降序、SKILL 名升序稳定排序 → 同一 SKILL 去重 → 截断到 `top_n`。
  - `build_vuln_to_skill_routes()` / `lookup_skill_for_vuln_type()`：供 `VulnFinding` 标注治理它的 SKILL。
- **接入点（已接到线上路径）**：`ScanExecutor.execute` 仅作 PoC 样本；**真实扫描路径 `core/parallel/orchestrator.py:run_parallel_test` 现已在 FastScanner 结果写回 sitemap 后（Step 4/Step 5 两处）调用 `_apply_skill_routing()`**，给 `VulnFinding.skill/skill_path` 打标 + 把 `skill_routes` 挂到 `session.sitemap`（供报告展示）。`scan_cfg.enable_skill_routing`(默认 True) + `skill_routing_top_n`(默认 3) 控制。`_apply_skill_routing` 异常安全：失败只记日志，绝不阻断主流程。
- **零 API 保证**：SKILL *选择* 完全由映射表决定，无任何模型调用；把 SKILL 散文正文展开成可执行探针的 LLM 层作为 `enable_skill_llm_expansion`（默认关、单次有界调用）留作后续，可选开启。
- **测试**：`tests/unit/test_skill_router.py` 11 用例全绿（注入假 `registry`，零网络/零文件），覆盖 87%（未覆盖项为错误分支兜底）。
- **对应原则**：这是 §1 原则 #1「确定性核心 100% 单测」与原则 #3「依赖注入、零全局可变状态」的**首个实装样本**——`VulnFinding` 的 `skill` 归属字段替代了"原地改全局 `VULN_TO_SKILL`"的反模式（见 §0 #1）。

---

## 4. 全测试覆盖方案

### 4.1 测试金字塔与分层策略

| 层 | 占比 | 对象 | 是否 IO | 关键技术 |
|----|------|------|---------|----------|
| **单元** | 70%+ | `domain/` 全部：假阳性铁律、WAF、归一化、时间盲注二次复现、XSS 上下文降级、SSRF 特征收紧、配置推导、去重、优先级、报告渲染 | 无 | pytest + hypothesis(属性测试) + 参数化；冻结 clock/random |
| **集成** | 20% | `adapters/` + `application/`：FastScanner 对本地 mock HTTP 目标、LLM 适配器对录制流量(VCR/cassette)、Browser 适配器对本地测试页 | 受控本地 IO | `http_target` 固件、流量录制回放、testcontainers |
| **端到端** | 10% | 完整扫描链路：对**故意漏洞靶场**（Juice Shop / DVWA / 本地脆弱 Flask，Docker 启动）+ 对**已知干净**的授权 staging 做"零严重误报"守护 | 真实网络/浏览器 | Docker Compose、已知 bug 基线、Golden Report 比对 |

### 4.2 覆盖率与门禁
- `pyproject.toml` 已加 `[tool.coverage.run]`（branch=true）+ `[tool.pytest.ini_options]` 带 `--cov`（已落地 PoC）。
- CI 强制 `pytest --cov-fail-under=70`（起步）→ 逐步提到 **85**（domain 层要求 95%+）。
- PR 门禁：**diff coverage ≥ 90%**（新增代码必须基本被覆盖）。
- 产出 `coverage.xml` + `htmlcov` 作为 CI 产物。

### 4.3 确定性（Hermetic Tests）
- 所有时间/随机/ID 走注入；测试用 `FakeClock` + 固定 seed。
- 外部响应走"录制—回放"黄金文件（golden fixtures），禁止测试内联真 LLM 调用。
- 标记 `@pytest.mark.slow` / `integration` / `e2e` / `llm`，CI 默认只跑快测，nightly 跑全量。

### 4.4 CI/CD 流水线（GitHub Actions）
- **矩阵**：Python 3.10 / 3.12；OS ubuntu-latest。
- **阶段**：lint(ruff) → type(pyright/mypy) → unit+integration(带 coverage 门禁) → mutation(mutmut/cosmic-ray，针对 `domain/rules`) → e2e(Docker 靶场) → 产物上传。
- **门禁**：任一门禁失败则 PR 不可合入。
- 新增 `.github/workflows/tests.yml`（替换仅有 docker 的现状）。

### 4.5 专项测试类别
- **安全回归测试（活文档）**：把 `test_fast_scanner_fp.py` 里 4 个历史误报场景（`code:500+用户未登录`、`data:null`、WAF 403、布尔盲注归一化）扩成**回归语料库** `tests/fixtures/fp_corpus/`，每条新增误报都加一个 pin 测试。
- **属性测试**：对 `_normalize_body` / `dedup_vuln_type` / checklist 排序用 hypothesis 做不变量断言（如"归一化后相似度对时间戳不敏感"）。
- **模糊测试**：对 Payload 生成器做输入 fuzz，验证规则引擎不崩溃、不误吞。
- **性能/容量测试**：FAST 模式时间预算（`lead_time=120s`、`total_fast_scan=180s`）在并发下的实测门禁。

### 4.6 定义"完成"（DoD）
- 新增/修改任一规则 → 必须有**单元测试 + 集成测试**，且覆盖率不降。
- 新增漏洞类型 → SKILL + 检测测试 + 危害验证测试三者齐备。
- 任一 PR 必须满足：lint/type 通过、单测绿、diff coverage ≥ 90%、无新增全局可变状态。

---

## 5. 迁移路线图（渐进、可回滚、不破坏扫描能力）

| 阶段 | 内容 | 交付物 | 风险 |
|------|------|--------|------|
| **P1 基座** | pytest/coverage 配置、`conftest`、可注入 `ScanConfig`、`RuleStore` 端口化、CI 雏形 | 可跑的测试基座 + PoC（**已落地**：测试基座跑通，44 单测绿，修复 2 个既有 bug） | 低 |
| **P2 抽 domain** | 把假阳性铁律等纯函数迁入 `domain/rules/`；定义 `ports/` 六接口；补 `tests/fakes/` | domain 层 95%+ 覆盖 | 低 |
| **P3 注入化** | FastScanner/AnalyzeWorker/HarmValidator 接收注入端口与 `ScanConfig`；移除全局单例；组合根装配 | 全引擎可单测实例化 | 中 |
| **P4 覆盖拉满** | 集成测试（mock HTTP 目标）、Docker e2e（靶场）、mutation 测试、属性测试 | 三层测试齐备、门禁生效 | 中 |
| **P5 加固** | 类型检查、性能测试、文档、SKILL 回归语料库 | 生产级交付 | 低 |

推荐**先合 P1**，因为它零业务风险且立刻让现有 29 个测试有门禁、有覆盖率、可复现。

---

## 6. 落地第一步（P1 清单，已开工部分标 ✅）

- ✅ `pyproject.toml`：`[tool.pytest.ini_options]` + `[tool.coverage.*]` + dev 依赖（pytest-cov/coverage）
- ✅ `tests/conftest.py`：日志隔离、可控时钟、`http_target` 本地 HTTP 固件
- ✅ `core/false_positive_manager.py`：`RuleStore` 端口 + `MemoryRuleStore` + `clock` 注入（向后兼容）
- ✅ `core/config_runtime.py`：`ScanConfig` 可注入门面 + `dedup/priority/checklist` 纯函数
- ✅ `tests/unit/test_false_positive_manager.py`、`tests/unit/test_scan_config.py`（已跑通）
- ✅ `core/skill_router.py`（新增，确定性 skill 路由，`VULN_TO_SKILL` 查表，零 LLM）+ `tests/unit/test_skill_router.py`（11 passed，覆盖 87%）
- ✅ 安装 `pytest-cov` 并跑通 `tests/unit/`：**44 passed**（含 2 个既有 bug 修复），取覆盖率基线（core 全量 2%，受大量未重构重型模块拖累，符合预期）
- ⬜ 新增 `.github/workflows/tests.yml`（矩阵 + 门禁）
- ⬜ 写 `tests/README.md`（测试策略与本地运行说明）

---

## 7. 风险与权衡

- **不重写业务**：SKILL 方法论、8 阶段流程、假阳性铁律的*语义*保持不变，只改*结构*与*可测性*。
- **向后兼容**：FP 管理器默认仍落 `data/false_positives.json`；`get_fp_manager()` 仍可用；配置默认值完全拷贝，行为零变化。
- **重依赖下沉**：Playwright/mitmproxy 等仅存在于 `adapters/`，不影响 `domain/` 与单测速度。
- **迁移成本**：P3 涉及多引擎构造函数签名变更，需配套更新组合根与调用点；用"适配层薄封装"降低改动面。

---

## 8. 成功度量（可量化）

- `domain/` 行+分支覆盖率 ≥ 95%；全仓 ≥ 85%；diff coverage ≥ 90%。
- 单测执行时间 < 60s（无网络/无浏览器）；集成 < 5min；e2e(nightly) < 20min。
- 历史 4 类误报 + 每新增 1 类误报均有 pin 测试；靶场检测率 ≥ 基线、staging 零严重误报回归。
- `ruff` + 类型检查 0 error；全局可变运行时状态 = 0（仅组合根可持有单例）。

---

### 附：我此前已落地的 PoC 文件（如不服方案可随时回滚）
- `core/config_runtime.py`（新增，可注入 ScanConfig）
- `core/false_positive_manager.py`（改写为端口化，向后兼容）
- `core/skill_router.py`（新增，确定性 skill 路由，零 LLM，供 fast 模式 skill 引导）+ `core/parallel/orchestrator.py`（`_apply_skill_routing` 已接到 `run_parallel_test` 线上路径，FastScanner 结果写回后打标并挂 `skill_routes`）+ `core/sitemap/report.py`（报告展示 Skill 引导小节）
- `tests/conftest.py` + `tests/unit/test_false_positive_manager.py` + `tests/unit/test_scan_config.py` + `tests/unit/test_skill_router.py`（新增）
- `pyproject.toml`（追加 pytest/coverage 配置与 dev 依赖）
