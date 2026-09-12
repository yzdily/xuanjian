# AI 安全项目三方比较方案

> 玄鉴 XuanJian (v2.0 封板) × CyberStrikeAI × Cybermes
> 撰写时间：2026-08-27
> 输出物：技术对比 · 差异化定位 · 选型建议 · 融合路线

---

## 一、TL;DR 一句话总结

| 项目 | 一句话定位 | 技术栈 | 成熟度 |
|------|----------|--------|--------|
| **玄鉴 XuanJian** | 浏览器驱动 + 流量拦截的 **Web/App 渗透测试 Agent**（v2.0 封板，AI-native 已迁出到 JianWei） | Python + Playwright + mitmproxy + FastAPI | ⭐⭐⭐⭐⭐ 国内一线 SRC 出品 |
| **CyberStrikeAI** | Go 全栈、**AI-native 网络安全行动系统**（Eino + MCP + RAG + WebShell/C2 + 100+ 工具） | Go 1.25+ + Eino + SQLite + SPA | ⭐⭐⭐⭐⭐ Apache 2.0，404Starlink 成员，2,220 commits |
| **Cybermes** | **MCP 原生 + Hermes Agent** 驱动的"零误报"漏洞赏金自动化框架 | Go + Python + PowerShell + Node（MCP 服务器） | ⭐⭐⭐ Apache 2.0，125 commits，3 周前刚发布 |

> **三者的核心差异**：玄鉴做"**Web 渗透执行者**"，CyberStrikeAI 做"**AI-native 安全操作系统**"，Cybermes 做"**MCP 化的攻击面工具集**"。

---

## 二、基础画像对比

| 维度 | 玄鉴 XuanJian | CyberStrikeAI | Cybermes |
|------|---------------|----------------|----------|
| **作者** | yzdily | Ed1s0nZ | Zyrexnn |
| **仓库** | github.com/yzdily/xuanjian | github.com/Ed1s0nZ/CyberStrikeAI | github.com/Zyrexnn/Cybermes |
| **许可证** | MIT | Apache 2.0 | Apache 2.0 |
| **代码规模** | core/ 212 Python 文件 + web SPA + 19 个 FastAPI Router | cmd + internal + 100+ YAML 工具配方 + SPA | Go 原生工具链 + Python 脚本 + 200+ Playbook + MCP 服务器 |
| **状态** | v2.0 封板（功能冻结，只修 bug） | 活跃迭代（最新提交 2026-08-26） | 活跃迭代（最新提交 2026-08-26） |
| **语言** | Python ≥ 3.10 | Go 1.25+ | Go + Python + PowerShell + Node |
| **核心依赖** | Playwright、mitmproxy、FastAPI、ddddocr、openai/anthropic、MCP | Eino、SQLite、YAML、go-yaml | yaml.v3、subfinder、httpx、katana、ffuf、nuclei、sqlmap、smart_pipe、search_knowledge |
| **数据库** | 内存 + 文件（无显式数据库） | SQLite | 文件系统（reports/、recon/） |
| **部署形态** | 单进程 `python start.py` | `go run` + `./run.sh` | CLI / Docker / Windows 原生 / Linux / macOS |
| **运行入口** | 7788 Web 控制台 | Web + IM 机器人（微信/企微/钉钉/飞书/TG/Slack/Discord/QQ） | 单一 CLI + MCP 服务器 |

---

## 三、架构对比

### 3.1 整体架构范式

```
┌─────────────────────────────────────────────────────────────────────┐
│                          玄鉴 XuanJian                              │
│   「Web/App 渗透测试 Agent」 — 单点纵深                              │
│   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐           │
│   │ 浏览器  │ → │ 流量拦截 │ → │ 业务理解 │ → │ 漏洞测试 │ → 报告   │
│   │(Playwr) │   │(mitmpr) │   │  (LLM)  │   │ (Agent) │           │
│   └─────────┘   └─────────┘   └─────────┘   └─────────┘           │
│   8 阶段状态机：P0→P0.5→P1→P1.5→P2a/2b→P2.55→P2.6→P3               │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                          CyberStrikeAI                              │
│   「AI-native 网络安全行动系统」 — 全场景平台                          │
│   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐          │
│   │  Eino  │ │  MCP   │ │  RAG   │ │  RBAC  │ │ IM Bot │          │
│   │ Agent  │ │ 工具层 │ │ 知识库 │ │ 审计   │ │ 集成   │          │
│   └────┬───┘ └────┬───┘ └────┬───┘ └────┬───┘ └────┬───┘          │
│        └──────────┴──────────┴─────┬────┴──────────┘              │
│                                   ▼                                  │
│   ┌──────────────────────────────────────────────────────┐          │
│   │   规划 / 执行 / 人在回路 / 证据 / 攻击链 / 重放       │          │
│   └──────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                          Cybermes                                   │
│   「MCP 化攻击面工具集 + Hermes Agent」 — 工具聚合                     │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐       │
│   │ Hermes  │ →  │  13+ AI │ →  │  200+   │ →  │  零误报 │       │
│   │ 推理    │    │  客户端 │    │ Playbook│    │  PoC    │       │
│   └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘       │
│        │              │              │              │              │
│   ┌────▼──────────────▼──────────────▼──────────────▼────┐         │
│   │  smart_pipe · secret_scan · search_knowledge         │         │
│   │  <50ms 本地知识库 · 200+ SOP · 反幻觉护栏            │         │
│   └─────────────────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 关键技术取舍

| 维度 | 玄鉴 | CyberStrikeAI | Cybermes |
|------|------|---------------|----------|
| **Agent 编排** | Python 手写状态机（chat_loop.py） | Go + Eino（Deep/Plan-Execute/Supervisor） | Hermes Agent（外置）+ MCP 工具 |
| **工具描述** | YAML 规则 + Python 注册函数 | YAML 工具配方（100+） + MCP 联邦 | Go 原生 CLI + MCP 服务器 |
| **去误报** | **检测层硬规则**（11 类铁律）+ LLM 审核员 | 人在回路审批 + 工具白名单 + 审计 Agent | **强制 PoC 执行** + 原始证据 |
| **多 Agent** | 3 个子 Agent 并行（Phase 2a） | 多模式（单/Deep/Plan-Execute/Supervisor） + 图工作流 | 单 Agent + 200+ SOP 技能 |
| **浏览器** | ✅ 深度集成 Playwright（手动登录、验证码 OCR、SPA 降级） | ✅ 截图分析（独立视觉模型，不存图） | ⚠️ 间接（通过 httpx/katana） |
| **流量代理** | ✅ mitmproxy 全量拦截 + 改包 | ⚠️ 通过 Burp 扩展集成 | ⚠️ 无原生代理 |
| **RAG** | ✅ 经验沉淀（memory.py） | ✅ 完整 RAG（改写→检索→重排→后处理） | ✅ 离线 <50ms 知识库（search_knowledge） |
| **知识来源** | 自建 SKILL 方法论 + 自训练经验 | 内置 RAG + 视觉模型分支 | HackTricks + PayloadsAllTheThings + Claude-BugHunter 上游 |
| **人在回路** | ⚠️ 弱（仅手动登录 + 验证码） | ✅ 强（审批模式 + 工具白名单 + 审计 Agent） | ⚠️ 弱（靠 scope.yaml） |
| **多用户** | ⚠️ 单用户 | ✅ RBAC 多用户多角色 | ⚠️ 单用户 |
| **IM 集成** | ❌ | ✅ 7 大平台（微信/企微/钉钉/飞书/TG/Slack/Discord/QQ） | ⚠️ Telegram 文档有 |
| **C2** | ❌ | ✅ 内置 C2（监听器/beacon/会话/任务队列） | ❌ |
| **WebShell** | ❌ | ✅ 虚拟终端 + AI 辅助 | ❌ |
| **多模态** | ✅ 验证码 OCR + JS 截图 | ✅ 独立视觉模型（截图/验证码/UI 识别） | ❌ |
| **跨平台** | ⚠️ 主要是 Linux/macOS（Playwright 全平台） | ✅ 全平台 + Docker | ✅ Windows/Linux/macOS/Docker |

---

## 四、核心能力对比

### 4.1 漏洞检测能力

| 漏洞类型 | 玄鉴 | CyberStrikeAI | Cybermes |
|---------|------|---------------|----------|
| **SQL 注入** | ✅ 内置 Fuzz 引擎（布尔盲注三层校验 + 时间盲注二次复现） | ✅ 集成 sqlmap | ✅ 集成 sqlmap |
| **XSS** | ✅ **13-step 专项引擎**（反射/存储/DOM + OOB + CSP 绕过 + LLM 辅助） | ✅ 集成 dalfox / xsser | ✅ playbook |
| **SSRF** | ✅ 检测 + OOB 带外验证 + 危害证明 | ✅ 工具集成 | ✅ playbook |
| **IDOR/越权** | ✅ | ✅ | ✅（专项 IDOR/BOLA/JWT/BPLA playbook） |
| **命令注入** | ✅ 特征收紧 | ✅ 工具集成 | ✅ |
| **未授权访问** | ✅ 业务错误码 + 空 data 过滤 | ✅ | ✅ |
| **CSRF** | ✅ Token 扩展识别 | ✅ | ✅ |
| **XXE / SSTI / 文件上传** | ✅ | ✅ | ✅ |
| **路径穿越** | ✅ WAF 拦截页识别 | ✅ | ✅ |
| **信息泄露** | ✅ 规则检测 | ✅ | ✅ |
| **验证码绕过** | ✅ OCR + 手动介入 | ⚠️ 视觉模型 | ❌ |
| **竞态条件** | ✅ 专项 Fuzz 引擎 | ⚠️ 工具集成 | ✅（专项 playbook） |
| **加密 API 突破** | ✅ **crypto_hook 加密回放**（独有） | ⚠️ 工具 | ⚠️ 工具 |
| **业务逻辑** | ✅ 业务理解阶段分析 | ✅ 角色 + 工具组合 | ✅ |
| **JS 深度分析** | ✅ js_analyzer.py（70KB） | ⚠️ Burp 集成 | ⚠️ katana 爬虫 |
| **目录扫描** | ✅ dir_scanner.py | ✅ 集成 dirb/gobuster/feroxbuster/ffuf | ✅ 集成 ffuf |
| **子域名枚举** | ❌（Web 端为主） | ✅ 集成 subfinder/amass/findomain | ✅ 集成 subfinder |
| **CVE 模板扫描** | ❌ | ✅ 集成 nuclei（100+ 模板） | ✅ nuclei（按需） |
| **网络端口扫描** | ❌ | ✅ nmap/masscan/rustscan | ❌ |
| **云安全** | ❌ | ✅ prowler/scout-suite/pacu | ❌ |
| **容器安全** | ❌ | ✅ trivy/clair/docker-bench | ❌ |
| **二进制分析** | ❌ | ✅ gdb/radare2/ghidra | ❌ |
| **密码破解** | ❌ | ✅ hashcat/john | ❌ |
| **取证分析** | ❌ | ✅ volatility/foremost | ❌ |
| **CTF 工具** | ❌ | ✅ cyberchef/stegsolve | ✅（含 HackTricks 知识） |

### 4.2 AI / Agent 能力

| 能力 | 玄鉴 | CyberStrikeAI | Cybermes |
|------|------|---------------|----------|
| **多 LLM 切换** | ✅ 10 个模型热切换 | ✅ openai_compatible（GPT-4o/DeepSeek/Qwen3-max） | ✅ 通过 MCP 客户端（13+ AI 客户端） |
| **Token 用量监控** | ✅ 内置监控模块 | ✅ 用量观测 | ⚠️ smart_pipe 流式优化 |
| **响应缓存** | ✅ `_response_cache.py` | ✅ | ⚠️ <50ms 离线知识库 |
| **技能体系** | ✅ SKILL 方法论（用户可自定义） | ✅ Agent Skills（按需加载） | ✅ 200+ 攻击性 Playbook |
| **角色系统** | ❌ | ✅ 12+ 预定义安全测试角色 + RBAC | ⚠️ 通过 .hermes 配置 |
| **多 Agent 协作** | ⚠️ 3 子 Agent 并行 | ✅ Deep/Plan-Execute/Supervisor/图工作流 | ⚠️ 单 Agent + Hermes |
| **经验沉淀** | ✅ 经验记忆 + 同类目标复用 | ✅ 运营证据保留 | ✅ 反幻觉护栏 + 知识库 |
| **RAG** | ✅ memory.py 经验库 | ✅ 完整 RAG 流程 | ✅ 离线 <50ms |
| **反幻觉** | ⚠️ 检测层硬规则（不靠 LLM） | ⚠️ 审计 Agent | ✅ 强反幻觉护栏（系统提示） |
| **业务理解** | ✅ Phase 0.5 业务理解 | ✅ 角色化提示词 | ⚠️ 间接 |
| **人机协作** | ⚠️ 手动登录 + 验证码 | ✅ 审批 + 白名单 | ⚠️ 弱 |

### 4.3 工程化能力

| 能力 | 玄鉴 | CyberStrikeAI | Cybermes |
|------|------|---------------|----------|
| **多会话** | ✅ 并发限制 | ✅ 资产/漏洞/任务/对话管理 | ✅ 目标隔离工作区 |
| **流量回放** | ✅ replay_api | ✅ | ❌ |
| **决策回放** | ✅ LLM 决策链追溯 | ✅ 攻击链重放 | ❌ |
| **日志回溯** | ✅ 完整 LLM + Agent 日志 | ✅ 审计日志 | ✅ recon/evidence |
| **报告模板** | ✅ 自定义模板 + 合规报告 | ✅ 多格式（HTML/PDF/JSON） | ✅ SUMMARY + metadata + HTML + PDF |
| **Burp 联动** | ✅ 原生 Burp 插件 | ✅ Burp 扩展 | ⚠️ 间接 |
| **浏览器扩展** | ❌ | ✅ Chrome/Edge 扩展 | ❌ |
| **REST API** | ✅ 19 个 FastAPI Router | ✅ | ⚠️ 弱（CLI 为主） |
| **Docker** | ✅ docker-compose | ⚠️ 文档提及 | ✅ docker-compose + GHCR 多架构 |
| **CI/CD** | ⚠️ | ⚠️ | ✅ ci.yml + mcp-release.yml |
| **健康检查** | ⚠️ | ⚠️ | ✅ doctor.py --fix |
| **跨平台启动器** | ⚠️ start.py | ✅ run.sh / upgrade.sh | ✅ cybermes.bat/.ps1/.sh + hermes |
| **配置管理** | ✅ .env + config_runtime | ✅ config.yaml | ✅ .hermes/config.yaml |

### 4.4 安全治理

| 能力 | 玄鉴 | CyberStrikeAI | Cybermes |
|------|------|---------------|----------|
| **认证** | ⚠️ auth_api | ✅ 完整认证 | ❌ |
| **RBAC** | ❌ | ✅ 多用户/角色/范围权限 | ❌ |
| **审计** | ✅ 决策回放 | ✅ 审计 Agent + 审计日志 | ⚠️ evidence 目录 |
| **工具白名单** | ❌ | ✅ 角色范围 | ✅ scope.yaml |
| **结果上限** | ❌ | ✅ 统一输出上限 | ✅ smart_pipe 落盘 |
| **风险评分** | ❌ | ✅ 漏洞 + 资产 + 攻击链 | ✅ 严重性分级 |
| **法律声明** | ✅ DISCLAIMER.md | ✅ SECURITY.md | ✅ README + scope.yaml |
| **合规报告** | ✅ 内置 | ⚠️ | ⚠️ |

---

## 五、典型使用场景对比

| 场景 | 最佳选择 | 理由 |
|------|---------|------|
| **企业 Web 应用 SRC 渗透** | 🥇 **玄鉴** | 浏览器驱动 + 流量拦截 + 业务理解 + 加密回放是国内 SRC 实战黄金组合 |
| **API 全自动化黑盒测试** | 🥇 **玄鉴** | Packet 模式 + 补测机制 + 假阳性铁律最契合 API 安全 |
| **授权漏洞赏金（Bug Bounty）** | 🥇 **Cybermes** | 零误报 PoC 闸 + 200+ Playbook + 反幻觉护栏专为赏金设计 |
| **多 AI 客户端接入** | 🥇 **Cybermes** | 13+ AI 客户端开箱即用（Claude/Cursor/Windsurf/Cline/Roo Code…） |
| **多 IM 入口（微信/钉钉/飞书）** | 🥇 **CyberStrikeAI** | 7 大 IM 平台原生集成，业界最广 |
| **基础设施安全（云/容器/二进制）** | 🥇 **CyberStrikeAI** | 唯一覆盖网络/云/容器/二进制/密码学的全栈平台 |
| **资产盘点 + 风险评分** | 🥇 **CyberStrikeAI** | 资产管理 + 攻击链建模 + 风险评分是平台独有 |
| **多用户/团队协作** | 🥇 **CyberStrikeAI** | RBAC + 角色 + 审计三件套唯一 |
| **WebShell / C2 后续** | 🥇 **CyberStrikeAI** | 内置 WebShell + C2（仅限授权场景） |
| **CTF / 漏洞研究** | 🥇 **CyberStrikeAI** + **Cybermes** | 两者都集成 CTF 工具集，Cybermes 有 HackTricks 知识库 |
| **Docker 一键部署** | 🥇 **Cybermes** | docker-compose + GHCR 多架构 + 自动安装器 |
| **Windows 原生体验** | 🥇 **Cybermes** | PowerShell 安装器 + 原生 Windows 体验最佳 |
| **离线知识库加速** | 🥇 **Cybermes** | <50ms 本地搜索 + 200+ SOP 业界最快 |
| **极致去误报** | 🥇 **玄鉴**（检测层硬规则）+ **Cybermes**（强制 PoC） | 两种范式互补 |
| **加密 API 突破** | 🥇 **玄鉴** | crypto_hook + 加密回放是独有杀手锏 |

---

## 六、差异化亮点提炼

### 6.1 玄鉴 XuanJian 独有优势

1. **「检测层假阳性铁律」**：在检测阶段（而非事后 LLM 裁决）执行硬规则过滤——这是国内 SRC 出品方打磨出来的实战经验，**真正能在 FAST 模式跳过 LLM 也能保证去误报**。Cybermes 走"强制 PoC 验证"路线，CyberStrikeAI 走"人在回路"路线，三种范式各有所长。
2. **「双轴正交扫描模式」**：扫描深度（FAST/STANDARD/DEEP/SMART）× 编排方式（Batch/Realtime/Packet）两维独立选择，覆盖从纯规则快扫到 LLM 全流程深扫的完整光谱。
3. **「加密回放 / crypto_hook」**：唯一对前端加密 API 提供系统性突破能力的项目，crypto_hook + crypto_engine 双模块是国内 SRC 的硬通货。
4. **「JS 深度分析器」**：70KB 的 js_analyzer.py 是国内 SRC 实战沉淀，配合 Playwright 能发现前端加密逻辑、白盒密钥、隐藏 API。
5. **「13-step XSS 专项引擎」**：反射/存储/DOM + OOB + CSP 绕过 + LLM 辅助判定，覆盖度业界第一梯队。
6. **「业务流程化状态机」**：8 阶段（Phase 0→0.5→1→1.5→2a/2b→2.55→2.6→3）配合业务理解 + 业务对账两个 LLM 深度介入点，是把 LLM 真正用在刀刃上的范式。
7. **「多入口联动」**：Web UI + Burp 插件 + REST API + SSE 实时反馈，渗透测试工程师工作流最顺滑。

### 6.2 CyberStrikeAI 独有优势

1. **「AI-native 行动系统」范式**：Eino 编排 + MCP 协议 + RAG + 治理审计五位一体，不是单点工具，而是平台操作系统。
2. **「MCP 三模式 + 联邦」**：HTTP / stdio / SSE + 外部联邦 + 动态工具发现，是 MCP 集成的标杆实现。
3. **「多 Agent 编排」**：Deep / Plan-Execute / Supervisor + 图工作流，是把 LLM 当成团队用的工程范式。
4. **「弹性工具执行」**：worker + 有限 Agent 等待 + execution_id 轮询 + 取消 + 熔断器 + 并发限制 + 输出上限——这是一套生产级分布式任务系统的设计。
5. **「治理优先」**：人在回路 + RBAC + 工具白名单 + 审计 Agent + 结果上限，是企业落地的关键。
6. **「攻防全杀伤链」**：侦察→漏洞→后渗透→WebShell→C2→取证→复盘，业内最完整。
7. **「7 大 IM 集成」**：微信/企微/钉钉/飞书/TG/Slack/Discord/QQ Bot 端到端，安全运营场景原生。

### 6.3 Cybermes 独有优势

1. **「MCP 原生 + 13 AI 客户端」**：NPM 一键安装，自动检测并配置所有已安装的 AI 客户端，是 MCP 落地速度最快的项目。
2. **「零误报 PoC 闸」**：强制要求独立、非破坏性 PoC 脚本 + 原始 HTTP 证据——这是赏金猎人真正能用的范式。
3. **「<50ms 离线知识库」**：search_knowledge 跨 HackTricks + PayloadsAllTheThings + 200+ SOP 做到 50ms 内查询，本地化速度领先。
4. **「smart_pipe Token 优化」**：原始日志落盘、只向 LLM 流式高信号内容，解决"日志淹没上下文"的痛点。
5. **「目标隔离工作区」**：每个 target 独立 `reports/<target_slug>/` 目录，杜绝跨任务污染。
6. **「跨平台原生 + Docker」**：Windows PowerShell 安装器 + Linux/macOS + Docker + GHCR 多架构，体验最丝滑。
7. **「反幻觉护栏」**：系统提示层强约束 + scope.yaml 范围控制 + 强制证据，是 LLM 滥用最严重的攻击性安全场景里最克制的设计。

---

## 七、技术债与风险

| 风险 | 玄鉴 | CyberStrikeAI | Cybermes |
|------|------|---------------|----------|
| **状态冻结** | ⚠️ v2.0 封板，新功能迁出 | ✅ 活跃 | ✅ 活跃但项目新（3 周） |
| **多用户/团队** | ❌ 单用户 | ✅ 完善 | ❌ 单用户 |
| **AI-native 安全（护栏/评测）** | ⚠️ 已迁出 JianWei | ⚠️ 无 | ⚠️ 无 |
| **规模** | 中型（core/ 212 文件） | 大型（cmd + internal + 100+ YAML） | 中型（Go + Python + MCP） |
| **后渗透/二进制** | ❌ | ✅ 强 | ❌ |
| **跨平台** | ⚠️ macOS/Linux 文档，Windows Playwright | ✅ 全平台 | ✅ 全平台（含 Windows 原生） |
| **依赖外部工具** | ⚠️ 无（自实现 Fuzz/扫描） | ⚠️ 重（100+ 工具需外部安装） | ⚠️ 重（subfinder/httpx/katana/sqlmap） |
| **依赖管理** | ✅ pyproject.toml | ✅ go.mod | ✅ go.mod + pyproject.toml + package.json |
| **CI/CD** | ⚠️ | ⚠️ | ✅ GitHub Actions |
| **可观测性** | ✅ LLM 用量监控 + 决策回放 | ✅ 审计日志 + 证据保留 | ⚠️ logs/ 目录 |
| **文档质量** | ✅ 中英 README + ARCHITECTURE + CHANGELOG | ✅ 双语 + 主题文档 | ✅ INSTALL/MCP/ROADMAP/troubleshooting |
| **活跃度** | ⚠️ 封板 | ✅ 2,220 commits | ✅ 125 commits（3 周） |

---

## 八、选型决策矩阵

### 场景 1：企业安全团队（10+ 人，多项目，多角色）

> **推荐：CyberStrikeAI 为主，玄鉴为辅**

- 主：CyberStrikeAI 的 RBAC + 角色 + 审计 + 7 大 IM + WebShell/C2 治理是多人协作必备
- 辅：玄鉴的 Web 渗透 Agent 在 SRC/渗透项目里仍是国内最强

### 场景 2：独立渗透测试工程师 / SRC 猎人

> **推荐：玄鉴 + Cybermes 双修**

- 玄鉴：Web 实战主力（浏览器 + 流量 + 加密回放）
- Cybermes：作为 MCP 服务器接到 Claude Desktop / Cursor 里加速

### 场景 3：漏洞赏金猎人

> **推荐：Cybermes 主力**

- 零误报 PoC 闸 + 200+ Playbook + 反幻觉护栏专为赏金设计
- 13+ AI 客户端支持可以把 Cybermes 当作"AI 的外挂大脑"

### 场景 4：AI 安全研究 / 平台自研

> **推荐：以 CyberStrikeAI 为蓝本**

- Eino 编排 + MCP 联邦 + 治理审计 + 多 IM 是最完整的 AI-native 安全平台架构
- 可借鉴其多 Agent 编排（图工作流）和弹性工具执行

### 场景 5：学生 / 入门学习

> **推荐：Cybermes 入门 → 玄鉴进阶 → CyberStrikeAI 平台视角**

- Cybermes 项目小、文档全、跨平台体验好，最适合学习 MCP + Agent 集成
- 玄鉴的代码组织（19 Router + core/ 子系统）是企业级 Python 项目的范本
- CyberStrikeAI 的 Eino + MCP + RBAC 是 Go 平台架构的范本

---

## 九、融合 / 借鉴路线建议（对玄鉴而言）

> 玄鉴 v2.0 已封板，但 JianWei 平台层可以吸收以下设计。

### 9.1 短期（季度级，可独立 PR）

1. **MCP 工具联邦**：把玄鉴的 FastScanner 检测能力、JS 分析、加密回放通过 MCP 暴露，参考 CyberStrikeAI 的三模式 + 联邦。
2. **目标工作区隔离**：参考 Cybermes 的 `reports/<target_slug>/` 结构，把当前 reports 目录从按 session_id 改为按 target 隔离。
3. **跨平台启动器**：补 Windows / macOS 原生 PowerShell / .sh 启动器与 setup 脚本（参考 Cybermes 的 cybermes.ps1 / cybermes.bat）。
4. **doctor.py 风格健康检查**：在 start.py 启动前自动检测浏览器内核、mitmproxy 证书、LLM Key、Playwright 依赖。

### 9.2 中期（半年级，平台层演进）

1. **"零误报 PoC 闸"借鉴**：在玄鉴的 PoC 生成基础上，加 PoC 执行 + 原始证据落盘的硬性约束，作为更高等级证据等级。
2. **反幻觉护栏借鉴**：在 LLM 提示词中引入 Cybermes 风格的"事实约束 + 范围控制 + 强制证据"模板。
3. **多 IM 入口**：通过 MCP 把 IM 客户端（钉钉/企微/飞书）接进来，参考 CyberStrikeAI 的设计。
4. **离线知识库加速**：把当前 memory.py 的 RAG 检索借鉴 Cybermes 的 <50ms 本地索引设计（可考虑 SQLite FTS5 或本地向量）。

### 9.3 长期（生态级）

1. **从"Web 渗透执行者"演进为"AI-native 安全操作系统"**：参考 CyberStrikeAI 的"规划+执行+人在回路+证据+重放"五位一体。
2. **多 Agent 协作 + 图工作流**：从当前 3 子 Agent 并行演进为 Eino 风格的图工作流。
3. **企业级 RBAC + 审计 + IM 集成**：补齐多人协作短板。
4. **从 Web 渗透扩展到云/容器/二进制**：参考 CyberStrikeAI 的"攻防全杀伤链"覆盖。

---

## 十、结论

- **玄鉴 XuanJian** 在 **Web/App 渗透执行** 维度仍是国内第一梯队（封板 v2.0 是成熟度体现），核心竞争力是 **浏览器+流量+LLM三位一体** 与 **检测层假阳性铁律**。
- **CyberStrikeAI** 是 **AI-native 安全操作系统** 的范本，核心竞争力是 **Eino+MCP+治理审计** 与 **攻防全杀伤链覆盖**；适合作为企业平台 / AI 安全研究的架构参考。
- **Cybermes** 是 **MCP 化攻击面工具集** 的新锐，核心竞争力是 **<50ms 离线知识库 + 零误报 PoC 闸 + 13+ AI 客户端**；适合作为漏洞赏金 / 个人安全工程师的加速器。

三者不是替代关系，而是 **执行者 / 平台 / 工具集** 三种范式的互补。玄鉴如要走得更远，建议在平台层（JianWei）吸收 CyberStrikeAI 的治理审计与 Cybermes 的离线知识库思路，同时把玄鉴的 Web 渗透执行力以 MCP 形式开放，反哺生态。

---

## 附录 A：参考资料

- 玄鉴 XuanJian：`F:\xuanjian-main\README.md` / `ARCHITECTURE.md`
- CyberStrikeAI：https://github.com/Ed1s0nZ/CyberStrikeAI
- Cybermes：https://github.com/Zyrexnn/Cybermes

## 附录 B：比较矩阵速查表（一页纸）

| 维度 \ 项目 | 玄鉴 XuanJian | CyberStrikeAI | Cybermes |
|------------|---------------|---------------|----------|
| **核心定位** | Web 渗透 Agent | AI-native 安全平台 | MCP 攻击面工具集 |
| **技术栈** | Python + Playwright + mitmproxy | Go + Eino + SQLite | Go + Python + MCP |
| **成熟度** | ⭐⭐⭐⭐⭐ 封板 | ⭐⭐⭐⭐⭐ 活跃 | ⭐⭐⭐ 新锐 |
| **Web 渗透** | ⭐⭐⭐⭐⭐ 业内最强 | ⭐⭐⭐ 工具集成 | ⭐⭐⭐ 工具集成 |
| **基础设施（云/容器/二进制）** | ❌ | ⭐⭐⭐⭐⭐ 唯一覆盖 | ❌ |
| **MCP 集成** | ⚠️ 自有 MCP | ⭐⭐⭐⭐⭐ 三模式 + 联邦 | ⭐⭐⭐⭐⭐ 13+ 客户端 |
| **去误报** | ⭐⭐⭐⭐⭐ 检测层铁律 | ⭐⭐⭐ 人在回路 | ⭐⭐⭐⭐⭐ 强制 PoC |
| **AI 编排** | ⭐⭐⭐ Python 状态机 | ⭐⭐⭐⭐⭐ Eino 多模式 | ⭐⭐⭐ Hermes + MCP |
| **多用户/团队** | ❌ | ⭐⭐⭐⭐⭐ RBAC | ❌ |
| **多 IM 集成** | ❌ | ⭐⭐⭐⭐⭐ 7 平台 | ⭐⭐ Telegram |
| **跨平台** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Docker** | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ GHCR 多架构 |
| **文档** | ⭐⭐⭐⭐ 中英 | ⭐⭐⭐⭐⭐ 双语 + 主题 | ⭐⭐⭐⭐ 详尽 |
| **可借鉴核心** | 检测层铁律 / 加密回放 / XSS 13-step | Eino 编排 / MCP 联邦 / 治理审计 | smart_pipe / <50ms 知识库 / 零误报 PoC |
