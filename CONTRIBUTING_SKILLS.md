# 贡献方法论 / Contributing a SKILL

玄鉴 XuanJian 以 **SKILL 方法论** 驱动，而非内置签名规则库。把你实战挖洞的经验写成可复用的 SKILL，是整个项目最欢迎的贡献方式——工具会随你的方法论一起变强。

XuanJian is driven by **SKILL methodologies**, not a built-in signature library. Encoding your real-world pentest experience as a reusable SKILL is the most welcome contribution — the agent grows with your methodology.

## 一个 SKILL 长什么样 / What a SKILL looks like

每个 SKILL 是一个目录，至少包含 `SKILL.md`：

Each SKILL is a directory containing at least a `SKILL.md`:

```
skills_my/discovery/builtin/_core/your-methodology/
└── SKILL.md          # 方法论本体（frontmatter + 正文）
```

`SKILL.md` 结构 / Structure:

```markdown
---
name: your-methodology
description: 一句话说明适用场景与触发条件（Agent 据此决定是否加载）
---

# 方法论标题

## 适用前提
...

## 测试步骤
1. ...
2. ...

## 判定标准（去误报）
...

## 参考
...
```

## 编写规范 / Authoring rules

- **frontmatter 必填** `name` / `description`；`description` 写清"什么时候用、测什么"，Agent 靠它做路由。
  Frontmatter **must** include `name` / `description`; the `description` should state *when to use it and what it tests* — the Agent routes on it.
- **步骤可执行**：每一步应是 Agent 能照做的具体动作，而非泛泛而谈。
  Steps must be actionable — concrete operations the Agent can follow, not vague advice.
- **明确去误报**：写明误报/假阳性判定条件（如业务错误码、空 data、WAF 拦截页）。
  State false-positive criteria explicitly (business error codes, empty `data`, WAF block pages…).
- **不放真实凭证**：SKILL 中不得包含任何 API Key、Cookie、目标域名/IP 等敏感信息。
  Never embed real secrets — no API keys, cookies, target domains/IPs.
- **语言**：中文、英文均可；示例一律用占位目标（如 `example.com`）。
  Chinese or English is fine; use placeholder targets (e.g. `example.com`) in examples.

## 放在哪 / Where to put it

| 目录 Directory | 含义 Meaning | 许可 License |
|------|------|------|
| `skills_my/discovery/builtin/` | 通用发现方法论 General discovery methodologies | MIT |
| `skills_my/discovery/personal/` | 个人/专项方法论 Personal / specialized | MIT |
| `skills_my/exploit/` | 利用/危害证明方法论 Exploitation / harm-proof | MIT |
| `skills_my/wooyun-legacy-main/` | Wooyun 历史漏洞库 Wooyun historical vuln library | **CC-BY-NC-SA-4.0（非商业 Non-Commercial）** |

> ⚠️ `wooyun-legacy-main/` 为第三方非商业内容，请勿在其中新增内容，也不要把商业用途内容混入。
> `wooyun-legacy-main/` is third-party non-commercial content — do not add to it, and do not mix in commercially-used content.

## 提交流程 / How to submit

1. Fork 本仓库，新建分支：`git checkout -b skill/your-methodology`
   Fork the repo and branch: `git checkout -b skill/your-methodology`
2. 在对应目录新建 SKILL 目录与 `SKILL.md`
   Create the SKILL directory and `SKILL.md` under the right path
3. 本地用 `--scan-mode` 跑一个目标验证 SKILL 能被正确加载与执行
   Validate locally that the SKILL loads and executes correctly against a target
4. 提交 PR，描述适用场景与验证结果
   Open a PR describing the use case and validation results

---

## 其他贡献 / Other contributions

- 🐛 **Issue**：bug 报告或功能建议 / bug reports or feature suggestions
- 🔧 **Pull Request**：代码改进、文档修正 / code improvements, doc fixes
- 📖 **方法论**：如上，把经验写成 SKILL / as above, encode experience as a SKILL

> 本仓库处于维护模式（v2.0 封板），新功能暂不接纳，仅 bugfix / 安全补丁 / 方法论贡献。
> This repo is in maintenance mode (v2.0 frozen); new features are not accepted — only bug fixes, security patches, and methodology contributions.
