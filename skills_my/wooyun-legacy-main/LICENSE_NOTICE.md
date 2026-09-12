# ⚠️ 许可证冲突声明 · wooyun-legacy

> **本目录内容为 CC-BY-NC-SA-4.0（非商业）许可证，与玄鉴 XuanJian 主项目的
> MIT License 冲突。** 本文件用于显式化冲突，避免误用。

## 许可证状态

| 项 | 许可证 | 商业使用 |
|---|---|---|
| 玄鉴 XuanJian 主项目（`core/`/`web/`/`mcp_servers/`/主 SKILL 库） | MIT | ✅ 允许 |
| **本目录 `skills_my/wooyun-legacy-main/`** | **CC-BY-NC-SA-4.0** | ❌ **禁止** |

来源：`.claude-plugin/marketplace.json:21` 声明 `"license": "CC-BY-NC-SA-4.0"`，
上游仓库 `https://github.com/tanweai/wooyun-legacy`。

## CC-BY-NC-SA-4.0 关键约束

- **NC（NonCommercial）**：禁止商业使用。任何商业产品/服务不得包含本目录内容。
- **SA（ShareAlike）**：衍生作品须以相同许可证 CC-BY-NC-SA-4.0 发布（不能转 MIT）。
- **BY（Attribution）**：须保留原作者署名（Tanwe Security Lab）。

## 使用边界

### ✅ 允许

- 个人学习、研究、内部安全测试参考本目录方法论。
- 非商业开源项目引用（须遵守 CC-BY-NC-SA-4.0，衍生作品同许可证）。

### ❌ 禁止

- 将本目录内容复制到玄鉴主 SKILL 库（`skills_my/discovery/`/`skills_my/exploit/` 等
  MIT 区域）——会污染主项目许可证。
- 商业产品/服务包含本目录内容。
- 去除本声明或原 marketplace.json 的许可证声明。

## 处置建议（待维护者决策）

本目录目前被 git 跟踪（149 文件），会随主仓库发布到公开 GitHub，造成
"MIT 仓库夹带 NC 内容"的合规风险。可选处置（任选其一，需维护者拍板）：

1. **隔离（推荐，低破坏）**：在 `.gitignore` 加 `skills_my/wooyun-legacy-main/`，
   `git rm --cached -r` 取消跟踪（本地文件保留），公开仓库不再含 NC 内容。
2. **重写为 MIT**：将方法论重写为 MIT 兼容表达，移除原 CC-BY-NC-SA 内容，注明灵感来源。
3. **移除**：直接删除本目录，主项目仅保留 MIT SKILL 库。

> 本文件本身以 MIT License 授权（声明文件，非 NC 内容）。
