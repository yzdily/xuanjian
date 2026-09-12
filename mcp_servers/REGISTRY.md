# 玄鉴 MCP 工具联邦

> **维护**：当任一 mcp_servers/*_mcp.py 增删/改名/换命名时，同步更新本文档。
> **更新日期**：2026-08-28（S1 短期落地首版）

---

## 命名规范

内部模块 `core/<layer>/<module>.py` ↔ MCP 工具名 `mcp__xuanjian__<capability>_<verb>`

- capability：业务域（sqli / bola / waf / scan / report / coverage）
- verb：动作（scan / probe / identify / render / matrix / sequence / verify）

格式校验正则：`^[a-z]+(_[a-z]+)*$`

---

## 注册表

| 内部模块 | MCP 工具名 | 暴露能力 | 文件 | 状态 |
|----------|-----------|----------|------|------|
| `core/fuzz/sqli.py` | `mcp__xuanjian__sqli_scan` | UNION/Boolean/Time 三型 SQLi 扫描 | `mcp_servers/sqli_mcp.py` | ✅ S1 新建 |
| `core/fuzz/sqli.py` | `mcp__xuanjian__sqli_verify` | SQLi 注入 + WAF 绕过验证 | `mcp_servers/sqli_mcp.py` | ✅ S1 新建 |
| `core/authz/bola_probe.py` | `mcp__xuanjian__bola_probe` | BOLA 双身份对照 | `mcp_servers/bola_mcp.py` | ✅ S1 新建 |
| `core/authz/bola_probe.py` | `mcp__xuanjian__bola_sequence` | ±N 顺序遍历序列生成 | `mcp_servers/bola_mcp.py` | ✅ S1 新建 |
| `core/parallel/orchestrator.py` | `mcp__xuanjian__target_add_scope` | 添加授权范围 | `mcp_servers/target_mcp.py` | ✅ v1.6 已有 |
| `core/parallel/orchestrator.py` | `mcp__xuanjian__target_check_scope` | 检查 URL 是否在授权范围 | `mcp_servers/target_mcp.py` | ✅ v1.6 已有 |
| `core/session/report_mixin.py` | `mcp__xuanjian__render_report` | 渲染报告 | `mcp_servers/report_mcp.py` | ✅ v1.6 已有 |
| `core/coverage_ledger.py` | `mcp__xuanjian__coverage_matrix` | 漏洞类型×端点矩阵 | `mcp_servers/custom_report_mcp.py` | ✅ v1.6 已有 |
| `core/fuzz/proxy.py` | `mcp__xuanjian__proxy_start` | 启动 mitmproxy 代理 | `mcp_servers/proxy_mcp.py` | ✅ v1.6 已有 |
| `core/browser/` | `mcp__xuanjian__browser_action` | 浏览器自动化（具体 tool 名以 server 源码为准） | `mcp_servers/browser_mcp.py` | ✅ v1.6 已有 |
| `core/notes/` | `mcp__xuanjian__note_add` | 笔记/记录（具体 tool 名以 server 源码为准） | `mcp_servers/note_mcp.py` | ✅ v1.6 已有 |
| `data/knowledge/` | `mcp__xuanjian__knowledge_lookup` | 知识库查询（具体 tool 名以 server 源码为准） | `mcp_servers/knowledge_mcp.py` | ✅ v1.6 已有 |
| `mitmproxy addon` | `mcp__xuanjian__addon_event` | mitmproxy 拦截 addon（具体 tool 名以 server 源码为准） | `mcp_servers/mitm_addon.py` | ✅ v1.6 已有 |

**合计**：13 项 MCP 工具 / 10 个 server 文件（2 新 + 8 已有）。

---

## 依赖说明

- `mcp>=1.0.0` 与 `fastmcp>=0.5.0` 已在 `pyproject.toml` 声明
- 缺 mcp 库时 sqli_mcp/bola_mcp 自动降级为 stub（所有 tool 抛 RuntimeError）
- 回滚开关：`XUANJIAN_MCP_DISABLED=1` → sqli/bola 整体退化为 stub

---

## 集成检查

```bash
# 1. REGISTRY 完整性
python -m pytest tests/integration/test_mcp_registry.py -v

# 2. 启动一个 server（需要 mcp 库）
python -m mcp_servers.sqli_mcp

# 3. inspector（外部工具）调通
mcp-inspector python -m mcp_servers.sqli_mcp
```

---

*本注册表为 2026-08-28 短期 S1 落地首版；后续 M1–M4 增项需同步更新本表。*
