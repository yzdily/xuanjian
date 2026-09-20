# PentestAgent Burp 插件

将 Burp Suite 中的 HTTP 请求发送到 PentestAgent，支持主动发送和被动扫描两种模式。

## 功能

- **右键菜单发送**：选中请求 → "Send to PentestAgent"，支持附加测试说明（如"重点测越权"）
- **被动扫描**：自动将代理流量发送到 Agent（智能去重 + 速率限制 + Scope 过滤 + 排队上限）
- **SSE 实时反馈**：流式接收检测进度（排队 → 检测中 → 各阶段 → 完成）
- **结果面板**：专用 Tab 页展示漏洞报告（Markdown 渲染 + 状态着色）
- **任务管理**：支持取消正在进行的扫描、重发历史任务、导出报告
- **配置持久化**：Agent URL / API Key / 被动开关 / Scope 过滤，重启 Burp 后自动恢复

## 被动扫描特性

- 可通过配置面板开关（默认关闭）
- 支持 Burp Target Scope 过滤（只扫描 Scope 内的请求）
- LRU 去重缓存（相同 method+path 只发送一次，最多 2000 条指纹）
- 速率限制（最少 2 秒间隔）
- 排队上限（最多 10 个被动任务同时排队，超出丢弃）
- 自动过滤静态资源（js/css/图片/字体等）
- 自动过滤无意义响应（3xx/4xx/5xx，保留 401/403）
- 路径归一化（数字 ID → `{id}`，提高去重效果）

## 安装

```bash
cd burp-plugin
./gradlew jar
# Burp Suite → Extender → Add → 选择 build/libs/pentestagent-burp-1.0.0.jar
```

## 配置

在 Burp Suite 的 PentestAgent Tab 页顶部配置栏修改：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| **Agent URL** | PentestAgent 服务地址 | `http://127.0.0.1:7788` |
| **API Key** | 接口认证密钥（可选） | 空 |
| **被动扫描** | 是否自动扫描代理流量 | 关闭 |
| **Scope Only** | 被动扫描是否只扫 Scope 内 | 开启 |

## API 端点

插件与后端通过以下接口通信：

- `POST /api/packet/scan` — 提交数据包（SSE 流式返回进度）
- `GET /api/packet/scan/{task_id}/result` — 查询最终结果
- `POST /api/packet/scan/{task_id}/abort` — 中止任务

## 技术栈

- Java 17 + Burp Montoya API
- OkHttp（SSE 客户端）
- Gson（JSON 解析）
