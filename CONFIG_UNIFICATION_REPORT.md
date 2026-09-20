# 配置值统一化变更报告

## 任务 1：修复 BROWSER_PROXY 默认端口不一致

### 问题描述
- `mcp_servers/browser_mcp.py:206` 使用 `http://127.0.0.1:18080`
- `web/api/system_api.py:39` 使用 `http://127.0.0.1:8080`

### 解决方案
统一使用 `http://127.0.0.1:18080`（匹配 MITM 代理端口）。

### 变更文件
1. **`d:\xuanjian-main\web\api\system_api.py`**
   - 第 39 行：`http://127.0.0.1:8080` → `http://127.0.0.1:18080`
   - 第 45 行：`parsed.port or 8080` → `parsed.port or 18080`

---

## 任务 2：集中化魔法数字常量

### 新增常量（`d:\xuanjian-main\core\config.py`）

```python
# ★ 响应截断阈值（统一管理，避免魔法数字）
MAX_RESPONSE_BODY_SIZE = 10000      # HTTP 响应体截断阈值（单次请求）
MAX_ERROR_MESSAGE_SIZE = 300        # 错误信息截断阈值
MAX_TOOL_RESULT = 6000              # 工具结果注入上下文前的截断阈值
MAX_API_DOC_SIZE = 500000           # API 文档最大尺寸（Swagger/GraphQL 等）
MAX_JS_FILE_SIZE = 500000           # JS 文件最大尺寸（Source Map/JS 审计）
MAX_REPORT_TEXT_SIZE = 80000        # 报告文本最大尺寸

# ★ 超时配置（统一管理）
DEFAULT_HTTP_TIMEOUT = 30.0         # 默认 HTTP 请求超时（秒）
DEFAULT_BROWSER_TIMEOUT = 60.0      # 默认浏览器操作超时（秒）
DEFAULT_TOOL_EXECUTION_TIMEOUT = 60.0  # 默认工具执行超时（秒）
HTTP_CONNECT_TIMEOUT = 8.0          # HTTP 连接超时（秒）
HTTP_PROXY_CHECK_TIMEOUT = 3.0      # 代理检查超时（秒）
BROWSER_PAGE_LOAD_TIMEOUT = 30000   # 浏览器页面加载超时（毫秒）
BROWSER_ELEMENT_WAIT_TIMEOUT = 5000 # 浏览器元素等待超时（毫秒）
```

---

## 变更文件汇总

### 1. `d:\xuanjian-main\core\config.py`
- 新增响应截断常量（7 个）
- 新增超时配置常量（7 个）

### 2. `d:\xuanjian-main\mcp_servers\mitm_addon.py`
- 导入 `MAX_RESPONSE_BODY_SIZE`
- 替换 `[:10000]` → `[:MAX_RESPONSE_BODY_SIZE]`（2 处）

### 3. `d:\xuanjian-main\mcp_servers\proxy_mcp.py`
- 导入 `MAX_RESPONSE_BODY_SIZE`, `DEFAULT_HTTP_TIMEOUT`, `MAX_ERROR_MESSAGE_SIZE`
- 替换超时常量：
  - `timeout=30` → `timeout=DEFAULT_HTTP_TIMEOUT`（6 处）
- 替换截断常量：
  - `[:10000]` → `[:MAX_RESPONSE_BODY_SIZE]`（5 处）
  - `[:2000]` → `[:MAX_ERROR_MESSAGE_SIZE]`（2 处）

### 4. `d:\xuanjian-main\mcp_servers\browser_mcp.py`
- 导入 `MAX_JS_FILE_SIZE`, `HTTP_PROXY_CHECK_TIMEOUT`, `MAX_RESPONSE_BODY_SIZE`
- 替换 `timeout=3` → `timeout=HTTP_PROXY_CHECK_TIMEOUT`
- 替换 `[:500000]` → `[:MAX_JS_FILE_SIZE]`

### 5. `d:\xuanjian-main\core\api_doc_discovery.py`
- 导入 `MAX_API_DOC_SIZE`, `HTTP_CONNECT_TIMEOUT`
- 替换超时常量：
  - `timeout=8` → `timeout=HTTP_CONNECT_TIMEOUT`（4 处）
- 替换截断常量：
  - `[:500000]` → `[:MAX_API_DOC_SIZE]`（4 处）

### 6. `d:\xuanjian-main\mcp_servers\custom_report_mcp.py`
- 导入 `MAX_REPORT_TEXT_SIZE`
- 替换 `[:80000]` → `[:MAX_REPORT_TEXT_SIZE]`

---

## 统计数据

| 类型 | 数量 |
|------|------|
| 新增配置常量 | 14 个 |
| 修改文件数 | 6 个 |
| 替换魔法数字 | 约 25 处 |

---

## 好处

1. **可维护性提升**：所有阈值和超时值集中在 `core/config.py`，修改时无需搜索整个代码库
2. **一致性保证**：同一配置在多处使用时，修改一处即可全局生效
3. **文档化**：每个常量都有注释说明用途，便于理解
4. **类型安全**：使用有意义的常量名而非数字，减少错误