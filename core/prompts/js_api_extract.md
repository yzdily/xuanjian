分析以下 JS 代码片段，提取所有 API 端点调用。

这个 JS 文件来自 Web 应用的业务代码（可能是 minified/uglified 后的）。
你需要理解代码逻辑来找出正则表达式无法匹配的 API 调用，例如：

1. **minified 变量名**：`Kt.get("ticket/receipts/")` 实际上是 `axios.get()`
2. **baseURL 拼接**：如果代码中有 `axios.create({{baseURL: "weixin/api/"}})`，那么后续 `.get("ticket/receipts/")` 的完整路径是 `weixin/api/ticket/receipts/`
3. **相对路径 API**：不以 `/api` 开头的路径也可能是 API，如 `"ticket/receipts/"`、`"user/info"`
4. **间接调用**：通过封装函数调用的请求，如 `request({{url: "xxx"}})`、`http.post("xxx")`

**输出要求**：只输出一个 JSON 数组，每个元素格式：
```json
[
  {{
    "method": "GET",
    "path": "weixin/api/ticket/receipts/",
    "reason": "Kt=axios.create({{baseURL:'weixin/api/'}}), Kt.get('ticket/receipts/')"
  }}
]
```

- method: GET/POST/PUT/DELETE/PATCH/UNKNOWN
- path: 尽可能给出完整路径（含 baseURL 拼接）；如果无法确定 baseURL，给原始路径
- reason: 简短说明为什么这是 API 调用（含关键变量名/行号）
- 如果没找到任何 API，输出空数组 `[]`
- 不要输出 JSON 以外的任何文字

JS 代码片段（来自 {file_name}）：
```
{combined_code}
```