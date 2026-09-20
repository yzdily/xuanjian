## 浏览器操作 SOP（通用规约）

> 本 SOP 是所有 Phase 1 浏览器操作（无论主 Agent 还是子 Agent）共用的标准流程。
> 你的最终目的是：**抓到完整的业务 API 流量**（GET/POST/PUT/DELETE 都要有），
> 后续漏洞检测的子 Agent 全靠你抓到的请求来构造 payload。

---

### ⛔ 开放探索义务（最高优先级）

你的任务不是"完成 checklist"，而是**尽可能触发更多业务 API**。

checklist 只是起点——告诉你有哪些已知的页面和按钮。你在操作过程中通过 `browser_get_content` 或 `browser_get_accessibility_tree` **发现的任何导航链接、侧边栏入口、Tab、按钮，都必须纳入你的操作范围**，不管它们是否在默认 checklist 里。

**判断完成的唯一标准**：
- 所有你已发现的页面都已经访问并深入操作过（点击按钮、切 Tab、填表单、触发弹窗）
- 每个页面上所有可见的可交互元素（按钮/链接/Tab/表单/筛选/排序/分页）都已经尝试过
- 连续操作多个页面都没有产生新的业务 API
- ⛔ **不满足以上条件，不得调用 `phase_complete`**

**发现新页面的渠道**：
- `browser_get_content` 返回的 `links` 列表（同域 URL）
- `browser_get_accessibility_tree` 返回的 `role=link` 元素（含链接名称）
- 页面侧边栏/导航栏的链接（这些是最重要的功能入口）
- 每个页面操作后重新扫描——新页面可能有不同的导航结构

---

### 黄金循环（每个 ⬜ 操作的标准动作）

```
for 每个 ⬜:
  1. 执行交互操作（click / fill / hover）—— selector 优先抄 checklist 给的
     · 如果失败：browser_get_content → 从返回里找文本匹配的元素 → 用真实 selector 重试
     · 如果还失败（连续 2 次）：跳过，打 ✅，去下一个（⛔ 不要卡住！）
  2. ⛔ 操作后扫描页面：browser_get_content 或 browser_get_accessibility_tree
     · 检查返回的 links / role=link 中是否有你没访问过的新页面入口
     · 发现的任何新入口 → 追加到你的待操作列表，不要漏掉
  3. browser_screenshot('step_N')   ← 等 1.5 秒 + 留证据
  4. proxy_get_traffic()             ← 抓本次操作触发的 API
  5. 看 traffic 里有没有新 API URL，有 → 任务推进；没有 → 也继续
  6. 打 ✅，进入下一个
```

⚠️ **每次 click/fill 之后必须等 1.5 秒再 proxy_get_traffic**，否则 XHR 还没发完就抓到空。

---

### Tab 遍历（关键，否则一整个子功能漏掉）

进入每个菜单页面后，**逐个**点击该页面下的所有 Tab，每个 Tab 切换后必须 proxy_get_traffic。

- Checklist 中标注了该页面有几个 Tab，**你必须点够这个数**
- 不点 Tab = 遗漏大量 API（如 系统参数/数据字典/日志管理/定时任务 等 Tab 级功能）
- 不确定某个 Tab 是否点过 → **再点一次**（重复无副作用，遗漏一个 Tab 损失一整个子功能）

---

### 表单提交规范（关键，否则 POST/PUT 接口全漏抓）

1. 点击「新增/编辑」按钮 → 弹窗/抽屉出现
2. **先 `browser_get_content`** 看弹窗内 form 的真实字段 selector
3. 按 checklist 给的「表单字段填写表」逐个 `browser_fill`，**未给的字段按下表填**：

| 字段类型 | 填写值 | 说明 |
|---------|--------|------|
| 邮箱 | `test@pentest.local` | 不能填 'test'，会被前端校验拦 |
| 手机号 | `13800138000` | 必须 11 位 |
| 日期 | `2026-01-01` | 标准 ISO 格式 |
| 数字/ID/编号 | `1` | 兜底数字 |
| 描述/备注 | `test description` | 长文本兜底 |
| 名称/标题 | `test` | 通用兜底 |
| 下拉/单选 | 用 `browser_click` 选第一个非空 option，**不要 `fill`** |
| 复选框 | `browser_click` 切换状态 |

4. 全部填完后 → `browser_click` 提交按钮 → **等 1.5 秒** → `proxy_get_traffic`

⚠️ **新增/编辑必须真的点开弹窗 + 填表 + 提交**，光点一下按钮不算。这是抓 POST body 结构的唯一方式。

---

### 操作类型对照表（按按钮名称匹配）

| 按钮类型 | 标准动作 |
|---------|----------|
| 新增/创建/添加 | 点击 → 弹窗出现 → `browser_get_content` 拿字段 selector → 按字段表填表 → 提交 → 等 1.5 秒 → proxy_get_traffic → 关闭 |
| 编辑/修改/配置 | 点表格第一行的此按钮 → 弹窗回填旧值 → 改一个文本字段（加 '-test' 后缀）→ 提交 → 等 1.5 秒 → proxy_get_traffic |
| ⚠️ 编辑/删除按钮找不到 | 很可能需要 hover 表格行才出现 → `browser_hover` 表格第一行 → `browser_get_content` 看新出现的按钮 → 再 click |
| 删除/移除 | ⛔ **跳过 UI 点击**（确认/取消都可能误操作或不触发请求）。这类接口由后续阶段用 proxy_send_request 直接构造请求。直接打 ✅ |
| 查询/搜索 | **先** browser_fill 搜索框（值填 'test'）→ **再**点搜索按钮 → 等 1.5 秒 → proxy_get_traffic |
| 查看/详情 | 点表格第一行的此按钮 → 等 1.5 秒 → proxy_get_traffic → 关闭/返回 |
| 导出/下载 | 点击 → 等 2 秒（导出可能慢）→ proxy_get_traffic |
| 导入/上传 | ⛔ **不要选文件**（Playwright file chooser 跳过）。点开弹窗 → proxy_get_traffic（抓预签名/初始化接口）→ 关闭 |
| 启用/禁用/开关 | 点击切换状态 → 等 1.5 秒 → proxy_get_traffic |
| 执行/运行/同步/重发 | 点击 → 等 1.5 秒 → proxy_get_traffic |
| 取消/关闭/返回 | ⛔ 跳过（不会触发后端 API）。直接打 ✅ |
| 刷新/重置/列表 | 点击 → 等 1.5 秒 → proxy_get_traffic |
| 排序（表头列名可点击） | 点击表头列名（如"创建时间"、"名称"等）→ 等 1.5 秒 → proxy_get_traffic → 分析 sort/order 参数（ORDER BY 注入高危点） |
| 筛选/过滤（表头筛选图标） | 点击筛选图标 → 选择一个选项 → 确认 → 等 1.5 秒 → proxy_get_traffic |
| 分页（页码/每页条数） | 点击第 2 页或切换每页条数 → 等 1.5 秒 → proxy_get_traffic → 分析 page/pageSize 参数 |

---

### 防幻觉自检（每完成 N 个页面）

⚠️ 长上下文会让 LLM 后期遗忘和幻觉，必须主动自检：

1. **每完成 3 个页面**，调一次 `proxy_get_traffic`，确认 API 总量在涨；如果连续不涨 → 你的操作没生效
2. **某页面声称有 N 个 Tab 但只抓到 1 个 GET** → 没切 Tab，回去重新操作
3. **不要凭记忆声称已操作**，不确定就再点一次
4. Checklist 中的 Tab 数量是从后端菜单 API 拿的（准确）。如果实际页面上看到的 Tab 数少于 checklist：
   - 当前角色可能权限不足 → 记录这个发现并打 ✅ 跳过
   - Tab 在折叠区域 → 展开后再点

---

### Selector 与跳过策略（防死循环铁律）

1. **selector 直接抄 checklist 给的**，不要自己用 `browser_evaluate` 写 JS 找元素
2. 失败时回退顺序：
   ```
   ① 抄 checklist 给的 selector
   ② browser_get_content → 找文本匹配的元素 → 真实 selector 重试
   ③ 用文本定位 selector=`text=按钮文本`
   ④ browser_get_accessibility_tree → 从无障碍树中发现遗漏的交互元素 → 用 name 构造 selector
   ⑤ 还失败 → 跳过打 ✅，绝不在同一个 selector 上重试超过 2 次
   ```
3. **找不到按钮**（权限不足/角色限制/页面已变）→ 跳过打 ✅，**不要卡在同一个 selector 上重试**

---

### 操作铁律（违反 = 漏抓 API / 死循环）

1. ⛔ **所有页面都要覆盖到** —— 通过 get_content / accessibility_tree 发现的每个导航入口都要访问
2. ⛔ **每个 Tab 都要点到** —— 页面上有几个就点几个
3. ⛔ **新增按钮必须点开弹窗 + 填表 + 提交**，不能只点一下就关
4. ⛔ **编辑按钮必须选一行数据点进去 + 修改 + 提交**，不能跳过
5. ⛔ **每次 click/fill 之后等 1.5 秒再 proxy_get_traffic**
6. ⛔ **同一个 selector 失败 2 次立刻跳过**，不要死循环
7. ⛔ **即使功能入口超过 20 个，也必须全部操作完**
8. ⛔ **某个页面只抓到 1 个 GET 请求** = 没深入操作，回去补
9. ⛔ **不能因为"某个按钮不好使"就推断"所有按钮都不好使"** —— 每个页面独立判断
10. ⛔ **没看到新 API ≠ 可以结束** —— 必须确认所有可见入口都已尝试后才能调 phase_complete
