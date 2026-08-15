"""
Tools — 统一工具定义

所有 OpenAI function calling 格式的工具声明集中在这里。
按用途分组，各模块按需取用。
"""
# noqa: giant

from __future__ import annotations


# ============================================================
# 浏览器工具
# ============================================================

BROWSER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "browser_goto",
            "description": (
                "用浏览器访问指定 URL。访问后页面会自动等待网络空闲。"
                "⚠️ 抓 SPA 路由切换的 API 时，goto 比点菜单更稳：直接 goto 目标 page_url 即可。"
                "调用后建议接 proxy_get_traffic 抓页面加载触发的接口。"
            ),
            "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_hover",
            "description": (
                "悬停（hover）到页面元素上，触发 hover 才出现的子菜单、操作按钮、下拉面板等。\n"
                "典型场景：表格行 hover 后出现的『编辑/删除』按钮、导航菜单 hover 展开子菜单。\n"
                "hover 后建议紧接 browser_get_content() 查看新出现的元素，再 browser_click 操作。"
            ),
            "parameters": {"type": "object", "properties": {"selector": {"type": "string"}}, "required": ["selector"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_click",
            "description": (
                "点击页面元素。selector 支持三种语法（按推荐顺序）：\n"
                "  ① CSS 选择器：`button.btn-add` / `[data-crawl-idx='12']`（最稳，Phase 0 爬虫输出的就是这种）\n"
                "  ② Playwright 文本：`text=新增` / `text=用户管理`（中文按钮可用）\n"
                "  ③ XPath：`//button[contains(.,'新增')]`（兜底）\n"
                "⚠️ 必读：\n"
                "  · 调用前**优先抄 checklist 上给的 selector**，不要自己用 browser_evaluate 写 JS 找元素。\n"
                "  · 找不到元素会抛错。**同一个 selector 失败 ≥ 2 次 → 立即跳过该步骤打 ✅**，不要无限重试。\n"
                "  · 点击后需要主动等待 1.5 秒（用 browser_screenshot 当作『等待+确认』也行），"
                "再调 proxy_get_traffic，否则异步 XHR 还没发完就抓到空。"
            ),
            "parameters": {"type": "object", "properties": {"selector": {"type": "string"}}, "required": ["selector"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_fill",
            "description": (
                "在输入框中填写内容（覆盖式 fill，会先清空再输入；不会自动按回车）。\n"
                "⚠️ 必读：\n"
                "  · 邮箱字段必须填合法邮箱（如 'test@pentest.local'），手机号必须 11 位（如 '13800138000'），"
                "否则前端校验会拦住，表单提交不出去 → 后端 API 漏抓。\n"
                "  · 下拉选择/单选/日期选择**不能用 fill**，要用 click 选 option。\n"
                "  · 富文本编辑器（contenteditable）也不能 fill，跳过。\n"
                "  · 填完所有字段后再点提交按钮，不要每填一个就提交。"
            ),
            "parameters": {
                "type": "object",
                "properties": {"selector": {"type": "string"}, "value": {"type": "string"}},
                "required": ["selector", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_get_content",
            "description": (
                "获取当前页面的可交互元素清单（forms/buttons/links/inputs）+ 文本摘要。"
                "**找不到 selector 时的首选工具**：返回里直接给你各元素的真实 selector，照抄即可。"
                "⚠️ 不要用它来读『页面上有什么数据』，只用它来『摸清可点击元素』。"
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_screenshot",
            "description": "截取当前页面截图（可用作『等待页面渲染完』的 barrier）",
            "parameters": {"type": "object", "properties": {"name": {"type": "string", "description": "截图文件名"}}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_get_accessibility_tree",
            "description": (
                "获取当前页面的无障碍树（Accessibility Tree），发现 DOM 提取遗漏的交互元素。"
                "当 browser_get_content 返回的按钮/链接很少（<5 个）时使用此工具作为补充。"
                "返回所有可交互节点（button/link/textbox/menuitem/tab 等）及其名称和角色。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "max_depth": {"type": "integer", "description": "遍历深度，默认 5", "default": 5}
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_get_cookies",
            "description": "获取当前浏览器的所有 Cookie",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_set_cookie",
            "description": "设置/替换 Cookie（用于切换用户身份测试越权）。⚠️ 设完通常需要 browser_goto 刷新一下才生效。",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Cookie 名称"},
                    "value": {"type": "string", "description": "Cookie 值"},
                    "domain": {"type": "string", "description": "Cookie 域名"},
                    "path": {"type": "string", "description": "Cookie 路径", "default": "/"},
                },
                "required": ["name", "value", "domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_evaluate",
            "description": (
                "在页面上下文中执行 JavaScript 并返回结果。"
                "⚠️ 仅用于读取数据（如 localStorage.getItem('token')、document.title），"
                "**不要用它来『找元素并点击』——找元素永远用 browser_get_content + browser_click**。"
                "不要写超过 3 行的复杂 JS。"
            ),
            "parameters": {
                "type": "object",
                "properties": {"js_code": {"type": "string", "description": "要执行的 JavaScript 代码（短，<=3 行）"}},
                "required": ["js_code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "js_extract_apis",
            "description": "列出当前页面加载的所有资源文件清单（JS/TS/JSON/Map/配置等，按类型分组+大小），供你根据渗透测试经验判断哪些值得深度分析。拿到清单后，选中有价值的文件调用 js_analyze_selected。",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "js_analyze_selected",
            "description": "对你选定的文件（JS/TS/JSON等）进行深度分析，提取 API 端点、密钥、WebSocket、baseURL 和 Source Map。先用 js_extract_apis 查看资源清单，再传入你判断有价值的 URL。",
            "parameters": {
                "type": "object",
                "properties": {
                    "js_urls_csv": {
                        "type": "string",
                        "description": "要分析的文件 URL，用逗号分隔"
                    }
                },
                "required": ["js_urls_csv"],
            },
        },
    },
]

# ============================================================
# HTTP 代理工具
# ============================================================

PROXY_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "proxy_get_traffic",
            "description": "获取最近的 HTTP 请求/响应流量记录",
            "parameters": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "description": "返回最近 N 条记录", "default": 20}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "proxy_replay",
            "description": "重放一个请求，可修改参数/Header/Body。⚠️ 默认继承原始 flow 的 Cookie/Authorization；做未授权测试时必须 drop_auth=true。",
            "parameters": {
                "type": "object",
                "properties": {
                    "flow_id": {"type": "string", "description": "要重放的流量 ID"},
                    "modifications": {
                        "type": "object",
                        "description": "要修改的内容，如 {\"body\": {\"user_id\": \"1002\"}}",
                    },
                    "drop_auth": {
                        "type": "boolean",
                        "description": "true=清掉原始 flow 的 Cookie/Authorization，做真正的无认证重放。做未授权访问测试时必须传 true。",
                        "default": False,
                    },
                },
                "required": ["flow_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "proxy_send_request",
            "description": "发送一个自定义 HTTP 请求（类似 Burp Repeater）。⚠️ 默认自动注入全局 Cookie/Authorization；做未授权测试时必须 drop_auth=true。",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]},
                    "url": {"type": "string"},
                    "headers": {"type": "object", "description": "自定义 Header"},
                    "body": {"type": "string", "description": "请求体"},
                    "drop_auth": {
                        "type": "boolean",
                        "description": "true=不注入全局认证头，请求真正以匿名身份发出。做未授权访问测试时必须传 true，否则返回的 200 其实是带认证态的结果。",
                        "default": False,
                    },
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "proxy_batch_send",
            "description": "并发发送多个相同/相似请求（用于竞态条件测试）。⚠️ 默认自动注入全局认证；做无认证并发测试时必须 drop_auth=true。",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                    "url": {"type": "string"},
                    "headers": {"type": "object", "description": "自定义 Header"},
                    "body": {"type": "string", "description": "请求体"},
                    "count": {"type": "integer", "description": "并发请求数量（默认 10，最大 50）", "default": 10},
                    "variations": {
                        "type": "array", "items": {"type": "object"},
                        "description": "每个请求的差异化参数",
                    },
                    "drop_auth": {
                        "type": "boolean",
                        "description": "true=本批所有请求都不带全局认证头。做未授权测试时必须传 true。",
                        "default": False,
                    },
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "proxy_diff_responses",
            "description": "对比两个响应的差异（用于越权检测）",
            "parameters": {
                "type": "object",
                "properties": {
                    "flow_id_a": {"type": "string"},
                    "flow_id_b": {"type": "string"},
                },
                "required": ["flow_id_a", "flow_id_b"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "proxy_get_flow_detail",
            "description": "获取某条流量的完整详情（含完整 Header 和 Body）",
            "parameters": {
                "type": "object",
                "properties": {"flow_id": {"type": "string", "description": "流量记录 ID"}},
                "required": ["flow_id"],
            },
        },
    },
]

# ============================================================
# 知识库工具
# ============================================================

KNOWLEDGE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "knowledge_search",
            "description": "从 Skills 知识库中搜索相关方法论",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "搜索关键词"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "knowledge_load_skill",
            "description": "加载一个完整的 SKILL.md 方法论到上下文",
            "parameters": {
                "type": "object",
                "properties": {"skill_name": {"type": "string", "description": "Skill 名称，如 idor-methodology"}},
                "required": ["skill_name"],
            },
        },
    },
]

# ============================================================
# 笔记/报告/目标工具
# ============================================================

NOTE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "note_add",
            "description": "记录一条笔记（info=资产信息, infer=推理分析, result=漏洞确认）",
            "parameters": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["info", "infer", "result"]},
                    "content": {"type": "string"},
                },
                "required": ["type", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "note_read",
            "description": "读取之前记录的所有笔记（可按类型过滤）",
            "parameters": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["info", "infer", "result", "all"]},
                },
            },
        },
    },
]

TARGET_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "target_check_scope",
            "description": "检查 URL 是否在授权测试范围内",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
]

REPORT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "report_generate",
            "description": "生成最终渗透测试报告。从 result 笔记中汇总漏洞发现，结合模板生成正式报告文件。",
            "parameters": {
                "type": "object",
                "properties": {
                    "report_type": {
                        "type": "string",
                        "enum": ["src", "pt"],
                        "description": "报告类型：src（SRC漏洞报告，每个漏洞独立）/ pt（渗透测试报告，完整评估）",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_check_template",
            "description": "检查是否有用户上传的自定义报告模版。在生成报告前调用，决定走自定义模版流程还是内置模版流程。",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_format_with_template",
            "description": "获取自定义报告模版内容和本次测试的结构化数据。返回模版原文+测试数据，你需要按模版格式组织报告后调用 report_save_formatted 保存。",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_save_formatted",
            "description": "保存按自定义模版格式化后的报告内容。将你按模版格式组织好的完整报告 Markdown 写入文件。",
            "parameters": {
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "按自定义模版格式组织好的完整报告内容（Markdown 格式）",
                    },
                },
                "required": ["content"],
            },
        },
    },
]

# ============================================================
# 漏洞验证工具
# ============================================================

VULN_VERIFY_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "vuln_verify",
            "description": "验证一个疑似漏洞是否真实存在",
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "漏洞类型"},
                    "description": {"type": "string", "description": "漏洞描述"},
                    "normal_flow_id": {"type": "string", "description": "正常请求的 flow_id"},
                    "attack_flow_id": {"type": "string", "description": "攻击请求的 flow_id"},
                    "verify_method": {
                        "type": "string",
                        "enum": ["response_diff", "status_code", "data_leak", "custom"],
                    },
                    "expected_evidence": {"type": "string", "description": "预期的漏洞证据"},
                },
                "required": ["vuln_type", "description", "verify_method", "expected_evidence"],
            },
        },
    },
]

# ============================================================
# 站点地图 / Checklist / 阶段控制工具
# ============================================================

SITEMAP_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "sitemap_add_page",
            "description": "向站点地图添加发现的页面",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string", "description": "这个页面的功能描述"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sitemap_add_feature",
            "description": "添加一个功能点到测试清单。需登录后台才能测试的功能请设 requires_auth=true。",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "功能点名称（二级功能，如'用户管理'、'角色分配'）"},
                    "description": {"type": "string", "description": "业务描述"},
                    "page_url": {"type": "string"},
                    "module": {"type": "string", "description": "所属模块层级，用 / 分隔多级。如'权限管理/用户管理'表示一级=权限管理、二级=用户管理。最末级功能用 name 字段表示。报告会按层级自动生成多级功能清单。"},
                    "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"],
                                 "description": "critical=涉及钱/权限/敏感数据, high=有可疑参数"},
                    "suggested_tests": {
                        "type": "array", "items": {"type": "string"},
                        "description": "你必须主动分析并填写建议测试的漏洞类型（必填）。分析思路：1)有用户输入→SQL注入+XSS(无论GET/POST) 2)分页/排序参数→SQL注入(ORDER BY注入) 3)操作他人资源→IDOR越权 4)创建/修改→SQL注入+Mass Assignment+CSRF 5)金额/积分→金额篡改+竞态。示例: ['SQL注入','IDOR越权','未授权访问']",
                    },
                    "requires_auth": {
                        "type": "boolean", "default": False,
                        "description": "是否需要登录后才能测试",
                    },
                },
                "required": ["name", "description", "priority"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sitemap_set_business",
            "description": "设置业务类型摘要和技术栈",
            "parameters": {
                "type": "object",
                "properties": {
                    "business_summary": {"type": "string", "description": "业务类型描述"},
                    "tech_stack": {"type": "string", "description": "技术栈"},
                },
                "required": ["business_summary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sitemap_get_coverage",
            "description": "获取当前测试覆盖率、未测试功能点列表、以及覆盖矩阵",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sitemap_activate_deferred",
            "description": "突破登录后调用：激活所有被延迟的后台功能点",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sitemap_report_discovery",
            "description": "测试过程中发现了新的 API 端点或功能入口时调用。系统自动判断：归入已有功能点 or 创建新功能点加入测试队列。发现任何未在 checklist 中的接口都应该上报。",
            "parameters": {
                "type": "object",
                "properties": {
                    "api_or_url": {"type": "string", "description": "发现的 API，如 'GET /api/admin/users' 或完整 URL"},
                    "description": {"type": "string", "description": "这个接口做什么"},
                },
                "required": ["api_or_url"],
            },
        },
    },
]

CHECKLIST_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "checklist_mark",
            "description": "标记当前功能点的某项测试完成。如果 result=vulnerable，必须同时填写 severity、reproduce_steps、fix_suggestion。\n\n"
                "★ 2026-05 改造：标 not_vuln/skipped 时，detail 必须按对应 SKILL 末尾的「最低必测自检清单」逐条交账，"
                "不允许用「业务正常」/「无入口」/「受 X 保护」这种笼统话术。",
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "漏洞类型"},
                    "result": {
                        "type": "string",
                        "enum": ["vulnerable", "not_vuln", "skipped", "needs_review"],
                    },
                    "detail": {
                        "type": "string",
                        "description": "测试结论详细说明。必须 ≥ 80 字，且按以下格式组织：\n"
                            "- result=vulnerable: ① 漏洞现象 ② 测试请求/关键响应 ③ 影响范围\n"
                            "- result=not_vuln/skipped: 必须按对应 SKILL 末尾「最低必测自检清单」逐条说明你做了什么。"
                            "示例: '试了①path ID 替换(返回403)②include 参数(无回显)③batch 接口(无)④CSRF 抓 token PUT 试 Mass Assignment(返回 invalid_field)。结论：所有路径已穷尽'\n"
                            "- result=needs_review: 说明疑似漏洞的现象，以及为什么暂不能确认（需要补什么条件才能确认）"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "漏洞等级（仅 result=vulnerable 时必填）。定级标准：\n"
                            "- critical: 可直接获取服务器权限、批量获取全部用户数据、任意用户接管、支付金额篡改为0\n"
                            "- high: 单用户数据越权访问（IDOR）、垂直权限提升、SQL注入有数据回显、存储型XSS影响管理员\n"
                            "- medium: 需用户交互的漏洞（反射型XSS/CSRF）、低影响信息泄露（非核心业务数据）、非关键功能越权\n"
                            "- low: 用户名枚举、目录遍历无敏感文件、缺少安全Header、详细错误信息泄露、Cookie缺少标志位\n"
                            "⚠️ 不要夸大等级！响应中出现手机号/邮箱但属于当前用户自己的数据=不算泄露。仅枚举到用户名但无法获取其他数据=low。"
                    },
                    "reproduce_steps": {
                        "type": "string",
                        "description": "复现步骤（仅 result=vulnerable 时必填）。用换行分隔的有序步骤，例：\n"
                            "'1. 以普通用户 luhan 登录，获取 Token\\n"
                            "2. 发送 GET /api/user/detail?id=7 返回自己的信息\\n"
                            "3. 修改 id=1，发送 GET /api/user/detail?id=1\\n"
                            "4. 返回管理员 admin 的完整个人信息（手机号、邮箱）'"
                    },
                    "fix_suggestion": {
                        "type": "string",
                        "description": "修复建议（仅 result=vulnerable 时必填）。针对性的修复方案，例：\n"
                            "'1. 服务端接口增加数据归属校验，确认请求的 id 属于当前登录用户\\n"
                            "2. 使用不可预测的 UUID 替代自增整数 ID\\n"
                            "3. 敏感字段（手机号、邮箱）在非必要场景下做脱敏处理'"
                    },
                    "evidence_flow_id": {"type": "string", "description": "漏洞证据的 flow_id（发送测试请求后从 proxy_get_traffic 中获取）"},
                    "tested_hypotheses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "（可选）本次测试覆盖了业务理解中哪些攻击假设的 ID，例：[\"ATH-01\", \"ATH-03\"]。用于 reconcile 阶段对账。"
                    },
                    "broken_promises": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "（可选，仅 vulnerable 时填）本漏洞打破了哪些系统承诺的 ID，例：[\"PROM-01\"]。用于危害验证阶段评估严重程度。"
                    },
                },
                "required": ["vuln_type", "result", "detail"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "checklist_view",
            "description": "查看当前功能点的测试 checklist",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]

PHASE_CONTROL_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "phase_complete",
            "description": "标记当前阶段完成，进入下一阶段",
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string", "description": "本阶段总结"}},
                "required": ["summary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "done",
            "description": "结束本轮渗透，给出总结",
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
            },
        },
    },
]

WORKER_DONE_TOOL = {
    "type": "function",
    "function": {
        "name": "worker_done",
        "description": "所有 checklist 项都处理完后调用，结束当前功能点测试",
        "parameters": {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
        },
    },
}

# ============================================================
# 加密工具（集成 CryptoHook 浏览器插件）
# ============================================================

CRYPTO_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "crypto_detect",
            "description": "检测目标网站是否有前端加密，并从 CryptoHook 浏览器插件读取已 hook 到的密钥/算法。"
                           "返回加密配置（algorithm、key、iv、mode）。如果插件未安装或未 hook 到密钥则返回空。"
                           "在 Phase 1 分析阶段调用，发现加密后会自动注册到系统中，Phase 2 子 Agent 可用 crypto_encrypt/crypto_decrypt。",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "crypto_encrypt",
            "description": "用目标网站的加密方式加密数据。需要先调用 crypto_detect 检测并注册加密配置。"
                           "用于测试 SQL注入/XSS 等时，先加密 payload 再发送。",
            "parameters": {
                "type": "object",
                "properties": {
                    "plaintext": {"type": "string", "description": "要加密的明文（如 SQL注入 payload）"},
                    "config_index": {"type": "integer", "description": "加密配置索引（默认 0，即第一个检测到的配置）", "default": 0},
                },
                "required": ["plaintext"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "crypto_decrypt",
            "description": "用目标网站的加密方式解密数据。用于解密服务端返回的加密响应。",
            "parameters": {
                "type": "object",
                "properties": {
                    "ciphertext": {"type": "string", "description": "要解密的密文"},
                    "config_index": {"type": "integer", "description": "加密配置索引（默认 0）", "default": 0},
                },
                "required": ["ciphertext"],
            },
        },
    },
]

# ============================================================
# 组合集合
# ============================================================

# ============================================================
# 经验教训记忆工具（Hermes 风格 — 从用户纠正中学习）
# ============================================================

MEMORY_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "record_lesson",
            "description": (
                "把刚刚从用户纠正/反思中学到的经验沉淀到长期记忆，下次同类场景会自动召回。\n"
                "什么时候应该调用：①用户明确指出你判断错误并讲清了正确做法 "
                "②你自己在多轮验证后发现某个先前结论是误报且可以总结成规则 "
                "③用户一句话说出了通用经验（如\"凡是返回里只有 success:true 的不算 IDOR\"）。\n"
                "**好教训的标准**：可操作、有触发条件、避免空话；不要把单次现象写成教训。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "enum": ["global", "host", "path", "vuln_type"],
                        "description": "作用域：global=所有目标都适用; host=只对某个域名; path=某个 URL 路径(支持*通配); vuln_type=某种漏洞类型",
                    },
                    "scope_value": {
                        "type": "string",
                        "description": "scope=host 填域名(example.com); scope=path 填 /api/x 或 /api/x/*; scope=vuln_type 填 sql_injection 等; scope=global 留空",
                    },
                    "trigger": {
                        "type": "string",
                        "description": "触发关键词，2-5 个，空格分隔（用于检索匹配，如 'login form 验证码 brute_force'）",
                    },
                    "lesson": {
                        "type": "string",
                        "description": "一句话经验：先说现象/陷阱，再说怎么做才对。例：'登录接口返回 200+success:false 不等于成功，必须看后续 /me 接口的 401 才能判定弱密码失败'",
                    },
                    "evidence": {
                        "type": "string",
                        "description": "可选：贴一段误判的原始证据片段（请求/响应/工具输出截取，<=500字）",
                    },
                },
                "required": ["scope", "lesson"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "recall_lessons",
            "description": (
                "主动检索历史经验。一般无需手动调用 —— 系统会在每轮 LLM 推理前自动注入相关经验。"
                "只有当你怀疑某个判断可能踩过坑时再调用做交叉确认。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "当前测试目标 URL，用于按 host/path 过滤"},
                    "vuln_type": {"type": "string", "description": "漏洞类型，如 sql_injection / idor / xss"},
                    "query": {"type": "string", "description": "查询关键词，空格分隔"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "forget_lesson",
            "description": "删除一条不再适用的旧经验（需提供 lesson_id）。仅在用户明确要求遗忘或经验已被推翻时使用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "lesson_id": {"type": "string", "description": "教训 ID（lsn_ 开头）"},
                },
                "required": ["lesson_id"],
            },
        },
    },
]


# 主 Agent 全量工具集
ALL_MAIN_TOOLS = (
    BROWSER_TOOLS + PROXY_TOOLS + KNOWLEDGE_TOOLS + NOTE_TOOLS +
    TARGET_TOOLS + REPORT_TOOLS + VULN_VERIFY_TOOLS +
    SITEMAP_TOOLS + CHECKLIST_TOOLS + PHASE_CONTROL_TOOLS +
    CRYPTO_TOOLS + MEMORY_TOOLS
)

# 子 Agent 可用工具名白名单
WORKER_ALLOWED_TOOL_NAMES = {
    "proxy_send_request", "proxy_replay", "proxy_get_traffic",
    "proxy_get_flow_detail", "proxy_batch_send", "proxy_diff_responses",
    "knowledge_search", "knowledge_load_skill",
    "note_add", "note_read",
    "sitemap_report_discovery",  # 动态发现新 API
    "crypto_encrypt", "crypto_decrypt",  # 加解密
}

# ============================================================
# BrowseWorker（Phase 1 浏览器操作子 Agent）专用工具白名单
# ★ 2026-05-25：BrowseWorker 是"按 checklist 点击 + 抓流量"型 agent，
#   工具集要尽量收窄，避免它跑题去做 JS 分析、添加功能点等不该做的事。
#   原本靠 prompt "⛔ 严格禁止" 这种弱约束，能力一般的 LLM 不靠谱，
#   现在直接在工具白名单层面砍掉。
# ============================================================
BROWSE_WORKER_ALLOWED_TOOL_NAMES = {
    # 浏览器：进入页面 + 看页面 + 点击 + 悬停 + 填写 + 截图 + 无障碍树
    "browser_goto",
    "browser_get_content",
    "browser_get_accessibility_tree",
    "browser_screenshot",
    "browser_click",
    "browser_hover",
    "browser_fill",
    # 流量：唯一目的就是抓流量
    "proxy_get_traffic",
    # 阶段控制：BrowseWorker 完成本组用 phase_complete
    "phase_complete",
    # 备忘：偶尔记关键发现
    "note_add",
}


def build_browse_worker_tools() -> list[dict]:
    """构建 BrowseWorker 子 Agent 的工具集。

    只暴露：browser_*（goto/get_content/screenshot/click/fill）+ proxy_get_traffic
          + phase_complete + note_add。
    禁掉：browser_evaluate（容易写跑偏的 JS）、js_extract_apis/js_analyze_selected
         （Phase 0 已做完）、sitemap_*（功能点由主 Agent 统一处理）、proxy_send_request
         （BrowseWorker 只点不打）、checklist_*（BrowseWorker 不评漏洞）。
    """
    pool = (BROWSER_TOOLS + PROXY_TOOLS + NOTE_TOOLS +
            PHASE_CONTROL_TOOLS)
    return [
        t for t in pool
        if t.get("function", {}).get("name") in BROWSE_WORKER_ALLOWED_TOOL_NAMES
    ]

# 浏览器工具名集合（需在主 event loop 中 await 的工具）
BROWSER_TOOL_NAMES = {
    "browser_goto", "browser_click", "browser_hover", "browser_fill",
    "browser_get_content", "browser_get_accessibility_tree",
    "browser_screenshot", "browser_get_cookies", "browser_set_cookie",
    "browser_evaluate", "js_extract_apis", "js_analyze_selected",
}


def build_worker_tools() -> list[dict]:
    """构建子 Agent 工具集：HTTP + 知识库 + checklist + 动态发现 + 加解密 + worker_done。"""
    allowed_tools = [t for t in (PROXY_TOOLS + KNOWLEDGE_TOOLS + NOTE_TOOLS + SITEMAP_TOOLS + CRYPTO_TOOLS)
                     if t.get("function", {}).get("name") in WORKER_ALLOWED_TOOL_NAMES]
    return allowed_tools + CHECKLIST_TOOLS + [WORKER_DONE_TOOL]
