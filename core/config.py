"""
Config — 集中管理所有配置常量

将原本散落在 sitemap.py / server.py 中的映射表、关键词集合统一到这里，
方便维护和外部配置化。
"""

from __future__ import annotations


# ---- 功能点 → 漏洞类型映射表 ----
# key = 关键词组, value = 应测试的漏洞类型列表
FEATURE_VULN_MAPPING: list[tuple[list[str], list[str]]] = [
    # 认证相关
    (["登录", "login", "signin", "sign_in"],
     ["SQL注入", "用户枚举", "验证码绕过", "Cookie/JWT安全", "弱密码/默认密码",
      "JS代码审计(硬编码密钥/绕过逻辑/敏感信息)", "密码重置逻辑"]),
    (["注册", "register", "signup", "sign_up"],
     ["用户枚举", "Mass Assignment", "短信轰炸", "验证码绕过"]),
    (["密码重置", "找回密码", "forgot", "reset_password", "reset-password"],
     ["密码重置逻辑", "Host头投毒", "验证码绕过", "Token可预测"]),
    (["oauth", "sso", "第三方登录", "微信登录", "qq登录"],
     ["OAuth劫持", "redirect_uri绕过", "state缺失"]),

    # 数据操作
    (["个人信息", "个人中心", "profile", "用户信息", "account", "设置"],
     ["IDOR越权", "CSRF", "Mass Assignment", "信息泄露"]),
    (["订单", "order", "交易", "transaction"],
     ["IDOR越权", "金额篡改", "状态篡改", "越权查看"]),
    (["搜索", "search", "查询", "query", "筛选", "filter"],
     ["XSS", "SQL注入", "信息泄露"]),
    (["评论", "留言", "反馈", "comment", "feedback", "message", "站内信", "通知"],
     ["存储型XSS", "IDOR越权"]),
    (["地址", "address", "收货"],
     ["IDOR越权", "CSRF"]),

    # 业务流程
    (["支付", "pay", "checkout", "结算", "下单", "购买", "purchase"],
     ["金额篡改", "数量篡改", "订单替换", "支付回调伪造", "竞态条件"]),
    (["优惠券", "coupon", "折扣", "discount", "红包", "积分", "兑换", "redeem"],
     ["重复使用", "并发领取", "枚举遍历", "金额篡改"]),
    (["余额", "钱包", "充值", "提现", "转账", "balance", "wallet", "withdraw", "transfer"],
     ["竞态条件", "金额篡改", "越权操作"]),

    # 文件操作
    (["上传", "upload", "头像", "avatar", "附件", "attachment", "导入", "import"],
     ["文件上传绕过", "XXE"]),
    (["导出", "export", "下载", "download", "报告生成", "pdf"],
     ["越权导出", "信息泄露", "PDF注入/SSRF"]),
    (["编辑器", "editor", "富文本", "tinymce", "ckeditor", "ueditor"],
     ["存储型XSS", "文件上传绕过"]),

    # URL/参数相关
    (["预览", "preview", "截图", "screenshot", "代理", "proxy", "webhook"],
     ["SSRF"]),
    (["跳转", "redirect", "回调", "callback", "return_url", "分享"],
     ["开放重定向"]),

    # API/管理
    (["管理", "admin", "后台", "manage", "dashboard", "控制台"],
     ["未授权访问", "垂直越权", "弱密码"]),
    (["api", "接口", "graphql"],
     ["未授权访问", "IDOR越权", "信息泄露"]),

    # 验证码
    (["验证码", "captcha", "短信", "sms", "邮件验证"],
     ["验证码绕过", "短信轰炸"]),

    # ★ B 端后台管理系统高频功能（管理后台、CMS、ERP、OA 等）
    (["列表", "分页", "page", "list", "查询", "筛选"],
     ["SQL注入", "信息泄露", "未授权访问"]),
    (["新增", "创建", "添加", "新建", "create", "add", "save"],
     ["SQL注入", "CSRF", "Mass Assignment", "未授权访问"]),
    (["编辑", "修改", "更新", "update", "edit", "modify"],
     ["IDOR越权", "SQL注入", "CSRF", "Mass Assignment", "未授权访问"]),
    (["删除", "remove", "delete", "批量删除", "batch"],
     ["IDOR越权", "CSRF", "未授权访问"]),
    (["详情", "detail", "info", "view", "查看"],
     ["IDOR越权", "信息泄露", "未授权访问"]),
    (["配置", "设置", "config", "setting", "参数"],
     ["未授权访问", "垂直越权", "信息泄露"]),
    (["日志", "log", "audit", "审计", "操作记录"],
     ["信息泄露", "未授权访问"]),
    (["字典", "dict", "enum", "枚举", "类型"],
     ["未授权访问", "信息泄露"]),
    (["任务", "job", "task", "定时", "调度", "cron", "schedule"],
     ["未授权访问", "垂直越权", "命令注入"]),
    (["用户", "user", "账号", "account", "成员", "member"],
     ["IDOR越权", "垂直越权", "信息泄露", "未授权访问"]),
    (["角色", "role", "权限", "permission", "授权"],
     ["垂直越权", "未授权访问", "IDOR越权"]),
    (["部门", "dept", "组织", "org", "团队", "team"],
     ["IDOR越权", "未授权访问", "信息泄露"]),
    (["模板", "template", "样板"],
     ["IDOR越权", "未授权访问", "SSTI"]),
    (["审核", "review", "审批", "approve", "reject"],
     ["IDOR越权", "状态篡改", "垂直越权", "未授权访问"]),
    (["同步", "sync", "推送", "push", "通知", "notify"],
     ["未授权访问", "SSRF"]),
    (["统计", "stats", "报表", "report", "分析", "analytics", "看板"],
     ["信息泄露", "未授权访问", "SQL注入"]),
    (["知识库", "knowledge", "文档", "document", "文章", "article"],
     ["IDOR越权", "未授权访问", "信息泄露"]),
    (["数据源", "datasource", "连接", "connection", "数据库"],
     ["未授权访问", "信息泄露", "SQL注入", "SSRF"]),
    (["智能", "ai", "生成", "generate", "翻译", "translate", "校核", "check"],
     ["未授权访问", "SSRF", "信息泄露"]),
]

# 通用检查项（critical/high 优先级功能点额外附加）
UNIVERSAL_CHECKS = ["未授权访问", "CORS配置"]

# ============================================================
# ★ 登录页专用 checklist — 登录页目标 5/5 产出 0 漏洞的专项治理
# ============================================================
# 问题根因：登录页目标在补测阶段被 _AUTH_PATH_PREFIXES 过滤为"非业务路径"，
# checklist 由通用 _auto_suggest_tests 生成，验证码绕过等关键项优先级=4 易被裁剪。
# 解决方案：对 /login /cas/login /Home/Login 等登录页，强制使用专用 checklist，
# 不受 MAX_CHECKLIST_PER_FP 裁剪影响，确保验证码安全等关键检测不被遗漏。

# 登录页 URL 匹配模式（case-insensitive，匹配路径片段）
LOGIN_PAGE_PATTERNS = (
    "/login", "/signin", "/sign-in", "/sign_in",
    "/cas/login", "/home/login", "/account/login", "/user/login",
    "/auth/login", "/sso/login", "/oauth/authorize",
    "/admin/login", "/manage/login", "/backend/login",
    "/登录", "/管理员登录",
)

# 登录页专用 checklist（按优先级排序，验证码安全提到最前）
LOGIN_PAGE_CHECKLIST = [
    "验证码绕过",              # 验证码答案泄露/复用/客户端校验（P0，曾因优先级=4被裁剪）
    "JS代码审计(硬编码密钥/绕过逻辑/敏感信息)",  # AES密钥/APPSECRET硬编码（P0）
    "SQL注入",                # 登录表单注入（P1）
    "弱密码/默认密码",         # admin/admin 等（P1）
    "用户枚举",               # 登录失败信息差异（P1）
    "未授权访问",             # 登录后接口直接可达（P1）
    "密码重置逻辑",           # 重置任意账号密码（P2）
    "Cookie/JWT安全",         # 会话固定/Token泄露（P2）
    "CSRF",                   # 登录CSRF（P2）
    "开放重定向",             # redirect 参数注入（P3）
    "Host头投毒",             # 密码重置链接 Host 注入（P3）
    "信息泄露",               # 报错信息/版本泄露（P3）
    "CORS配置",               # 跨域凭证泄露（P3）
]


def is_login_page(page_url: str) -> bool:
    """检测 URL 是否为登录页（case-insensitive 路径片段匹配）。

    纯函数，无 IO。用于 feature_gen 和 supplemental_test_agent 决定是否
    使用登录页专用 checklist。
    """
    if not page_url:
        return False
    _url_lower = page_url.lower()
    # 去掉 query/fragment 后匹配路径片段
    _path = _url_lower.split("?")[0].split("#")[0]
    for _pattern in LOGIN_PAGE_PATTERNS:
        if _pattern.lower() in _path:
            return True
    return False

# 需要浏览器才能完整测试的漏洞类型
BROWSER_REQUIRED_VULNS = {
    "XSS", "存储型XSS", "反射型XSS", "DOM XSS",
    "CSRF",
    "验证码绕过",
    "Cookie/JWT安全",
    "OAuth劫持", "redirect_uri绕过", "state缺失",
    "开放重定向",
}

# 漏洞类型 → SKILL 目录名映射（消除 LLM 猜名幻觉）
VULN_TO_SKILL: dict[str, str] = {
    "SQL注入": "sql-injection-methodology",
    "XSS": "xss-methodology",
    "存储型XSS": "xss-methodology",
    "反射型XSS": "xss-methodology",
    "IDOR越权": "idor-methodology",
    "越权查看": "idor-methodology",
    "越权操作": "idor-methodology",
    "垂直越权": "idor-methodology",
    "CSRF": "csrf-methodology",
    "SSRF": "ssrf-methodology",
    "文件上传绕过": "file-upload-methodology",
    "XXE": "xxe-injection-methodology",
    "命令注入": "command-injection-methodology",
    "SSTI": "ssti-methodology",
    "开放重定向": "open-redirect",
    "信息泄露": "user-enum-data-leak",
    "用户枚举": "user-enum-data-leak",
    "未授权访问": "401-403-bypass",
    "CORS配置": "cors-misconfiguration",
    "Cookie/JWT安全": "jwt-attack-methodology",
    "金额篡改": "business-logic-attack",
    "数量篡改": "business-logic-attack",
    "订单替换": "business-logic-attack",
    "支付回调伪造": "business-logic-attack",
    "竞态条件": "exploit-race-condition",
    "重复使用": "exploit-race-condition",
    "并发领取": "exploit-race-condition",
    "密码重置逻辑": "password-reset-attack",
    "弱密码/默认密码": "password-reset-attack",
    "JS代码审计(硬编码密钥/绕过逻辑/敏感信息)": "js-api-extract",
    "Host头投毒": "http-host-header-attacks",
    "验证码绕过": "captcha-bypass",
    "短信轰炸": "captcha-bypass",
    "OAuth劫持": "oauth-sso-attack",
    "redirect_uri绕过": "oauth-sso-attack",
    "state缺失": "oauth-sso-attack",
    "Mass Assignment": "idor-methodology",
    "Token可预测": "password-reset-attack",
    "越权导出": "idor-methodology",
    "PDF注入/SSRF": "pdf-generation-attack",
    "弱密码": "password-reset-attack",
    "枚举遍历": "idor-methodology",
    "状态篡改": "business-logic-attack",
}

# ---- 关键词集合（功能点自动分类） ----

# 后台功能关键词 → 自动标 requires_auth=True
BACKEND_KEYWORDS = {
    "后台", "管理", "admin", "dashboard", "控制台", "manage",
    "工作台", "监控", "monitor", "告警", "alarm", "调度", "schedule",
    "台区", "设备", "device", "用户管理", "角色", "权限",
}

# 外围功能关键词 → 强制 requires_auth=False
PUBLIC_KEYWORDS = {
    "登录", "login", "注册", "register", "signup", "密码重置",
    "forgot", "reset", "oauth", "sso",
}

# Checklist 项的详细操作指引
VULN_DETAIL_HINTS: dict[str, str] = {
    "JS代码审计(硬编码密钥/绕过逻辑/敏感信息)": (
        "① 先检查 JS 文件末尾有无 sourceMappingURL，请求 .js.map 文件。"
        "② 如果 Source Map 可访问 → 分析 sources 字段判断框架（Vite/Webpack）→ "
        "尝试直接请求 /src/main.ts 探测 Dev Server 是否在线 → "
        "审计 request.ts/auth.ts/router/index.ts 找硬编码 Token 和鉴权绕过 → "
        "Vite 场景尝试 /@fs/ 路径读取 .env、prisma/seed.ts、docker-compose.yml 等服务端文件。"
        "③ 无 Source Map 则用 `proxy_send_request` 下载关键 JS（router/auth/request 相关），"
        "分析硬编码 API Key/Token/密码、前端 isAdmin 判断、隐藏路由、Source Map 泄露。"
        "→ 加载 SKILL: `knowledge_load_skill(\"js-api-extract\")` 中的 1.2.1 章节有完整攻击链"
    ),
    "弱密码/默认密码": (
        "尝试常见默认凭据：admin/admin, admin/123456, admin/admin123, test/test, "
        "admin/password, root/root, admin/Admin@123"
    ),
}

# ---- LLM suggested_tests 语义去重 ----
# LLM 经常传入与系统自动生成项语义重复但名称不同的测试类型
# key = LLM 可能传的名字，value = 系统已有的标准名（如果匹配到就丢弃 LLM 传的）
VULN_SYNONYMS: dict[str, str] = {
    "暴力破解防护": "弱密码/默认密码",
    "暴力破解": "弱密码/默认密码",
    "JWT/Token安全": "Cookie/JWT安全",
    "JWT安全": "Cookie/JWT安全",
    "Token安全": "Cookie/JWT安全",
    "默认密码测试": "弱密码/默认密码",
    "默认密码": "弱密码/默认密码",
    "弱口令": "弱密码/默认密码",
    "登录绕过": "未授权访问",
    "认证绕过": "未授权访问",
    "权限绕过": "未授权访问",
    "水平越权": "IDOR越权",
    "横向越权": "IDOR越权",
    "越权访问": "IDOR越权",
    "反射型XSS": "XSS",
    "DOM XSS": "XSS",
    "任意文件上传": "文件上传绕过",
    "文件上传": "文件上传绕过",
    "敏感信息泄露": "信息泄露",
    "越权修改": "IDOR越权",
    "越权删除": "IDOR越权",
    "参数篡改": "金额篡改",
    # 英文名去重（LLM 经常传英文）
    "sql-injection": "SQL注入",
    "sql_injection": "SQL注入",
    "sqli": "SQL注入",
    "xss": "XSS",
    "cross-site-scripting": "XSS",
    "idor": "IDOR越权",
    "insecure-direct-object-reference": "IDOR越权",
    "ssrf": "SSRF",
    "server-side-request-forgery": "SSRF",
    "csrf": "CSRF",
    "cross-site-request-forgery": "CSRF",
    "default-credentials": "弱密码/默认密码",
    "default_credentials": "弱密码/默认密码",
    "user-enumeration": "用户枚举",
    "user_enumeration": "用户枚举",
    "username-enumeration": "用户枚举",
    "jwt-analysis": "Cookie/JWT安全",
    "jwt_analysis": "Cookie/JWT安全",
    "jwt-attack": "Cookie/JWT安全",
    "rate-limiting": "速率限制",
    "rate_limiting": "速率限制",
    "rate-limit": "速率限制",
    "open-redirect": "开放重定向",
    "open_redirect": "开放重定向",
    "redirect": "开放重定向",
    "mass-assignment": "Mass Assignment",
    "mass_assignment": "Mass Assignment",
    "unauthorized-access": "未授权访问",
    "unauthorized_access": "未授权访问",
    "information-disclosure": "信息泄露",
    "information_disclosure": "信息泄露",
    "info-disclosure": "信息泄露",
    "file-upload": "文件上传绕过",
    "file_upload": "文件上传绕过",
    # 大小写/带空格变体（LLM 偶尔会输出非标准格式）
    "SQLi": "SQL注入",
    "SQL Injection": "SQL注入",
    "SQL injection": "SQL注入",
    "IDOR": "IDOR越权",
    "BOLA": "IDOR越权",
    "Mass-Assignment": "Mass Assignment",
    "race-condition": "竞态条件",
    "race_condition": "竞态条件",
    "Race Condition": "竞态条件",
    "payment-logic": "金额篡改",
    "payment_logic": "金额篡改",
    # ---- 2026-08-07 补充：日志中 agent 反复尝试的变体 ----
    "IDOR 越权": "IDOR越权",          # checklist 显示带空格，内部无空格
    "broken-object-level-authorization": "IDOR越权",
    "broken_object_level_authorization": "IDOR越权",
    "insecure-direct-object-reference": "IDOR越权",
    "insecure_direct_object_reference": "IDOR越权",
    "horizontal-privilege-escalation": "IDOR越权",
    "horizontal_privilege_escalation": "IDOR越权",
    "vertical-privilege-escalation": "垂直越权",
    "vertical_privilege_escalation": "垂直越权",
    "access-control-bypass": "未授权访问",
    "access_control_bypass": "未授权访问",
    "authorization-bypass": "未授权访问",
    "authorization_bypass": "未授权访问",
    "privilege-escalation": "垂直越权",
    "privilege_escalation": "垂直越权",
    "object-authorization-bypass": "IDOR越权",
    "object_authorization_bypass": "IDOR越权",
    "越权漏洞": "IDOR越权",
    "越权测试": "IDOR越权",
    "越权检测": "IDOR越权",
    "越权风险": "IDOR越权",
    "越权问题": "IDOR越权",
    "越权审查": "IDOR越权",
    "越权审计": "IDOR越权",
    "越权探测": "IDOR越权",
    "越权扫描": "IDOR越权",
    "数据越权": "IDOR越权",
    "用户数据越权": "IDOR越权",
    "接口越权": "IDOR越权",
    "API越权": "IDOR越权",
    "API 越权": "IDOR越权",
    "功能越权": "IDOR越权",
    "资源越权": "IDOR越权",
    "访问控制": "未授权访问",
    "Access Control": "未授权访问",
    "Access Control Bypass": "未授权访问",
    "Authorization Bypass": "未授权访问",
    "Privilege Escalation": "垂直越权",
    "Broken Access Control": "未授权访问",
    "broken-access-control": "未授权访问",
    "身份认证绕过": "未授权访问",
    "认证绕过漏洞": "未授权访问",
    "会话管理": "Cookie/JWT安全",
    "安全配置": "信息泄露",
    "安全头缺失": "信息泄露",
    "安全审计": "信息泄露",
    "逻辑漏洞": "业务逻辑",
    "业务逻辑漏洞": "业务逻辑",
    "竞态条件漏洞": "竞态条件",
    "竞态漏洞": "竞态条件",
    "密码重置漏洞": "密码重置逻辑",
    "账户接管": "未授权访问",
    "账户接管漏洞": "未授权访问",
    "枚举漏洞": "用户枚举",
    "用户名枚举": "用户枚举",
    "拒绝服务": "DDoS",
    "DDoS": "DDoS",
    "dos": "DDoS",
    "denial-of-service": "DDoS",
    "denial_of_service": "DDoS",
}

# ---- 原子操作级 checklist 自动推导规则 ----
# 根据 API 的 HTTP 方法 + URL 路径特征自动生成 checklist 项

# HTTP 方法 → 基础漏洞类型
# 原则：宁可多测几项（子 Agent 可以快速排除不适用的），不能漏测
METHOD_VULN_MAP: dict[str, list[str]] = {
    "GET":    ["未授权访问", "IDOR越权", "信息泄露"],
    "POST":   ["未授权访问", "IDOR越权", "SQL注入", "XSS", "CSRF"],
    "PUT":    ["未授权访问", "IDOR越权", "SQL注入", "CSRF"],
    "PATCH":  ["未授权访问", "IDOR越权", "SQL注入", "CSRF"],
    "DELETE": ["未授权访问", "IDOR越权", "垂直越权", "CSRF"],
}

# URL 路径特征 → 额外漏洞类型
PATH_VULN_PATTERNS: list[tuple[list[str], list[str]]] = [
    # 路径含 ID 参数 → IDOR
    ([r"/\d+", r"/{id}", r"/:id"], ["IDOR越权"]),
    # 搜索/查询 → SQL注入 + XSS
    (["search", "query", "keyword", "filter", "q="], ["SQL注入", "XSS"]),
    # 列表/分页接口 → SQL注入（后台系统的 GET /list、/page、/records 等几乎都接了数据库查询）
    (["list", "page", "records", "items", "all", "datalist"], ["SQL注入"]),
    # 上传/导入 → 文件上传 + XXE
    (["upload", "import", "attach"], ["文件上传绕过", "XXE"]),
    # 导出/下载 → 越权导出 + 信息泄露
    (["export", "download", "report", "excel", "csv"], ["越权导出", "信息泄露", "PDF注入/SSRF"]),
    # 支付/订单 → 金额篡改 + 竞态
    (["pay", "order", "checkout", "purchase", "price", "amount", "recharge"],
     ["金额篡改", "竞态条件"]),
    # 密码/认证 → 认证类
    (["password", "passwd", "reset", "token", "auth", "login", "signin"],
     ["密码重置逻辑", "弱密码/默认密码"]),
    # 管理/系统 → 垂直越权
    (["admin", "manage", "system", "config", "setting", "role", "permission"],
     ["垂直越权", "信息泄露"]),
    # 用户相关 → IDOR + 信息泄露
    (["user", "profile", "account", "member", "info", "detail"],
     ["IDOR越权", "信息泄露"]),
    # 发送/通知 → 短信轰炸/验证码绕过
    (["send", "sms", "email", "verify", "captcha", "code"],
     ["验证码绕过", "短信轰炸"]),
    # 文件/资源路径 → SSRF + 路径穿越
    (["url", "link", "proxy", "fetch", "webhook", "callback"],
     ["SSRF", "开放重定向"]),
    # 批量操作 → 竞态条件
    (["batch", "bulk", "queue", "task"],
     ["竞态条件"]),
    # 删除/移除 → 越权删除
    (["delete", "remove", "destroy", "cancel"],
     ["垂直越权"]),
    # 创建/新增 → Mass Assignment
    (["create", "add", "new", "register", "save"],
     ["Mass Assignment"]),
]

# 交互元素类型 → 额外漏洞类型
ELEMENT_VULN_MAP: dict[str, list[str]] = {
    "input_text": ["XSS", "SQL注入"],         # 文本输入框
    "textarea": ["XSS", "存储型XSS"],          # 多行文本
    "file_upload": ["文件上传绕过"],            # 文件上传
    "form_submit": ["CSRF"],                    # 表单提交
    "search_box": ["SQL注入", "XSS"],           # 搜索框
}

# ---- 运行时常量 ----

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
MAX_WORKERS = 5              # Phase 2 最大并行子 Agent 数（并发限制）
MAX_FEATURES_PER_GROUP = 4   # ★ P0-2: 从8降至4，防止子Agent初始上下文即超限（8 FP×4K样本+2 SKILL≈56K tokens > 65536窗口）
WORKER_MAX_ROUNDS = 100      # 子 Agent 每个功能点的最大轮数
CONTEXT_BATCH_SIZE = 10      # 每 N 轮保存一次状态
WORKER_EVENT_TIMEOUT = 120   # 子 Agent 事件等待超时（秒）
WORKER_STUCK_TIMEOUT = 600   # 子 Agent 无事件最长时间（秒），超过则强制取消（防 LLM 挂起）
MAIN_MAX_ROUNDS = 1000       # 主 Agent 单次 chat 最大轮数（防死循环）
REPEAT_TOOL_THRESHOLD = 3    # 同一工具+相同参数连续重复 N 次，强制中断

# ★ 性能优化：并发与模式控制
FAST_SCAN_MAX_WORKERS = 20   # 本地规则引擎并发数（纯 HTTP，不涉及 LLM，可激进）
FAST_SCAN_RATE_LIMIT = 15.0  # 本地规则引擎全局速率（req/s）；原默认 5 太慢，50 目标×200 请求需 33min
LLM_SCAN_MAX_WORKERS = 3     # LLM 分析并发数（贴合常见 API 并发上限，避免 429 后大量重试）
SKIP_BUSINESS_UNDERSTANDING = False   # True: 跳过 Phase 1 业务理解（减少 1 轮 LLM 调用）
SKIP_META_ANALYSIS = False            # True: 跳过 Phase 2 LLM 元分析（直接按规则初筛 + 子 Agent）

# ★ 快速模式超时配置（本地规则请求更轻量，超时更短）
FAST_MODE_TIMEOUTS = {
    "request": 6.0,          # 本地规则单个请求超时
    "crawl_page": 15.0,      # 快速爬虫单页超时
    "worker_event": 60.0,    # 快速模式下 worker 事件等待超时
    "total_fast_scan": 180.0,  # 整个快速扫描模块最大耗时（秒）
    # FastScanner 先行等待时长：超过则放弃等待，回退到与 LLM 准备阶段并行
    # （保证总时长不因 FastScanner 慢而劣化；FastScanner 仍在后台继续跑完）
    "lead_time": 120.0,
    # ★ 硬超时：从 FastScanner 启动算起的总最大耗时；Step 5 超过则取消 task
    # 避免速率限制 + 大量目标导致后台扫描无限拖慢总流程
    "hard_timeout": 600.0,
}

# ★ 单个功能点 checklist 项数上限（保险丝：防止规则匹配爆炸）
# 原因：FEATURE_VULN_MAPPING + METHOD_VULN_MAP + PATH_VULN_PATTERNS 三层叠加，
# 高频功能点（登录/用户/管理）容易并集出 30+ 项，子 Agent 测不完且分散注意力。
# 经验值：15 项足以覆盖一个功能点的主要攻击面，超出部分按 VULN_PRIORITY 排序裁剪。
MAX_CHECKLIST_PER_FP = 15

# ★ 漏洞类型优先级排序（数值越小越靠前；用于 checklist 超出 MAX_CHECKLIST_PER_FP 时的裁剪依据）
# 原则：高危且常见 → 中危 → 低危/兜底；越权类按业务危害排序
VULN_PRIORITY: dict[str, int] = {
    # P0 高危 - 直接危害
    "SQL注入": 1,
    "命令注入": 1,
    "文件上传绕过": 1,
    "SSRF": 1,
    "XXE": 1,
    "SSTI": 1,
    "未授权访问": 1,
    "金额篡改": 1,
    "支付回调伪造": 1,
    # P1 高危 - 业务关键
    "IDOR越权": 2,
    "垂直越权": 2,
    "越权操作": 2,
    "越权查看": 2,
    "越权导出": 2,
    "Mass Assignment": 2,
    "状态篡改": 2,
    "数量篡改": 2,
    "订单替换": 2,
    "竞态条件": 2,
    "弱密码/默认密码": 2,
    "弱密码": 2,
    "Cookie/JWT安全": 2,
    "密码重置逻辑": 2,
    # P2 中危 - 常见漏洞
    "XSS": 3,
    "存储型XSS": 3,
    "反射型XSS": 3,
    "DOM XSS": 3,
    "CSRF": 3,
    "开放重定向": 3,
    "OAuth劫持": 3,
    "redirect_uri绕过": 3,
    "state缺失": 3,
    "Host头投毒": 3,
    "PDF注入/SSRF": 3,
    "重复使用": 3,
    "并发领取": 3,
    "枚举遍历": 3,
    "用户枚举": 3,
    "Token可预测": 3,
    # P3 低危 / 信息收集
    "信息泄露": 4,
    "CORS配置": 4,
    "验证码绕过": 4,
    "短信轰炸": 4,
    "JS代码审计(硬编码密钥/绕过逻辑/敏感信息)": 4,
}
# 未在表中的漏洞类型默认优先级（介于 P2 和 P3 之间）
VULN_PRIORITY_DEFAULT = 5


# ============================================================
# 与 SKILL Registry 联动
# ============================================================
# 启动 / 热重载时由 core.skill_registry 调用，把 SKILL.md frontmatter 里
# 自注册的 vuln_types / triggers / synonyms 合并进上面 3 个字典/列表。
#
# 关键：必须**原地更新**对象（clear+update），不能重新赋值，
# 否则其它模块 `from core.config import VULN_TO_SKILL` 仍持有旧引用。

# 备份默认值（模块加载时立即记录原始值，热重载时用作"恢复 + 重新合并"的基线）
# 关键：必须在模块加载时立即执行，否则在 apply_skill_registry 第一次调用前已被合并的话备份的是污染值
_DEFAULT_VULN_TO_SKILL: dict[str, str] = dict(VULN_TO_SKILL)
_DEFAULT_FEATURE_VULN_MAPPING: list = [(list(kw), list(vt)) for kw, vt in FEATURE_VULN_MAPPING]
_DEFAULT_VULN_SYNONYMS: dict[str, str] = dict(VULN_SYNONYMS)

# ★ 竞态保护：全局映射表更新锁，防止多线程下 clear+update 竞态
from threading import Lock as _Lock
_mapping_lock = _Lock()


def _backup_defaults() -> None:
    """兼容性 noop（默认值已在模块导入时备份，此函数仅为保留旧 API 调用）。"""
    pass


def apply_skill_registry(registry) -> dict:
    """把 SkillRegistry 中合并后的映射，原地写入本模块的三个全局字典/列表。

    返回统计 {"vuln_to_skill": n, "feature_triggers": n, "synonyms": n}，供日志使用。
    """
    _backup_defaults()
    with _mapping_lock:
        # 1) VULN_TO_SKILL（原地）
        VULN_TO_SKILL.clear()
        VULN_TO_SKILL.update(registry.vuln_to_skill)

        # 2) FEATURE_VULN_MAPPING（原地，list 不能 clear+update，用 slice 赋值）
        FEATURE_VULN_MAPPING[:] = registry.feature_triggers

        # 3) VULN_SYNONYMS（原地）
        VULN_SYNONYMS.clear()
        VULN_SYNONYMS.update(registry.vuln_synonyms)

    return {
        "vuln_to_skill": len(VULN_TO_SKILL),
        "feature_triggers": len(FEATURE_VULN_MAPPING),
        "synonyms": len(VULN_SYNONYMS),
    }


def reset_to_defaults() -> None:
    """把三个映射恢复到 .py 中的默认值（不含任何 SKILL frontmatter 合并）。"""
    _backup_defaults()
    with _mapping_lock:
        if _DEFAULT_VULN_TO_SKILL is not None:
            VULN_TO_SKILL.clear()
            VULN_TO_SKILL.update(_DEFAULT_VULN_TO_SKILL)
        if _DEFAULT_FEATURE_VULN_MAPPING is not None:
            FEATURE_VULN_MAPPING[:] = _DEFAULT_FEATURE_VULN_MAPPING
        if _DEFAULT_VULN_SYNONYMS is not None:
            VULN_SYNONYMS.clear()
            VULN_SYNONYMS.update(_DEFAULT_VULN_SYNONYMS)
