"""
菜单优先级排序器 — 决定"99 个菜单按什么顺序点"。

──────────────────────────────────────────────────────────────────
痛点（来自 2026-05-22 与用户的诊断）
──────────────────────────────────────────────────────────────────
现代网站首页菜单条上常常有 50-100+ 个项，DOM 顺序≠业务价值顺序。
若按 DOM 顺序点击，关键入口（如"登录"）可能排在第 99 位被超时丢掉，
而预算却花在 80 个营销/法务装饰菜单上。

实测案例：
- bitget 首页 99 菜单 → 点到第 5 个（"登录"）后预算耗尽，剩 94 个全部丢掉
- launchdarkly 首页 57 菜单 → 全是 Privacy/About/Careers/Read More 等装饰

──────────────────────────────────────────────────────────────────
核心设计：分场景两种工作模式
──────────────────────────────────────────────────────────────────

模式 A — "marketing"（登录前 / 营销站）：
    特征：DOM 中存在大量营销/法务/PR 装饰菜单，业务入口稀少
    策略：负分丰富 + 正分极少
        - 重负分把 Privacy / About / Careers / Read More 等沉底
        - 正分把"登录/注册/控制台"提顶
        - 没识别的中性词保持 DOM 顺序
    目标：让稀少的关键入口必定先被点到

模式 B — "business" / "post_login"（业务后台 / SaaS 应用）：
    特征：菜单几乎全是业务功能（用户管理、订单、设置等），不能漏
    策略：以正分为主，仅给"权限/秘钥/审计/财务"等高危/高价值小幅加分
        - 不打负分（除非命中明确的非业务关键词）
        - 其他菜单保持 DOM 顺序
    目标：高危先测，其余完整覆盖（靠"进度感知不超时"机制保证）

post_login = business 的别名，区分日志可观测，行为同 business。

──────────────────────────────────────────────────────────────────
模式自动判定（detect_menu_mode）
──────────────────────────────────────────────────────────────────
- 角色 != "anonymous" → post_login
- 角色 = "anonymous" 且菜单中"营销特征词"占比 > 30% → marketing
- 否则视为 business（如 moa.jd.com 即使匿名也是后台）

外部可通过 force 参数强制覆盖（用于回归 / 调试）。
"""

from __future__ import annotations

from typing import Literal


MenuMode = Literal["marketing", "business", "post_login", "auto"]


# ============================================================
# 关键词清单 — 200+ 中英文 + href 模式
# ============================================================

# ─────────────────────────────────────────────────────────
# A 模式（营销站）：负分关键词 — 装饰菜单沉底
# ─────────────────────────────────────────────────────────

# 法务合规类（-80）
_LEGAL_KEYWORDS = (
    # 英文
    "privacy", "privacy policy", "terms", "terms of service",
    "terms & conditions", "terms and conditions", "cookies", "cookie policy",
    "cookie notice", "legal", "legal notice", "gdpr", "ccpa", "do not sell",
    "do not share", "compliance", "accessibility", "sitemap", "site map",
    "imprint", "disclaimer",
    # 中文
    "隐私", "隐私政策", "隐私权", "条款", "服务条款", "用户协议", "使用协议",
    "法律", "法律声明", "合规", "无障碍", "网站地图", "免责声明", "不出售",
)

# 公司介绍类（-70）
_COMPANY_KEYWORDS = (
    # 英文
    "about", "about us", "our story", "our team", "our mission", "mission",
    "values", "leadership", "founders", "team", "company",
    "careers", "career", "jobs", "hiring", "join us", "work with us",
    "press", "media", "newsroom", "awards", "recognition",
    "investors", "investor relations", "ir",
    "partners", "partner program", "partnership", "alliances",
    "customers", "case study", "case studies", "testimonials",
    "success story", "success stories",
    "culture", "corporate culture",
    "franchise", "join as partner",
    # 中文
    "关于", "关于我们", "公司介绍", "公司简介", "我们的故事", "团队",
    "招聘", "职业", "加入我们", "工作机会",
    "新闻", "媒体", "新闻中心", "新闻动态", "奖项",
    "投资者", "投资者关系",
    "合作伙伴", "合作", "客户", "客户案例", "案例", "成功案例",
    "企业文化", "文化", "愿景", "使命",
    "加盟", "合伙人", "招商",
)

# 内容营销类（-60）
_CONTENT_MARKETING_KEYWORDS = (
    # 英文
    "blog", "blogs", "articles", "ebooks", "ebook", "whitepaper", "whitepapers",
    "white paper", "webinar", "webinars", "podcast", "podcasts",
    "videos", "video library", "resources", "resource center", "library",
    "guides", "guide", "tutorials", "tutorial", "learn", "learning",
    "academy", "university", "knowledge base", "kb",
    "documentation", "docs", "api docs", "api reference", "developer docs",
    "events", "event", "conferences", "conference", "summit",
    "newsletter", "subscribe",
    # 中文
    "博客", "文章", "电子书", "白皮书", "网络研讨会", "线上活动",
    "播客", "视频", "视频中心", "资源", "资源中心", "学习中心",
    "指南", "教程", "学院", "知识库", "文档", "开发文档", "API 文档",
    "活动", "大会", "峰会", "订阅",
)

# 社交链接类（-90，最重）
_SOCIAL_KEYWORDS = (
    "twitter", "x.com", "facebook", "linkedin", "youtube", "instagram",
    "tiktok", "github", "discord", "slack community", "wechat",
    "share", "follow us", "social", "subscribe to newsletter",
    "weibo",
    # 中文
    "分享", "关注我们", "微博", "微信",
)

# 通用低价值动作（-50）
_GENERIC_LOW_VALUE = (
    # 英文
    "read more", "learn more", "see more", "view all", "show more",
    "view details", "view post", "back to top", "scroll", "go to top",
    "get the app", "download app", "install", "get started free",
    "watch demo", "watch video", "play video",
    "contact", "contact us", "get in touch",
    "support", "help center", "help", "faq", "faqs", "q&a",
    "feedback", "report bug",
    # 中文
    "了解更多", "查看更多", "查看全部", "查看详情", "更多",
    "返回顶部", "下载 APP", "下载应用", "安装",
    "联系", "联系我们", "客服", "帮助", "帮助中心", "常见问题", "问答",
    "反馈", "意见反馈",
)

# 装饰按钮类（-40）
_DECORATION_KEYWORDS = (
    "language", "region", "country", "currency", "theme",
    "dark mode", "light mode", "search",
    # 中文
    "语言", "地区", "国家", "货币", "主题", "搜索",
)

# 营销活动 / 试用 / Demo（-30，比"了解更多"轻一点，因为它们可能引向真实功能）
_MARKETING_CTA = (
    "free trial", "start free trial", "start trial", "try free",
    "request demo", "book a demo", "book demo", "schedule a demo",
    "talk to sales", "talk to expert", "get a quote", "request quote",
    "join waitlist", "early access",
    # 中文
    "免费试用", "免费体验", "申请试用", "申请演示", "预约演示",
    "联系销售", "咨询报价", "报价", "申请加入",
)

# ★ 2026-05-29 新增：导航离开类（-200 最低）— 会导致页面跳转离开当前系统
# 这类菜单点击后会跳到其他系统/页面，导致 DOM 完全变化，
# 后续菜单项选择器全部失效。必须排到最后点击。
_NAV_AWAY_KEYWORDS = (
    # 中文
    "返回门户", "返回首页", "返回主页", "回到首页", "回到门户",
    "退出登录", "退出系统", "退出", "注销", "登出", "安全退出",
    "切换账号", "切换用户", "切换租户", "切换组织",
    "返回上级", "返回上一级", "回到上级",
    # 英文
    "logout", "log out", "log-out", "sign out", "sign-out", "signout",
    "exit", "quit", "leave",
    "back to portal", "back to home", "return to portal", "return to home",
    "switch account", "switch user", "switch tenant", "switch org",
    "go back", "go home",
)


# ─────────────────────────────────────────────────────────
# ★ SEC-7/PM-4: 页脚噪音 + 人员姓名/职务 — 沉底避免误点
# 8.2.txt 日志 L18「贵公网安备52011502000171号」被排首位（+80），
# L32「陈 彧 党委书记、董事长」等 5 个人员被当菜单逐个点击全 0 API。
# ─────────────────────────────────────────────────────────

# 页脚备案号/版权类（-150 沉底，比社交链接更靠后）
_FOOTER_NOISE_KEYWORDS = (
    "公网安备", "公安备", "icp备", "icp证", "ip备", "备案号",
    "版权所有", "copyright", "all rights reserved",
    "技术支持", "powered by", "站点地图",
)

# 人员姓名 + 职务特征（-100 沉底，避免逐个点击人员卡片）
# 命中其中任一关键词即视为人员介绍类菜单，非业务功能
_PERSON_TITLE_KEYWORDS = (
    "党委书记", "党委副书记", "党委常委", "党委委员",
    "董事长", "副董事长", "总经理", "副总经理", "总裁", "副总裁",
    "主任", "副主任", "局长", "副局长", "处长", "副处长",
    "院长", "副院长", "校长", "副校长",
    "总工程师", "总会计师", "总经济师",
    "领导班子", "领导成员",
)


# ─────────────────────────────────────────────────────────
# B 模式（业务系统）：正分关键词 — 高危 / 高价值优先
# ─────────────────────────────────────────────────────────

# 身份与认证（+120 最高）— 任何模式下都是首测目标
_AUTH_KEYWORDS = (
    "登录", "登入", "登陆", "sign in", "sign-in", "signin",
    "log in", "log-in", "login",
    "注册", "sign up", "sign-up", "signup", "register", "registration",
    "create account", "join now",
    "忘记密码", "找回密码", "重置密码", "forgot password", "reset password",
    "单点登录", "sso", "oauth", "saml",
    "二步验证", "两步验证", "双因子", "2fa", "mfa",
    "password", "密码", "authenticator", "认证", "authentication",
    "biometric", "生物识别", "指纹登录",
)

# 权限与账户（+110）
_PERMISSION_KEYWORDS = (
    "权限", "permissions", "权限管理", "角色", "roles", "role management",
    "access control", "访问控制", "rbac", "abac",
    "用户管理", "user management", "users",
    "成员", "成员管理", "members", "member management",
    "团队", "team", "teams",
    "admin", "administrator", "管理员", "超级管理员", "super admin", "root",
    "组织", "organization", "orgs", "org management",
    "群组", "groups", "group management",
    "部门", "department", "departments",
    "tenant", "tenants", "租户",
)

# 密钥与令牌（+115）— 安全研究最高价值
_SECRET_KEYWORDS = (
    "api key", "api keys", "api 密钥", "密钥",
    "access token", "tokens", "personal access token", "pat",
    "令牌", "secret", "secrets", "凭证", "credentials",
    "oauth app", "oauth apps", "oauth applications", "应用授权",
    "webhook", "webhooks", "回调",
    "integration", "integrations", "集成", "connector", "connectors", "连接器",
    "ssh key", "ssh keys", "deploy key", "deploy keys",
    "service account", "service accounts", "服务账号",
    "encryption key", "签名密钥", "signing key",
)

# 财务与计费（+100）
_FINANCE_KEYWORDS = (
    "账单", "billing", "invoice", "invoices", "发票",
    "payment", "payments", "支付", "付款方式", "payment method",
    "充值", "recharge", "top up", "topup",
    "提现", "withdraw", "withdrawal", "withdrawals", "提款",
    "转账", "transfer", "transfers", "汇款",
    "钱包", "wallet", "wallets",
    "余额", "balance", "balances",
    "subscription", "subscriptions", "订阅",
    "plan", "plans", "套餐", "pricing", "定价",
    "财务", "finance", "结算", "settlement",
    "退款", "refund", "refunds",
    "报销", "reimbursement",
    "account balance", "账户余额", "credits", "积分",
    "coupons", "优惠券", "代金券", "voucher", "vouchers",
)

# 敏感操作（+95）
_SENSITIVE_OPS = (
    "删除", "delete", "remove", "移除", "销毁", "destroy",
    "archive", "归档",
    "导出", "export", "导出数据", "导入", "import",
    "备份", "backup", "backups", "restore", "恢复",
    "迁移", "migrate", "migration",
    "重置", "reset", "清空", "clear",
    "transfer ownership", "转让所有权",
    "freeze", "冻结", "解冻", "unfreeze",
)

# 审计与日志（+90）
_AUDIT_KEYWORDS = (
    "审计", "audit", "audit log", "audit logs", "审计日志",
    "操作日志", "activity log", "activity logs", "action log",
    "operation log", "operation logs",
    "日志", "logs", "log",
    "history", "历史", "历史记录",
    "登录历史", "login history", "登录日志",
    "sessions", "session management", "会话", "会话管理",
    "事件", "events", "事件中心",
)

# 业务核心（+80，电商/SaaS 通用）
_BUSINESS_CORE = (
    "订单", "order", "orders", "订单管理",
    "商品", "product", "products", "商品管理",
    "sku", "skus",
    "库存", "inventory", "stock", "库存管理",
    "客户", "customer", "customers", "客户管理",
    "联系人", "contact", "contacts",
    "合同", "contract", "contracts",
    "工单", "ticket", "tickets",
    "项目", "project", "projects",
    "任务", "task", "tasks",
    "工作流", "workflow", "workflows", "流程",
    "交易", "transaction", "transactions", "流水",
    "报表", "report", "reports", "reporting",
    "数据", "data", "数据中心", "data center",
    "lead", "leads", "线索", "deals", "商机",
    "campaign", "campaigns", "营销活动",
)

# 安全配置（+105）
_SECURITY_CONFIG = (
    "安全", "security", "security settings", "安全设置", "安全中心",
    "ip 白名单", "ip whitelist", "ip allowlist", "白名单",
    "ip blocklist", "黑名单",
    "防火墙", "firewall",
    "加密", "encryption",
    "certificate", "certificates", "证书", "ssl", "tls",
    "vulnerability", "漏洞", "scan", "扫描", "security scan",
    "policy", "policies", "策略", "security policy",
    "compliance", "合规检查",
    "device management", "设备管理", "trusted devices", "可信设备",
    "ip restrictions", "ip 限制",
)

# 系统配置（+70）— 比业务核心略低，因为通常已限定 admin
_SYSTEM_CONFIG = (
    "设置", "settings", "preferences", "偏好设置",
    "配置", "config", "configuration", "configurations",
    "系统设置", "system settings", "system",
    "环境变量", "environment", "env", "environments",
    "feature flag", "feature flags", "功能开关", "toggle", "toggles",
    "domain", "domains", "域名",
    "dns", "smtp", "邮件配置", "email config", "email settings",
    "sso config", "sso 配置",
    "branding", "品牌设置", "logo",
    "customization", "自定义",
)

# 个人 / 账户中心（+75）
_PERSONAL_CENTER = (
    "我的", "个人中心", "用户中心", "账户中心", "account center",
    "profile", "my profile", "我的资料", "个人资料",
    "account", "my account", "账户", "账号",
    "dashboard", "我的工作台", "workbench", "workspace",
    "console", "管理台", "控制台", "管理后台", "admin panel", "admin",
    "portal", "门户",
)


# ─────────────────────────────────────────────────────────
# href 模式（不分模式）
# ─────────────────────────────────────────────────────────

_HREF_POSITIVE = (
    "/login", "/signin", "/sign-in", "/sign_in",
    "/signup", "/sign-up", "/sign_up", "/register",
    "/auth/", "/oauth/", "/sso/",
    "/admin", "/administrator", "/console", "/dashboard",
    "/portal", "/workspace", "/workbench",
    "/account", "/accounts", "/profile", "/user", "/users",
    "/members", "/member", "/team", "/teams", "/org", "/orgs",
    "/organization", "/tenant", "/tenants",
    "/settings", "/setting", "/config", "/preferences",
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql",
    "/webhook", "/webhooks", "/integration", "/integrations",
    "/key", "/keys", "/api-key", "/api-keys", "/token", "/tokens",
    "/secret", "/secrets", "/credential", "/credentials",
    "/billing", "/payment", "/payments", "/invoice", "/invoices",
    "/subscription", "/subscriptions", "/wallet", "/finance",
    "/audit", "/log", "/logs", "/history",
    "/security", "/permission", "/permissions", "/role", "/roles",
    "/order", "/orders", "/product", "/products",
    "/ticket", "/tickets", "/project", "/projects",
)

_HREF_NEGATIVE = (
    "/blog/", "/blog?", "/news/", "/press/", "/media/",
    "/careers/", "/career/", "/jobs/", "/job/",
    "/about", "/team", "/our-story",
    "/privacy", "/terms", "/legal", "/cookies", "/cookie-policy",
    "/gdpr", "/ccpa", "/sitemap", "/imprint", "/disclaimer",
    "/customers/", "/customer-stories/",
    "/case-studies/", "/case-study/", "/testimonials/",
    "/resources/", "/library/", "/docs/", "/documentation/",
    "/api-reference/", "/api-docs/", "/dev/",
    "/events/", "/event/", "/webinars/", "/webinar/",
    "/podcasts/", "/podcast/", "/videos/", "/video/",
    "/tutorials/", "/tutorial/", "/guides/", "/guide/",
    "/learn/", "/learning/", "/academy/", "/university/",
    "/contact", "/support", "/help", "/faq",
    "/partners/", "/partnership/",
)


# ─────────────────────────────────────────────────────────
# 营销特征词（用于 detect_menu_mode 自动判定）
# ─────────────────────────────────────────────────────────
# 命中其中之一即视为"营销味"。占比 > 30% → marketing 模式
_MARKETING_SIGNAL = set()
for _kws in (_LEGAL_KEYWORDS, _COMPANY_KEYWORDS, _CONTENT_MARKETING_KEYWORDS,
             _SOCIAL_KEYWORDS, _MARKETING_CTA):
    _MARKETING_SIGNAL.update(_kws)


# ============================================================
# 打分主函数
# ============================================================

def _text_match(text_lower: str, keywords: tuple) -> bool:
    """关键词匹配：包含即命中（不要求完整词，因为菜单文本常常带前后缀）。

    例：菜单文本 "用户管理 (User Management)" 命中 "用户管理" / "user management"。
    """
    for kw in keywords:
        if kw in text_lower:
            return True
    return False


def _href_match(href_lower: str, patterns: tuple) -> bool:
    for p in patterns:
        if p in href_lower:
            return True
    return False


def score_menu(menu: dict, *, mode: MenuMode = "business") -> int:
    """给单个菜单项打分。

    打分原则：
    - 文本关键词 + href 模式 + DOM 位置（如有）
    - A 模式（marketing）：负分丰富 + 正分稀少 → 把营销菜单沉底
    - B 模式（business / post_login）：以正分为主 → 把高危/高价值菜单提顶

    返回值：分数（int）。越高越优先点击。
    """
    text = (menu.get("text") or "").strip().lower()
    href = (menu.get("href") or "").strip().lower()
    score = 0

    # ─── 通用：身份认证（任何模式下都是首测目标） ───
    if _text_match(text, _AUTH_KEYWORDS):
        score += 120

    # ─── 通用：导航离开类（任何模式下都排到最后） ───
    # 这类菜单点击后会跳转离开当前系统，导致 DOM 变化，必须最后点击
    if _text_match(text, _NAV_AWAY_KEYWORDS):
        score -= 200

    # ─── 通用：SEC-7/PM-4 页脚备案号 + 人员姓名/职务降权 ───
    # 8.2.txt L18/L32 暴露：备案号被排首位、人员姓名被逐个点击全 0 API
    if _text_match(text, _FOOTER_NOISE_KEYWORDS):
        score -= 150
    if _text_match(text, _PERSON_TITLE_KEYWORDS):
        score -= 100

    # ─── B 模式专属正分：高危 / 高价值业务功能 ───
    if mode in ("business", "post_login"):
        if _text_match(text, _SECRET_KEYWORDS):
            score += 115
        if _text_match(text, _PERMISSION_KEYWORDS):
            score += 110
        if _text_match(text, _SECURITY_CONFIG):
            score += 105
        if _text_match(text, _FINANCE_KEYWORDS):
            score += 100
        if _text_match(text, _SENSITIVE_OPS):
            score += 95
        if _text_match(text, _AUDIT_KEYWORDS):
            score += 90
        if _text_match(text, _BUSINESS_CORE):
            score += 80
        if _text_match(text, _PERSONAL_CENTER):
            score += 75
        if _text_match(text, _SYSTEM_CONFIG):
            score += 70

    # ─── A 模式专属：负分把装饰菜单沉底 ───
    if mode == "marketing":
        # 同样在 marketing 下，"个人中心""控制台"也是关键入口
        if _text_match(text, _PERSONAL_CENTER):
            score += 75

        # 营销专属负分
        if _text_match(text, _SOCIAL_KEYWORDS):
            score -= 90
        if _text_match(text, _LEGAL_KEYWORDS):
            score -= 80
        if _text_match(text, _COMPANY_KEYWORDS):
            score -= 70
        if _text_match(text, _CONTENT_MARKETING_KEYWORDS):
            score -= 60
        if _text_match(text, _GENERIC_LOW_VALUE):
            score -= 50
        if _text_match(text, _DECORATION_KEYWORDS):
            score -= 40
        if _text_match(text, _MARKETING_CTA):
            score -= 30

    # ─── B 模式下也少量降低明显的非业务菜单（比如登录后页脚仍有 Privacy）───
    if mode in ("business", "post_login"):
        # 仅给最明显的"非业务"关键词小幅减分，不过度
        if _text_match(text, _LEGAL_KEYWORDS):
            score -= 30
        if _text_match(text, _SOCIAL_KEYWORDS):
            score -= 50

    # ─── href 模式（不分模式，正负都给） ───
    if href:
        if _href_match(href, _HREF_POSITIVE):
            score += 80
        if _href_match(href, _HREF_NEGATIVE):
            score -= 50

    return score


def detect_menu_mode(role: str, menus: list, *, force: str | None = None) -> MenuMode:
    """检测当前应使用的菜单排序模式。

    规则：
    - force 参数指定 → 直接用
    - 角色 != "anonymous" → post_login（登录后场景）
    - 角色 = "anonymous" 且菜单中"营销特征词"占比 > 30% → marketing
    - 否则 → business（如 moa.jd.com 等"匿名也是后台"的场景）
    """
    if force in ("marketing", "business", "post_login"):
        return force  # type: ignore[return-value]

    if role and role != "anonymous":
        return "post_login"

    if not menus:
        return "business"  # 没菜单不需要排序

    marketing_hits = 0
    for m in menus:
        text = (m.get("text") or "").strip().lower()
        if not text:
            continue
        if _text_match(text, tuple(_MARKETING_SIGNAL)):
            marketing_hits += 1

    ratio = marketing_hits / max(len(menus), 1)
    return "marketing" if ratio > 0.30 else "business"


def rank_menus(
    menus: list,
    *,
    mode: MenuMode = "business",
    page_url: str = "",
) -> list:
    """按业务价值重排菜单列表。

    Args:
        menus: 单页内已去重的菜单项列表，每项是 dict（含 text/href/selector 等）
        mode: 排序模式
        page_url: 页面 URL（保留参数，未来可能用于位置加分）

    Returns:
        新列表（与输入引用不同），按分数降序。同分保持 DOM 顺序（Python sort 稳定）。
    """
    # 记录原始 DOM 顺序作为同分时的次序键
    indexed = [(idx, m, score_menu(m, mode=mode)) for idx, m in enumerate(menus)]
    # 按 (-score, idx) 排序：分数高优先，同分按 DOM 顺序
    indexed.sort(key=lambda t: (-t[2], t[0]))
    return [m for _, m, _ in indexed]


def get_top_n_summary(menus: list, mode: MenuMode, n: int = 5) -> list[tuple[str, int]]:
    """工具函数：返回前 N 名的 (text, score) — 供日志展示用。"""
    scored = [(m.get("text", "")[:24], score_menu(m, mode=mode)) for m in menus]
    return scored[:n]
