"""
Phase 1 user message builders — chat_loop.py 中 Phase 1 三套路径的 user message 外移。

为什么外移：
- 这些字符串总计约 200 行，跟主流程代码混在一起难维护
- 改提示词不应该需要碰主流程的爬虫/异常处理代码
- 路径 A/B/C 在文档上明确独立，应该有清晰的边界

注意：
- 通用的"浏览器操作 SOP"已经在 core/prompts/browse_sop.md 里，这里不重复
- 这些函数只产出 user message 文本，不做任何 IO / 状态变更
- 返回字符串字节级与原 inline 实现一致（已通过等价性测试）
"""

from __future__ import annotations

from typing import Any


# ============================================================
# 路径 A：有菜单树 → 子 Agent 分组调度
# ============================================================

def build_path_a_login_msg(target_info: str, sitemap_summary: str) -> str:
    """路径 A.1 — 主 Agent 只负责登录，登录完后立刻 phase_complete 把控制权交给子 Agent。"""
    return (
        f"## 用户指令\n\n{target_info}\n\n"
        f"## 自动生成的原子功能点\n\n{sitemap_summary}\n\n"
        "## 你的任务（快速完成）\n\n"
        "系统将使用多个子 Agent 分段操作菜单页面，你只需要：\n"
        "1. 调用 `sitemap_set_business` 设置业务类型和技术栈\n"
        "2. 调用 `browser_goto` 访问目标并登录系统（子 Agent 需要登录态）\n"
        "3. 登录成功后立即调用 `phase_complete`（后续操作由子 Agent 接管）\n\n"
        "⛔ 不要遍历菜单！不要添加功能点！只登录就行。"
    )


def build_path_a_post_browse_msg(sitemap_summary: str, apis_count: int) -> str:
    """路径 A.2 — 子 Agent 完成所有菜单深度操作后，主 Agent 回来补功能点。"""
    return (
        f"## 当前状态\n\n{sitemap_summary}\n\n"
        f"子 Agent 已完成所有菜单页面的深度操作，抓取了 {apis_count} 个 API。\n\n"
        "## 你现在的任务\n\n"
        "1. 用 `sitemap_get_coverage` 查看当前功能点和 API 覆盖情况\n"
        "2. 对照菜单结构，用 `sitemap_add_feature` 补充遗漏的功能点\n"
        "   - 每个功能点必须传 `related_apis`、`module`、`page_url`\n"
        "3. 调用 `crypto_detect` 检测前端加密\n"
        "4. 调用 `phase_complete` 进入测试阶段\n\n"
        "⛔ 不需要再操作浏览器！流量已经抓完了。只补功能点。"
    )


# ============================================================
# 路径 B：无菜单树/菜单太少 → 主 Agent 单循环操作所有菜单
# ============================================================

def _path_b_login_step(has_cookie_inject: bool) -> str:
    """路径 B 的"第 1 步：登录"片段。"""
    if has_cookie_inject:
        return (
            "**第 1 步：进入系统**\n"
            "  ✅ 用户已提供 Cookie/Token，系统已自动注入，无需登录。\n"
            "  直接 `browser_goto` 访问目标 URL 进入后台。\n\n"
        )
    return (
        "**第 1 步：登录系统**\n"
        "  用 `browser_goto` 访问目标 → `browser_fill` 填写账号密码 → `browser_click` 点击登录。\n"
        "  登录成功后用 `browser_get_content` 确认进入后台。\n\n"
    )


def build_path_b_user_msg(
    *,
    target_info: str,
    atomic_features_count: int,
    auto_summary: str,
    js_context: str,
    menu_report: str,
    menu_tree_hint: str,
    traversal_checklist: str,
    has_cookie_inject: bool,
) -> str:
    """路径 B — 主 Agent 单循环操作所有菜单页面，依赖通用 SOP（已注入 system）。"""
    login_step = _path_b_login_step(has_cookie_inject)
    return (
        f"## 用户指令\n\n{target_info}\n\n"
        f"## 自动生成的原子功能点\n\n系统已从爬取结果自动生成了 **{atomic_features_count} 个功能点**。\n\n"
        f"{auto_summary}\n\n"
        f"{js_context}\n\n"
        f"{menu_report}\n\n"
        f"{menu_tree_hint}\n\n"
        "## 你的任务\n\n"
        "系统已自动生成基础功能点，**你的核心价值是用浏览器深入操作每个页面，抓取完整的业务流量**。\n"
        "你抓到的流量越完整，Phase 2 子 Agent 的漏洞检测就越准确。\n\n"
        "📖 **浏览器操作 SOP 已注入 system 上下文**（黄金循环、表单填值表、Tab 遍历、跳过策略、铁律）。\n"
        "下面只列路径独有的步骤，所有通用操作规约**必须严格按 SOP 执行**。\n\n"
        "---\n\n"
        f"{login_step}"
        "**第 2 步：调用 `sitemap_set_business`** 设置业务类型和技术栈\n\n"
        "**第 3 步（核心）：按下方遍历 Checklist 逐页操作**\n"
        "  - 严格按 SOP 的「黄金循环」「Tab 遍历」「表单提交规范」「按钮操作类型对照表」执行\n"
        "  - 每个 ⬜ 完成后打 ✅，每完成 5 个页面调一次 `sitemap_get_coverage` 自检 API 数有没有涨\n\n"
        f"{traversal_checklist}\n\n"
        "**第 4 步：添加业务功能点（必做！）**\n"
        "  ⚠️ 系统自动生成的功能点是**单个 API 级别**（如 menu/list、menu/create），没有业务语义。\n"
        "  你必须**按业务菜单/页面**添加功能点，每个菜单页面 = 1 个功能点，关联该页面的所有 API：\n"
        "  ```\n"
        "  sitemap_add_feature(\n"
        "    name='用户管理',\n"
        "    description='系统用户的增删改查、启用禁用、角色分配',\n"
        "    module='系统管理/用户管理',\n"
        "    page_url='http://目标/#/admin/users',\n"
        "    related_apis=['GET /api/.../user/page', 'POST /api/.../user/add', ...],\n"
        "    priority='high'\n"
        "  )\n"
        "  ```\n"
        "  - related_apis 必须填第 3 步 proxy_get_traffic 抓到的所有 API\n"
        "  - 一个菜单页面多个 Tab → 一个功能点关联所有 Tab 的 API\n"
        "  - **不要跳过这一步！** 没有业务功能点，Phase 2 子 Agent 无法按业务模块分组测试\n\n"
        "**第 5 步：调用 `crypto_detect`** 检测前端加密（可选）\n\n"
        "**第 6 步：调用 `phase_complete`** 进入测试阶段\n\n"
        "---\n\n"
        "## ⛔ 路径独有铁律（SOP 之外的）\n"
        "- 第 3 步不可跳过！每个菜单每个 Tab 都要点到（具体怎么点 → 看 SOP）\n"
        "- 第 4 步不可跳过！每个菜单页面必须 `sitemap_add_feature` 添加一个业务功能点\n"
        "- 系统自动生成的 API 级功能点（如 menu/list）不需要重复添加，但业务级功能点必须添加\n"
        "- 即使菜单超过 20 个，也必须全部操作完"
    )


# ============================================================
# 路径 C：crawl_result is None（爬虫 + mitmproxy 双兜底都失败）
# ============================================================

def _path_c_feature_hint_with_credentials(
    credentials: list[dict[str, Any]], has_cookie_inject: bool
) -> str:
    """路径 C 在"有 credentials"分支下的 第 3+4+5 步合并文本。"""
    if has_cookie_inject:
        login_step_text = (
            "**第 3 步（登录）**: ✅ 用户已提供 Cookie/Token，无需登录\n"
            "  - 系统已自动注入 Cookie/Authorization，浏览器和所有 HTTP 请求都已带认证\n"
            "  - 直接 `browser_goto` 访问目标 URL，应该已是登录后状态\n"
            "  - 若访问后被踢回登录页，说明 Cookie 已过期，请告知用户重新提供\n\n"
        )
    else:
        cred_text = ", ".join(
            [f"{c.get('username','')}:{c.get('password','')}" for c in credentials]
        )
        login_step_text = (
            "**第 3 步（登录）**: 用提供的账号登录系统\n"
            f"  - 账号信息: {cred_text}\n"
            "  - 用 `browser_fill` 填写账号密码，`browser_click` 点击登录\n"
            "  - 登录成功后用 `browser_get_content` 查看完整菜单结构\n\n"
        )
    return (
        login_step_text
        + "**第 4 步（⚠️ 核心步骤）**: 获取完整菜单列表 → 逐个遍历 → 深入每个页面操作\n"
        "  4.1 用 `browser_evaluate` / `browser_get_content` 获取侧边栏/导航栏的**全部菜单项**\n"
        "  4.2 把菜单列表打印出来作为待遍历清单\n"
        "  4.3 **从第 1 个菜单开始逐个操作，严格按 SOP 的「黄金循环」「Tab 遍历」「表单提交规范」「按钮操作类型对照表」执行**\n"
        "  4.4 有子菜单/下拉菜单的，展开后对每个子菜单项也执行 4.3\n"
        "  4.5 全部菜单都操作完后，回顾清单确认无遗漏\n\n"
        "  ⚠️ **核心目的**：你在这里抓到的每一个真实请求（含完整 URL、参数、Body、Header），\n"
        "  都会自动存入流量样本文件，直接传给漏洞检测的子 Agent。\n"
        "  抓到的请求越完整，越容易发现 IDOR、越权、注入等漏洞。\n\n"
        "**第 5 步**: 逐个添加功能点\n"
        "  - 每个菜单项/页面 = 1 个功能点\n"
        "  - **必须传 `related_apis`**（第 4 步抓到的该页面触发的全部 API 列表，含增删改查）\n"
        "  - **必须传 `module`**（用 / 分隔层级，如 '系统管理/用户管理'）\n"
        "  - **必须传 `page_url`**（该菜单对应的页面 URL）\n"
        "  - 不要合并功能点！\n"
    )


def _path_c_feature_hint_no_credentials() -> str:
    """路径 C 在"无 credentials"分支下的 第 4 步（JS 反向）。"""
    return (
        "**第 4 步**: 从 JS 分析结果中逐个添加功能点（⚠️ 关键步骤）：\n"
        "  - 必须把 `js_analyze_selected` 发现的**每个路由页面**都添加为功能点\n"
        "  - 后台功能设 `requires_auth=true`（自动延迟，只生成未授权访问 checklist）\n"
        "  - 登录页/公开页设 `requires_auth=false`（正常生成完整 checklist）\n"
        "  - **必须传 `module` 参数**（用 / 分隔层级，如 '安全预警/告警中心'）\n"
        "  - **必须传 `related_apis` 参数**（该功能关联的 API 路径列表）\n"
        "  - 不要合并功能点！每个页面/路由 = 1 个功能点\n"
    )


def build_path_c_user_msg(
    *,
    url: str,
    user_message: str,
    credentials: list[dict[str, Any]],
    has_cookie_inject: bool,
) -> str:
    """路径 C — 爬虫数据缺失，主 Agent 自己 JS 反向 + 手动浏览。"""
    if credentials:
        feature_hint = _path_c_feature_hint_with_credentials(credentials, has_cookie_inject)
    else:
        feature_hint = _path_c_feature_hint_no_credentials()
    return (
        f"目标: {url}\n用户指令: {user_message}\n\n"
        "⚠️ 爬虫数据缺失（自动爬取与 mitmproxy 兜底均未产生结果）。"
        "请按以下步骤手动浏览目标，严格按 system 中的浏览器操作 SOP 执行。\n\n"
        "**第 1 步**: 用 `browser_goto` 访问目标，`browser_get_content` 分析页面\n\n"
        "**第 2 步（⚠️ 必做）**: 调用 `js_extract_apis` 获取页面加载的所有资源文件清单。\n"
        "  拿到清单后，根据渗透测试经验判断哪些文件值得深度分析（业务JS、source map、配置文件等），\n"
        "  然后调用 `js_analyze_selected` 传入选中的 URL。\n"
        "  **必须完成这两个调用后才能执行后续步骤！**\n\n"
        "**第 3 步**: 调用 `sitemap_set_business` 设置业务类型和技术栈\n\n"
        f"{feature_hint}\n"
        "**第 6 步**: 调用 `crypto_detect` 检测前端加密\n\n"
        "**第 7 步**: 调用 `phase_complete` 进入测试阶段\n\n"
        "⛔ **铁律**：\n"
        "- 不调用 `js_extract_apis` + `js_analyze_selected` 就添加功能点 = 遗漏大量 API\n"
        "- 浏览操作严格按 SOP（黄金循环 + Tab 遍历 + 表单填表）\n"
        "- 不添加功能点就无法进入测试阶段"
    )
