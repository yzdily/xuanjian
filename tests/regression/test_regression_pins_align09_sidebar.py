"""回归钉（侧栏骨架对齐 demo r15）—— 防回退。

背景：`web/index.html` 的侧栏曾有**三处结构错位**，与 demo 定稿
（`.workbuddy/artifacts/terminal-tools-demo.html` r15，2026-09-19）不一致：

1. **新建任务**被埋在会话面板内（导航之下）→ 定稿是**导航之上**（WorkBuddy 左上形态）。
2. **高级工具**是 `.collapsed` 驱动的内联展开，占侧栏纵向空间；flyout 仅在
   「侧栏折叠 + :hover」可见 → 展开态永远飞不出去，且 hover-only 键盘不可达。
   定稿是 `.open` 驱动的**飞出面板**（absolute，落到侧栏右边界之外）。
3. **设置**混在主导航第 5 位 → 定稿是**侧栏最下角**（会话面板之下、版本之上，
   且主导航只有 4 项）。

这些都是「看起来只是挪了一下」的改动，最容易被后续调整无声推翻，故逐条落钉。
配套浏览器级验收：`_align09_sidebar_check.py`（34 项，含「面板 left >= 侧栏 right」实测）。

另一类易回退点：删除 `nav-group-flyout` 后若只删元素不删 CSS，会留下死代码——
与阶段 6 主题切换器同款陷阱，故按「CSS 规则定义形态」检查而非字符串搜索。
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INDEX_HTML = PROJECT_ROOT / "web" / "index.html"


@pytest.fixture(scope="module")
def index_src() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


def _rule_body(src: str, selector: str) -> str:
    """取出某个 CSS 选择器的第一条规则体（用于断言属性真正写在规则里）。"""
    m = re.search(re.escape(selector) + r"\s*\{(.*?)\}", src, re.S)
    assert m, f"CSS 规则缺失: {selector}"
    return m.group(1)


def _first_index(src: str, needle: str) -> int:
    i = src.find(needle)
    assert i >= 0, f"标记缺失: {needle}"
    return i


# ------------------------------------------------- 错位 1：新建任务在导航之上

def test_new_task_button_is_above_nav(index_src):
    """新建任务必须位于品牌区之后、主导航之前（demo r15 骨架）。"""
    brand = _first_index(index_src, 'class="sidebar-brand"')
    new_task = _first_index(index_src, 'class="new-task-btn"')
    nav = _first_index(index_src, '<nav class="nav-menu">')
    assert brand < new_task < nav, (
        "新建任务不在导航之上——demo r15 要求「品牌 → ⊕ 新建任务 → 主导航」"
    )


def test_new_task_is_native_button(index_src):
    """新建任务必须是原生 button（键盘可达），且仍调用 newTaskFromSidebar。"""
    m = re.search(r"<button[^>]*class=\"new-task-btn\"[^>]*>", index_src)
    assert m, "new-task-btn 不是 <button>"
    assert "newTaskFromSidebar()" in index_src, "新建任务的处理函数被改名/移除"


def test_legacy_new_task_in_session_panel_removed(index_src):
    """会话面板内的旧新建入口（.sess-new-btn）不应复活，否则出现两个新建按钮。"""
    assert "sess-new-btn" not in index_src, "旧 sess-new-btn 残留（新建入口应唯一）"


# ------------------------------------------------- 错位 2：高级工具外翻

def test_advanced_tools_panel_flies_out(index_src):
    """高级工具面板必须是 absolute 外翻，且 left 要越过侧栏右边界。

    纯 left:100% 只到 nav-menu 内容盒右边界，会残留约 3px 压在侧栏上
    （浏览器实测 panel.left=237 < sidebar.right=240），故要求 calc(100% + Npx)。
    """
    body = _rule_body(index_src, ".nav-group-items")
    assert "position: absolute" in body, "高级工具面板不是 absolute（会占掉侧栏纵向空间）"
    assert re.search(r"left:\s*calc\(100%\s*\+", body), (
        "外翻位移不足：需 left: calc(100% + Npx) 才能真正落到侧栏之外"
    )
    assert "position: relative" in _rule_body(index_src, ".nav-group"), \
        ".nav-group 未设 relative，absolute 面板会相对更外层定位"


def test_advanced_tools_default_hidden_and_open_driven(index_src):
    """.open 驱动显隐：默认 display:none，打开时 display:flex。"""
    assert re.search(r"display:\s*none", _rule_body(index_src, ".nav-group-items")), \
        "面板默认未隐藏（会常驻占位，违背「外翻」）"
    m = re.search(r"\.nav-group\.open\s+\.nav-group-items\s*\{(.*?)\}", index_src, re.S)
    assert m, "缺少 .nav-group.open 驱动规则（外翻面板打不开）"
    assert "display: flex" in m.group(1), ".open 时未显示面板"


def test_no_inline_expand_leftover(index_src):
    """内联展开的旧实现必须彻底移除：不得再有 .collapsed 控制的面板显隐。"""
    assert not re.search(r"\.nav-group\.collapsed\s+\.nav-group-items\s*[{\s]", index_src), \
        "内联展开旧规则残留（现在应是 .open 驱动的外翻）"
    m = re.search(r'<div class="nav-group([^"]*)"\s+id="navGroupAdvanced"', index_src)
    assert m, "navGroupAdvanced 容器结构被破坏"
    assert "collapsed" not in m.group(1), "分组容器仍带 collapsed 类（应改为默认无类，靠 .open）"


def test_duplicate_flyout_panel_and_dead_css_removed(index_src):
    """两套面板（nav-group-items 与 nav-group-flyout）只应保留一套，且不留 CSS 死代码。

    按「CSS 规则定义形态」匹配，避免注释里提到类名（说明为何删除）造成误判。
    """
    assert not re.search(r"\.nav-group-flyout\s*[{,]", index_src), \
        "nav-group-flyout 的 CSS 死代码残留（元素已删）"
    assert not re.search(r"\.flyout-item\s*[{,]", index_src), \
        "flyout-item 的 CSS 死代码残留（元素已删）"
    assert not re.search(r"button\.flyout-item\s*[,{]", index_src), \
        "button.flyout-item 重置规则残留"


def test_advanced_panel_keyboard_path_exists(index_src):
    """外翻面板必须有键盘路径：显式关闭函数 + Esc + 点面板外关闭 + aria 同步。

    原实现靠 :hover 显示，键盘用户完全无法访问（这是本次修复的核心动机之一）。
    """
    assert "function closeAdvancedGroup" in index_src, "缺少显式关闭函数（hover-only 的老路）"
    assert re.search(r"e\.key === 'Escape'[\s\S]{0,80}closeAdvancedGroup", index_src), \
        "Esc 未接入关闭逻辑"
    assert re.search(r"!g\.contains\(e\.target\)[\s\S]{0,60}closeAdvancedGroup", index_src), \
        "点面板之外未接入关闭逻辑"
    assert 'aria-controls="navGroupAdvanced"' in index_src, "分组头缺 aria-controls"
    assert "aria-expanded" in index_src, "展开态未向读屏暴露"
    assert "collapsed ? 'false' : 'true'" not in index_src, \
        "toggleNavGroup 仍按 collapsed 语义同步 aria（应对齐 .open 语义）"


# ------------------------------------------------- 错位 3：设置下移到最下角

def test_settings_moved_to_sidebar_bottom(index_src):
    """设置必须在会话面板之后、版本区之前（侧栏最下角）。"""
    sess = _first_index(index_src, 'class="sidebar-sess"')
    settings = _first_index(index_src, 'class="nav-item sidebar-settings"')
    footer = _first_index(index_src, 'class="sidebar-footer"')
    assert sess < settings < footer, (
        "设置不在会话面板之下 / 版本之上——demo r15 要求它是侧栏最下角入口"
    )


def test_settings_keeps_nav_to_contract(index_src):
    """设置移出 nav-menu 后仍须保留 .nav-item + data-page，否则 navTo 高亮丢失。"""
    m = re.search(r"<button[^>]*class=\"nav-item sidebar-settings\"[^>]*>", index_src)
    assert m, "设置按钮结构被破坏"
    assert 'data-page="settings"' in m.group(0), "设置缺 data-page，navTo 无法定位激活项"
    assert "navTo('settings')" in m.group(0), "设置未接 navTo"
    # navTo 的定位契约本身不能被改成只认 nav-menu 内元素
    m2 = re.search(r"function navTo\(page\)\s*\{(.*?)\n\}", index_src, re.S)
    assert m2, "navTo 结构被破坏"
    assert '.nav-item[data-page="${page}"]' in m2.group(1), \
        "navTo 改变了定位方式，设置按钮的高亮会失效"


def test_main_nav_has_no_settings(index_src):
    """主导航只应有 4 项（设置不在其中）。"""
    start = _first_index(index_src, '<nav class="nav-menu">')
    end = _first_index(index_src, 'id="navGroupAdvanced"')
    segment = index_src[start:end]
    assert 'data-page="settings"' not in segment, "设置仍留在主导航内"
    labels = re.findall(r'data-page="(\w+)"', segment)
    assert labels == ["targets", "scans", "vulns", "reports"], \
        f"主导航项异常：{labels}"


# ------------------------------------------------- 工具分组：8 项全在「更多工具」面板内

def test_all_tools_inside_more_tools_group(index_src):
    """0919 修订：8 个高级工具全部收进「更多工具」飞出面板，主导航不再额外常驻。"""
    start = _first_index(index_src, '<nav class="nav-menu">')
    end = _first_index(index_src, 'id="navGroupAdvanced"')
    nav_before_group = index_src[start:end]
    for path in ["/dashboard", "/traffic", "/replay-theater",
                 "/skill-manager", "/memory", "/sitemap-diff",
                 "/crypto-templates", "/llm-monitor"]:
        assert f"openAdvancedTool('{path}')" not in nav_before_group, \
            f"{path} 不应出现在主导航区，应收进「更多工具」分组"

    grp_start = _first_index(index_src, 'id="navGroupAdvanced"')
    grp_end = _first_index(index_src, '</nav>')
    group = index_src[grp_start:grp_end]
    for tool, path in [("仪表盘", "/dashboard"),
                       ("流量管理", "/traffic"),
                       ("决策回放", "/replay-theater"),
                       ("方法论", "/skill-manager"),
                       ("记忆管理", "/memory"),
                       ("站点地图", "/sitemap-diff"),
                       ("加密模板", "/crypto-templates"),
                       ("LLM 监控", "/llm-monitor")]:
        assert f"openAdvancedTool('{path}')" in group, f"{tool} 未在「更多工具」分组内"

    assert '<span class="nav-group-label">更多工具</span>' in index_src, \
        "分组名应为「更多工具」"


# ------------------------------------------------- 缺项 5：会话面板撑满

def test_session_panel_fills_sidebar(index_src):
    """会话面板与列表都应 flex:1 撑满——原 max-height:240px 会让下半截留白。"""
    assert "flex: 1" in _rule_body(index_src, ".sidebar-sess"), "会话面板未撑满侧栏"
    list_body = re.search(r"\.sess-list\s*\{(.*?)\}", index_src, re.S)
    assert list_body, ".sess-list 规则缺失"
    assert "flex: 1" in list_body.group(1), "会话列表未撑满"
    assert "max-height: 240px" not in list_body.group(1), "旧的 max-height 写死值残留"


# ------------------------------------------------- 行为级：服务端吐出的就是新骨架

def test_served_index_has_new_skeleton():
    """行为级回归钉：真实服务端返回的 HTML 必须已是新骨架（防止只改了副本）。"""
    pytest.importorskip("fastapi")
    httpx = pytest.importorskip("httpx")
    from web import server  # noqa: WPS433  (延迟导入，避免无依赖环境整体收集失败)

    import asyncio

    async def _fetch() -> tuple[int, str]:
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/")
            return r.status_code, r.text

    code, html = asyncio.run(_fetch())
    assert code == 200, f"/ 应返回 200，实际 {code}"
    assert 'class="new-task-btn"' in html, "服务端返回的页面没有「导航之上」的新建任务"
    assert 'class="nav-item sidebar-settings"' in html, "服务端返回的页面没有底部设置入口"
    assert 'class="nav-group" id="navGroupAdvanced"' in html, "高级工具容器仍是旧结构"
    assert "sess-new-btn" not in html, "服务端仍返回旧的会话内新建入口"
