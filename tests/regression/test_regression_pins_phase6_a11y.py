"""回归钉（阶段 6 字体一致 / 主题收敛 / 无障碍）—— 防回退。

阶段 6 做了四件事，每件都容易被后续改动无声推翻：

1. **FR-8.1 字体一致**：控件字体栈统一走 --font-sans（否则 button 回落系统 UI 字体，
   与 div/span 承载的导航项渲染不一致 —— 本项目已踩两次）。
2. **FR-7 主题收敛**：主题唯一入口 = 设置页「外观」卡片；顶栏下拉菜单与侧栏底部切换器已移除。
3. **FR-8.3 键盘可达**：原来 103 处 div onclick 不可键盘访问，现全部改为 <button>
   或 role="button" + tabindex；弹层支持 Esc / 点遮罩关闭 / 打开移焦。
4. **FR-8.4 实时播报**：日志流 / toast / 漏洞推送 / 终端状态都有 aria-live。
5. **FR-8.5 保图去链**：韩立主题背景图本地化，断网可用。

另含一条**行为级**回归钉：修复了 `_auth_middleware` 对非 /api/ 路径隐式返回 None 的
既有 bug（曾导致 /dashboard 与 /vendor/* 全部 500，且 dompurify 静默加载失败）。
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INDEX_HTML = PROJECT_ROOT / "web" / "index.html"
SERVER_PY = PROJECT_ROOT / "web" / "server.py"
HANLI_BG = PROJECT_ROOT / "web" / "static" / "hanli-sidebar.jpg"


@pytest.fixture(scope="module")
def index_src() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def server_src() -> str:
    return SERVER_PY.read_text(encoding="utf-8")


# ---------------------------------------------------------------- FR-8.1 字体

def test_sans_font_token_defined_and_used(index_src):
    """--font-sans 必须存在，且控件与正文都用它（不能回落到硬编码字体名）。"""
    assert "--font-sans:" in index_src, "--font-sans 变量缺失（FR-8.1 字体统一的前提）"
    assert "font-family: var(--font-sans)" in index_src, "正文未使用 --font-sans"
    m = re.search(r"button, select, textarea, input \{[^}]*\}", index_src)
    assert m, "控件字体继承规则缺失"
    assert "var(--font-sans)" in m.group(0), "控件未统一到 --font-sans（会回落系统 UI 字体）"


# ---------------------------------------------------------------- FR-8.3 焦点

def test_focus_visible_uses_dedicated_ring_token(index_src):
    """焦点轮廓用 --focus-ring 而非 --accent-indigo。

    韩立主题的 --accent-indigo(#6633cc) 在深紫底上仅 2.72:1，低于 WCAG 1.4.11 的 3:1；
    若回退成 accent-indigo，键盘焦点在该主题下将不可见。
    """
    assert ":focus-visible" in index_src, "缺少键盘焦点可见样式"
    m = re.search(r":focus-visible \{(.*?)\}", index_src, re.S)
    assert m, "focus-visible 规则结构被破坏"
    assert "var(--focus-ring" in m.group(1), "焦点轮廓未使用 --focus-ring（韩立主题下会不可见）"
    assert "var(--accent-indigo" not in m.group(1), "焦点轮廓回退到了低对比的 accent-indigo"


def test_focus_ring_defined_per_theme(index_src):
    """三个主题都必须各自定义 --focus-ring，否则会串用别主题的值。"""
    for block_pat, name in [
        (r":root \{(.*?)\}", "dark"),
        (r'\[data-theme="light"\] \{(.*?)\}', "light"),
        (r'\[data-theme="hanli"\] \{(.*?)\}', "hanli"),
    ]:
        m = re.search(block_pat, index_src, re.S)
        assert m, f"{name} 主题变量块缺失"
        assert "--focus-ring" in m.group(1), f"{name} 主题缺 --focus-ring 定义"


# ---------------------------------------------------------------- FR-8.3 键盘可达

def test_no_keyboard_inaccessible_click_handlers(index_src):
    """非原生控件（div/span/li/td/tr）带 onclick 时，必须 role=button + tabindex。

    这是阶段 6 最核心的改动：原 103 处 div onclick 键盘完全不可达。
    """
    tag_re = re.compile(r"<(div|span|li|td|tr)\b[^>]*>")
    clickable = [m.group(0) for m in tag_re.finditer(index_src) if "onclick=" in m.group(0)]
    blocked = [t for t in clickable if not ('role="button"' in t and "tabindex" in t)]
    assert not blocked, (
        f"{len(blocked)} 个可点击元素键盘不可达（应改 <button> 或补 role=button+tabindex）：\n"
        + "\n".join(f"  {t[:110]}" for t in blocked[:5])
    )


def test_nav_items_are_buttons(index_src):
    """侧栏导航项必须是 <button>，且保留 data-page（JS 依赖该属性切换 active）。"""
    buttons = re.findall(r'<button[^>]*class="nav-item[^"]*"[^>]*>', index_src)
    assert len(buttons) >= 5, f"nav-item 未按钮化（找到 {len(buttons)} 个）"
    assert 'data-page="targets"' in index_src, "data-page 属性丢失，navTo/switchPage 会失效"


def test_terminal_context_menu_is_button(index_src):
    """终端「＋」菜单项改按钮后，data-act/data-mode 属性必须保留（JS 委托依赖）。"""
    assert index_src.count('class="tp-item') >= 7, "tp-item 数量异常"
    assert '<button type="button" class="tp-item" data-act="file">' in index_src
    assert "data-mode=\"deep\"" in index_src, "扫描模式选项丢失"


def test_role_button_has_enter_space_delegate(index_src):
    """role=button 的元素必须有 Enter/Space 键盘委托，否则等于没补 tabindex。"""
    assert '[role="button"][tabindex]' in index_src, "缺少 role=button 的键盘委托选择器"
    m = re.search(r"e\.key !== 'Enter' && e\.key !== ' '", index_src)
    assert m, "键盘委托未处理 Enter/Space"


def test_modal_esc_and_outside_click(index_src):
    """弹层三件套：ARIA 注入 / Esc 关闭 + 焦点还原 / 点遮罩关闭。"""
    assert "_applyModalAria" in index_src, "modal ARIA 统一注入被移除"
    assert "aria-modal" in index_src
    assert "_openModalStack" in index_src, "modal 栈（Esc 关最上层）被移除"
    assert "_modalReturnFocus" in index_src, "焦点还原被移除"
    assert re.search(r"if \(e\.target === overlay\) closeModal\(id\)", index_src), "点遮罩关闭被移除"


# ---------------------------------------------------------------- FR-8.4 实时播报

def test_toast_has_aria_live(index_src):
    """toast 是实时通知，必须有 role=status + aria-live。"""
    m = re.search(r'<div class="toast-container"[^>]*>', index_src)
    assert m, "toast 容器缺失"
    assert "aria-live" in m.group(0), "toast 容器缺 aria-live（读屏用户无法感知通知）"
    assert "role=\"status\"" in m.group(0), "toast 容器缺 role=status"


def test_terminal_log_and_live_region(index_src):
    """终端日志流 + 视觉隐藏播报区都要 live。"""
    assert 'role="log"' in index_src, "终端日志流丢了 role=log"
    assert 'id="a11yLiveRegion"' in index_src, "缺少 a11yLiveRegion 播报区"
    assert ".sr-only" in index_src, "缺少 sr-only 工具类"
    # sr-only 必须用 clip 而非 display:none —— display:none 会被排除出无障碍树
    m = re.search(r"\.sr-only \{(.*?)\}", index_src, re.S)
    assert m and "clip:" in m.group(1), "sr-only 若用 display:none 则读屏不播报"


def test_vuln_push_announces(index_src):
    """漏洞推送属后台静默更新，必须播报。"""
    m = re.search(r"function addVulnFromEvent[\s\S]*?\n\}", index_src)
    assert m, "addVulnFromEvent 结构被破坏"
    assert "announce(" in m.group(0), "漏洞推送未向读屏播报"


# ---------------------------------------------------------------- FR-7 主题收敛

def test_theme_converged_to_settings_card(index_src):
    """主题唯一入口 = 设置页外观卡片（.theme-cards），顶栏菜单与侧栏切换器均已移除。"""
    assert 'class="theme-cards"' in index_src, "设置页外观卡片缺失"
    assert "getElementById('themeMenu')" not in index_src, "顶栏主题菜单残留（应已收敛）"
    assert "toggleThemeMenu" not in index_src, "toggleThemeMenu 死代码残留"
    # 只检「CSS 规则定义」形态，避免注释里提及类名（说明为何删除）导致误判
    assert not re.search(r"\.sidebar-theme-(?:btn|switcher|label|buttons)\s*[{\[,:]", index_src), \
        "侧栏主题切换器 CSS 死代码残留（应随元素一并清理）"
    assert '<h3>外观</h3>' in index_src, "设置页缺少「外观」卡片标题"


def test_theme_cards_sync_aria_pressed(index_src):
    """外观卡片用 aria-pressed 暴露选中态（单选语义），setTheme 必须同步它。"""
    assert 'aria-pressed="true"' in index_src, "外观卡片缺 aria-pressed 初始态"
    m = re.search(r"function setTheme\(theme\)[\s\S]*?\n\}", index_src)
    assert m, "setTheme 结构被破坏"
    body = m.group(0)
    assert "aria-pressed" in body, "setTheme 未同步 aria-pressed"
    assert ".theme-cards" in body, "setTheme 未更新外观卡片选中态"


# ---------------------------------------------------------------- FR-8.5 保图去链

def test_hanli_background_is_local(index_src):
    """韩立主题背景图必须本地化：不能再向 trae-api 第三方发请求，且文件要真实存在。"""
    assert "trae-api-cn.mchost.guru" not in index_src, "韩立主题仍在加载第三方外链生图"
    assert "/static/hanli-sidebar.jpg" in index_src, "韩立背景未指向本地资源"
    assert HANLI_BG.is_file(), f"本地背景图不存在: {HANLI_BG}"
    assert HANLI_BG.stat().st_size > 1024, "本地背景图疑似为空/损坏"


def test_no_external_url_resources(index_src):
    """全站不应再有 url('http...') 形式的外部资源（断网/内网可用性）。"""
    ext = re.findall(r"url\('(https?://[^']+)'\)", index_src)
    assert not ext, f"仍存在外链资源：{ext[:3]}"


# ---------------------------------------------------------------- 对比度

def _luminance(hexcolor: str) -> float:
    h = hexcolor.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))

    def lin(c: float) -> float:
        c = c / 255.0
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def _contrast(fg: str, bg: str) -> float:
    a, b = _luminance(fg), _luminance(bg)
    lo, hi = sorted((a, b))
    return (hi + 0.05) / (lo + 0.05)


def _theme_vars(src: str) -> dict[str, dict[str, str]]:
    var_re = re.compile(r"(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})")
    dark = {m.group(1): m.group(2) for m in var_re.finditer(re.search(r":root \{(.*?)\}", src, re.S).group(1))}
    out = {"dark": dark}
    for name in ("light", "hanli"):
        blk = re.search(rf'\[data-theme="{name}"\] \{{(.*?)\}}', src, re.S)
        cur = dict(dark)
        cur.update({m.group(1): m.group(2) for m in var_re.finditer(blk.group(1))})
        out[name] = cur
    return out


@pytest.mark.parametrize("theme", ["dark", "light", "hanli"])
def test_text_contrast_meets_wcag_aa(index_src, theme):
    """FR-8.2：正文类文字对比度 ≥4.5:1（WCAG 2.1 · 1.4.3）。

    修复前：--text-dim #475569(2.46:1) / --text-muted #64748b(3.95:1) 不达标。
    """
    v = _theme_vars(index_src)[theme]
    fails = []
    for fg, bg in [("--text-muted", "--bg-base"), ("--text-dim", "--bg-base"),
                   ("--text-muted", "--bg-surface"), ("--text-dim", "--bg-surface"),
                   ("--text-dim", "--bg-elevated")]:
        if fg not in v or bg not in v:
            continue
        ratio = _contrast(v[fg], v[bg])
        if ratio < 4.5:
            fails.append(f"{theme}: {fg}{v[fg]} on {bg}{v[bg]} = {ratio:.2f}:1")
    assert not fails, "对比度不达 WCAG AA 4.5:1：\n" + "\n".join(fails)


# ---------------------------------------------------------------- 既有 bug 钉（行为级）

def test_auth_middleware_has_non_api_fallback(server_src):
    """回归钉：_auth_middleware 必须对非 /api/ 路径显式放行。

    原实现缺少这条兜底 return，未命中白名单且非 /api/ 的路径会隐式返回 None，
    触发 Starlette "TypeError: 'NoneType' object is not callable"。
    受害：/dashboard（侧栏入口）、/vendor/marked.min.js、/vendor/dompurify.min.js。
    """
    m = re.search(r"async def _auth_middleware\(request: Request, call_next\):(.*?)\n@app\.middleware", server_src, re.S)
    assert m, "_auth_middleware 结构被破坏"
    body = m.group(1)
    assert "if path.startswith(\"/api/\"):" in body, "API 鉴权分支丢失"
    # 兜底放行必须处于函数体第一层（4 空格缩进）；API 分支内的放行都在 if 里 → 8 空格。
    top_level = re.findall(r"^    return await call_next\(request\)$", body, re.M)
    assert top_level, (
        "_auth_middleware 缺少函数级兜底放行：非 /api/ 且未命中白名单的路径会隐式返回 None → 500"
    )


def test_static_dir_is_mounted(server_src):
    """回归钉：/static 必须挂载，否则韩立背景图 404。"""
    assert '_STATIC_DIR = WEB_ROOT / "static"' in server_src, "/static 目录常量缺失"
    assert 'app.mount("/static"' in server_src, "/static 未挂载，本地背景图不可访问"


def test_non_api_routes_serve_200():
    """行为级回归钉：页面与静态资源必须 200，且 API 鉴权不能被削弱（仍应 401）。"""
    pytest.importorskip("fastapi")
    httpx = pytest.importorskip("httpx")
    from web import server  # noqa: WPS433  (延迟导入，避免无依赖环境整体收集失败)

    import asyncio

    async def _probe():
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return {p: await c.get(p) for p in [
                "/", "/dashboard", "/vendor/marked.min.js",
                "/vendor/dompurify.min.js", "/static/hanli-sidebar.jpg",
                "/api/loops/matrix",
            ]}

    codes = {p: r.status_code for p, r in asyncio.run(_probe()).items()}
    for p in ["/", "/dashboard", "/vendor/marked.min.js",
              "/vendor/dompurify.min.js", "/static/hanli-sidebar.jpg"]:
        assert codes[p] == 200, f"{p} 应可访问，实际 {codes[p]}"
    # 安全不能被顺带放开：受保护的 API 仍须 401
    assert codes["/api/loops/matrix"] == 401, "API 鉴权被削弱（应仍返回 401）"
