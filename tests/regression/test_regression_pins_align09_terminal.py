"""回归钉（智能终端助手面板 · 拖拽改高 / 默认展开 / 输入框撑高）—— 防回退。

背景：三态机制（拖拽改高 / 最大化 / 收起）早已实现，但方案里的三个参数没落地，
其中**拖拽上限**是"代码注释与行为互相矛盾"的硬 bug：

  JS `:4414` 注释写「上限 85vh」，代码也确实算 `innerHeight * 0.85`，
  但 CSS 的 `max-height: 50vh` 优先级更高 —— 实测设 `height:2000px` 只得到 450px(=50.0vh)。
  读代码只能看到"一致"的假象，必须实测量 `offsetHeight` 才能发现。

另三条：面板默认收起（拖拽条 `display:none`，用户以为没这功能）、
输入框 `max-height:80px`、输入框不按内容撑高（8 行文本仍 32px）。

配套浏览器级验收：`_term_panel_check.py`（14 项，含刷新后仍保持收起的实测）。
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
    m = re.search(re.escape(selector) + r"\s*\{(.*?)\}", src, re.S)
    assert m, f"CSS 规则缺失: {selector}"
    return m.group(1)


# ------------------------------------------------- 上限一致性（本次 bug 的根因）

def test_terminal_max_height_css_matches_js(index_src):
    """CSS max-height 必须与 JS TERM_MAX_RATIO 同源。

    这是本次修复的核心：两者不一致时，较小的那个生效且**没有任何报错**，
    表现只是"拖到一半拖不动"，极易被当成手感问题而反复排查 JS。
    """
    body = _rule_body(index_src, ".terminal-panel")
    mm = re.search(r"max-height:\s*(\d+)vh", body)
    assert mm, "terminal-panel 未以 vh 定义 max-height（JS 用视口比例计算，两者必须同源）"
    css_vh = int(mm.group(1))

    m2 = re.search(r"const TERM_MAX_RATIO\s*=\s*([0-9.]+)", index_src)
    assert m2, "TERM_MAX_RATIO 常量缺失"
    js_vh = round(float(m2.group(1)) * 100)

    assert css_vh == js_vh, (
        f"CSS max-height({css_vh}vh) 与 JS TERM_MAX_RATIO({js_vh}vh) 不一致 —— "
        f"拖拽上限会被较小者夹住（改上限必须同时改两处）"
    )
    assert css_vh >= 80, f"上限应 ≥80vh（方案第 3 条：50vh → 80vh），当前 {css_vh}vh"


def test_terminal_heights_use_single_source(index_src):
    """高度钳制必须走 clampTermH，不得再出现散落的写死数值。

    修复前有三套互不相同的上限：CSS 50vh / 拖拽钳制 85vh / 记忆校验 90vh。
    记忆校验比 CSS 宽松时，存进去的值下次读出来用不了。
    """
    assert "function clampTermH" in index_src, "clampTermH 缺失"
    assert "TERM_MIN_H" in index_src and "TERM_MAX_RATIO" in index_src, "高度常量缺失"

    # 高度改写在 mousemove handler 里（mousedown 只记起始位移），锚点取 dragY 判定那行
    drag = re.search(r"if \(dragY === null\) return;([\s\S]*?)\n  \}\);", index_src)
    assert drag, "拖拽 mousemove handler 结构被破坏"
    assert "clampTermH(" in drag.group(1), "拖拽未走 clampTermH（会出现 CSS/JS 上限不一致）"

    # 记忆校验也走同一比例
    sv = re.search(r"function termSavedHeight\(\)\s*\{(.*?)\n\}", index_src, re.S)
    assert sv, "termSavedHeight 结构被破坏"
    assert "TERM_MAX_RATIO" in sv.group(1), "记忆校验未使用 TERM_MAX_RATIO"
    assert "window.innerHeight * 0.9" not in sv.group(1), "记忆校验残留比 CSS 更宽松的 0.9 上限"


def test_no_stale_hardcoded_limits(index_src):
    """不得残留 0.85 这类与 CSS 不一致的写死比例（territory 回归钉）。"""
    assert "window.innerHeight * 0.85" not in index_src, \
        "残留 innerHeight*0.85 写死上限（与 CSS max-height 不同源）"


# ------------------------------------------------- 默认展开 + 收起态记忆

def test_terminal_defaults_to_open(index_src):
    """HTML 不得写死 collapsed：默认展开，收起态由 JS 依 localStorage 恢复。

    否则「记住收起态」会被初始 HTML 覆盖（加载瞬间收起 → JS 再展开，或反之）。
    """
    m = re.search(r'<div class="terminal-panel([^"]*)"\s+id="terminalPanel"', index_src)
    assert m, "terminalPanel 容器结构被破坏"
    assert "collapsed" not in m.group(1), "HTML 写死了 collapsed（默认应为展开）"


def test_collapsed_pref_persisted(index_src):
    """收起态必须记忆：切换时写键，初始化时读键（用户明确要求）。"""
    assert "const TERM_COLLAPSE_KEY" in index_src, "收起态记忆键常量缺失"
    assert "function applyTermCollapsedPref" in index_src, "缺少收起态恢复函数"

    tog = re.search(r"function toggleTerminal\(\)\s*\{(.*?)\n\}", index_src, re.S)
    assert tog, "toggleTerminal 结构被破坏"
    assert "localStorage.setItem(TERM_COLLAPSE_KEY" in tog.group(1), \
        "切换收起态时未写入记忆（刷新后会被默认展开冲掉）"

    init = re.search(r"function initTerminalResize\(\)\s*\{(.*?)\n  // ——", index_src, re.S)
    assert init, "initTerminalResize 结构被破坏"
    assert "applyTermCollapsedPref()" in init.group(1), \
        "初始化未应用收起态记忆（必须在决定高度之前调用）"
    # 顺序契约：先恢复态，再算高度
    assert init.group(1).index("applyTermCollapsedPref()") < init.group(1).index("termSavedHeight()"), \
        "应先 applyTermCollapsedPref() 再 termSavedHeight()，否则收起态下会被套上展开高度"


# ------------------------------------------------- 输入框

def test_textarea_max_height_and_autogrow(index_src):
    """输入框上限 200px，且按内容自动撑高（原 resize:none + 80px 会压成一行）。"""
    body = _rule_body(index_src, ".terminal-input-area textarea")
    mm = re.search(r"max-height:\s*(\d+)px", body)
    assert mm, "terminal-input-area textarea 未定义 max-height"
    assert int(mm.group(1)) >= 200, f"输入框 max-height 应 ≥200px（方案第 5 条），当前 {mm.group(1)}px"

    m2 = re.search(r"const TERM_INPUT_MAX_H\s*=\s*(\d+)", index_src)
    assert m2, "TERM_INPUT_MAX_H 常量缺失"
    assert int(m2.group(1)) == int(mm.group(1)), \
        f"JS TERM_INPUT_MAX_H({m2.group(1)}) 与 CSS max-height({mm.group(1)}) 不一致"

    assert "function autoGrowTerminalInput" in index_src, "缺少输入框自动撑高函数"
    assert "addEventListener('input', autoGrowTerminalInput)" in index_src, \
        "自动撑高未绑定到 input 事件"
    assert "scrollHeight" in index_src, "自动撑高未按 scrollHeight 计算"


def test_terminal_input_area_present(index_src):
    """输入框元素与 id 不得被改名（autoGrow 依赖 terminalInput）。"""
    assert 'id="terminalInput"' in index_src, "terminalInput 元素丢失（自动撑高会静默失效）"


# ------------------------------------------------- 终端命令解析器（0919 追加）

def test_terminal_command_parser_exists(index_src):
    """sendTerminalMessage 之前必须有 handleTerminalCommand，且扫描中也能执行命令。"""
    assert "async function handleTerminalCommand" in index_src, "缺少终端命令解析器"
    assert "async function sendTerminalMessage" in index_src, "sendTerminalMessage 结构被破坏"

    send = re.search(r"async function sendTerminalMessage\(\)\s*\{(.*?)^\}", index_src, re.S | re.M)
    assert send, "sendTerminalMessage 结构被破坏"
    body = send.group(1)
    assert "handleTerminalCommand(msg)" in body, "sendTerminalMessage 未调用命令解析器"
    cmd_idx = body.index("handleTerminalCommand(msg)")
    block_idx = body.index("if (isStreaming)")
    assert cmd_idx < block_idx, "命令解析必须在 isStreaming 拦截之前，否则「暂停」等命令无法停止扫描"


def test_terminal_pause_command_wired(index_src):
    """「暂停/停止」命令必须能中止当前 SSE / 扫描任务。"""
    parser = re.search(r"async function handleTerminalCommand\(msg\)\s*\{(.*?)^\}", index_src, re.S | re.M)
    assert parser, "handleTerminalCommand 结构被破坏"
    body = parser.group(1)
    assert "暂停" in body and "停止" in body, "暂停/停止 不在命令表"
    assert "pauseCurrentTask" in body, "暂停命令未映射到 pauseCurrentTask"


def test_terminal_command_list_readable(index_src):
    """帮助命令列出常用命令，用户可知能输入什么。"""
    assert "'帮助'" in index_src or '"帮助"' in index_src, "帮助命令缺失"
    assert "可用命令" in index_src, "帮助命令未输出命令列表"
