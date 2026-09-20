"""回归钉（阶段 3 高级选项重设计）—— 固化"真开关 / 诚实标注 / 主题收敛"，防回退。

阶段 3 的本质是把设置页里**三个假开关**（无 onchange 绑定的 checkbox）改成真控件，
并诚实标注后端未就绪项（自动保存报告需后端钩子、凭证隔离是架构债）。
任何一端回退（比如又写成无 onchange 的 checked checkbox）都应被钉住。
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


def test_concurrent_is_dropdown_not_fake_switch(index_src):
    """并发扫描从「无绑定的 checkbox」改为「1/3/5/10 下拉」，接 settings.concurrent。"""
    assert 'id="settingConcurrent"' in index_src, "批量扫描并发数下拉缺失"
    assert "onConcurrentChange" in index_src, "并发下拉无 onchange 接线"


def test_realtime_vuln_is_real_switch(index_src):
    """实时漏洞推送是真开关（有 id + onchange），不再是裸 checked checkbox。"""
    assert 'id="settingRealtimeVuln"' in index_src
    assert 'onRealtimeVulnChange(this.checked)' in index_src


def test_autosave_switch_is_real_and_honest(index_src):
    """自动保存报告是真开关 + 诚实徽标「需后端补钩子」（不做假开关）。"""
    assert 'id="settingAutoSave"' in index_src
    assert 'onAutoSaveChange(this.checked)' in index_src
    assert "需后端补钩子" in index_src, "自动保存报告未诚实标注后端钩子缺失"


def test_dark_theme_bool_switch_removed(index_src):
    """移除与三主题体系冲突的「暗色主题」布尔开关（toggleTheme）。"""
    assert 'id="themeToggle"' not in index_src, "暗色主题布尔开关应已移除"
    assert "toggleTheme(" not in index_src, "toggleTheme() 调用应已移除"


def test_realtime_vuln_guarded_by_settings(index_src):
    """vuln 事件渲染受 settings.realtimeVulnPush 守卫，可被真开关关闭。"""
    m = re.search(r"else if \(type === 'vuln'\)\s*\{(.*?)\n  \}", index_src, re.S)
    assert m, "vuln 事件分支结构被破坏"
    assert "settings.realtimeVulnPush" in m.group(1), "实时推送未受开关守卫"
    assert "addVulnFromEvent(event)" in m.group(1)


def test_scan_all_sends_concurrent(index_src):
    """批量扫描接口必须带上 concurrent 参数（上限 10，对齐后端 system_api）。"""
    m = re.search(r"/api/targets/scan-all[\s\S]*?JSON.stringify\(\{(.*?)\}\)", index_src, re.S)
    assert m, "scan-all 调用结构被破坏"
    assert "concurrent" in m.group(1), "scan-all 未传 concurrent"


def test_topbar_delete_entry_removed(index_src):
    """I1 护栏 UI 配套：顶栏不再有一键删除当前会话入口（避免误删）。"""
    assert 'onclick="deleteCurrentSession()"' not in index_src, "顶栏删除入口应已移除"
    # 侧栏 ⋯ 菜单仍保留删除能力（二次确认）
    assert "doDeleteSession" in index_src
