"""§4 Phase 2 item 4：skill_loader 单元测试。

验证：
1. 8 个 risk_domain 均有五段内容
2. load_skill_sections 拼装结构正确
3. include 参数按需注入（降 token）
4. 未知域回退通用兜底
5. token_estimate 粗估合理
"""
from __future__ import annotations

from core.skill_loader import (
    SECTION_NAMES,
    DOMAINS,
    available_domains,
    get_sections,
    load_skill_sections,
    token_estimate,
)


def test_all_8_domains_registered():
    assert available_domains() == list(DOMAINS)
    assert len(DOMAINS) == 8
    for d in DOMAINS:
        secs = get_sections(d)
        assert set(secs.keys()) == set(SECTION_NAMES), f"{d} 缺五段"
        for v in secs.values():
            assert v and v.strip(), f"{d} 某段为空"


def test_load_skill_sections_structure():
    md = load_skill_sections("upload")
    assert md.startswith("## upload 方法论")
    # 五段标题齐全
    for title in ("概述", "检测步骤", "绕过技巧", "误报判断", "报告要点"):
        assert f"### {title}" in md


def test_include_subset_reduces_size():
    full = load_skill_sections("authz")
    subset = load_skill_sections("authz", include=["steps", "bypass"])
    assert len(subset) < len(full)
    assert "### 检测步骤" in subset
    assert "### 绕过技巧" in subset
    assert "### 概述" not in subset
    assert "### 误报判断" not in subset


def test_include_unknown_sections_ignored():
    md = load_skill_sections("ssrf", include=["overview", "nonexistent"])
    assert "### 概述" in md
    # 只注入了 overview 一段
    assert "### 检测步骤" not in md


def test_unknown_domain_falls_back_to_generic():
    md = load_skill_sections("nonexistent_domain")
    assert "## nonexistent_domain 方法论" in md
    assert "### 概述" in md
    secs = get_sections("nonexistent_domain")
    # 通用兜底应包含关键字
    assert "OWASP" in secs["steps"]


def test_token_estimate_positive_and_subset_smaller():
    full = token_estimate("injection")
    assert full > 0
    subset = token_estimate("injection", include=["overview"])
    assert subset < full
    # 粗估：每段至少几十个字符
    assert token_estimate("injection") >= 20


def test_all_sections_have_fp_control():
    """每域必须有'误报判断'段（误报控制铁律）。"""
    for d in DOMAINS:
        secs = get_sections(d)
        assert secs["fp_control"], f"{d} 缺误报判断段"
        # 应包含'确认条件'字样
        assert "确认条件" in secs["fp_control"], f"{d} 误报判断缺'确认条件'"


def test_domain_specific_content():
    """各域内容应体现域特性，不能全是通用模板。"""
    upload = get_sections("upload")["steps"]
    assert "上传" in upload or "upload" in upload.lower()
    ssrf = get_sections("ssrf")["steps"]
    assert "169.254" in ssrf or "内网" in ssrf
