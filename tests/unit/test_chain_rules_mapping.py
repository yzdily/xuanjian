"""漏8 / 漏V3-8 契约测试：四套分类体系必须统一且有映射，链模板词表不得越界。

对应方案：plan/链式规则_技术方案_20261003_v4.md §8（映射表契约）。
运行（在 xuanjian venv）：
    python -m pytest tests/unit/test_chain_rules_mapping.py -q -o addopts="" -p no:cacheprovider
"""
from __future__ import annotations

import os
import re
from typing import List

import pytest

from core.testflow import chain_rules as m

_PLAYBOOK_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "core", "testflow", "playbooks")


# --------------------------------------------------------------------------- #
# 1. 计数契约（漏V3-8 锁定数字）
# --------------------------------------------------------------------------- #
def test_taxonomy_counts():
    assert len(m.RISK_DOMAINS) == 8, "风险域必须 8 个"
    assert len(m.VULN_GROUPS) == 11, "漏洞组必须 11 个"
    assert len(m.XUANJIAN_VULN_TYPES) == 18, "漏洞类型必须 18 个"
    assert len(m.STRIX_INDEX) == 29, "strix 类必须 29 个"


# --------------------------------------------------------------------------- #
# 2. 每个 18 类型都落入 ≥1 个 8 域
# --------------------------------------------------------------------------- #
def test_every_type_has_domains():
    for t in m.XUANJIAN_VULN_TYPES:
        doms = m.vuln_type_domains(t)
        assert doms, f"类型 {t} 未映射到任何域"
        assert all(d in m.RISK_DOMAINS for d in doms), f"类型 {t} 映射到未知域 {doms}"


# --------------------------------------------------------------------------- #
# 3. 每个 strix 类都能解析且落入 ≥1 个 8 域（不得有孤儿）
# --------------------------------------------------------------------------- #
def test_every_strix_resolves_and_domained():
    for e in m.STRIX_INDEX:
        slug = e["slug"]
        resolved = m.resolve_vuln_type(slug)
        assert resolved, f"strix 类 {slug} 解析为空"
        doms = m.vuln_type_domains(slug)
        assert doms, f"strix 类 {slug} 未映射到任何域"
        assert all(d in m.RISK_DOMAINS for d in doms), f"strix 类 {slug} 映射到未知域 {doms}"
        if e["xuanjian_type"]:
            assert resolved == e["xuanjian_type"], f"{slug} -> {resolved} 期望 {e['xuanjian_type']}"
            assert e["xuanjian_type"] in m.XUANJIAN_VULN_TYPES


# --------------------------------------------------------------------------- #
# 4. 别名解析（英文 / strix slug / playbook 技能 id / 中文标准名）
# --------------------------------------------------------------------------- #
def test_alias_resolution():
    cases = {
        "idor": "idor",
        "sql_injection": "sqli",
        "idor-broken-object-authorization": "idor",
        "insecure-file-upload": "upload",
        "privilege-escalation": "privilege_escalation",
        "information_disclosure": "sensitive_response",
        "agentic_system_security": "agentic_system_security",
    }
    for raw, exp in cases.items():
        assert m.resolve_vuln_type(raw) == exp, f"resolve({raw!r}) 失败"

    # 中文标准名方向（复用 VULN_TYPE_MAP；缺依赖环境降级跳过）
    if m.CHINESE_TO_CANON:
        assert m.resolve_vuln_type("SQL注入") == "sqli"
        assert m.resolve_vuln_type("XSS") == "xss"
        assert m.resolve_vuln_type("路径穿越") == "lfi"
    else:
        pytest.skip("VULN_TYPE_MAP 不可用，中文标准名解析降级，跳过")


# --------------------------------------------------------------------------- #
# 5. 契约门：链模板引用的 vuln_type / domain 必须都在映射表内
# --------------------------------------------------------------------------- #
def test_validate_chain_template_gate():
    ok, why = m.validate_chain_template({"vuln_types": ["sqli", "idor"], "domains": ["injection", "authz"]})
    assert ok, why

    bad, why = m.validate_chain_template({"vuln_types": ["ghost_type"], "domains": ["injection"]})
    assert not bad, "应拒绝未知 vuln_type"

    bad2, why2 = m.validate_chain_template({"domains": ["ghost_domain"]})
    assert not bad2, "应拒绝未知 domain"


# --------------------------------------------------------------------------- #
# 6. 现有链模板（playbook）的域字段必须 ∈ 8 域；技能 id 必须可解析
# --------------------------------------------------------------------------- #
def _scan_playbooks() -> List[str]:
    files = []
    if os.path.isdir(_PLAYBOOK_DIR):
        for fn in sorted(os.listdir(_PLAYBOOK_DIR)):
            if fn.endswith((".yaml", ".yml")):
                files.append(os.path.join(_PLAYBOOK_DIR, fn))
    return files


def test_playbook_domains_valid():
    for path in _scan_playbooks():
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        for mt in re.finditer(r"^domain:\s*(\S+)\s*$", text, re.M):
            assert mt.group(1) in m.RISK_DOMAINS, f"{path} 引用未知域 {mt.group(1)!r}"
        for mt in re.finditer(r"^\s+skill:\s*(\S+)\s*$", text, re.M):
            sid = mt.group(1)
            if "-" in sid:  # 仅校验连字符复合技能 id（strix 风格）
                assert sid in m.VULN_TYPE_ALIAS, f"{path} 技能 id {sid!r} 未在映射表内"


def test_playbook_dir_nonempty():
    # 防止重构误删 playbook 导致契约测试空跑
    assert _scan_playbooks(), "core/testflow/playbooks 下未发现任何 playbook"


# --------------------------------------------------------------------------- #
# 7. 组 → 成员一致性（11 组并集必须正好等于 18 类型）
# --------------------------------------------------------------------------- #
def test_group_members_consistency():
    members = {t for ts in m.VULN_GROUPS.values() for t in ts}
    assert members == set(m.XUANJIAN_VULN_TYPES)
