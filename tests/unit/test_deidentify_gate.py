"""§4 Phase 2 item 2：去标识化卡点单元测试。

逐规则正/负样本 + 重叠消费（ID_CARD vs BANK_CARD）+ scan_tree 排除 +
run_gate 退出码。所有用例纯内存（tmp_path 合成文件）。
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts.deidentify_gate import (
    RULES,
    Rule,
    Violation,
    render_report,
    run_gate,
    scan_text,
    scan_tree,
)


def _by_rule(violations: list[Violation]) -> dict[str, list[Violation]]:
    out: dict[str, list[Violation]] = {}
    for v in violations:
        out.setdefault(v.rule_id, []).append(v)
    return out


# ============================================================
# 1. SECRET
# ============================================================
def test_secret_aws_akia():
    vs = scan_text("AWS key: AKIAIOSFODNN7EXAMPLE", "f", RULES)
    assert vs and vs[0].rule_id == "SECRET"


def test_secret_github_pat():
    vs = scan_text("token: ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD", "f", RULES)
    assert vs and vs[0].rule_id == "SECRET"


def test_secret_jwt():
    vs = scan_text("auth=eyJhbGciOiJIUzI1.NiIsInR5cCI6IkpXVCJ9.SflKxwRJSMX", "f", RULES)
    assert vs and vs[0].rule_id == "SECRET"


def test_secret_pem():
    vs = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIabc", "f", RULES)
    assert vs and vs[0].rule_id == "SECRET"


def test_secret_negative_normal_text():
    vs = scan_text("just normal text without any secret here", "f", RULES)
    assert all(v.rule_id != "SECRET" for v in vs)


# ============================================================
# 2. INTERNAL_IP
# ============================================================
def test_internal_ip_private_ranges():
    for ip in ("10.0.0.1", "172.16.5.5", "192.168.1.100"):
        vs = scan_text(f"host={ip}", "f", RULES)
        assert any(v.rule_id == "INTERNAL_IP" for v in vs), ip


def test_internal_ip_allowlist_loopback():
    vs = scan_text("server=127.0.0.1 and bcast=0.0.0.0", "f", RULES)
    assert all(v.rule_id != "INTERNAL_IP" for v in vs)


def test_internal_ip_negative_public():
    vs = scan_text("8.8.8.8 is google dns", "f", RULES)
    assert all(v.rule_id != "INTERNAL_IP" for v in vs)


# ============================================================
# 3. INTERNAL_HOST
# ============================================================
def test_internal_host_suffixes():
    for h in ("vpn.internal", "gw.corp", "node1.local", "switch.lan"):
        vs = scan_text(f"connect to {h}", "f", RULES)
        assert any(v.rule_id == "INTERNAL_HOST" for v in vs), h


def test_internal_host_negative_public():
    vs = scan_text("api.github.com is fine", "f", RULES)
    assert all(v.rule_id != "INTERNAL_HOST" for v in vs)


# ============================================================
# 4. EMAIL
# ============================================================
def test_email_real_address():
    vs = scan_text("contact: real.user@company.cn", "f", RULES)
    assert any(v.rule_id == "EMAIL" for v in vs)


def test_email_allowlist_placeholder():
    for ph in ("user@example.com", "noreply@example.org", "foo@example.net"):
        vs = scan_text(f"email={ph}", "f", RULES)
        assert all(v.rule_id != "EMAIL" for v in vs), ph


# ============================================================
# 5. PHONE_CN
# ============================================================
def test_phone_cn_positive():
    vs = scan_text("phone=13812345678", "f", RULES)
    assert any(v.rule_id == "PHONE_CN" for v in vs)


def test_phone_cn_negative_too_short():
    vs = scan_text("phone=123456789", "f", RULES)
    assert all(v.rule_id != "PHONE_CN" for v in vs)


def test_phone_cn_negative_starts_with_1x_invalid():
    # 12x... 不是有效手机号
    vs = scan_text("tel=12012345678", "f", RULES)
    assert all(v.rule_id != "PHONE_CN" for v in vs)


# ============================================================
# 6. ID_CARD_CN + 7. BANK_CARD 重叠消费
# ============================================================
def test_id_card_positive():
    vs = scan_text("id=11010119900307803X", "f", RULES)
    assert any(v.rule_id == "ID_CARD_CN" for v in vs)


def test_id_card_consumed_not_double_as_bank_card():
    """18 位身份证命中后，不应再被 BANK_CARD 双计。"""
    text = "id=110101199003078038"
    vs = scan_text(text, "f", RULES)
    by = _by_rule(vs)
    assert "ID_CARD_CN" in by
    assert "BANK_CARD" not in by, "身份证段被 BANK_CARD 双计"


def test_bank_card_positive_16_digit():
    vs = scan_text("card=4111111111111111", "f", RULES)
    by = _by_rule(vs)
    assert "BANK_CARD" in by
    # 不应误判为身份证（不以 1-9 开头 18 位）
    assert "ID_CARD_CN" not in by


def test_bank_card_negative_short():
    vs = scan_text("order=1234567890123", "f", RULES)
    assert all(v.rule_id != "BANK_CARD" for v in vs)


# ============================================================
# scan_text 行号/列号
# ============================================================
def test_scan_text_line_col():
    text = "line1\nline2\nAKIAIOSFODNN7EXAMPLE here"
    vs = scan_text(text, "f.py", RULES)
    assert vs[0].line == 3
    assert vs[0].col == 1


# ============================================================
# scan_tree + 排除
# ============================================================
def test_scan_tree_finds_secret_in_py(tmp_path: Path):
    (tmp_path / "module.py").write_text(
        "key = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    vs = scan_tree(tmp_path, RULES,
                   exclude_dirs=set(), exclude_file_patterns=[])
    assert any(v.rule_id == "SECRET" for v in vs)


def test_scan_tree_excludes_test_files_by_default(tmp_path: Path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_leak.py").write_text(
        "x = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    (tmp_path / "mod.py").write_text("ok = 1\n", encoding="utf-8")
    vs = scan_tree(tmp_path, RULES)  # 默认排除 tests/
    assert all("tests" not in v.file for v in vs)


def test_scan_tree_excludes_conftest_by_pattern(tmp_path: Path):
    (tmp_path / "conftest.py").write_text(
        "x = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    vs = scan_tree(tmp_path, RULES,
                   exclude_dirs=set(), exclude_file_patterns=["conftest.py"])
    assert all("conftest" not in v.file for v in vs)


def test_scan_tree_only_text_files(tmp_path: Path):
    # .bin 不在文本后缀白名单，即使含密钥也不扫
    (tmp_path / "data.bin").write_text(
        "AKIAIOSFODNN7EXAMPLE", encoding="utf-8")
    vs = scan_tree(tmp_path, RULES,
                   exclude_dirs=set(), exclude_file_patterns=[])
    assert vs == []


# ============================================================
# run_gate 退出码
# ============================================================
def test_run_gate_pass_when_clean(tmp_path: Path, capsys):
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    rc = run_gate(tmp_path, RULES, exclude_dirs=set(),
                  exclude_file_patterns=[])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PASS" in out


def test_run_gate_fail_when_secret(tmp_path: Path, capsys):
    (tmp_path / "leak.py").write_text(
        "k='AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    rc = run_gate(tmp_path, RULES, exclude_dirs=set(),
                  exclude_file_patterns=[])
    out = capsys.readouterr().out
    assert rc == 1
    assert "FAIL" in out
    assert "SECRET" in out


# ============================================================
# render_report
# ============================================================
def test_scan_text_truncates_long_match():
    """scan_text 产出的 match 对超长命中做 60 字符截断。

    用 BANK_CARD（16-19 位）不触发截断；构造一个长命中让 EMAIL 规则命中超长串。
    实际触发截断的是 EMAIL 规则：本地部分超长。
    """
    # EMAIL 本地部分超长，整体 > 60 字符
    long_local = "a" * 80
    vs = scan_text(f"x={long_local}@example.com", "f.py", RULES)
    # 但 example.com 在允许列表里 -> 不应命中。换真实域
    vs = scan_text(f"x={long_local}@company.cn", "f.py", RULES)
    assert vs, "超长邮箱应被 EMAIL 命中"
    assert len(vs[0].match) == 60
    assert vs[0].match.endswith("...")


def test_render_report_grouping():
    vs = [Violation("SECRET", "真实密钥泄露", "a.py", 1, 1, "AKIAIOSFODNN7EXAMPLE")]
    md = render_report(vs)
    assert "FAIL" in md and "[SECRET]" in md
    assert "a.py:1:1" in md


def test_render_report_empty():
    assert "PASS" in render_report([])
