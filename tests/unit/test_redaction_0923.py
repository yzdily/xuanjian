"""去标识化（脱敏）单元测试。

★ 背景：0923 实测违规一次 —— ``data/notes/task_1790149459_b5c238-info.md``
含真实客户名「中信百信银行」，而项目铁律要求报告/日志/笔记/知识库回流
不得出现真实客户名、内网 IP、账号口令。

★ 更重要的回归：脱敏工具**绝不能吃掉结构字符**。
第一版正则的值部分写成 ``[^\\s,;|]{8,}``，会把 JSON 字符串收尾引号
（甚至 ``\\"`` 转义与后续 ``},``）一起吞掉，直接破坏
``data/tasks/*-sitemap.json``（14 个文件因此无法解析）。
下面用 JSON 往返断言把这条硬约束钉死。
"""

from __future__ import annotations

import json

import pytest


class TestRedactText:
    @pytest.mark.parametrize("src,expect_absent,expect_present", [
        ("目标为「中信百信银行企业网银系统」", "中信百信银行", "<客户机构>"),
        ("百信银行 U盾体系", "百信银行", "<客户机构>"),
        ("db=10.0.0.5 与 192.168.1.10", "10.0.0.5", "<内网IP>"),
        ("backend at 172.16.5.9", "172.16.5.9", "<内网IP>"),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwx",
         "abcdefghijklmnopqrstuvwx", "<REDACTED>"),
        ("admin@bank.example.com", "admin@bank.example.com", "<邮箱>"),
        ("联系 13800138000", "13800138000", "<手机号>"),
    ])
    def test_redacts_each_class(self, src, expect_absent, expect_present):
        from core.redaction import redact_text
        out = redact_text(src)
        assert expect_absent not in out, f"{expect_absent!r} 未被脱敏: {out!r}"
        assert expect_present in out

    def test_jwt_redacted(self):
        from core.redaction import redact_text
        jwt = ("eyJhbGciOiJIUzI1NiJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "abcdefghijklmnopqrstuvwxyz")
        assert jwt not in redact_text(f"token={jwt}")

    def test_idempotent(self):
        from core.redaction import redact_text
        s = "中信百信银行 db=10.0.0.5 admin@a.com 13800138000"
        once = redact_text(s)
        assert redact_text(once) == once, "重复脱敏不得再变一层"

    def test_empty_and_none(self):
        from core.redaction import redact_text
        assert redact_text("") == ""
        assert redact_text(None) is None

    def test_extra_aliases(self):
        from core.redaction import redact_text
        out = redact_text("某某科技集团公司", extra_aliases={"某某科技集团": "<客户机构>"})
        assert "某某科技集团" not in out

    def test_whitespace_tolerant_alias(self):
        """机构名中间夹空格/换行也要命中（模型常这样断行）。"""
        from core.redaction import redact_text
        assert "中信百信银行" not in redact_text("中信百信\n银行")


class TestRedactDoesNotBreakJson:
    """★ 关键回归：脱敏不得破坏 JSON 结构（0923 踩过的坑）。"""

    @pytest.mark.parametrize("payload", [
        {"url": "https://x/login?user=a&password=b"},
        {"u": "https://x/?password=abcdefgh"},
        {"h": {"Cookie": "sid=abcdefghijklmn"}},
        {"nested": {"k": "password=\"secret-value-here\""}},
        {"arr": ["token=abcdefghijklmn", "ok"]},
        {"escaped": "quote is \" here and password=abcdefghij"},
    ])
    def test_json_roundtrip_preserved(self, payload):
        from core.redaction import redact_text
        src = json.dumps(payload, ensure_ascii=False)
        out = redact_text(src)
        json.loads(out)  # 不应抛 JSONDecodeError
        # 结构键保持不变
        assert json.loads(out).keys() == payload.keys()

    def test_redact_file_refuses_to_break_json(self, tmp_path):
        """当脱敏会破坏 JSON 时，redact_file 必须放弃写入而非写坏文件。"""
        from core.redaction import redact_file
        p = tmp_path / "broken.json"
        # 已经是坏 JSON：应跳过，不得二次破坏
        p.write_text('{"a": "unterminated', encoding="utf-8")
        changed, msg = redact_file(p, extra_aliases={"unterminated": "X"})
        assert changed is False
        assert "跳过" in msg
        assert p.read_text(encoding="utf-8") == '{"a": "unterminated'

    def test_redact_file_preserves_newlines(self, tmp_path):
        """读写往返不得翻译换行（否则裸 CR 会变 CRLF，破坏 JSON 字符串语义）。"""
        from core.redaction import redact_file
        p = tmp_path / "n.json"
        original = '{"v": "中信百信银行", "n": 1}\n'
        p.write_text(original, encoding="utf-8", newline="")
        changed, _ = redact_file(p)
        assert changed is True
        # ★ 兼容性：read_text(newline=) 需 Python 3.13+，本仓 >=3.10 → 用 open()
        with open(p, "r", encoding="utf-8", newline="") as _f:
            after = _f.read()
        assert "中信百信银行" not in after
        assert after.endswith("}\n"), "尾部换行必须保持 LF，不得变成 CRLF"

    def test_clean_file_not_touched(self, tmp_path):
        from core.redaction import redact_file
        p = tmp_path / "clean.json"
        p.write_text('{"a": 1}', encoding="utf-8")
        changed, msg = redact_file(p)
        assert changed is False
        assert "无需改动" in msg

    def test_missing_file(self, tmp_path):
        from core.redaction import redact_file
        changed, msg = redact_file(tmp_path / "nope.md")
        assert changed is False
        assert "不存在" in msg


class TestNoteMcpWiring:
    def test_note_add_redacts_before_write(self):
        """笔记落盘前必须脱敏（这是 0923 违规的直接入口）。

        直接读源码而不是 import：``mcp`` 包在测试环境不一定装（本 venv 就没有）。
        """
        from pathlib import Path
        src = (Path(__file__).resolve().parents[2]
               / "mcp_servers" / "note_mcp.py").read_text(encoding="utf-8")
        assert "def note_add" in src
        # note_add 函数体内必须调用 _redact
        body = src.split("async def note_add", 1)[1].split("@mcp.tool()", 1)[0]
        assert "_redact(" in body, "note_add 必须先脱敏再落盘"


class TestSitemapLoadResilience:
    def test_corrupt_cache_does_not_raise(self, tmp_path):
        """坏 sitemap 缓存不得炸掉会话恢复（修正前 json.loads 异常会穿透）。"""
        from core.sitemap import Sitemap
        bad = tmp_path / "task_x-sitemap.json"
        bad.write_text('{"target": "unterminated', encoding="utf-8")

        sm = Sitemap(target="https://x/", task_id="task_x")
        sm._persist_path = bad
        assert sm.load() is False  # 不得抛异常

    def test_non_dict_top_level_rejected(self, tmp_path):
        from core.sitemap import Sitemap
        p = tmp_path / "task_y-sitemap.json"
        p.write_text("[1,2,3]", encoding="utf-8")
        sm = Sitemap(target="https://y/", task_id="task_y")
        sm._persist_path = p
        assert sm.load() is False
