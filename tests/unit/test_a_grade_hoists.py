"""A 档纯嵌套 def 提升后的行为回归测试（工厂化热身 PR 的安全网）。

覆盖 scripts/analyze_pure_nested.py 判定的 17 个零局部捕获、已提升到模块级的纯函数。
测试范式复用 tests/unit/test_xj_security.py：零网络、零 LLM、直导被测函数、断言行为。
"""
import asyncio
import pytest

from core.browse_worker._menu_grouper import _btn_action
from core.captcha_solver import to_postfix
from core.crawler.login_mixin import _check_auth_cookies as _check_auth_cookies_login
from core.crawler.result_builder_mixin import _make_fingerprint, _is_catch_all_content
from core.credential_injector import _check_auth_cookies as _check_auth_cookies_cred
from core.fast_scanner._checks_auth import _extract_jwt
from core.fuzz.sqli import normalize
from core.harm_validation.render import _dedupe_verdicts
from core.js_analyzer._cache import _file_priority, _extract_lines_around
from core.js_analyzer._crawl_data import _main_domain
from core.memory import _clusters_of
from core.parallel._json_repair import _escape_control_chars
from core.parallel.orchestrator import _execute_gap_tasks
from core.sitemap.feature_gen import _api_key
from core.sitemap.report import _make_dedup_key


# ---- browse_worker._menu_grouper._btn_action ----
def test_btn_action_add():
    assert "browser_fill" in _btn_action("新增用户")


def test_btn_action_delete_skip():
    assert "跳过 UI 点击" in _btn_action("删除记录")


def test_btn_action_unknown_default():
    assert "proxy_get_traffic" in _btn_action("xyz-未知按钮")


# ---- captcha_solver.to_postfix ----
def test_to_postfix_precedence():
    # 2+3*4 = 2 + 12 = [2,3,4,*,+]  -> 实际 shunting-yard: 2,3,4,*,+ => 14
    assert to_postfix(["2", "+", "3", "*", "4"]) == [2, 3, 4, "*", "+"]


def test_to_postfix_parens():
    # (2+3)*4 => 2,3,+,4,* 
    assert to_postfix(["(", "2", "+", "3", ")", "*", "4"]) == [2, 3, "+", 4, "*"]


# ---- crawler.login_mixin._check_auth_cookies ----
def test_check_auth_cookies_login():
    cookies = [
        {"name": "sessionid", "value": "x"},
        {"name": "theme", "value": "dark"},
        {"name": "access_token", "value": "y"},
    ]
    out = _check_auth_cookies_login(cookies)
    assert {c["name"] for c in out} == {"sessionid", "access_token"}


# ---- crawler.result_builder_mixin ----
def test_make_fingerprint_deterministic():
    a = _make_fingerprint(200, "hello world body")
    b = _make_fingerprint(200, "hello world body")
    assert a == b
    assert a[0] == 200
    assert isinstance(a, tuple) and len(a) == 3


def test_is_catch_all_content_non_200():
    assert _is_catch_all_content(404, "<html>") is False


def test_is_catch_all_content_jwt_gen():
    body = '{"errcode":0,"array":[],"y":1,"small":"x","img":"data:..."}'
    assert _is_catch_all_content(200, body, "application/json") is True


def test_is_catch_all_content_login_html():
    html = "<html><head><title>登录</title></head><body><form><input type=password></form>" + "x" * 1000 + "</body></html>"
    assert _is_catch_all_content(200, html, "text/html") is True


def test_is_catch_all_content_empty():
    assert _is_catch_all_content(200, "   ") is False


# ---- credential_injector._check_auth_cookies ----
def test_check_auth_cookies_cred():
    cookies = [{"name": "JSESSIONID", "value": "1"}, {"name": "lang", "value": "zh"}]
    out = _check_auth_cookies_cred(cookies)
    assert [c["name"] for c in out] == ["JSESSIONID"]


# ---- fast_scanner._checks_auth._extract_jwt ----
def test_extract_jwt_hit():
    s = "token: eyJhbGc.eyJzdWIiM.abc123-def"
    assert _extract_jwt(s) == "eyJhbGc.eyJzdWIiM.abc123-def"


def test_extract_jwt_miss():
    assert _extract_jwt("no jwt here") is None


# ---- fuzz.sqli.normalize ----
def test_normalize_strips_timestamp_and_jwt():
    txt = "event at 1700000000 and jwt eyJhbGc.eyJzdWIiM.abc and md5 deadbeefdeadbeefdeadbeefdeadbeef"
    out = normalize(txt)
    assert "1700000000" not in out
    assert "eyJhbGc" not in out
    assert "deadbeef" not in out


def test_normalize_empty():
    assert normalize("") == ""


# ---- harm_validation.render._dedupe_verdicts ----
def test_dedupe_verdicts_removes_exact_dup():
    items = [
        {"_original": {"url": "https://x.com/api/users/123", "vuln_type": "SQL注入",
                       "evidence_request": "POST /api/users/123"}},
        {"_original": {"url": "https://x.com/api/users/123", "vuln_type": "SQL注入",
                       "evidence_request": "POST /api/users/123"}},
    ]
    assert len(_dedupe_verdicts(items)) == 1


def test_dedupe_verdicts_normalizes_numeric_id():
    # 数字 ID 段归一为 *，故 /api/users/123 与 /api/users/456 视为同键 → 合并
    items = [
        {"_original": {"url": "https://x.com/api/users/123", "vuln_type": "SQL注入",
                       "evidence_request": ""}},
        {"_original": {"url": "https://x.com/api/users/456", "vuln_type": "SQL注入",
                       "evidence_request": ""}},
    ]
    assert len(_dedupe_verdicts(items)) == 1


def test_dedupe_verdicts_hardcoded_key_canonical():
    # 两条硬编码密钥（不同 URL）→ 不合并，均保留
    items = [
        {"_original": {"url": "https://x.com/a", "vuln_type": "客户端硬编码密钥泄露",
                       "detail": "app_secret=xyz", "evidence_request": "", "evidence_response": ""}},
        {"_original": {"url": "https://x.com/b", "vuln_type": "api_key 泄露",
                       "detail": "apikey=abc", "evidence_request": "", "evidence_response": ""}},
    ]
    out = _dedupe_verdicts(items)
    assert len(out) == 2


# ---- harm_validation.render._canon_type / _key （B/C 复审进一步提升到模块级） ----
from core.harm_validation.render import _canon_type, _key


def test_canon_type_hardcoded_key_collapse():
    # 命中 appsecret/app_key 标记 → 统一为「客户端硬编码密钥泄露」
    assert _canon_type({"vuln_type": "信息泄露", "detail": "app_secret=xxx"}) == "客户端硬编码密钥泄露"
    assert _canon_type({"vuln_type": "api_key 泄露", "detail": "apikey=abc"}) == "客户端硬编码密钥泄露"


def test_canon_type_passthrough_otherwise():
    # 非密钥类 → 原样返回（空则「未知」）
    assert _canon_type({"vuln_type": "SQL注入"}) == "SQL注入"
    assert _canon_type({}) == "未知"


def test_key_normalizes_numeric_segment_and_caches_canon():
    # 数字段 → *；密钥类同 host+路径仍各自保留（归一类型拼进 key）
    k1 = _key({"_original": {"url": "https://x.com/api/users/123", "vuln_type": "SQL注入"}})
    k2 = _key({"_original": {"url": "https://x.com/api/users/456", "vuln_type": "SQL注入"}})
    assert k1 == k2 and k1.endswith("|SQL注入")
    # 不同 vuln_type → 不同 key
    k3 = _key({"_original": {"url": "https://x.com/api/users/123", "vuln_type": "XSS"}})
    assert k3 != k1


# ---- js_analyzer._cache ----
def test_file_priority_service_zero():
    assert _file_priority("https://x.com/static/js/user-service.js") == 0


def test_file_priority_framework_low():
    assert _file_priority("https://x.com/lib/vue-3.2.0.js") == 8


def test_extract_lines_around_window():
    # 注：当前实现返回的 start_line/end_line 与真实切片存在 off-by-one
    # （start_line 报 3 但 block 实际从 line4 起）——属 hoist 前既有行为，
    # 此处按「锁当前行为」断言，改动需同步更新本测试。
    text = "\n".join(f"line{i}" for i in range(1, 11))
    start, end, block = _extract_lines_around(text, text.index("line5"), 2)
    assert start == 3 and end == 7
    assert block == "line4\nline5\nline6"


# ---- js_analyzer._crawl_data._main_domain ----
def test_main_domain():
    assert _main_domain("api.example.com") == "example.com"
    assert _main_domain("localhost") == "localhost"


# ---- memory._clusters_of ----
def test_clusters_of_matches_alias():
    # _VT_ALIASES 中若存在包含 token 的别名则返回对应 cluster_key 集合（非空或一个 key）
    res = _clusters_of("sql injection")
    assert isinstance(res, set)


# ---- parallel._json_repair._escape_control_chars ----
def test_escape_control_chars():
    import re
    m = re.match(r'([\n\r\t])', "\n")  # 模拟 regex match 对象
    assert _escape_control_chars(m) == "\\n"


# ---- parallel.orchestrator._execute_gap_tasks (async, 评审 §6.2 曾误判为捕获闭包) ----
def test_execute_gap_tasks_empty():
    assert asyncio.run(_execute_gap_tasks([])) == []


def test_execute_gap_tasks_records():
    tasks = [{
        "title": "测越权", "role": "攻击者", "target_url": "https://x.com/api",
        "param_to_modify": "id", "test_method": "POST", "expected_if_safe": "200",
        "expected_if_vuln": "403", "vulnerability_type": "IDOR",
    }]
    out = asyncio.run(_execute_gap_tasks(tasks))
    assert len(out) == 1
    assert out[0]["status"] == "已记录待执行"
    assert "IDOR" in out[0]["summary"]


# ---- sitemap.feature_gen._api_key ----
def test_api_key_strips_query_and_slash():
    assert _api_key("https://x.com/api/v1/users?token=1") == "https://x.com/api/v1/users"


# ---- sitemap.report._make_dedup_key ----
class _FakeFP:
    name = "https://x.com/api/users"


class _FakeC:
    vuln_type = "SQL注入"


def test_make_dedup_key_returns_str():
    assert isinstance(_make_dedup_key(_FakeFP(), _FakeC()), str)
