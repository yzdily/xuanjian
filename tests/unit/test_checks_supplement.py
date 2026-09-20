"""§2.8 全类别补检（0918 §3.12.2 批次1 + §3.12.3 批次2）9 项检查的单元测试。

覆盖：
- 批次1（5 项）：NoSQL 注入 / 403 绕过 / 用户枚举+频控 / 验证码答案泄露 / Host 头注入
- 批次2（4 项）：表达式注入 / GraphQL 滥用 / 批量赋值 / 竞态条件
- 检查表接线：9 个 _check_* 方法均能通过 FastScanner mixin 解析

所有测试均通过 monkeypatch 实例 _request 模拟响应，不发起真实网络请求。
"""

import httpx
import pytest

from core.fast_scanner import FastScanner, ScanTarget

_RULES_9 = [
    "nosql_injection", "expression_injection",
    "403_bypass", "user_enum", "captcha_leak", "mass_assignment",
    "host_header", "graphql_abuse", "race_condition",
]


def _scanner(fake):
    s = FastScanner(max_workers=1)
    s._request = fake
    return s


def _resp(status: int = 200, text: str = "", **headers) -> httpx.Response:
    return httpx.Response(status, text=text, headers=headers)


# ---------------------------------------------------------------------------
# 批次1：NoSQL 注入
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nosql_injection_positive_operator_bypass():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(200, '{"code":-1,"msg":"未登录"}')  # 基线业务拒绝
        if rule_tag == "NoSQLi":
            return _resp(200, '{"code":0,"data":[{"name":"admin","id":1}]}')  # 注入后出数据
        return None

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/api/user", method="GET", params={"id": "1"})
    findings = await scanner._check_nosql_injection(target)
    assert findings, "基线业务拒绝 + 注入后出现真实数据，应报 NoSQL 注入"
    assert findings[0].vuln_type == "NoSQL注入"
    assert findings[0].rule_tag == "NoSQLi"
    assert findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_nosql_injection_negative_no_bypass():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"code":-1,"msg":"未登录"}')  # 注入后仍业务拒绝

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/api/user", method="GET", params={"id": "1"})
    findings = await scanner._check_nosql_injection(target)
    assert not findings


# ---------------------------------------------------------------------------
# 批次1：表达式注入（SpEL/OGNL/EL）
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_expression_injection_positive_double_verify():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(200, "welcome")
        if "8*8" in payload_tag:
            return _resp(200, "welcome 64")  # 二次验证 64
        if rule_tag == "ExprInj":
            return _resp(200, "welcome 49")  # ${7*7} -> 49
        return None

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/hello", method="GET", params={"name": "admin"})
    findings = await scanner._check_expression_injection(target)
    assert findings, "注入回显 49 + 二次复现 64，应报表达式注入"
    assert findings[0].vuln_type == "表达式注入"
    assert findings[0].rule_tag == "ExprInj"


@pytest.mark.asyncio
async def test_expression_injection_negative_no_verify():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(200, "welcome")
        return _resp(200, "welcome 49")  # 一次命中但二次验证不出现 64

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/hello", method="GET", params={"name": "admin"})
    findings = await scanner._check_expression_injection(target)
    assert not findings


# ---------------------------------------------------------------------------
# 批次1：403 绕过
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_403_bypass_positive_case_variant():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(403, "forbidden")
        if rule_tag == "403Bypass":
            # 大小写变体命中：200 + 敏感数据
            return _resp(200, '{"users":[{"name":"admin","phone":"13800138000"}]}')
        return None

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/admin", method="GET")
    findings = await scanner._check_403_bypass(target)
    assert findings, "基线 403 + 变体 200 且含敏感数据，应报 403 绕过"
    assert findings[0].vuln_type == "403绕过"
    assert findings[0].rule_tag == "403Bypass"
    assert findings[0].severity == "high"


@pytest.mark.asyncio
async def test_403_bypass_negative_still_403():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(403, "forbidden")

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/admin", method="GET")
    findings = await scanner._check_403_bypass(target)
    assert not findings


# ---------------------------------------------------------------------------
# 批次1：用户枚举 + 频控缺失
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_user_enum_positive_and_rate_limit_missing():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "rate_check":
            return _resp(200, "ok")  # 并发 5 次全成功，无 429/Retry-After
        if payload_tag == "user=admin":
            return _resp(200, "登录成功，欢迎 admin")
        if payload_tag.startswith("user="):
            return _resp(404, "用户不存在")
        return None

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/login", method="POST")
    findings = await scanner._check_user_enum(target)
    types = {f.vuln_type for f in findings}
    assert "用户枚举" in types, "存在/不存在用户响应可区分，应报用户枚举"
    assert "频控缺失" in types, "并发 5 次无限流，应报频控缺失"
    assert all(f.rule_tag == "UserEnum" for f in findings)


@pytest.mark.asyncio
async def test_user_enum_negative_identical_responses():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "rate_check":
            return _resp(429, "too many")  # 有限流 → 不报频控缺失
        return _resp(200, "invalid credentials")  # 两用户响应一致 → 不报枚举

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/login", method="POST")
    findings = await scanner._check_user_enum(target)
    assert not findings


# ---------------------------------------------------------------------------
# 批次1：验证码答案泄露
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_captcha_leak_positive_answer_field():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"code":200,"data":{"answer":"x7k3","x":12,"y":34}}')

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/captcha/getcode", method="GET")
    findings = await scanner._check_captcha_leak(target)
    assert findings, "验证码接口响应含 answer 字段，应报验证码答案泄露"
    assert findings[0].vuln_type == "验证码答案泄露"
    assert findings[0].rule_tag == "CaptchaLeak"


@pytest.mark.asyncio
async def test_captcha_leak_negative_status_marker_only():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        # {"code":0} 是纯成功标记，不应被误判为答案
        return _resp(200, '{"code":0,"msg":"ok","data":{}}')

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/captcha/getcode", method="GET")
    findings = await scanner._check_captcha_leak(target)
    assert not findings


# ---------------------------------------------------------------------------
# 批次1：Host 头注入
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_host_header_positive_reflected():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if headers and str(headers.get("Host", "")).lower() == "evil.com":
            # 响应体反射注入的 Host → 密码重置投毒
            return _resp(200, "reset link: http://evil.com/reset?token=abc")
        return _resp(200, "welcome")

    scanner = _scanner(fake)
    target = ScanTarget(url="http://example.com/", method="GET")
    findings = await scanner._check_host_header(target)
    assert findings, "Host 头被反射到响应体，应报 Host 头注入"
    assert findings[0].vuln_type == "Host头注入"
    assert findings[0].rule_tag == "HostHdr"


@pytest.mark.asyncio
async def test_host_header_negative_no_reflection():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, "welcome")

    scanner = _scanner(fake)
    target = ScanTarget(url="http://example.com/", method="GET")
    findings = await scanner._check_host_header(target)
    assert not findings


# ---------------------------------------------------------------------------
# 批次2：GraphQL 滥用（内省 + 批量）
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_graphql_abuse_positive_introspection_and_batch():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "introspection":
            return _resp(200, '{"data":{"__schema":{"types":[{"name":"Query"}]}}}')
        if payload_tag == "batch":
            return _resp(200, '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Mutation"}}]')
        return _resp(200, "{}")

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/graphql", method="POST",
                        body='{"query":"{user{id}}"}')
    findings = await scanner._check_graphql_abuse(target)
    assert findings, "内省开放 + 批量执行，应报 GraphQL 滥用"
    assert all(f.vuln_type == "GraphQL滥用" for f in findings)
    assert any(f.severity == "high" for f in findings)  # 批量滥用


@pytest.mark.asyncio
async def test_graphql_abuse_negative_no_introspection():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "introspection":
            return _resp(200, '{"errors":[{"message":"must provide operation"}]}')
        if payload_tag == "batch":
            return _resp(200, '{"data":{"__typename":"Query"}}')  # 单次执行
        return _resp(200, "{}")

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/graphql", method="POST",
                        body='{"query":"{user{id}}"}')
    findings = await scanner._check_graphql_abuse(target)
    assert not findings


# ---------------------------------------------------------------------------
# 批次2：批量赋值
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mass_assignment_positive_role_escalation():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        if payload_tag == "baseline":
            return _resp(200, '{"code":-1,"msg":"无权限"}')  # 基线业务拒绝
        if rule_tag == "MassAssign":
            return _resp(200, '{"code":0,"msg":"success"}')  # 注入 role 后成功
        return None

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/users", method="POST", body='{"name":"x"}')
    findings = await scanner._check_mass_assignment(target)
    assert findings, "基线业务拒绝 + 注入 role=admin 后成功，应报批量赋值"
    assert findings[0].vuln_type == "批量赋值"
    assert findings[0].rule_tag == "MassAssign"
    assert findings[0].severity == "high"


@pytest.mark.asyncio
async def test_mass_assignment_negative_deny_after_inject():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"code":-1,"msg":"无权限"}')  # 注入后仍业务拒绝

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/users", method="POST", body='{"name":"x"}')
    findings = await scanner._check_mass_assignment(target)
    assert not findings


# ---------------------------------------------------------------------------
# 批次2：竞态条件
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_race_condition_positive_all_success():
    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        return _resp(200, '{"msg":"领取成功"}')

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/api/coupon/redeem", method="POST",
                        body='{"coupon":"C-001"}')
    findings = await scanner._check_race_condition(target)
    assert findings, "并发 5 次全成功且含成功标记，应报竞态条件"
    assert findings[0].vuln_type == "竞态条件"
    assert findings[0].rule_tag == "RaceCond"


@pytest.mark.asyncio
async def test_race_condition_negative_rate_limited():
    state = {"n": 0}

    async def fake(method, url, headers=None, content=None, drop_auth=False,
                   rule_tag="", payload_tag=""):
        state["n"] += 1
        if state["n"] == 1:
            return _resp(429, "too many")  # 并发中出现限流 → 非竞态证据
        return _resp(200, '{"msg":"领取成功"}')

    scanner = _scanner(fake)
    target = ScanTarget(url="http://x/api/coupon/redeem", method="POST",
                        body='{"coupon":"C-001"}')
    findings = await scanner._check_race_condition(target)
    assert not findings


# ---------------------------------------------------------------------------
# 接线：9 项检查均通过 mixin 解析 + 完整扫描路径无异常
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_all_9_checks_registered_and_resolvable():
    scanner = FastScanner(max_workers=1)
    for rule in _RULES_9:
        handler = getattr(scanner, f"_check_{rule}", None)
        assert handler is not None, f"FastScanner 应能解析 _check_{rule}"
        assert callable(handler)


@pytest.mark.asyncio
async def test_scan_target_runs_supplement_rules_without_error():
    """完整扫描路径：全部请求失败时 9 项补检规则不抛异常、零误报。"""
    scanner = FastScanner(max_workers=2)

    async def no_net(method, url, headers=None, content=None, drop_auth=False,
                     rule_tag="", payload_tag=""):
        return None  # 模拟全部请求失败/熔断

    scanner._request = no_net
    target = ScanTarget(url="http://x/login", method="POST",
                        body='{"username":"a","password":"b"}', params={"id": "1"})
    result = await scanner.scan_target(target)
    # 全部请求失败 → 零发现
    assert result.findings == []
    # 默认规则表已包含 9 项补检（16 项原有 + 9 项新增）
    assert result.rules_run >= 25, f"rules_run={result.rules_run}，应 >= 25"
