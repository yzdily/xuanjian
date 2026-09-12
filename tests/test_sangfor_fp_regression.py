"""
针对 task_1785909608_d49bbc 报告中 4 个误报漏洞的回归测试。

误报场景：
1. SQL注入(apiversion) — login_auth.csp：参数被忽略，True≈基线，False 是极短响应(1字符) → 误报
2. SQL注入(encrypt) — login_psw.csp：参数被忽略，True≈基线，False 是风控拦截 → 误报
3. 未授权访问 — login_psw.csp：登录提交接口本身允许匿名访问 → 误报
4. CSRF — login_psw.csp：缺少 anti_replay/CSRF_RAND_CODE 识别 → 误报
"""
import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from core.fast_scanner import FastScanner, ScanTarget


def _make_target(url, method="GET", params=None, body="", headers=None):
    """构造 ScanTarget"""
    return ScanTarget(
        url=url,
        method=method,
        params=params or {},
        body=body,
        headers=headers or {},
        auth_headers={},
    )


def _make_resp(status=200, text="", headers=None):
    """构造模拟响应"""
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = headers or {"content-type": "text/xml"}
    return resp


def _run(coro):
    """同步运行 async 方法"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("loop closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@pytest.fixture
def scanner():
    return FastScanner()


class TestSQLiFalsePositiveSangfor:
    """Sangfor VPN SQL 注入误报回归"""

    def test_sqli_skip_when_true_equals_baseline_and_false_is_short(self, scanner):
        """True≈基线(参数被忽略) + False 是极短响应 → 不报 SQL注入

        场景：login_auth.csp?apiversion=1
        - 基线: 133 字符 XML 配置
        - True (' OR '1'='1): 133 字符（参数被忽略，返回相同配置）
        - False (' OR '1'='2): 1 字符（单引号触发路由错误）
        """
        baseline_text = '<login_auth success="1"><RSA_ENCRYPT_KEY>xxx</RSA_ENCRYPT_KEY></login_auth>'
        true_text = baseline_text  # 参数被忽略
        false_text = "1"  # 极短响应（路由错误）

        target = _make_target(
            "https://v.znlh.com/por/login_auth.csp",
            params={"apiversion": "1"},
        )

        async def mock_request(method, url, **kwargs):
            payload_tag = kwargs.get("payload_tag", "")
            if "false_condition" in payload_tag:
                return _make_resp(200, false_text)
            elif "OR" in payload_tag or "1=1" in payload_tag:
                return _make_resp(200, true_text)
            else:
                return _make_resp(200, baseline_text)

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = _run(scanner._check_sql_injection(target))

        sqli_findings = [f for f in findings if f.vuln_type == "SQL注入"]
        assert len(sqli_findings) == 0, f"应跳过SQL注入误报，但报了 {len(sqli_findings)} 个"

    def test_sqli_skip_when_true_equals_baseline_and_false_is_403(self, scanner):
        """True≈基线 + False 返回 403(WAF拦截) → 不报 SQL注入

        场景：login_psw.csp 的 encrypt 参数
        - 基线: 5871 字符
        - True: 5871 字符（参数被忽略）
        - False: 301 字符 + 403 状态码（WAF 拦截）
        """
        baseline_text = "x" * 5871
        true_text = baseline_text
        false_text = "x" * 301

        target = _make_target(
            "https://v.znlh.com/por/login_psw.csp",
            params={"encrypt": "1"},
        )

        async def mock_request(method, url, **kwargs):
            payload_tag = kwargs.get("payload_tag", "")
            if "false_condition" in payload_tag:
                return _make_resp(403, false_text)
            elif "OR" in payload_tag or "1=1" in payload_tag:
                return _make_resp(200, true_text)
            else:
                return _make_resp(200, baseline_text)

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = _run(scanner._check_sql_injection(target))

        sqli_findings = [f for f in findings if f.vuln_type == "SQL注入"]
        assert len(sqli_findings) == 0, f"应跳过SQL注入误报(WAF拦截)，但报了 {len(sqli_findings)} 个"

    def test_sqli_skip_when_both_true_false_equal_baseline(self, scanner):
        """True≈基线 + False≈基线 → 参数完全被忽略，不报 SQL注入"""
        baseline_text = '<config><key>value</key></config>'
        true_text = baseline_text
        false_text = baseline_text

        target = _make_target(
            "https://v.znlh.com/por/login_auth.csp",
            params={"apiversion": "1"},
        )

        async def mock_request(method, url, **kwargs):
            payload_tag = kwargs.get("payload_tag", "")
            if "false_condition" in payload_tag:
                return _make_resp(200, false_text)
            elif "OR" in payload_tag or "1=1" in payload_tag:
                return _make_resp(200, true_text)
            else:
                return _make_resp(200, baseline_text)

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = _run(scanner._check_sql_injection(target))

        sqli_findings = [f for f in findings if f.vuln_type == "SQL注入"]
        assert len(sqli_findings) == 0


class TestUnauthorizedFalsePositiveLogin:
    """登录接口未授权访问误报回归"""

    def test_unauth_skip_login_psw_endpoint(self, scanner):
        """login_psw.csp 是登录提交接口，不应检测未授权访问"""
        target = _make_target("https://v.znlh.com/por/login_psw.csp", method="POST")

        with patch.object(scanner, "_request", new_callable=AsyncMock) as mock_req:
            findings = _run(scanner._check_unauthorized(target))
            assert mock_req.call_count == 0
            assert len(findings) == 0

    def test_unauth_skip_login_auth_endpoint(self, scanner):
        """login_auth.csp 是认证初始化接口，不应检测未授权访问"""
        target = _make_target("https://v.znlh.com/por/login_auth.csp")

        with patch.object(scanner, "_request", new_callable=AsyncMock) as mock_req:
            findings = _run(scanner._check_unauthorized(target))
            assert mock_req.call_count == 0
            assert len(findings) == 0

    def test_unauth_skip_login_cert_endpoint(self, scanner):
        """login_cert.csp 是证书登录接口，不应检测未授权访问"""
        target = _make_target("https://v.znlh.com/por/login_cert.csp")

        with patch.object(scanner, "_request", new_callable=AsyncMock) as mock_req:
            findings = _run(scanner._check_unauthorized(target))
            assert mock_req.call_count == 0

    def test_unauth_skip_signin_endpoint(self, scanner):
        """普通 /signin 路径也应跳过"""
        target = _make_target("https://example.com/api/signin", method="POST")

        with patch.object(scanner, "_request", new_callable=AsyncMock) as mock_req:
            findings = _run(scanner._check_unauthorized(target))
            assert mock_req.call_count == 0

    def test_unauth_still_checks_non_login_endpoints(self, scanner):
        """非登录接口仍正常检测未授权访问"""
        target = _make_target("https://example.com/api/users/list")

        mock_auth = _make_resp(200, '{"data": [{"email": "a@b.com", "phone": "13800000001"}]}')
        mock_noauth = _make_resp(200, '{"data": [{"email": "a@b.com", "phone": "13800000001"}]}')

        with patch.object(scanner, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = [mock_auth, mock_noauth]
            findings = _run(scanner._check_unauthorized(target))
            assert mock_req.call_count == 2


class TestCSRFCsFalsePositiveSangfor:
    """Sangfor VPN CSRF 误报回归"""

    def test_csrf_recognizes_anti_replay(self, scanner):
        """识别 anti_replay 参数为 CSRF 防护"""
        target = _make_target(
            "https://v.znlh.com/por/login_psw.csp",
            method="POST",
            body="anti_replay=1&encrypt=1&svpn_name=admin&svpn_password=x",
        )
        assert scanner._check_csrf_token_presence(target) is True

    def test_csrf_recognizes_csrf_rand_code(self, scanner):
        """识别 CSRF_RAND_CODE 参数为 CSRF 防护"""
        target = _make_target(
            "https://v.znlh.com/por/login_psw.csp",
            method="POST",
            body="CSRF_RAND_CODE=abc123&svpn_name=admin",
        )
        assert scanner._check_csrf_token_presence(target) is True

    def test_csrf_recognizes_anti_replay_in_params(self, scanner):
        """URL query 中的 anti_replay 也应识别"""
        target = _make_target(
            "https://v.znlh.com/por/login_psw.csp?anti_replay=1&encrypt=1",
            method="POST",
            body="svpn_name=admin&svpn_password=x",
            params={"anti_replay": "1", "encrypt": "1"},
        )
        assert scanner._check_csrf_token_presence(target) is True

    def test_csrf_skip_when_anti_replay_present(self, scanner):
        """有 anti_replay 的 POST 不报 CSRF"""
        target = _make_target(
            "https://v.znlh.com/por/login_psw.csp?anti_replay=1&encrypt=1",
            method="POST",
            body="svpn_name=admin&svpn_password=x",
            params={"anti_replay": "1", "encrypt": "1"},
        )

        with patch.object(scanner, "_request", new_callable=AsyncMock) as mock_req:
            findings = _run(scanner._check_csrf(target))
            assert len(findings) == 0
            assert mock_req.call_count == 0
