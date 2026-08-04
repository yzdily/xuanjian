"""
FastScanner 假阳性防护单元测试

覆盖 P0-P2 优化的核心防误报函数：
- _is_business_deny: 业务层拒绝检测（HTTP 200 + 业务码表示未登录）
- _is_empty_data: 空 data 检测
- _is_waf_block_page: WAF 拦截页识别
- _normalize_body: 响应归一化
- _bodies_similar: 归一化后相似度比较
- _is_xss_executable_context: XSS 可执行上下文判断
- _body_contains_sensitive_data / _is_public_data: 多因素验证
"""

import pytest
from unittest.mock import MagicMock

from core.fast_scanner import (
    _is_business_deny,
    _is_empty_data,
    _is_waf_block_page,
    _normalize_body,
    _bodies_similar,
    _is_xss_executable_context,
    _body_contains_sensitive_data,
    _is_public_data,
    _header_value_leaks_version,
    _verify_sensitive_path_content,
)


# ============================================================
# P0: 业务层拒绝检测
# ============================================================

class TestBusinessDeny:
    """测试 _is_business_deny：HTTP 200 但业务码表示未登录/未授权"""

    def test_business_code_500_with_message(self):
        """历史报告中的典型误报：code:500 + message:用户未登录"""
        body = '{"code":500,"message":"用户未登录","result":{"errorCode":"0030072"}}'
        assert _is_business_deny(body) is True

    def test_business_code_401(self):
        body = '{"code":401,"message":"未授权"}'
        assert _is_business_deny(body) is True

    def test_business_code_403(self):
        body = '{"code":403,"message":"无权限"}'
        assert _is_business_deny(body) is True

    def test_error_code_40300(self):
        body = '{"errorCode":40300,"msg":"access denied"}'
        assert _is_business_deny(body) is True

    def test_success_false(self):
        body = '{"success":false,"message":"token expired"}'
        assert _is_business_deny(body) is True

    def test_normal_success_data(self):
        """正常业务数据不应被判定为业务拒绝"""
        body = '{"code":0,"message":"success","data":{"id":1,"name":"test"}}'
        assert _is_business_deny(body) is False

    def test_normal_data_list(self):
        body = '{"code":200,"data":[{"id":1},{"id":2}]}'
        assert _is_business_deny(body) is False

    def test_empty_body(self):
        assert _is_business_deny("") is False
        assert _is_business_deny(None) is False

    def test_chinese_deny_messages(self):
        """中文拒绝消息变体"""
        messages = [
            '{"message":"请登录"}',
            '{"message":"登录失效"}',
            '{"message":"身份验证失败"}',
            '{"message":"token无效"}',
            '{"message":"权限不足"}',
        ]
        for msg in messages:
            assert _is_business_deny(msg) is True, f"Failed: {msg}"

    def test_english_deny_messages(self):
        """英文拒绝消息变体"""
        messages = [
            '{"message":"unauthorized"}',
            '{"message":"please login"}',
            '{"message":"permission denied"}',
            '{"message":"token expired"}',
        ]
        for msg in messages:
            assert _is_business_deny(msg) is True, f"Failed: {msg}"


# ============================================================
# P0: 空 data 检测
# ============================================================

class TestEmptyData:
    """测试 _is_empty_data"""

    def test_data_null(self):
        assert _is_empty_data('{"code":0,"data":null}') is True

    def test_data_empty_array(self):
        assert _is_empty_data('{"code":0,"data":[]}') is True

    def test_data_empty_string(self):
        assert _is_empty_data('{"code":0,"data":""}') is True

    def test_data_empty_object(self):
        assert _is_empty_data('{"code":0,"data":{}}') is True

    def test_result_null(self):
        assert _is_empty_data('{"result":null}') is True

    def test_result_empty_array(self):
        assert _is_empty_data('{"result":[]}') is True

    def test_records_empty(self):
        assert _is_empty_data('{"records":[]}') is True

    def test_empty_body(self):
        assert _is_empty_data("") is True
        assert _is_empty_data("   ") is True

    def test_normal_data(self):
        """正常数据不应判定为空"""
        assert _is_empty_data('{"data":[{"id":1,"name":"user"}]}') is False

    def test_large_response_with_empty_field(self):
        """长响应中某个字段为空不应判定为整体空 data"""
        large_body = '{"data":null,"padding":"' + 'x' * 600 + '"}'
        assert _is_empty_data(large_body) is False


# ============================================================
# P2: WAF 拦截页识别
# ============================================================

class TestWafBlockPage:
    """测试 _is_waf_block_page"""

    def _mock_resp(self, status_code, text):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        return resp

    def test_waf_403_blocked(self):
        resp = self._mock_resp(403, "<html>Request blocked by WAF</html>")
        assert _is_waf_block_page(resp) is True

    def test_waf_403_firewall(self):
        resp = self._mock_resp(403, "已被防火墙拦截")
        assert _is_waf_block_page(resp) is True

    def test_waf_429_intercepted(self):
        resp = self._mock_resp(429, "Request intercepted by security rules")
        assert _is_waf_block_page(resp) is True

    def test_waf_503_chinese(self):
        resp = self._mock_resp(503, "安全拦截：请求被规则拦截")
        assert _is_waf_block_page(resp) is True

    def test_normal_403_no_waf_keyword(self):
        """403 但无 WAF 关键词 → 不是 WAF 拦截页"""
        resp = self._mock_resp(403, "Forbidden")
        assert _is_waf_block_page(resp) is False

    def test_normal_200(self):
        resp = self._mock_resp(200, "正常页面内容")
        assert _is_waf_block_page(resp) is False

    def test_403_empty_body(self):
        resp = self._mock_resp(403, "")
        assert _is_waf_block_page(resp) is False


# ============================================================
# P1: 响应归一化
# ============================================================

class TestNormalizeBody:
    """测试 _normalize_body"""

    def test_strip_unix_timestamp(self):
        body = '{"time": 1690000000, "data": "test"}'
        normalized = _normalize_body(body)
        assert "1690000000" not in normalized
        assert "test" in normalized

    def test_strip_iso_time(self):
        body = '{"created": "2026-08-04T12:00:00Z", "data": "test"}'
        normalized = _normalize_body(body)
        assert "2026-08-04T12:00:00Z" not in normalized
        assert "test" in normalized

    def test_strip_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        body = f'{{"token": "{jwt}", "data": "test"}}'
        normalized = _normalize_body(body)
        assert jwt not in normalized
        assert "test" in normalized

    def test_strip_csrf_token(self):
        body = '{"csrf_token": "abc123def456ghi789jkl012", "data": "test"}'
        normalized = _normalize_body(body)
        assert "abc123def456ghi789jkl012" not in normalized
        assert "test" in normalized

    def test_strip_hash(self):
        body = '{"hash": "5d41402abc4b2a76b9719d911017c592", "data": "test"}'
        normalized = _normalize_body(body)
        assert "5d41402abc4b2a76b9719d911017c592" not in normalized

    def test_preserve_content(self):
        body = '<html><body>Hello World</body></html>'
        normalized = _normalize_body(body)
        assert "Hello World" in normalized

    def test_empty_body(self):
        assert _normalize_body("") == ""
        assert _normalize_body(None) == ""


class TestBodiesSimilar:
    """测试 _bodies_similar"""

    def test_identical_bodies(self):
        body = '{"data": "test", "name": "user"}'
        assert _bodies_similar(body, body) is True

    def test_bodies_with_timestamp_diff(self):
        """仅时间戳不同 → 归一化后应相似"""
        b1 = '{"time": 1690000000, "data": "test value"}'
        b2 = '{"time": 1690000001, "data": "test value"}'
        assert _bodies_similar(b1, b2) is True

    def test_completely_different_bodies(self):
        b1 = '{"data": "first response content here"}'
        b2 = '{"data": "completely different response here ok"}'
        assert _bodies_similar(b1, b2) is False

    def test_empty_bodies(self):
        assert _bodies_similar("", "") is True
        assert _bodies_similar("data", "") is False


# ============================================================
# P1: XSS 可执行上下文判断
# ============================================================

class TestXssExecutableContext:
    """测试 _is_xss_executable_context"""

    PROBE = 'xuanjianxss<>"\''

    def test_html_body_context(self):
        """探针在 HTML body 中 → 可执行"""
        text = '<html><body>' + self.PROBE + '</body></html>'
        assert _is_xss_executable_context(text, self.PROBE) is True

    def test_html_comment_context(self):
        """探针在 HTML 注释中 → 不可执行"""
        text = '<!-- ' + self.PROBE + ' -->'
        assert _is_xss_executable_context(text, self.PROBE) is False

    def test_script_context(self):
        """探针在 <script> 标签内 → 可执行"""
        text = '<script>var x = ' + self.PROBE + ';</script>'
        assert _is_xss_executable_context(text, self.PROBE) is True

    def test_textarea_context(self):
        """探针在 <textarea> 中 → 不可执行（浏览器转义）"""
        text = '<textarea>' + self.PROBE + '</textarea>'
        assert _is_xss_executable_context(text, self.PROBE) is False

    def test_pure_json_response(self):
        """纯 JSON 响应 → 不可执行"""
        text = '{"error": "' + self.PROBE + '"}'
        assert _is_xss_executable_context(text, self.PROBE) is False

    def test_probe_not_found(self):
        assert _is_xss_executable_context("no probe here", "xuanjianxss") is False


# ============================================================
# 多因素验证
# ============================================================

class TestSensitiveDataDetection:
    """测试 _body_contains_sensitive_data"""

    def test_api_key(self):
        # SENSITIVE_DATA_PATTERNS 匹配 key=value 格式（非 JSON 引号包裹）
        body = "api_key=sk-1234567890abcdef"
        assert _body_contains_sensitive_data(body) is True

    def test_password_field(self):
        body = "password=secret123456"
        assert _body_contains_sensitive_data(body) is True

    def test_access_token(self):
        body = "access_token: abcdef1234567890abcd"
        assert _body_contains_sensitive_data(body) is True

    def test_user_list_html(self):
        # SENSITIVE_DATA_PATTERNS 匹配 <userList HTML 标签
        body = '<userList><user>admin</user></userList>'
        assert _body_contains_sensitive_data(body) is True

    def test_database_connection(self):
        body = '{"config": "jdbc:mysql://localhost:3306/db"}'
        assert _body_contains_sensitive_data(body) is True

    def test_normal_content(self):
        body = '{"message": "hello world", "status": "ok"}'
        assert _body_contains_sensitive_data(body) is False

    def test_empty(self):
        assert _body_contains_sensitive_data("") is False
        assert _body_contains_sensitive_data("hi") is False


class TestPublicDataDetection:
    """测试 _is_public_data"""

    def test_spa_shell(self):
        body = '<!doctype html><html><div id="root"></div></html>'
        assert _is_public_data(body) is True

    def test_login_page(self):
        body = '<title>登录</title><form>...</form>'
        assert _is_public_data(body) is True

    def test_announcement(self):
        body = '{"公告": "系统维护通知"}'
        assert _is_public_data(body) is True

    def test_sensitive_data_not_public(self):
        body = '{"api_key": "sk-1234567890abcdef"}'
        assert _is_public_data(body) is False

    def test_empty_is_public(self):
        assert _is_public_data("") is True


class TestHeaderVersionLeak:
    """测试 _header_value_leaks_version"""

    def test_nginx_with_version(self):
        assert _header_value_leaks_version("nginx/1.18.0") is True

    def test_apache_with_version(self):
        assert _header_value_leaks_version("Apache/2.4.41 (Ubuntu)") is True

    def test_express_with_version(self):
        assert _header_value_leaks_version("Express/4.18.2") is True

    def test_nginx_no_version(self):
        assert _header_value_leaks_version("nginx") is False

    def test_cloudflare_no_version(self):
        assert _header_value_leaks_version("cloudflare") is False

    def test_empty(self):
        assert _header_value_leaks_version("") is False


class TestSensitivePathFingerprint:
    """测试 _verify_sensitive_path_content"""

    def test_env_file_matched(self):
        text = "DB_HOST=localhost\nDB_PASSWORD=secret123\nAPP_KEY=base64key"
        matched, quality = _verify_sensitive_path_content("/.env", text)
        assert matched is True
        assert quality == "content_match"

    def test_git_config_matched(self):
        text = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]"
        matched, quality = _verify_sensitive_path_content("/.git/config", text)
        assert matched is True
        assert quality == "content_match"

    def test_spa_fallback_not_matched(self):
        """SPA 兜底页（返回 HTML 壳而非敏感文件内容）→ 不匹配"""
        text = '<!doctype html><html><div id="root"></div></html>'
        matched, quality = _verify_sensitive_path_content("/.env", text)
        assert matched is False

    def test_business_deny_in_response(self):
        """业务拒绝响应不应匹配敏感路径指纹"""
        text = '{"code":500,"message":"用户未登录"}'
        matched, quality = _verify_sensitive_path_content("/eval.php", text)
        assert matched is False


# ============================================================
# 集成测试：关键误报场景
# ============================================================

class TestKeyFpScenarios:
    """历史报告中真实出现的误报场景验证"""

    def test_scenario_unauthorized_with_business_deny(self):
        """历史报告误报 #1：去认证后 200 + code:500 + 用户未登录 → 不应报未授权访问"""
        noauth_text = '{"code":500,"message":"用户未登录","result":{"errorCode":"0030072","message":"用户未登录"}}'
        assert _is_business_deny(noauth_text) is True
        # 即使 _body_contains_sensitive_data 返回 False（不含敏感数据），
        # _is_business_deny 应先拦截，不进入漏洞报告流程

    def test_scenario_unauthorized_with_empty_data(self):
        """历史报告误报 #2：去认证后 200 + data:null → 不应报未授权访问"""
        noauth_text = '{"code":0,"message":"success","data":null}'
        assert _is_empty_data(noauth_text) is True

    def test_scenario_infoleak_business_deny(self):
        """历史报告误报 #3：/eval.php 返回 code:500 用户未登录 → 不应报信息泄露"""
        resp_text = '{"code":500,"message":"用户未登录"}'
        assert _is_business_deny(resp_text) is True
        matched, _ = _verify_sensitive_path_content("/eval.php", resp_text)
        assert matched is False

    def test_scenario_waf_block_not_vuln(self):
        """历史报告误报 #4：WAF 403 拦截 → 不应报漏洞"""
        resp = MagicMock()
        resp.status_code = 403
        resp.text = '<html><body>Request blocked by WAF firewall</body></html>'
        assert _is_waf_block_page(resp) is True

    def test_scenario_boolean_blind_no_fp(self):
        """布尔盲注归一化：动态时间戳不应导致误判"""
        true_resp = '{"time":1690000000,"data":"user list"}'
        baseline = '{"time":1690000000,"data":"user list"}'
        false_resp = '{"time":1690000001,"error":"no data found here"}'
        # True 与 baseline 归一化后应相似
        assert _bodies_similar(true_resp, baseline) is True
        # True 与 False 应不相似
        assert _bodies_similar(true_resp, false_resp) is False
