"""
FastScanner 漏洞检测引擎测试（零网络：mock self._request）。

补齐此前零覆盖的 async 检测方法，覆盖「命中」与「未命中」两类分支：
- SQL 注入（报错注入）
- XSS（反射型）
- SSRF（云元数据 / 内网服务特征）
- XXE（外部实体文件读取）
- 命令注入
- 路径穿越
- 未授权访问（medium / high 两档证据质量）
- IDOR（认证矩阵三身份对照）

所有用例通过 conftest 的 route_request 注入伪造 httpx.Response，不发起真实请求、
不依赖 LLM，可确定性重复运行。
"""
from __future__ import annotations

from core.fast_scanner import VulnFinding

from conftest import run_async


# ============================================================
# SQL 注入
# ============================================================
class TestSqlInjection:
    def test_error_based_detected(self, fast_scanner, route_request, sample_target, make_response):
        err = make_response(200, text="You have an error in your SQL syntax near ''xxx'' MySQL")
        route_request(fast_scanner, {"": err})  # 所有请求都返回报错页
        target = sample_target("http://t.com/product?id=1", params={"id": "1"})
        findings = run_async(fast_scanner._check_sql_injection(target))
        assert len(findings) >= 1
        assert findings[0].vuln_type == "SQL注入"
        assert findings[0].severity == "critical"
        assert findings[0].evidence_quality == "body_confirmed"

    def test_clean_response_no_finding(self, fast_scanner, route_request, sample_target, make_response):
        ok = make_response(200, text="<html><body>Welcome to our shop</body></html>")
        route_request(fast_scanner, {"": ok})
        target = sample_target("http://t.com/product?id=1", params={"id": "1"})
        findings = run_async(fast_scanner._check_sql_injection(target))
        assert findings == []


# ============================================================
# XSS（反射型）
# ============================================================
class TestXssReflected:
    def test_reflected_xss_detected(self, fast_scanner, route_request, sample_target, make_response):
        probe = 'xuanjianxss<>"\''
        page = make_response(200, text=f"<html><body><div>{probe}</div></body></html>")
        route_request(fast_scanner, {"": page})
        target = sample_target("http://t.com/search?q=hi", params={"q": "hi"})
        findings = run_async(fast_scanner._check_xss(target))
        assert any(f.vuln_type == "XSS" for f in findings)
        assert findings[0].severity == "high"

    def test_no_reflection_no_finding(self, fast_scanner, route_request, sample_target, make_response):
        page = make_response(200, text="<html><body><div>safe output</div></body></html>")
        route_request(fast_scanner, {"": page})
        target = sample_target("http://t.com/search?q=hi", params={"q": "hi"})
        findings = run_async(fast_scanner._check_xss(target))
        assert findings == []


# ============================================================
# SSRF
# ============================================================
class TestSsrf:
    def test_aws_metadata_critical(self, fast_scanner, route_request, sample_target, make_response):
        meta = make_response(200, text="ami-id: ami-12345\ninstance-id: i-0abc\nsome aws metadata")
        route_request(fast_scanner, {"": meta})
        # 参数名需含 url/link/redirect/callback/proxy/fetch/src 之一
        target = sample_target(
            "http://t.com/fetch?url=http://example.com", params={"url": "http://example.com"}
        )
        findings = run_async(fast_scanner._check_ssrf(target))
        assert any(f.vuln_type == "SSRF" for f in findings)
        assert findings[0].severity == "critical"

    def test_normal_response_no_finding(self, fast_scanner, route_request, sample_target, make_response):
        ok = make_response(200, text="<html><body>normal page, nothing interesting</body></html>")
        route_request(fast_scanner, {"": ok})
        target = sample_target(
            "http://t.com/fetch?url=http://example.com", params={"url": "http://example.com"}
        )
        findings = run_async(fast_scanner._check_ssrf(target))
        assert findings == []

    def test_non_url_param_skipped(self, fast_scanner, route_request, sample_target, make_response):
        meta = make_response(200, text="ami-id: ami-12345")
        route_request(fast_scanner, {"": meta})
        # 参数名不含 url 类关键字 -> 不进入 SSRF 检测
        target = sample_target("http://t.com/api?name=test", params={"name": "test"})
        findings = run_async(fast_scanner._check_ssrf(target))
        assert findings == []


# ============================================================
# XXE
# ============================================================
class TestXxe:
    def test_xxe_file_read_detected(self, fast_scanner, route_request, sample_target, make_response):
        resp = make_response(200, text="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin")
        route_request(fast_scanner, {"": resp})
        target = sample_target(
            "http://t.com/api/upload", method="POST", headers={"Content-Type": "application/xml"}
        )
        findings = run_async(fast_scanner._check_xxe(target))
        assert any(f.vuln_type == "XXE" for f in findings)
        assert findings[0].severity == "high"

    def test_normal_xml_no_finding(self, fast_scanner, route_request, sample_target, make_response):
        resp = make_response(200, text='<root><status>ok</status></root>')
        route_request(fast_scanner, {"": resp})
        target = sample_target(
            "http://t.com/api/upload", method="POST", headers={"Content-Type": "application/xml"}
        )
        findings = run_async(fast_scanner._check_xxe(target))
        assert findings == []


# ============================================================
# 命令注入
# ============================================================
class TestCommandInjection:
    def test_cmd_injection_detected(self, fast_scanner, route_request, sample_target, make_response):
        # 真实命令输出特征，而非 payload 本身被回显
        resp = make_response(200, text="uid=33(www-data) gid=33(www-data) groups=33(www-data)")
        route_request(fast_scanner, {"": resp})
        target = sample_target("http://t.com/ping?host=1.1.1.1", params={"host": "1.1.1.1"})
        findings = run_async(fast_scanner._check_command_injection(target))
        assert any(f.vuln_type == "命令注入" for f in findings)
        assert findings[0].severity == "critical"

    def test_payload_reflection_not_false_positive(self, fast_scanner, route_request, sample_target, make_response):
        # 仅回显 payload、无命令输出特征 -> 不应判漏洞
        resp = make_response(200, text="you sent: ;id")
        route_request(fast_scanner, {"": resp})
        target = sample_target("http://t.com/ping?host=x", params={"host": "x"})
        findings = run_async(fast_scanner._check_command_injection(target))
        assert findings == []


# ============================================================
# 路径穿越
# ============================================================
class TestPathTraversal:
    def test_traversal_detected(self, fast_scanner, route_request, sample_target, make_response):
        resp = make_response(200, text="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin")
        route_request(fast_scanner, {"": resp})
        target = sample_target("http://t.com/dl?file=report.pdf", params={"file": "report.pdf"})
        findings = run_async(fast_scanner._check_path_traversal(target))
        assert any(f.vuln_type == "目录穿越" for f in findings)
        assert findings[0].severity == "critical"

    def test_normal_file_no_finding(self, fast_scanner, route_request, sample_target, make_response):
        resp = make_response(200, text="PDF report content here, no system file")
        route_request(fast_scanner, {"": resp})
        target = sample_target("http://t.com/dl?file=report.pdf", params={"file": "report.pdf"})
        findings = run_async(fast_scanner._check_path_traversal(target))
        assert findings == []


# ============================================================
# 未授权访问
# ============================================================
class TestUnauthorized:
    def test_medium_when_no_sensitive_data(self, fast_scanner, route_request, sample_target, make_response):
        _ct = {"content-type": "application/json"}
        auth = make_response(200, text="AUTH RESPONSE page with token abcdef123456 content here", headers=_ct)
        noauth = make_response(200, text="NOAUTH RESPONSE page with other text xyz987 content here", headers=_ct)
        route_request(fast_scanner, {"": auth}, drop_auth_map={"": noauth})
        target = sample_target("http://t.com/api/profile", params={})
        findings = run_async(fast_scanner._check_unauthorized(target))
        assert len(findings) >= 1
        assert findings[0].vuln_type == "未授权访问"
        assert findings[0].severity == "medium"  # 仅状态码+长度证据

    def test_high_when_sensitive_data_leaked(self, fast_scanner, route_request, sample_target, make_response):
        _ct = {"content-type": "application/json"}
        auth = make_response(200, text="AUTH RESPONSE normal page content abc", headers=_ct)
        # 去认证后泄露含 3 个邮箱的敏感数据 -> 强证据 high
        noauth_body = "user alice@corp.com bob@corp.com carol@corp.com list data here"
        noauth = make_response(200, text=noauth_body, headers=_ct)
        route_request(fast_scanner, {"": auth}, drop_auth_map={"": noauth})
        target = sample_target("http://t.com/api/users/me", params={})
        findings = run_async(fast_scanner._check_unauthorized(target))
        assert any(f.severity == "high" for f in findings)

    def test_no_finding_when_401(self, fast_scanner, route_request, sample_target, make_response):
        noauth = make_response(401, text="Unauthorized")
        route_request(fast_scanner, {"": make_response(200, "auth ok")}, drop_auth_map={"": noauth})
        target = sample_target("http://t.com/api/secret", params={})
        findings = run_async(fast_scanner._check_unauthorized(target))
        assert findings == []

    def test_login_endpoint_skipped(self, fast_scanner, route_request, sample_target, make_response):
        route_request(fast_scanner, {"": make_response(200, "x")})
        target = sample_target("http://t.com/login", params={})
        findings = run_async(fast_scanner._check_unauthorized(target))
        assert findings == []  # 登录接口本身允许匿名访问


# ============================================================
# IDOR（认证矩阵三身份对照）
# ============================================================
class TestIdor:
    def test_idor_detected(self, fast_scanner, route_request, sample_target, make_response):
        auth = make_response(200, text="AUTH RESPONSE for user 100 normal data abc")
        noauth = make_response(200, text="NOAUTH different page content here xyz")
        # 越权访问他人资源（id=101）返回含敏感数据（3 个邮箱）
        idor_hit = make_response(
            200, text="user dave@corp.com eve@corp.com frank@corp.com secret of user 101"
        )
        route_request(
            fast_scanner,
            {"/users/100": auth, "/users/101": idor_hit},
            drop_auth_map={"/users/100": noauth},
        )
        target = sample_target("http://t.com/api/users/100", params={})
        findings = run_async(fast_scanner._check_auth_matrix(target))
        assert any(f.vuln_type == "IDOR" for f in findings)
        assert findings[0].severity == "high"

    def test_no_id_no_finding(self, fast_scanner, route_request, sample_target, make_response):
        # 无资源 ID -> 无对照、无 IDOR -> 空
        route_request(fast_scanner, {"": make_response(200, "same content page")})
        target = sample_target("http://t.com/home", params={})
        findings = run_async(fast_scanner._check_auth_matrix(target))
        assert findings == []
