#!/usr/bin/env python3
r"""
Mock 漏洞服务器 + FastScanner 规则验证脚本

启动一个本地 HTTP 服务器，模拟包含 SQL 注入、XSS、命令注入、路径穿越、
未授权访问、信息泄露、CORS 错误配置等漏洞的端点，
然后用优化后的 FastScanner 扫描这些端点，验证规则是否命中。

用法：
    cd d:\xuanjian-main
    python mock_vuln_server.py
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ============================================================
# Mock 漏洞服务器
# ============================================================

# 模拟的 /etc/passwd 内容（用于路径穿越检测）
ETC_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
"""

# 模拟的 .env 文件内容（用于信息泄露检测）
ENV_FILE = """DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=s3cr3t_p@ss
API_KEY=sk-1234567890abcdef
SECRET_KEY=django-insecure-abc123def456
REDIS_URL=redis://localhost:6379/0
"""

# 模拟的用户列表 JSON（用于未授权访问检测）
USER_LIST_JSON = json.dumps({
    "code": 0,
    "message": "success",
    "data": [
        {"id": 1, "username": "admin", "email": "admin@example.com", "role": "superadmin", "phone": "13800138000"},
        {"id": 2, "username": "user1", "email": "user1@example.com", "role": "user", "phone": "13900139000"},
        {"id": 3, "username": "user2", "email": "user2@example.com", "role": "user", "phone": "13700137000"},
    ]
}, ensure_ascii=False)

# Spring Actuator env 响应
ACTUATOR_ENV = json.dumps({
    "activeProfiles": ["prod"],
    "propertySources": [
        {
            "name": "applicationConfig: [classpath:/application.yml]",
            "properties": {
                "spring.datasource.url": {"value": "jdbc:mysql://10.0.0.5:3306/prod_db"},
                "spring.datasource.password": {"value": "p@ssw0rd123"},
                "spring.redis.password": {"value": "redis_secret"},
            }
        }
    ]
}, ensure_ascii=False)


class MockVulnHandler(BaseHTTPRequestHandler):
    """模拟包含各种漏洞的 HTTP 请求处理器"""

    def _send(self, status: int, body: str, content_type: str = "text/html",
              extra_headers: dict | None = None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _get_param(self, name: str, default: str = "") -> str:
        """从 query string 提取参数"""
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        return qs.get(name, [default])[0]

    def _get_all_param_values(self) -> list[str]:
        """获取所有参数值（用于检测任意参数的注入字符）"""
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        return [v[0] for v in qs.values() if v]

    def _has_injection_char(self) -> tuple[str, str]:
        """检查任意参数值是否含注入字符，返回 (匹配的值, 注入类型)"""
        for val in self._get_all_param_values():
            # 布尔条件需先于通用 SQLi 检查（因为它们也含单引号）
            if "'1'='1" in val or "1=1" in val or (" OR " in val.upper() and "'1'='2" not in val):
                return val, "boolean_true"
            if "'1'='2" in val or "1=2" in val:
                return val, "boolean_false"
            if "'" in val or "/*" in val:
                return val, "sqli"
            if "UNION" in val.upper():
                return val, "sqli"
        return "", ""

    def _has_auth(self) -> bool:
        """检查是否携带认证头"""
        return bool(self.headers.get("Authorization") or self.headers.get("Cookie"))

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path

        # ---- SQL 注入：报错型 ----
        if path == "/vuln/sqli/error":
            id_val = self._get_param("id", "1")
            inj_val, inj_type = self._has_injection_char()
            # 任意参数含注入字符时返回 SQL 报错
            if inj_val:
                self._send(200,
                    f"<html><body>MySQL Error: You have an error in your SQL syntax; "
                    f"check the manual that corresponds to your MySQL server version "
                    f"for the right syntax to use near '{inj_val}'</body></html>")
            else:
                self._send(200, f"<html><body>Product ID: {id_val}</body></html>")
            return

        # ---- SQL 注入：布尔盲注 ----
        if path == "/vuln/sqli/boolean":
            id_val = self._get_param("id", "1")
            _, inj_type = self._has_injection_char()
            if inj_type == "boolean_true":
                # True 条件：返回完整列表
                self._send(200,
                    f"<html><body>"
                    f"<h1>Product List</h1>"
                    f"<ul><li>Product A</li><li>Product B</li><li>Product C</li></ul>"
                    f"</body></html>")
            elif inj_type == "boolean_false":
                # False 条件：返回空列表
                self._send(200, "<html><body><h1>Product List</h1><ul></ul></body></html>")
            elif inj_type == "sqli":
                # SQL 报错（但布尔盲注端点不返回报错信息）
                self._send(200, f"<html><body>Product List</h1><ul><li>Product A</li></ul></body></html>")
            else:
                self._send(200, f"<html><body><h1>Product List</h1><ul><li>Product A</li></ul></body></html>")
            return

        # ---- XSS：反射型 ----
        if path == "/vuln/xss/reflected":
            # 反射所有参数值（模拟未编码输出）
            all_vals = self._get_all_param_values()
            reflected = " ".join(all_vals) if all_vals else ""
            self._send(200,
                f"<html><body>"
                f"<h1>Search Results</h1>"
                f"<div>You searched for: {reflected}</div>"
                f"</body></html>")
            return

        # ---- 命令注入 ----
        if path == "/vuln/cmd":
            host_val = self._get_param("host", "localhost")
            all_vals = self._get_all_param_values()
            combined = " ".join(all_vals)
            # 当任意参数含注入字符时返回命令输出
            if re.search(r'[;|`$(&]', combined):
                self._send(200,
                    f"<html><body>"
                    f"<pre>uid=0(root) gid=0(root) groups=0(root)\n"
                    f"uid=33(www-data) gid=33(www-data)\n</pre>"
                    f"</body></html>")
            elif "whoami" in combined.lower():
                self._send(200,
                    f"<html><body><pre>root@example.com\n</pre></body></html>")
            else:
                self._send(200, f"<html><body>Ping result for {host_val}: 64 bytes from host</body></html>")
            return

        # ---- 路径穿越 ----
        if path == "/vuln/traversal":
            file_val = self._get_param("file", "report.pdf")
            all_vals = self._get_all_param_values()
            combined = " ".join(all_vals)
            if "../" in combined or "..\\" in combined or "etc/passwd" in combined:
                self._send(200, f"<html><body><pre>{ETC_PASSWD}</pre></body></html>")
            else:
                self._send(200, f"<html><body>File: {file_val}</body></html>")
            return

        # ---- 未授权访问：无认证也能获取用户列表 ----
        if path == "/api/users":
            if self._has_auth():
                # 带认证：正常返回
                self._send(200, USER_LIST_JSON, "application/json")
            else:
                # 无认证：仍然返回数据（漏洞！正常应该返回 401）
                self._send(200, USER_LIST_JSON, "application/json")
            return

        # ---- 信息泄露：.env 文件 ----
        if path == "/.env":
            self._send(200, ENV_FILE, "text/plain")
            return

        # ---- 信息泄露：.git/config ----
        if path == "/.git/config":
            self._send(200,
                "[core]\n\trepositoryformatversion = 0\n"
                "\tfilemode = false\n\tbare = false\n"
                "[remote \"origin\"]\n\turl = git@github.com:corp/secret-repo.git\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n")
            return

        # ---- 信息泄露：Spring Actuator ----
        if path == "/actuator/env":
            self._send(200, ACTUATOR_ENV, "application/json")
            return

        # ---- CORS 错误配置 ----
        if path == "/api/data":
            self._send(200, '{"data": "sensitive info"}', "application/json",
                       extra_headers={
                           "Access-Control-Allow-Origin": "*",
                           "Access-Control-Allow-Credentials": "true",
                       })
            return

        # ---- 安全端点（正常页面，不应触发漏洞）----
        if path == "/safe/page":
            self._send(200, "<html><body><h1>Welcome</h1><p>This is a safe page.</p></body></html>")
            return

        # ---- 404 ----
        self._send(404, '{"error": "Not Found"}', "application/json")

    def do_OPTIONS(self):  # noqa: N802
        """处理 CORS 预检请求"""
        path = urlparse(self.path).path
        if path == "/api/data":
            self._send(200, "", "text/plain", extra_headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            })
        else:
            self._send(204, "", "text/plain")

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length else ""

        # ---- SQL 注入：POST JSON ----
        if path == "/vuln/sqli/json":
            try:
                data = json.loads(body)
                username = data.get("username", "")
                if "'" in username or "OR" in username.upper():
                    self._send(200,
                        '{"error": "SQLSTATE[HY000]: General error: 1064 You have an error '
                        'in your SQL syntax near \\"' + username + '\\""}',
                        "application/json")
                else:
                    self._send(200, '{"code": 0, "data": {"id": 1, "name": "test"}}', "application/json")
            except json.JSONDecodeError:
                self._send(400, '{"error": "Invalid JSON"}', "application/json")
            return

        # ---- XSS：POST 表单 ----
        if path == "/vuln/xss/post":
            # 解析表单数据
            params = parse_qs(body)
            comment = params.get("comment", [""])[0]
            self._send(200,
                f"<html><body><h1>Comments</h1><div>{comment}</div></body></html>")
            return

        # ---- 默认 ----
        self._send(404, '{"error": "Not Found"}', "application/json")

    def log_message(self, format, *args):  # noqa: A002
        """静默日志（可用 --verbose 开启）"""
        if "--verbose" in sys.argv:
            super().log_message(format, *args)


# ============================================================
# FastScanner 规则验证
# ============================================================

async def run_scan(base_url: str):
    """对 Mock 服务器执行全部规则扫描，输出命中结果"""
    from core.fast_scanner import FastScanner, ScanTarget

    scanner = FastScanner(max_workers=5, timeout=5.0, request_rate_limit=0)

    # 定义测试目标（URL 不带 query string，params 单独传入避免重复拼接）
    targets: list[tuple[str, ScanTarget, str]] = [
        ("SQL注入-报错型", ScanTarget(
            url=f"{base_url}/vuln/sqli/error",
            params={"id": "1"},
        ), "sql_injection"),
        ("SQL注入-布尔盲注", ScanTarget(
            url=f"{base_url}/vuln/sqli/boolean",
            params={"id": "1"},
        ), "sql_injection"),
        ("XSS-反射型", ScanTarget(
            url=f"{base_url}/vuln/xss/reflected",
            params={"q": "test"},
        ), "xss"),
        ("命令注入", ScanTarget(
            url=f"{base_url}/vuln/cmd",
            params={"host": "localhost"},
        ), "command_injection"),
        ("路径穿越", ScanTarget(
            url=f"{base_url}/vuln/traversal",
            params={"file": "report.pdf"},
        ), "path_traversal"),
        ("未授权访问", ScanTarget(
            url=f"{base_url}/api/users",
            auth_headers={"Authorization": "Bearer test-token-12345"},
        ), "unauthorized"),
        ("信息泄露-.env", ScanTarget(
            url=f"{base_url}/safe/page",
        ), "info_disclosure"),
        ("信息泄露-.git/config", ScanTarget(
            url=f"{base_url}/safe/page",
        ), "info_disclosure"),
        ("信息泄露-Actuator", ScanTarget(
            url=f"{base_url}/safe/page",
        ), "info_disclosure"),
        ("CORS错误配置", ScanTarget(
            url=f"{base_url}/api/data",
            auth_headers={"Authorization": "Bearer test-token"},
        ), "cors"),
        ("SQL注入-POST JSON", ScanTarget(
            url=f"{base_url}/vuln/sqli/json",
            method="POST",
            body=json.dumps({"username": "test", "password": "123"}),
            headers={"Content-Type": "application/json"},
        ), "sql_injection"),
        ("安全页面(不应命中)", ScanTarget(
            url=f"{base_url}/safe/page",
        ), "sql_injection"),
    ]

    print("\n" + "=" * 80)
    print("  FastScanner 规则验证 — Mock 漏洞服务器")
    print("=" * 80)

    total_hit = 0
    total_miss = 0
    total_findings = 0

    for name, target, rule_type in targets:
        # 每个目标重置 scanner 状态
        scanner._waf_blocked = False
        scanner._timeout_blocked = False
        scanner._catchall_blocked = False
        scanner._catchall_same_count = 0
        scanner._catchall_last_signature = ""
        scanner._consecutive_timeout_count = 0

        result = await scanner.scan_target(target, enabled_rules=[rule_type])

        status = "HIT" if result.findings else "MISS"
        if result.findings:
            total_hit += 1
            total_findings += len(result.findings)
        else:
            total_miss += 1

        # 输出结果
        icon = "[+]" if result.findings else "[-]"
        color = "\033[92m" if result.findings else "\033[91m"
        reset = "\033[0m"

        print(f"\n  {icon} {color}{name}{reset} ({rule_type})")
        print(f"      URL: {target.url}")
        print(f"      状态: {color}{status}{reset} | 请求数: {result.total_requests} | 规则数: {result.rules_run}")

        if result.waf_blocked:
            print(f"      [!] WAF 封禁触发")
        if result.catchall_blocked:
            print(f"      [!] Catch-all 熔断触发")

        for i, f in enumerate(result.findings):
            print(f"      漏洞 #{i+1}: {f.vuln_type} [{f.severity}]")
            print(f"      证据质量: {f.evidence_quality}")
            print(f"      Payload: {f.payload[:80] if f.payload else '(无)'}")
            detail = f.detail[:120].replace("\n", " ") if f.detail else ""
            print(f"      详情: {detail}")
            if f.trace_id:
                print(f"      TraceID: {f.trace_id}")

    # 汇总
    print("\n" + "=" * 80)
    print(f"  汇总: {total_hit} 命中 / {total_miss} 未命中 / {total_findings} 条漏洞发现")
    expected = sum(1 for n, _, _ in targets if "不应命中" not in n)
    print(f"  预期命中: {expected} | 实际命中: {total_hit}")
    if total_hit >= expected:
        print("  [PASS] 所有规则验证通过")
    else:
        print(f"  [WARN] 有 {expected - total_hit} 条规则未命中，请检查")
    print("=" * 80 + "\n")

    await scanner._close()


def main():
    # 启动 Mock 服务器
    port = 18899
    server = ThreadingHTTPServer(("127.0.0.1", port), MockVulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    print(f"  Mock 漏洞服务器已启动: {base_url}")
    print(f"  可用漏洞端点:")
    print(f"    /vuln/sqli/error?id=1      (SQL注入-报错型)")
    print(f"    /vuln/sqli/boolean?id=1    (SQL注入-布尔盲注)")
    print(f"    /vuln/sqli/json            (SQL注入-POST JSON)")
    print(f"    /vuln/xss/reflected?q=test (XSS-反射型)")
    print(f"    /vuln/xss/post             (XSS-POST表单)")
    print(f"    /vuln/cmd?host=localhost   (命令注入)")
    print(f"    /vuln/traversal?file=x.pdf (路径穿越)")
    print(f"    /api/users                 (未授权访问)")
    print(f"    /.env                      (信息泄露-.env)")
    print(f"    /.git/config               (信息泄露-.git)")
    print(f"    /actuator/env              (信息泄露-Actuator)")
    print(f"    /api/data                  (CORS错误配置)")
    print(f"    /safe/page                 (安全端点-对照组)")

    # 运行扫描
    try:
        asyncio.run(run_scan(base_url))
    except KeyboardInterrupt:
        print("\n  扫描已中断")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
