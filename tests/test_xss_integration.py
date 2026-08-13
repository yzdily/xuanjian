"""XSS 模块端到端集成测试 — 用本地 HTTP server 验证全链路。"""

import asyncio
import sys
import threading
import pytest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# 启动一个简单的本地 HTTP server 模拟"反射型 XSS 靶场"
class XssTestHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        pass  # 静默

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/search":
            # 反射型 XSS 靶子 - HTML body 上下文
            q = params.get("q", [""])[0]
            html = f"""<html><body>
<h1>搜索结果</h1>
<p>您搜索的关键词: {q}</p>
</body></html>"""
            body_bytes = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)
            return

        if path == "/profile":
            # 安全的（HTML 转义）
            name = params.get("name", [""])[0]
            escaped = name.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            html = f"<html><body><div>profile: {escaped}</div></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode())
            return

        if path == "/jsdetail":
            # JS 字符串上下文
            id_val = params.get("id", [""])[0]
            html = f"""<html><body>
<script>
var detail = "{id_val}";
console.log(detail);
</script>
</body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode())
            return

        if path == "/api/data":
            # JSON API（无 XSS 风险）
            q = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"q":"{q}","result":[]}}'.encode())
            return

        if path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html><body>XSS test server</body></html>")
            return

        self.send_response(404)
        self.end_headers()


def start_server(port=18765):
    server = HTTPServer(("127.0.0.1", port), XssTestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


import pytest


def test_xss_full_pipeline_integration(http_target):
    """XSS 模块端到端集成测试 — 用本地 HTTP server 验证全链路。"""
    asyncio_mod = asyncio

    # 启动测试 HTTP 服务器
    # http_target 是 conftest.py 中的工厂固件，返回 base_url
    # 我们需要用自定义路由
    import http.server
    import threading

    server_holder = {}

    def _make_handler():
        class Handler(XssTestHandler):
            routes = {}
        return Handler

    port_holder = [0]
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_handler())
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port_holder[0] = httpd.server_address[1]
    base = f"http://127.0.0.1:{port_holder[0]}"

    try:
        # 构造 mock sitemap
        from core.sitemap import Sitemap, APIEndpoint
        sm = Sitemap(target=base, task_id="xss_test")
        sm.apis = {
            f"GET {base}/search?q=hello": APIEndpoint(method="GET", url=f"{base}/search?q=hello"),
            f"GET {base}/profile?name=user1": APIEndpoint(method="GET", url=f"{base}/profile?name=user1"),
            f"GET {base}/jsdetail?id=1": APIEndpoint(method="GET", url=f"{base}/jsdetail?id=1"),
            f"GET {base}/api/data?q=test": APIEndpoint(method="GET", url=f"{base}/api/data?q=test"),
        }

        # mock LLM client — 对 /profile（已转义）返回 rejected，其他返回 confirmed
        class MockLLM:
            def chat(self, messages, **kwargs):
                # 从 messages 中提取被研判的 URL
                msg_text = " ".join(
                    (m.get("content") or "") if isinstance(m, dict) else (m.content or "")
                    for m in messages
                )
                is_profile = "/profile" in msg_text
                status = "rejected" if is_profile else "confirmed"
                severity = "info" if is_profile else "high"
                class FakeResp:
                    content = f'''```json
{{
  "status": "{status}",
  "severity": "{severity}",
  "title": "反射型 XSS 测试",
  "description": "测试 LLM 研判流程",
  "reasoning": "mock judge — /profile 已转义应拒收",
  "confidence": 0.9,
  "reproduce_steps": "1. 访问 PoC URL\\n2. 触发 alert",
  "fix_suggestion": "HTML 实体编码"
}}
```'''
                return FakeResp()

        # 跑 XSS 扫描
        from core.xss import XssScanner
        scanner = XssScanner(
            sitemap=sm,
            llm=MockLLM(),
            proxy="",
            enable_param_mining=False,
            enable_browser_verify=False,
            enable_dom_scan=False,
            enable_llm_judge=True,
            max_targets=20,
        )

        done_received = False
        event_count = 0
        for evt in asyncio_mod.run(_collect_events(scanner)):
            event_count += 1
            if evt.get("type") == "xss_done":
                done_received = True

        assert event_count > 0, "应产生至少一个事件"
        assert done_received, "应收到 xss_done 事件"

        # 验证 /search 有 confirmed XSS
        search_confirmed = sum(
            1 for f in scanner.findings
            if "/search" in f.candidate.target.url and f.status.value == "confirmed"
        )
        assert search_confirmed >= 1, f"/search 应有 confirmed XSS，实际 {search_confirmed}"

        # 验证 /jsdetail 有 confirmed XSS
        jsdetail_confirmed = sum(
            1 for f in scanner.findings
            if "/jsdetail" in f.candidate.target.url and f.status.value == "confirmed"
        )
        assert jsdetail_confirmed >= 1, f"/jsdetail 应有 confirmed XSS，实际 {jsdetail_confirmed}"

        # 验证 /profile 无 confirmed XSS（已转义）
        profile_confirmed = sum(
            1 for f in scanner.findings
            if "/profile" in f.candidate.target.url and f.status.value == "confirmed"
        )
        assert profile_confirmed == 0, f"/profile 不应有 confirmed XSS，实际 {profile_confirmed}"
    finally:
        httpd.shutdown()
        httpd.server_close()


async def _collect_events(scanner):
    """收集 scanner.run() 的所有事件。"""
    events = []
    async for evt in scanner.run():
        events.append(evt)
    return events
