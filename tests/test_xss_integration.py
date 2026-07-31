"""XSS 模块端到端集成测试 — 用本地 HTTP server 验证全链路。"""

import asyncio
import sys
import threading
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


async def main():
    server, port = start_server()
    base = f"http://127.0.0.1:{port}"
    print(f"✓ 测试 HTTP server 启动: {base}")

    # 构造 mock sitemap
    from core.sitemap import Sitemap, APIEndpoint
    sm = Sitemap(target=base, task_id="xss_test")
    # 注入几个 API（模拟 Phase 0 爬取结果）
    sm.apis = {
        f"GET {base}/search?q=hello": APIEndpoint(method="GET", url=f"{base}/search?q=hello"),
        f"GET {base}/profile?name=user1": APIEndpoint(method="GET", url=f"{base}/profile?name=user1"),
        f"GET {base}/jsdetail?id=1": APIEndpoint(method="GET", url=f"{base}/jsdetail?id=1"),
        f"GET {base}/api/data?q=test": APIEndpoint(method="GET", url=f"{base}/api/data?q=test"),
    }

    # mock LLM client — 不真实调 LLM，直接 fake 一个 confirmed/false_positive 判定
    class MockLLM:
        def chat(self, messages, **kwargs):
            class FakeResp:
                content = '''```json
{
  "status": "confirmed",
  "severity": "high",
  "title": "反射型 XSS 测试",
  "description": "测试 LLM 研判流程",
  "reasoning": "mock judge",
  "confidence": 0.9,
  "reproduce_steps": "1. 访问 PoC URL\\n2. 触发 alert",
  "fix_suggestion": "HTML 实体编码"
}
```'''
            return FakeResp()

    # 跑 XSS 扫描
    from core.xss import XssScanner
    scanner = XssScanner(
        sitemap=sm,
        llm=MockLLM(),
        proxy="",  # 不走 mitmproxy
        enable_param_mining=False,  # 节省时间
        enable_browser_verify=False,  # 节省时间 — 全链路单测时不起浏览器
        enable_dom_scan=False,
        enable_llm_judge=True,
        max_targets=20,
    )

    print("\n=== 开始 XSS 扫描 ===")
    async for evt in scanner.run():
        msg = evt.get('data', '')
        print(f"  [{evt['type']}] {msg[:200]}")

    print(f"\n=== 扫描完成 ===")
    print(f"findings 总数: {len(scanner.findings)}")
    for f in scanner.findings:
        d = f.to_dict()
        print(f"\n[{d['status']}] {d.get('title','')}")
        print(f"  URL: {d['url']}")
        print(f"  Param: {d['param']}")
        print(f"  Payload: {d['payload'][:80]}")
        print(f"  Context: {d['echo_contexts']}")
        print(f"  Confidence: {d['judge_confidence']:.2f}")

    # 校验：/search 应该有 confirmed XSS，/profile 应该全部 false_positive，/api/data 也应该 fp
    search_confirmed = sum(1 for f in scanner.findings
                            if "/search" in f.candidate.target.url
                            and f.status.value == "confirmed")
    profile_findings = [f for f in scanner.findings if "/profile" in f.candidate.target.url]
    jsdetail_confirmed = sum(1 for f in scanner.findings
                              if "/jsdetail" in f.candidate.target.url
                              and f.status.value == "confirmed")

    print(f"\n=== 验证结果 ===")
    print(f"  /search confirmed: {search_confirmed} 个 (期望 ≥1)")
    print(f"  /profile findings: {len(profile_findings)} 个 (期望: 大部分应是 needs_review 或 false_positive)")
    print(f"  /jsdetail confirmed: {jsdetail_confirmed} 个 (期望 ≥1)")

    server.shutdown()
    print("\n✅ 测试完成")


if __name__ == "__main__":
    asyncio.run(main())
