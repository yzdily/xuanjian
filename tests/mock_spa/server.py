"""模拟 SPA 后端服务器 — 提供静态文件服务 + API 端点 + Cookie 认证。

用于本地验证：
  1. js_analyzer.py 的 JS 路由解析（axios baseURL / WebSocket / SSE / router）
  2. spa_mixin.py 的 Cookie 注入和认证态复用

启动：
  python tests/mock_spa/server.py
  # 默认 http://localhost:9876

API 端点清单：
  POST /api/auth/login          — 登录，设置 Cookie + 返回 token
  GET  /api/auth/userinfo        — 需要 Cookie 认证
  GET  /api/users/list           — 需要 Cookie 认证
  GET  /api/users/detail         — 需要 Cookie 认证
  POST /api/system/config        — 需要 Cookie 认证
  GET  /api/v1/dashboard         — 需要 Cookie 认证
  GET  /api/v2/export/data       — 需要 Cookie 认证
  GET  /api/public/health        — 公开接口
  GET  /api/sse/notifications    — SSE 端点（模拟）
  WS   /ws/chat                  — WebSocket 端点（模拟）
"""

from __future__ import annotations

import json
import time
import hashlib
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = 9876
STATIC_DIR = "static"

# 有效凭证
VALID_USERNAME = "admin"
VALID_PASSWORD = "admin123"

# Session 存储：token -> { username, expire_ts }
_SESSIONS: dict[str, dict] = {}

# 预设用户数据
_USERS = [
    {"id": 1, "name": "Alice", "role": "admin", "email": "alice@test.com"},
    {"id": 2, "name": "Bob", "role": "user", "email": "bob@test.com"},
    {"id": 3, "name": "Charlie", "role": "manager", "email": "charlie@test.com"},
]


def _make_token(username: str) -> str:
    """生成简单 token（模拟 JWT）。"""
    raw = f"{username}:{int(time.time())}:mock_secret"
    return hashlib.md5(raw.encode()).hexdigest()


def _check_auth(headers) -> str | None:
    """从 Cookie 或 Authorization header 中提取并验证 token。"""
    # 1. Cookie
    cookie_header = headers.get("Cookie", "")
    if cookie_header:
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        if "auth_token" in cookie:
            token = cookie["auth_token"].value
            session = _SESSIONS.get(token)
            if session and session["expire_ts"] > time.time():
                return session["username"]
    # 2. Authorization Bearer
    auth_header = headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        session = _SESSIONS.get(token)
        if session and session["expire_ts"] > time.time():
            return session["username"]
    return None


class MockSPAHandler(SimpleHTTPRequestHandler):
    """处理静态文件 + API 请求的混合 handler。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    # ---- 通用响应工具 ----

    def _json(self, data: dict, status: int = 200, extra_headers: dict | None = None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _unauthorized(self):
        self._json({"code": 401, "message": "Unauthorized: token missing or expired"}, 401)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    # ---- 路由分发 ----

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ---- API 路由 ----
        if path == "/api/public/health":
            self._json({"code": 0, "message": "ok", "data": {"status": "healthy"}})
            return

        if path == "/api/auth/userinfo":
            user = _check_auth(self.headers)
            if not user:
                self._unauthorized()
                return
            self._json({"code": 0, "data": {"username": user, "role": "admin"}})
            return

        if path == "/api/users/list":
            user = _check_auth(self.headers)
            if not user:
                self._unauthorized()
                return
            self._json({"code": 0, "data": _USERS})
            return

        if path == "/api/users/detail":
            user = _check_auth(self.headers)
            if not user:
                self._unauthorized()
                return
            uid = parsed.query.split("=")[-1] if "=" in parsed.query else "1"
            found = next((u for u in _USERS if str(u["id"]) == uid), _USERS[0])
            self._json({"code": 0, "data": found})
            return

        if path == "/api/v1/dashboard":
            user = _check_auth(self.headers)
            if not user:
                self._unauthorized()
                return
            self._json({
                "code": 0,
                "data": {"total_users": 128, "active_sessions": 42, "cpu": 35.2},
            })
            return

        if path == "/api/v2/export/data":
            user = _check_auth(self.headers)
            if not user:
                self._unauthorized()
                return
            self._json({"code": 0, "data": {"export_url": "/files/export_20260813.csv"}})
            return

        if path == "/api/sse/notifications":
            # 模拟 SSE（只发送一帧就关闭，用于测试端点发现）
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"data: {\"type\":\"connected\",\"ts\":9999}\n\n")
            self.wfile.flush()
            return

        # ---- 静态文件 ----
        # SPA fallback：所有非 API 路径返回 index.html
        if path.startswith("/api/") or path.startswith("/ws/"):
            self._json({"code": 404, "message": f"Not found: {path}"}, 404)
            return

        # 尝试静态文件
        if path == "/" or path == "":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/auth/login":
            body = self._read_body()
            username = body.get("username", "")
            password = body.get("password", "")
            if username == VALID_USERNAME and password == VALID_PASSWORD:
                token = _make_token(username)
                _SESSIONS[token] = {
                    "username": username,
                    "expire_ts": time.time() + 3600,
                }
                self._json(
                    {"code": 0, "message": "login success", "data": {"token": token}},
                    extra_headers={"Set-Cookie": f"auth_token={token}; Path=/; HttpOnly"},
                )
            else:
                self._json({"code": 401, "message": "Invalid credentials"}, 401)
            return

        if path == "/api/system/config":
            user = _check_auth(self.headers)
            if not user:
                self._unauthorized()
                return
            body = self._read_body()
            self._json({"code": 0, "message": "config updated", "data": body})
            return

        if path == "/api/users/create":
            user = _check_auth(self.headers)
            if not user:
                self._unauthorized()
                return
            body = self._read_body()
            self._json({"code": 0, "message": "user created", "data": {"id": 999, **body}})
            return

        self._json({"code": 404, "message": f"Not found: {path}"}, 404)

    def do_PUT(self):
        self._json({"code": 0, "message": "updated"})

    def do_DELETE(self):
        self._json({"code": 0, "message": "deleted"})

    def log_message(self, format, *args):
        # 简化日志：只打印 API 请求
        if "/api/" in (args[1] if len(args) > 1 else ""):
            print(f"  [{self.log_date_time_string()}] {format % args}")


def run_server(port: int = PORT):
    """启动模拟服务器。"""
    server = HTTPServer((HOST, port), MockSPAHandler)
    print(f"Mock SPA Server running on http://{HOST}:{port}")
    print(f"  Static files:  {STATIC_DIR}/")
    print(f"  API endpoints: /api/*")
    print(f"  Login:         POST /api/auth/login  (admin / admin123)")
    print(f"  WebSocket:     ws://{HOST}:{port}/ws/chat (simulated)")
    print()
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run_server(port)
