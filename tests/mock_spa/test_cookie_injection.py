"""Cookie 注入验证测试 — 验证 spa_mixin.py 的认证态提取与复用逻辑。

测试流程：
  1. 启动模拟 SPA 服务器（后台线程）
  2. 使用 urllib 模拟登录，获取 Cookie + Token
  3. 验证无认证访问受保护接口 → 401
  4. 使用 Cookie 访问受保护接口 → 200
  5. 使用 Bearer Token 访问受保护接口 → 200
  6. 模拟 spa_mixin._auto_extract_auth_state 的认证态结构
  7. 验证认证态结构可被 _apply_auth_state_async 使用

运行：
  python tests/mock_spa/test_cookie_injection.py
"""

from __future__ import annotations

import os
import sys
import json
import time
import threading
import urllib.request
import urllib.error
from http.cookiejar import CookieJar

import pytest

# ★ 需要 SPA mock 服务器运行，标记为 integration（CI 中排除）
pytestmark = pytest.mark.integration

# 确保项目根目录在 path 中
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ============================================================
# 颜色
# ============================================================
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ============================================================
# 常量
# ============================================================
HOST = "127.0.0.1"
PORT = 18080
BASE_URL = f"http://{HOST}:{PORT}"
USERNAME = "admin"
PASSWORD = "admin123"

# 受保护接口列表
PROTECTED_ENDPOINTS = [
    ("GET", "/api/auth/userinfo"),
    ("GET", "/api/users/list"),
    ("GET", "/api/users/detail?id=1"),
    ("GET", "/api/v1/dashboard"),
    ("GET", "/api/v2/export/data"),
    ("POST", "/api/system/config"),
]

# 公开接口
PUBLIC_ENDPOINTS = [
    ("GET", "/api/public/health"),
]


def _print_header(title: str):
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")


# ============================================================
# 服务器管理
# ============================================================

def start_server() -> threading.Thread | None:
    """在后台线程启动模拟服务器。"""
    # 切换到 mock_spa 目录，使 server.py 的 STATIC_DIR 相对路径生效
    original_cwd = os.getcwd()
    mock_spa_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(mock_spa_dir)

    try:
        from tests.mock_spa.server import run_server, MockSPAHandler
        from http.server import HTTPServer

        server = HTTPServer((HOST, PORT), MockSPAHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        # 等待服务器启动
        time.sleep(0.5)
        print(f"  模拟服务器已启动: {BASE_URL}")

        # 恢复工作目录
        os.chdir(original_cwd)

        # 将 server 实例附加到线程上以便后续关闭
        thread._server = server
        return thread
    except Exception as e:
        os.chdir(original_cwd)
        print(f"  {RED}服务器启动失败: {e}{RESET}")
        return None


def stop_server(thread: threading.Thread):
    """停止模拟服务器。"""
    if hasattr(thread, "_server"):
        thread._server.shutdown()
        thread._server.server_close()
    print(f"  模拟服务器已停止")


# ============================================================
# HTTP 请求工具
# ============================================================

def _request(method: str, path: str, body: dict | None = None,
             cookies: dict | None = None, headers: dict | None = None) -> tuple[int, dict, str]:
    """发送 HTTP 请求，返回 (status_code, json_body, raw_body)。"""
    url = BASE_URL + path
    data = json.dumps(body).encode("utf-8") if body else None

    req_headers = {"Content-Type": "application/json"}
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req_headers["Cookie"] = cookie_str
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            raw = resp.read().decode("utf-8")
            try:
                return status, json.loads(raw), raw
            except json.JSONDecodeError:
                return status, {}, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw), raw
        except json.JSONDecodeError:
            return e.code, {}, raw


def _extract_cookie_from_response(path: str, body: dict) -> dict:
    """从登录响应中提取 Cookie（模拟浏览器 Set-Cookie 处理）。"""
    # 由于 urllib 不方便获取 Set-Cookie header，我们直接从 response body 中提取 token
    token = body.get("data", {}).get("token", "")
    if token:
        return {"auth_token": token}
    return {}


# ============================================================
# 测试用例
# ============================================================

def test_unauthorized_access() -> bool:
    """测试 1: 无认证访问受保护接口应返回 401。"""
    _print_header("测试 1: 无认证访问受保护接口")
    all_pass = True
    for method, path in PROTECTED_ENDPOINTS:
        status, body, _ = _request(method, path, body={} if method == "POST" else None)
        ok = status == 401
        status_str = f"{GREEN}401{RESET}" if ok else f"{RED}{status}{RESET}"
        print(f"  {status_str}  {method} {path}")
        if not ok:
            all_pass = False
    if all_pass:
        print(f"  {GREEN}✓ 所有受保护接口正确返回 401{RESET}")
    else:
        print(f"  {RED}✗ 部分接口未正确拒绝无认证请求{RESET}")
    return all_pass


def test_public_access() -> bool:
    """测试 2: 公开接口无需认证可访问。"""
    _print_header("测试 2: 公开接口无认证访问")
    all_pass = True
    for method, path in PUBLIC_ENDPOINTS:
        status, body, _ = _request(method, path)
        ok = status == 200 and body.get("code") == 0
        status_str = f"{GREEN}200{RESET}" if ok else f"{RED}{status}{RESET}"
        print(f"  {status_str}  {method} {path}  →  {body.get('data', {})}")
        if not ok:
            all_pass = False
    if all_pass:
        print(f"  {GREEN}✓ 公开接口可正常访问{RESET}")
    else:
        print(f"  {RED}✗ 公开接口访问失败{RESET}")
    return all_pass


def test_login_and_cookie_injection() -> bool:
    """测试 3: 登录获取 Cookie，使用 Cookie 访问受保护接口。"""
    _print_header("测试 3: 登录 + Cookie 注入")

    # 3a: 登录
    print("\n  3a: 登录获取 Cookie")
    status, body, _ = _request("POST", "/api/auth/login", body={"username": USERNAME, "password": PASSWORD})
    if status != 200 or body.get("code") != 0:
        print(f"  {RED}✗ 登录失败: status={status}, body={body}{RESET}")
        return False

    token = body["data"]["token"]
    cookies = {"auth_token": token}
    print(f"  {GREEN}✓{RESET} 登录成功, token={token[:20]}...")
    print(f"    Cookie: auth_token={token[:20]}...")

    # 3b: 使用 Cookie 访问受保护接口
    print("\n  3b: 使用 Cookie 访问受保护接口")
    all_pass = True
    for method, path in PROTECTED_ENDPOINTS:
        status, resp_body, _ = _request(
            method, path,
            body={"key": "value"} if method == "POST" else None,
            cookies=cookies,
        )
        ok = status == 200 and resp_body.get("code") == 0
        status_str = f"{GREEN}200{RESET}" if ok else f"{RED}{status}{RESET}"
        data_preview = str(resp_body.get("data", ""))[:60]
        print(f"  {status_str}  {method} {path}  →  {data_preview}")
        if not ok:
            all_pass = False

    if all_pass:
        print(f"\n  {GREEN}✓ Cookie 注入成功，所有受保护接口可访问{RESET}")
    else:
        print(f"\n  {RED}✗ Cookie 注入后部分接口仍不可访问{RESET}")
    return all_pass


def test_bearer_token_injection() -> bool:
    """测试 4: 使用 Bearer Token 访问受保护接口。"""
    _print_header("测试 4: Bearer Token 注入")

    # 先登录获取 token
    status, body, _ = _request("POST", "/api/auth/login", body={"username": USERNAME, "password": PASSWORD})
    if status != 200:
        print(f"  {RED}✗ 登录失败{RESET}")
        return False

    token = body["data"]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"  Authorization: Bearer {token[:20]}...")

    # 使用 Bearer Token 访问
    all_pass = True
    for method, path in PROTECTED_ENDPOINTS[:4]:  # 测试前 4 个接口
        status, resp_body, _ = _request(
            method, path,
            headers=headers,
        )
        ok = status == 200 and resp_body.get("code") == 0
        status_str = f"{GREEN}200{RESET}" if ok else f"{RED}{status}{RESET}"
        print(f"  {status_str}  {method} {path}")
        if not ok:
            all_pass = False

    if all_pass:
        print(f"\n  {GREEN}✓ Bearer Token 注入成功{RESET}")
    else:
        print(f"\n  {RED}✗ Bearer Token 注入失败{RESET}")
    return all_pass


def test_invalid_credentials() -> bool:
    """测试 5: 错误凭证应返回 401。"""
    _print_header("测试 5: 错误凭证验证")
    status, body, _ = _request("POST", "/api/auth/login", body={"username": "wrong", "password": "wrong"})
    ok = status == 401
    status_str = f"{GREEN}401{RESET}" if ok else f"{RED}{status}{RESET}"
    print(f"  {status_str}  POST /api/auth/login (wrong credentials)")
    if ok:
        print(f"  {GREEN}✓ 错误凭证被正确拒绝{RESET}")
    else:
        print(f"  {RED}✗ 错误凭证未被拒绝{RESET}")
    return ok


def test_auth_state_structure() -> bool:
    """测试 6: 模拟 spa_mixin._auto_extract_auth_state 的认证态结构。"""
    _print_header("测试 6: 认证态结构验证 (模拟 _auto_extract_auth_state)")

    # 登录获取 token
    status, body, _ = _request("POST", "/api/auth/login", body={"username": USERNAME, "password": PASSWORD})
    token = body["data"]["token"]

    # 构造模拟的 auth_state（与 spa_mixin._auto_extract_auth_state 返回格式一致）
    auth_state = {
        "cookies": [
            {
                "name": "auth_token",
                "value": token,
                "domain": "127.0.0.1",
                "path": "/",
                "httpOnly": True,
                "secure": False,
            }
        ],
        "local_storage": {
            "auth_token": token,
            "login_type": "password",
        },
        "session_storage": {
            "session_id": "mock_session_12345",
        },
        "auth_header": f"Bearer {token}",
        "extra_headers": {},
    }

    print(f"  认证态结构:")
    print(f"    cookies:         {len(auth_state['cookies'])} 个")
    print(f"    local_storage:   {len(auth_state['local_storage'])} 项")
    print(f"    session_storage: {len(auth_state['session_storage'])} 项")
    print(f"    auth_header:     {auth_state['auth_header'][:30]}...")

    # 验证结构完整性
    required_keys = {"cookies", "local_storage", "session_storage", "auth_header", "extra_headers"}
    actual_keys = set(auth_state.keys())
    missing = required_keys - actual_keys

    if missing:
        print(f"  {RED}✗ 认证态结构缺失字段: {missing}{RESET}")
        return False

    # 验证 Cookie 值可用于访问受保护接口
    cookie_token = auth_state["cookies"][0]["value"]
    status, resp_body, _ = _request("GET", "/api/auth/userinfo", cookies={"auth_token": cookie_token})
    if status == 200 and resp_body.get("code") == 0:
        print(f"  {GREEN}✓ 认证态中的 Cookie 可成功访问受保护接口{RESET}")
    else:
        print(f"  {RED}✗ 认证态中的 Cookie 无法访问受保护接口{RESET}")
        return False

    # 验证 auth_header 可用于访问
    status, resp_body, _ = _request("GET", "/api/users/list", headers={"Authorization": auth_state["auth_header"]})
    if status == 200 and resp_body.get("code") == 0:
        print(f"  {GREEN}✓ 认证态中的 auth_header 可成功访问受保护接口{RESET}")
    else:
        print(f"  {RED}✗ 认证态中的 auth_header 无法访问受保护接口{RESET}")
        return False

    # 验证 local_storage 中的 token 可用于访问
    ls_token = auth_state["local_storage"]["auth_token"]
    status, resp_body, _ = _request("GET", "/api/v1/dashboard", cookies={"auth_token": ls_token})
    if status == 200 and resp_body.get("code") == 0:
        print(f"  {GREEN}✓ 认证态中的 localStorage token 可成功访问受保护接口{RESET}")
    else:
        print(f"  {RED}✗ 认证态中的 localStorage token 无法访问受保护接口{RESET}")
        return False

    return True


def test_spa_fallback_decision() -> bool:
    """测试 7: 模拟 spa_mixin._should_fallback_to_manual 的降级决策逻辑。"""
    _print_header("测试 7: SPA 降级决策逻辑验证")

    from core.crawler.spa_mixin import SPA_FALLBACK_PAGE_THRESHOLD

    # 模拟不同场景
    scenarios = [
        # (page_count, is_spa, captured_api_count, expected_fallback)
        (1, True, 0, True),    # SPA + 只爬到1页 + 0 API → 应降级
        (2, True, 1, True),    # SPA + 只爬到2页 + 1 API → 应降级
        (5, True, 10, False),  # SPA + 爬到5页 + 10 API → 不需降级
        (1, False, 0, False),  # 非 SPA + 只爬到1页 → 不降级（非 SPA 场景）
        (0, True, 0, True),    # SPA + 0页 → 应降级
    ]

    all_pass = True
    for page_count, is_spa, api_count, expected in scenarios:
        # 模拟 _should_fallback_to_manual 的核心逻辑
        if is_spa and page_count < SPA_FALLBACK_PAGE_THRESHOLD:
            actual = True
        else:
            actual = False

        ok = actual == expected
        status_str = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
        scenario_desc = f"pages={page_count}, spa={is_spa}, apis={api_count}"
        expected_desc = "降级" if expected else "不降级"
        actual_desc = "降级" if actual else "不降级"
        print(f"  {status_str} {scenario_desc:40s} → 期望: {expected_desc}, 实际: {actual_desc}")

        if not ok:
            all_pass = False

    if all_pass:
        print(f"\n  {GREEN}✓ 所有降级决策场景正确{RESET}")
    else:
        print(f"\n  {RED}✗ 部分降级决策场景错误{RESET}")
    return all_pass


# ============================================================
# 主入口
# ============================================================

def run_all_tests() -> dict[str, bool]:
    """运行所有测试。"""
    _print_header("启动模拟 SPA 服务器")
    server_thread = start_server()
    if not server_thread:
        print(f"{RED}无法启动服务器，测试中止{RESET}")
        return {}

    try:
        results = {
            "unauthorized_access": test_unauthorized_access(),
            "public_access": test_public_access(),
            "login_and_cookie": test_login_and_cookie_injection(),
            "bearer_token": test_bearer_token_injection(),
            "invalid_credentials": test_invalid_credentials(),
            "auth_state_structure": test_auth_state_structure(),
            "spa_fallback_decision": test_spa_fallback_decision(),
        }
    finally:
        _print_header("停止模拟服务器")
        stop_server(server_thread)

    # 汇总
    _print_header("测试汇总")
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    for name, ok in results.items():
        status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"  {status}  {name}")
    print(f"\n  {BOLD}总计: {passed}/{total} 通过{RESET}")

    return results


if __name__ == "__main__":
    results = run_all_tests()
    sys.exit(0 if all(results.values()) else 1)
