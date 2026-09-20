"""一键启动脚本 — 启动模拟 SPA 服务器 + 运行全部验证测试。

用法：
  python tests/mock_spa/run_mock_spa.py            # 运行所有测试
  python tests/mock_spa/run_mock_spa.py --server    # 仅启动服务器（手动浏览测试用）
  python tests/mock_spa/run_mock_spa.py --js        # 仅运行 JS 解析测试
  python tests/mock_spa/run_mock_spa.py --cookie    # 仅运行 Cookie 注入测试

服务器信息：
  URL:    http://127.0.0.1:9876
  登录:   POST /api/auth/login  (admin / admin123)
  静态:   /index.html, /js/*.js
"""

from __future__ import annotations

import os
import sys

# 确保项目根目录在 path 中
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

MOCK_SPA_DIR = os.path.dirname(os.path.abspath(__file__))

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"


def run_js_analysis_test() -> bool:
    """运行 JS 路由解析测试。"""
    print(f"\n{BOLD}{'#'*60}{RESET}")
    print(f"{BOLD}  JS 路由解析验证{RESET}")
    print(f"{BOLD}{'#'*60}{RESET}")

    from tests.mock_spa.test_js_analysis import run_all_tests as run_js_tests
    results = run_js_tests()
    return all(results.values())


def run_cookie_injection_test() -> bool:
    """运行 Cookie 注入测试。"""
    print(f"\n{BOLD}{'#'*60}{RESET}")
    print(f"{BOLD}  Cookie 注入验证{RESET}")
    print(f"{BOLD}{'#'*60}{RESET}")

    from tests.mock_spa.test_cookie_injection import run_all_tests as run_cookie_tests
    results = run_cookie_tests()
    return all(results.values())


def start_server_only():
    """仅启动服务器（供手动浏览测试）。"""
    os.chdir(MOCK_SPA_DIR)
    from tests.mock_spa.server import run_server
    run_server()


def main():
    args = sys.argv[1:]

    if "--server" in args:
        start_server_only()
        return

    js_ok = True
    cookie_ok = True

    if "--js" in args or not args:
        js_ok = run_js_analysis_test()

    if "--cookie" in args or not args:
        cookie_ok = run_cookie_injection_test()

    # 最终汇总
    print(f"\n{BOLD}{'#'*60}{RESET}")
    print(f"{BOLD}  最终汇总{RESET}")
    print(f"{BOLD}{'#'*60}{RESET}")
    js_status = f"{GREEN}PASS{RESET}" if js_ok else f"{RED}FAIL{RESET}"
    cookie_status = f"{GREEN}PASS{RESET}" if cookie_ok else f"{RED}FAIL{RESET}"
    print(f"  JS 路由解析:     {js_status}")
    print(f"  Cookie 注入:     {cookie_status}")
    print()

    if js_ok and cookie_ok:
        print(f"  {GREEN}{BOLD}✓ 所有验证通过！{RESET}")
        print(f"\n  下一步：启动服务器进行手动浏览测试：")
        print(f"    python tests/mock_spa/run_mock_spa.py --server")
        print(f"  然后在浏览器中访问 http://127.0.0.1:9876 进行手动操作")
    else:
        print(f"  {RED}{BOLD}✗ 部分验证未通过，请检查上方输出{RESET}")

    sys.exit(0 if (js_ok and cookie_ok) else 1)


if __name__ == "__main__":
    main()
