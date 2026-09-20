"""回归钉（阶段 4-E1 凭证隔离）—— 防回退。

阶段 4-E1 的本质：把凭证从**进程级 os.environ** 迁到**会话级作用域**（contextvar）。

为什么必须钉住：原实现（``chat_loop.py:700-702`` 先 pop 掉 5 个注入键再写本会话值）
会让并行会话互相**清除**凭证 —— 实测复现见 ``_e1_repro_crosstalk.py``：

    会话 A 注入 sid=SESSION_A_SECRET → B 注入后 A 再读 → 拿到 token=TOKEN_B_SECRET

任何一处回退（重新往 env 写、读取点绕过作用域、指纹退回读 env）都应被钉住。

附带钉住 L2 修复：``get_session_info`` 必须按目标域过滤 cookie，
否则共享 browser context 会把跨目标 cookie 拼进同一个 Cookie 头。
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CORE = PROJECT_ROOT / "core"
MCP = PROJECT_ROOT / "mcp_servers"

#: 凭证注入类环境变量（不含 PENTEST_PACKET_MODE / PENTEST_NOISE_DETECT 等非凭证开关）
INJECT_ENV_PREFIX = "PENTEST_INJECT_"
TARGET_URL_KEY = "PENTEST_TARGET_URL"


# ------------------------------------------------------------------ 源码级钉子

def _iter_py(*roots: Path):
    for root in roots:
        yield from root.rglob("*.py")


def test_no_credential_writes_to_process_env():
    """★ 核心钉子：凭证不得再写入进程级 env。

    这是并行会话串扰（M3）的根源 —— 只要有一处回退，串扰就会重新出现。
    允许的例外：``cred_scope.py``（其 ``clear_env_injections`` 是 *清理* 而非写入）。
    """
    write_re = re.compile(
        rf'os\.environ\[\s*[\'"]({INJECT_ENV_PREFIX}\w+|{TARGET_URL_KEY})[\'"]\s*\]\s*=|'
        rf'os\.environ\.setdefault\(\s*[\'"]({INJECT_ENV_PREFIX}\w+|{TARGET_URL_KEY})[\'"]'
    )
    offenders: list[str] = []
    for p in _iter_py(CORE, MCP):
        if p.name == "cred_scope.py":
            continue
        src = p.read_text(encoding="utf-8")
        for m in write_re.finditer(src):
            line_no = src[: m.start()].count("\n") + 1
            offenders.append(f"{p.relative_to(PROJECT_ROOT)}:{line_no}  {m.group(0).strip()}")
    assert not offenders, (
        "发现凭证写回进程级 env（会让并行会话互相覆盖/清除，M3 串扰根因）：\n  "
        + "\n  ".join(offenders)
    )


def test_cred_scope_module_api():
    """作用域模块的核心 API 必须齐备（写入 / 读取 / 更新 / 回退 / 清理）。"""
    from core.session import cred_scope as cs

    for name in ("CredScope", "set_scope", "get_scope", "update_scope", "reset_scope",
                 "has_scope", "has_credentials", "current_cookies", "current_auth",
                 "current_headers", "current_local_storage", "current_target_url",
                 "clear_env_injections", "legacy_env_fingerprint", "bind", "enabled"):
        assert hasattr(cs, name), f"cred_scope 缺少 {name}"


def test_scope_mask_never_leaks_plaintext():
    """供日志/SSE/前端用的 mask() 绝不能包含明文凭证。"""
    from core.session.cred_scope import CredScope

    scope = CredScope(cookies="sid=SUPER_SECRET", auth="Bearer TOKEN_SECRET")
    masked = scope.mask()
    dumped = str(masked)
    assert "SUPER_SECRET" not in dumped, "mask() 泄漏了 cookie 明文"
    assert "TOKEN_SECRET" not in dumped, "mask() 泄漏了 token 明文"
    assert masked["has_cookies"] is True and masked["has_auth"] is True


def test_chat_loop_injection_uses_scope():
    """主注入点必须写入作用域，且显式清理遗留 env。"""
    src = (CORE / "session" / "chat_loop.py").read_text(encoding="utf-8")
    assert "cred_scope" in src, "chat_loop 未接入凭证作用域"
    assert "_cs.set_scope(" in src, "chat_loop 主注入点未调用 set_scope"
    assert "_cs.clear_env_injections()" in src, "chat_loop 未清理进程级遗留 env"


def test_get_session_info_filters_by_target():
    """★ L2 修复钉子：按目标域过滤 cookie（否则跨目标 cookie 混进同一 Cookie 头）。"""
    src = (CORE / "parallel" / "session_info.py").read_text(encoding="utf-8")
    assert "async def get_session_info(target_url: str = \"\")" in src, \
        "get_session_info 缺少 target_url 参数"
    assert "cookies(effective_target)" in src, "未按目标域过滤 cookie（L2 未修复）"


def test_browser_and_proxy_read_from_scope():
    """browser_mcp / proxy_mcp 的凭证来源必须是作用域（同进程 contextvar 可穿透）。"""
    browser = (MCP / "browser_mcp.py").read_text(encoding="utf-8")
    proxy = (MCP / "proxy_mcp.py").read_text(encoding="utf-8")
    assert "cred_scope" in browser, "browser_mcp 未接入作用域"
    assert "legacy_env_fingerprint" in browser, "browser_mcp 指纹未改为作用域计算"
    assert "cred_scope" in proxy, "proxy_mcp 未接入作用域"


# ------------------------------------------------------------------ 行为级钉子

def test_concurrent_tasks_are_isolated():
    """★ 行为级：两个独立 asyncio task 的凭证互不可见（真实并发结构）。"""
    from core.session import cred_scope as cs

    async def scenario() -> tuple[str, str]:
        async def session(cookie: str) -> str:
            cs.set_scope(cs.CredScope(cookies=cookie, source=cs.SOURCE_MANUAL))
            await asyncio.sleep(0.01)        # 制造交错，放大竞态
            return cs.current_cookies()

        results = await asyncio.gather(session("sid=A_SECRET"), session("token=B_SECRET"))
        return results[0], results[1]

    cs.clear_env_injections()
    a, b = asyncio.run(scenario())
    assert a == "sid=A_SECRET", f"会话 A 的凭证被污染: {a!r}"
    assert b == "token=B_SECRET", f"会话 B 的凭证被污染: {b!r}"


def test_scope_empty_falls_back_to_env():
    """迁移期兼容：作用域未绑定时只读回退 env（CLI 直设 env 的用法不能被破坏）。"""
    import os

    from core.session import cred_scope as cs

    async def scenario() -> tuple[str, str]:
        # 干净 task：未绑定作用域 → 应回退 env
        return cs.current_cookies(), cs.current_target_url()

    os.environ["PENTEST_INJECT_COOKIES"] = "env_cookie"
    os.environ["PENTEST_TARGET_URL"] = "http://env.local"
    try:
        cookies, target = asyncio.run(scenario())
        assert cookies == "env_cookie", f"未回退 env: {cookies!r}"
        assert target == "http://env.local"
    finally:
        cs.clear_env_injections()


def test_update_scope_preserves_other_fields():
    """登录回写用 update_scope 增量更新，不能把其它字段清掉。"""
    from core.session import cred_scope as cs

    async def scenario() -> tuple[str, str, str]:
        cs.set_scope(cs.CredScope(cookies="c1", auth="a1", target_url="http://t.local",
                                  headers={"X-Sign": "s"}, source=cs.SOURCE_MANUAL))
        cs.update_scope(cookies="c2", source=cs.SOURCE_AUTO_LOGIN)
        s = cs.get_scope()
        return s.cookies, s.auth, s.target_url

    cs.clear_env_injections()
    cookies, auth, target = asyncio.run(scenario())
    assert cookies == "c2", "cookies 未更新"
    assert auth == "a1", "update_scope 误清了 auth"
    assert target == "http://t.local", "update_scope 误清了 target_url"


def test_bind_context_manager_restores():
    """bind() 退出后必须还原，避免污染调用方 task。"""
    from core.session import cred_scope as cs

    cs.clear_env_injections()
    assert cs.has_scope() is False
    with cs.bind(cs.CredScope(cookies="inner")):
        assert cs.current_cookies() == "inner"
    assert cs.current_cookies() == "", "bind 退出后未还原"
