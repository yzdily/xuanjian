"""回归钉（阶段 4-E1 · L3b 方案 C：每会话独立浏览器 context）—— 防回退。

## 为什么必须钉住

L3b 是决策门实测确认的**致命场景**：同站点多账号并行做越权测试时，两个会话共享
同一个 browser context，`add_cookies` 会把同域同名 cookie（如 `JSESSIONID`）互相覆盖：

    账号1 注入 JSESSIONID=ADMIN_SESSION
    账号2 注入 JSESSIONID=USER_SESSION
    → jar 中只剩 USER_SESSION，账号1 的测试实际以账号2 身份发起，越权结论完全不可信

方案 C 的隔离手段：**1 browser + 每会话独立 context**
（实测每 context ≈29ms / ≈1.4MB，成本可接受 —— 见 `_l3b_context_isolation_probe.py`）。

## 顺带钉住的历史陷阱

`from mcp_servers.browser_mcp import _page` 是**值拷贝** —— 导入时刻 `_page` 为 None，
导入方永远拿到 None。`core/mcp_bridge.py` 与 `batch_test.py` 曾因此静默失效
（"从浏览器补拿 token"的逻辑从未执行）。故必须用函数式入口 `await get_page()`。
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _src(rel: str) -> str:
    return (PROJECT_ROOT / rel).read_text(encoding="utf-8")


def _code_only(src: str) -> str:
    """只保留代码行（去掉整行注释）。

    否则「修复说明注释」里提到的旧写法（如 `from ... import _page`）会把断言误伤 ——
    这是本文件第一版踩到的坑。
    """
    return "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))


# ---------------------------------------------------------------- 源码级钉子

def test_browser_mcp_has_per_session_registries():
    """每会话独立 context 的注册表与入口必须齐备。"""
    from mcp_servers import browser_mcp as bm

    for name in ("_contexts", "_pages", "_injection_fingerprints",
                 "get_page", "release_session", "active_session_count", "_session_key"):
        assert hasattr(bm, name), f"browser_mcp 缺少 {name}"


def test_ensure_browser_does_not_kill_shared_browser():
    """★ 关键：某个会话的 page 失效时，不能把 `_browser` 置 None。

    旧实现遇异常会 `_browser = None`，在方案 C 下会**连带毁掉其它并行会话**的 context。
    """
    src = _src("mcp_servers/browser_mcp.py")
    # 存活检查分支里只应回收本会话的三个注册表项，不得出现 `_browser = None`
    marker = "只回收**本会话**的 context"
    assert marker in src, "存活检查未按会话回收"
    tail = src[src.index(marker): src.index(marker) + 900]
    assert "_browser = None" not in tail, "会话失效时误将共享 _browser 置 None（会毁掉其它会话）"


def test_injection_fingerprint_is_per_session():
    """指纹必须按会话记录 —— 共用全局指纹会让另一会话的刷新被误判为"已最新"而跳过。"""
    src = _src("mcp_servers/browser_mcp.py")
    assert "_injection_fingerprints.get(key)" in src, "注入指纹未按会话比对"
    assert "_injection_fingerprints[key] = fingerprint" in src, "注入指纹未按会话写入"


def test_mcp_bridge_no_longer_exports_page():
    """★ 值拷贝陷阱：不得再导出 `_page`（导入方永远拿到 None）。"""
    code = _code_only(_src("core/mcp_bridge.py"))
    assert "get_page" in code, "mcp_bridge 未导出函数式入口"
    # 注意：必须用词边界 —— `"_page" in code` 会把 `get_page` 也算命中（子串陷阱）
    assert not re.search(r"(?<![A-Za-z0-9_])_page(?![A-Za-z0-9_])", code), \
        "mcp_bridge 仍在代码中引用 _page（值拷贝陷阱）"


def test_batch_test_uses_functional_entry():
    """batch_test 必须用函数式入口（原 `import _page` 导致该段逻辑从未执行）。"""
    code = _code_only(_src("core/parallel/batch_test.py"))
    assert "from core.mcp_bridge import get_page" in code, "batch_test 未改用 get_page"
    assert not re.search(r"(?<![A-Za-z0-9_])_page(?![A-Za-z0-9_])", code), \
        "batch_test 仍用值拷贝方式引用 _page"


def test_cred_scope_carries_session_key():
    """会话标识必须随凭证作用域传递（浏览器层靠它选 context）。"""
    from core.session import cred_scope as cs

    assert hasattr(cs, "current_session_key")
    s = cs.CredScope(session_key="task_x")
    assert s.session_key == "task_x"
    with cs.bind(s):
        assert cs.current_session_key() == "task_x"


def test_all_injection_points_set_session_key():
    """所有凭证注入点都要带 session_key（漏一处就会退化成共享 context）。"""
    offenders = []
    for rel in ("core/session/chat_loop.py", "core/session/base.py",
                "core/session/idle_mixin.py", "core/session/focused_test_mixin.py"):
        src = _src(rel)
        n = src.count("CredScope(")
        m = src.count("session_key=")
        if m < n:
            offenders.append(f"{rel}: CredScope( ×{n} 但 session_key= ×{m}")
    assert not offenders, "有注入点未带 session_key：\n  " + "\n  ".join(offenders)


def test_session_context_is_released():
    """会话重置时必须释放 context（否则每会话泄漏约 1.4MB）。"""
    src = _src("core/session/base.py")
    assert "release_session" in src, "未释放浏览器 context（会累积泄漏）"
    assert "_reset_for_new_task" in src


# ---------------------------------------------------------------- 行为级钉子

def _fake_check_proxy(monkeypatch):
    """跳过真实代理探测（否则每次要等 3 个 URL 超时，拖慢测试）。"""
    from mcp_servers import browser_mcp as bm

    async def _never(_url: str) -> bool:
        return False

    monkeypatch.setattr(bm, "_check_proxy", _never)
    monkeypatch.setenv("BROWSER_HEADLESS", "true")


def test_same_domain_cookies_are_isolated_between_sessions(monkeypatch):
    """★ 核心行为验证：同域同名 cookie 不再跨会话覆盖（L3b 的真实验收）。"""
    pytest.importorskip("playwright")
    _fake_check_proxy(monkeypatch)

    import asyncio

    from core.session import cred_scope as cs
    from mcp_servers import browser_mcp as bm

    async def scenario():
        with cs.bind(cs.CredScope(session_key="l3b_A", target_url="http://shop.local")):
            pa = await bm.get_page()
            await pa.context.add_cookies([{
                "name": "JSESSIONID", "value": "ADMIN_SESSION",
                "domain": "shop.local", "path": "/",
            }])
        with cs.bind(cs.CredScope(session_key="l3b_B", target_url="http://shop.local")):
            pb = await bm.get_page()
            await pb.context.add_cookies([{
                "name": "JSESSIONID", "value": "USER_SESSION",
                "domain": "shop.local", "path": "/",
            }])

        a_jar = [c["value"] for c in await pa.context.cookies() if c["name"] == "JSESSIONID"]
        b_jar = [c["value"] for c in await pb.context.cookies() if c["name"] == "JSESSIONID"]
        distinct_pages = pa is not pb
        count = bm.active_session_count()
        return a_jar, b_jar, distinct_pages, count

    try:
        a_jar, b_jar, distinct, count = asyncio.run(scenario())
    finally:
        async def _cleanup():
            await bm.release_session("l3b_A")
            await bm.release_session("l3b_B")
            if bm._browser is not None:
                try:
                    await bm._browser.close()
                except Exception:
                    pass
                bm._browser = None
        try:
            asyncio.run(_cleanup())
        except Exception:
            pass

    assert distinct, "两个会话拿到同一个 page（未隔离）"
    assert a_jar == ["ADMIN_SESSION"], f"会话 A 的身份被覆盖: {a_jar}"
    assert b_jar == ["USER_SESSION"], f"会话 B 的身份被覆盖: {b_jar}"
    assert count >= 2, f"活跃 context 数异常: {count}"


def test_release_session_drops_context(monkeypatch):
    """释放后该会话的 context 应被移除（不泄漏）。"""
    pytest.importorskip("playwright")
    _fake_check_proxy(monkeypatch)

    import asyncio

    from core.session import cred_scope as cs
    from mcp_servers import browser_mcp as bm

    async def scenario():
        with cs.bind(cs.CredScope(session_key="l3b_R")):
            await bm.get_page()
            before = "l3b_R" in bm._pages
        released = await bm.release_session("l3b_R")
        return before, released, "l3b_R" in bm._pages

    try:
        before, released, after = asyncio.run(scenario())
    finally:
        async def _cleanup():
            if bm._browser is not None:
                try:
                    await bm._browser.close()
                except Exception:
                    pass
                bm._browser = None
        try:
            asyncio.run(_cleanup())
        except Exception:
            pass

    assert before, "未注册到 _pages"
    assert released, "release_session 未报告已释放"
    assert not after, "释放后仍在 _pages 中（泄漏）"
