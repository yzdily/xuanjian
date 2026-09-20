"""回归锁：防止 core/auth.py（认证）被同名包遮蔽。

背景（2026-08-28 事故）：新增 RBAC 时建了 `core/auth/` 包，与既有的
`core/auth.py` 同名。Python 的导入器中「包优先于模块」，于是
`from core import auth` 拿到的是 RBAC 包，`verify_token` / `init_default_user`
全部缺失 —— Web 层所有 /api/* 返回 500，表现为"扫描跑不起来"。

修复：RBAC 迁至 `core/rbac/`，认证仍是 `core/auth.py`。本文件把这条边界钉死。

零外部依赖，无网络 / 无 IO。
"""
from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize(
    "attr",
    ["verify_token", "login", "register", "get_user", "init_default_user"],
)
def test_core_auth_exposes_authentication_api(attr):
    """core.auth 必须解析到认证模块并暴露完整鉴权面。"""
    auth = importlib.import_module("core.auth")
    assert hasattr(auth, attr), (
        f"core.auth 缺少 {attr}：多半又被同名包 core/auth/ 遮蔽了，"
        f"当前解析到 {getattr(auth, '__file__', None)}"
    )


def test_core_auth_resolves_to_module_not_package():
    """core.auth 必须是 auth.py 模块，不能是 core/auth/__init__.py。"""
    auth = importlib.import_module("core.auth")
    assert auth.__file__.replace("\\", "/").endswith("core/auth.py"), (
        f"core.auth 解析到了 {auth.__file__}，期望 core/auth.py"
    )


def test_core_rbac_resolves_to_package():
    """core.rbac 必须可用，且与 core.auth 是两个不同的模块对象。"""
    auth = importlib.import_module("core.auth")
    rbac = importlib.import_module("core.rbac")
    assert auth is not rbac
    assert hasattr(rbac, "Role") and hasattr(rbac, "check") and hasattr(rbac, "require")


def test_no_auth_directory_alongside_auth_module():
    """core/ 下不得同时存在 auth.py 与 auth/ 目录。"""
    from pathlib import Path

    core_dir = Path(importlib.import_module("core").__path__[0])
    assert not (core_dir / "auth").is_dir(), (
        "core/auth/ 目录与 core/auth.py 同名，会遮蔽认证模块"
    )


# 「掏空拆分」遗留的有意遮蔽：包 __init__ 已完整 re-export 原模块公开面，
# 属设计内兼容壳。新增任何条目都必须确认包 __init__ 做了等价 re-export，
# 否则就是下一个 core/auth/ 事故。
ALLOWED_SHADOWED = {
    "browse_worker",
    "dir_scanner",
    "fast_scanner",
    "js_analyzer",
    "llm",
    "supplemental_test_agent",
    "worker_agent",
}


def test_no_new_module_shadowing():
    """除白名单外，core/web 下不得再出现「同名包遮蔽同名模块」。"""
    from pathlib import Path

    found = set()
    for root_name in ("core", "web"):
        root = Path(importlib.import_module(root_name).__path__[0])
        for d in root.rglob("*"):
            if d.is_dir() and (d / "__init__.py").exists() and d.with_suffix(".py").exists():
                found.add(d.relative_to(root).as_posix())

    unexpected = found - ALLOWED_SHADOWED
    assert not unexpected, (
        f"发现未登记的模块遮蔽：{sorted(unexpected)}。"
        f"若属有意拆分，请确认包 __init__ 完整 re-export 后加入 ALLOWED_SHADOWED"
    )
