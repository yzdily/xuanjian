"""cli.doctor — 启动前自检（短期 S4）。

按 XUANJIAN_ROADMAP_SHORT_TERM §5.3 落地：
- 8 项独立 check 装饰器收集
- 失败给可执行修复建议
- 全绿退出码 0，失败 1
- 零外部依赖（仅 stdlib：socket/pathlib/os/importlib）

回滚：`XUANJIAN_DOCTOR_SKIP=1` 跳过特定项（不推荐）。
"""
from __future__ import annotations

import importlib
import os
import socket
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 检查项收集（装饰器模式，每项独立可测）
# ---------------------------------------------------------------------------

CHECKS: list = []  # type: ignore[type-arg]


def check(fn):
    """收集 check 函数到 CHECKS 列表。fn 签名: () -> (ok: bool, msg: str)。"""
    CHECKS.append(fn)
    return fn


# ---------------------------------------------------------------------------
# 8 项 check
# ---------------------------------------------------------------------------


@check
def python_version() -> tuple[bool, str]:
    """Python 版本 ≥ 3.11。"""
    need = (3, 11)
    cur = sys.version_info[:2]
    ok = cur >= need
    return ok, f"Python {'.'.join(map(str, cur))}（需要 ≥{'.'.join(map(str, need))}）"


@check
def mitmproxy_port() -> tuple[bool, str]:
    """mitmproxy 默认端口 8080 空闲。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", 8080))
        s.close()
        return True, "端口 8080 空闲"
    except OSError as e:
        return False, f"端口 8080 被占用（运行 `lsof -i :8080` 查进程；err={e.strerror or e}）"


@check
def data_dir_writable() -> tuple[bool, str]:
    """data/ 目录可写。"""
    p = Path("data")
    try:
        p.mkdir(exist_ok=True)
        probe = p / ".doctor_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True, "data/ 目录可写"
    except OSError as e:
        return False, f"data/ 不可写：{e}"


@check
def tenant_dir_writable() -> tuple[bool, str]:
    """当前 tenant 目录可写（S2 工作区前置）。"""
    tid = os.environ.get("XUANJIAN_TENANT", "default")
    p = Path(f"data/tenants/{tid}")
    try:
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".doctor_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True, f"tenant[{tid}] 目录可写"
    except OSError as e:
        return False, f"tenant[{tid}] 目录不可写：{e}"


@check
def llm_api_key() -> tuple[bool, str]:
    """LLM API key 已设置（DEEP 模式必需）。"""
    key = os.environ.get("XUANJIAN_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    return (bool(key), "LLM API key 已设置" if key else "缺 XUANJIAN_LLM_API_KEY（DEEP 模式必需）")


@check
def core_modules() -> tuple[bool, str]:
    """核心模块可 import。"""
    mods = [
        "core.context",
        "core.parallel.orchestrator",
        "core.session.report_mixin",
        "core.workspace",  # 短期 S2 新建
    ]
    miss = [m for m in mods if not _can_import(m)]
    return (not miss, ("全部核心模块可 import" if not miss else f"缺: {miss}"))


@check
def mcp_registry() -> tuple[bool, str]:
    """MCP 注册表存在（短期 S1 配套）。"""
    p = Path("mcp_servers/REGISTRY.md")
    return (p.exists(), "MCP 注册表存在" if p.exists() else "缺 mcp_servers/REGISTRY.md（短期 S1 未完成）")


@check
def auth_total_switch() -> tuple[bool, str]:
    """v1.6 O2 总闸可读性自检：开总闸时 ⚠️ 告警。"""
    v = os.environ.get("XUANJIAN_AUTH_DISABLED", "0")
    if v == "1":
        return True, "⚠️  XUANJIAN_AUTH_DISABLED=1（总闸已开，所有请求走匿名）"
    return True, "认证总闸关闭（默认）"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _can_import(mod: str) -> bool:
    try:
        importlib.import_module(mod)
        return True
    except Exception:
        return False


def run_doctor() -> int:
    """执行所有 check；返回 0=全绿 1=有失败。"""
    print("== xuanjian doctor ==\n")
    fail = 0
    for fn in CHECKS:
        try:
            ok, msg = fn()
        except Exception as e:  # 单项 check 自身抛错也算失败
            ok, msg = False, f"check 自身异常: {e}"
        icon = "OK " if ok else "FAIL"
        print(f"  [{icon}] {fn.__name__}: {msg}")
        if not ok:
            fail += 1
    print(f"\n总结: {len(CHECKS) - fail}/{len(CHECKS)} 项通过")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(run_doctor())
