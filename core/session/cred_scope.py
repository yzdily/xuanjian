"""会话级凭证作用域（阶段 4-E1 凭证隔离）。

## 为什么需要

凭证原先走**进程级** ``os.environ``：注入点 ``chat_loop.py:700-702`` 在写入本会话凭证前会
``pop`` 掉全部 5 个注入键，于是并行的另一个会话一旦注入，就把前一个会话的凭证**彻底清除**
（不是覆盖，是清空）。实测复现见 ``_e1_repro_crosstalk.py``：

    会话 A 注入 sid=SESSION_A_SECRET → B 注入后 A 再读 → 拿到 token=TOKEN_B_SECRET

后果是 M3（跨目标凭证污染）非 0，**越权/鉴权类测试结论不可信**。

## 做法

用 ``contextvars`` 把凭证绑定到「会话所在的 asyncio task」。同一 task 及其**之后创建**的
子 task 可见；不同会话各自的 task 天然隔离。

可行性已实测（``_e1_contextvar_feasibility.py`` 6/6 通过），三条前提：

1. **必须先 set_scope 再 create_task** —— 子 task 复制的是**创建时**的 context 快照，
   先建 task 后 set 的话子 task 读到空值。
2. **并行会话必须各自独立 asyncio task** —— 同一 task 内顺序 set 会互相覆盖。
   已核实 ``web/server.py:738`` 是 ``asyncio.create_task(producer())``，注释明确「session 级」。
3. **跨进程不生效** —— 当前 ``browser_mcp`` / ``proxy_mcp`` 均为同进程 ``from mcp_servers import ...``，
   无此风险；若日后改为 MCP 子进程，需另走显式传参。

## 迁移期策略

- **写入侧**：只写 contextvar，**不再写 os.environ**（这是消除 L1 串扰的关键）。
- **读取侧**：优先 contextvar，未设置时**只读回退** env —— 兼容进程外调用（CLI 直接设 env）
  与尚未迁移的调用点。
- 开关 ``XJ_CRED_CONTEXTVAR=0`` 可整体回退到旧的 env 行为（灰度/回滚）。
"""

from __future__ import annotations

import contextvars
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import Iterator

log_prefix = "[cred_scope]"

#: 进程级注入键（迁移期仅用于「读取回退」与「清理遗留值」）
ENV_KEYS = (
    "PENTEST_INJECT_COOKIES",
    "PENTEST_INJECT_AUTH",
    "PENTEST_INJECT_HEADERS",
    "PENTEST_INJECT_LOCAL_STORAGE",
    "PENTEST_TARGET_URL",
)

#: 凭证来源（供 D3 CredScope 前端显示：手动挂载 / 自动登录回写 / 预设）
SOURCE_MANUAL = "manual"
SOURCE_AUTO_LOGIN = "auto_login"
SOURCE_PRESET = "preset"


def enabled() -> bool:
    """迁移期总开关：``XJ_CRED_CONTEXTVAR=0`` 时整体回退旧 env 行为。"""
    return os.getenv("XJ_CRED_CONTEXTVAR", "1") != "0"


@dataclass(frozen=True)
class CredScope:
    """一个会话的凭证集合（不可变；更新用 :func:`update_scope`）。"""

    cookies: str = ""
    auth: str = ""
    headers: dict = field(default_factory=dict)
    local_storage: dict = field(default_factory=dict)
    target_url: str = ""
    source: str = SOURCE_MANUAL
    #: 会话标识（task_id）。阶段 4-E1 · 方案 C 用它把**浏览器 context** 也按会话隔离 ——
    #: 凭证隔离了但浏览器 cookie jar 共享的话，同域同名 cookie 仍会互相覆盖（L3b）。
    session_key: str = ""

    @property
    def is_empty(self) -> bool:
        return not (self.cookies or self.auth or self.headers or self.local_storage)

    def mask(self) -> dict:
        """脱敏摘要（供日志 / SSE / 前端徽标；**绝不含明文凭证**）。"""
        return {
            "has_cookies": bool(self.cookies),
            "cookie_len": len(self.cookies),
            "has_auth": bool(self.auth),
            "header_names": sorted(self.headers.keys()),
            "local_storage_keys": sorted(self.local_storage.keys()),
            "target_url": self.target_url,
            "source": self.source,
        }


#: 当前会话凭证。``None`` = 未设置（读取时回退 env）
_scope: contextvars.ContextVar[CredScope] = contextvars.ContextVar("xj_cred_scope", default=None)


# --------------------------------------------------------------------- 写

def set_scope(scope: CredScope) -> contextvars.Token:
    """设置当前 task 的凭证作用域，返回 token 供 :func:`reset_scope` 还原。"""
    return _scope.set(scope)


def reset_scope(token: contextvars.Token) -> None:
    _scope.reset(token)


def update_scope(**changes) -> CredScope:
    """在当前 task 的 scope 上增量更新（如登录后回写 cookie），返回新 scope。

    未设置 scope 时以 env 回退值作基线，保证老调用点平滑迁移。
    """
    base = get_scope()
    new = replace(base, **changes)
    _scope.set(new)
    return new


@contextmanager
def bind(scope: CredScope) -> Iterator[CredScope]:
    """在 with 块内绑定凭证，退出自动还原（用于测试与一次性任务）。"""
    token = set_scope(scope)
    try:
        yield scope
    finally:
        reset_scope(token)


# --------------------------------------------------------------------- 读

def _scope_from_env() -> CredScope:
    """从进程级 env 构造（迁移期只读回退，兼容 CLI / 未迁移调用点）。"""
    headers: dict = {}
    raw_headers = os.getenv("PENTEST_INJECT_HEADERS", "")
    if raw_headers:
        try:
            parsed = json.loads(raw_headers)
            if isinstance(parsed, dict):
                headers = parsed
        except (ValueError, TypeError):
            pass

    local_storage: dict = {}
    raw_ls = os.getenv("PENTEST_INJECT_LOCAL_STORAGE", "")
    if raw_ls:
        try:
            parsed_ls = json.loads(raw_ls)
            if isinstance(parsed_ls, dict):
                local_storage = parsed_ls
        except (ValueError, TypeError):
            pass

    return CredScope(
        cookies=os.getenv("PENTEST_INJECT_COOKIES", ""),
        auth=os.getenv("PENTEST_INJECT_AUTH", ""),
        headers=headers,
        local_storage=local_storage,
        target_url=os.getenv("PENTEST_TARGET_URL", ""),
        source=SOURCE_PRESET,
    )


def get_scope() -> CredScope:
    """取当前会话凭证：优先 contextvar，未设置则**只读回退** env。"""
    if not enabled():
        return _scope_from_env()
    current = _scope.get()
    if current is not None:
        return current
    return _scope_from_env()


def has_scope() -> bool:
    """当前 task 是否显式绑定过 scope（区分「已绑定空凭证」与「未绑定」）。"""
    return _scope.get() is not None


def current_cookies() -> str:
    return get_scope().cookies


def current_auth() -> str:
    return get_scope().auth


def current_headers() -> dict:
    return dict(get_scope().headers)


def current_local_storage() -> dict:
    return dict(get_scope().local_storage)


def current_target_url() -> str:
    return get_scope().target_url


def current_session_key() -> str:
    """当前会话标识（task_id）。

    供浏览器层做 context 隔离（方案 C）。未绑定作用域时返回空串 ——
    调用方应把它当作"默认会话"处理，保持向后兼容（CLI / 单会话场景）。
    """
    return get_scope().session_key


def has_credentials() -> bool:
    s = get_scope()
    return bool(s.cookies or s.auth)


# --------------------------------------------------------------------- 维护

def clear_env_injections() -> list[str]:
    """清空进程级注入键，返回实际被清理的键名。

    **仅在迁移期清理历史遗留值 / 测试隔离时使用** —— 常规写入路径只写 contextvar，
    不再写 env（这正是消除 L1 串扰的关键）。
    """
    cleared = []
    for k in ENV_KEYS:
        if os.environ.pop(k, None) is not None:
            cleared.append(k)
    return cleared


# --------------------------------------------------------------------- 兼容

def legacy_env_fingerprint(scope: CredScope | None = None) -> str:
    """凭证指纹。

    ``browser_mcp._current_injection_fingerprint()`` 原先直接读 5 个 env 键；
    迁移后 env 不再被写入，改为基于 scope 计算，保持「凭证变化才重新注入」的语义。
    """
    s = scope if scope is not None else get_scope()
    return "\n".join((
        f"cookies={s.cookies}",
        f"auth={s.auth}",
        f"headers={json.dumps(s.headers, sort_keys=True, ensure_ascii=False)}",
        f"ls={json.dumps(s.local_storage, sort_keys=True, ensure_ascii=False)}",
        f"target={s.target_url}",
    ))
