"""Web 层共享安全工具（单源）。

设计目标（对应 XUANJIAN_MASTER_PLAN §3.1 D9 S6 / S1 扩展）：

★ D9 S6 单源：所有 web 子模块统一从此处取「项目根目录」与「task_id 校验」，
   消除 reports_api / system_api / sessions_api 各自实现正则、各自
   ``Path(__file__)`` 解析的漂移。

★ S1 扩展：把原本仅 reports_api 单点实现的路径穿越防护，提升为 web 层共享能力，
   覆盖 system_api（``/api/scans/compare``）、sessions_api
   （``/api/sessions/switch``、``/api/sessions/{id}/history``）等所有直接把
   task_id / target_id 拼进文件路径（sitemap / chat 历史 / 报告）的端点。

★ 全局安全响应头：以最低成本给所有 HTTP 响应补上纵深防御头。
"""

from __future__ import annotations

import re

# ★ S1：task_id / target_id 统一白名单正则（仅字母、数字、下划线、连字符）。
# 不允许多点、斜杠、反斜杠、空白、shell 元字符 —— 这些都可能用于路径穿越或命令注入。
_TASK_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")

# ★ S6：web 包内「项目根目录 / web 目录」解析统一从 web._paths 单源取，
# 避免各模块各自 Path(__file__) 解析漂移（D9 S6）。re-export 保持向后兼容。
from web._paths import PROJECT_ROOT, WEB_ROOT  # noqa: F401


def validate_task_id(task_id: str) -> bool:
    """校验 task_id / target_id 是否安全（仅允许字母、数字、下划线、连字符）。

    用于任何会把标识符拼进文件路径（sitemap / chat 历史 / 报告）的端点之前，
    防止路径穿越（``../../etc/passwd``）与通配符注入。

    Args:
        task_id: 待校验的标识符（可能来自 URL path / query / JSON body）。

    Returns:
        True 表示安全可用；False 表示含非法字符，调用方应拒绝。
    """
    if not task_id or not isinstance(task_id, str):
        return False
    return bool(_TASK_ID_PATTERN.match(task_id))


# ★ 全局安全响应头（防御性纵深，最低成本覆盖所有响应）。
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # 本地自托管工具：仅允许同源资源；允许内联 script/style（前端 HTML 内联，
    # 不引入额外资源文件）；允许同源 ws/wss 以支持 SSE/实时通信。
    "Content-Security-Policy": (
        "default-src 'self'; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'"
    ),
}


def apply_security_headers(response) -> None:
    """为响应对象追加全局安全头（已存在的头不覆盖）。

    Args:
        response: Starlette/FastAPI Response 实例（需具备 ``.headers`` 字典）。
    """
    for key, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
