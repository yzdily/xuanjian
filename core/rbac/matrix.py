"""core.rbac.matrix — 4 角色 + 权限矩阵（长期 L3）。

按 XUANJIAN_ROADMAP_LONG_TERM §4.3 落地：
- admin: 全权（含 policy.write / audit.read）
- operator: 跑扫描 + 看结果，不可写策略
- viewer: 只读（report.read）
- auditor: 只读 + 审计日志

零外部依赖。

★ 命名约束：本模块不得放回 core/auth/。
  core.auth 是「认证」模块（token 登录），core.rbac 是「授权」模块（角色权限）。
  同名包会遮蔽 core/auth.py，导致 verify_token 不可用、全站 500（2026-08-28 事故）。
"""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    """4 角色。"""

    ADMIN = "admin"        # 全权
    OPERATOR = "operator"  # 跑扫描 + 看结果
    VIEWER = "viewer"      # 只读
    AUDITOR = "auditor"    # 只读 + 审计日志


# 权限矩阵：(role, action) -> allowed
PERMISSIONS: dict[tuple[str, str], bool] = {
    # admin: 全开
    ("admin", "scan.run"): True,
    ("admin", "scan.config"): True,
    ("admin", "report.read"): True,
    ("admin", "report.export"): True,
    ("admin", "policy.write"): True,
    ("admin", "audit.read"): True,
    # operator: 不能写策略
    ("operator", "scan.run"): True,
    ("operator", "scan.config"): True,
    ("operator", "report.read"): True,
    ("operator", "report.export"): True,
    ("operator", "policy.write"): False,
    ("operator", "audit.read"): False,
    # viewer: 只读
    ("viewer", "scan.run"): False,
    ("viewer", "scan.config"): False,
    ("viewer", "report.read"): True,
    ("viewer", "report.export"): False,
    ("viewer", "policy.write"): False,
    ("viewer", "audit.read"): False,
    # auditor: 只读 + 审计
    ("auditor", "scan.run"): False,
    ("auditor", "scan.config"): False,
    ("auditor", "report.read"): True,
    ("auditor", "report.export"): True,
    ("auditor", "policy.write"): False,
    ("auditor", "audit.read"): True,
}


def check(role: Role, action: str) -> bool:
    """单点权限校验。"""
    return PERMISSIONS.get((role.value, action), False)


def require(role: Role, action: str) -> None:
    """未授权抛 PermissionError。"""
    if not check(role, action):
        raise PermissionError(f"角色 {role.value} 无权执行 {action}")


__all__ = ["Role", "PERMISSIONS", "check", "require"]
