"""core.rbac — 授权（RBAC 角色/权限矩阵，长期 L3）。

职责边界：
- core.auth  = 认证（authentication）：登录、注册、token 签发与校验
- core.rbac  = 授权（authorization）：角色定义、权限矩阵判定

★ 两者必须分名存放。历史上本包曾叫 core/auth/，与认证模块 core/auth.py
  同名，Python 包优先于模块导致认证被完全遮蔽，全站 /api/* 返回 500
  （2026-08-28）。新增代码请勿再建 core/auth/ 目录。
"""
from __future__ import annotations

from core.rbac.matrix import PERMISSIONS, Role, check, require

__all__ = ["Role", "PERMISSIONS", "check", "require"]
