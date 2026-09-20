r"""core.workspace — 目标工作区隔离（短期 S2）。

按 XUANJIAN_ROADMAP_SHORT_TERM §3.3 落地：
- tenant_root(tenant_id) -> data/tenants/{tid}/
- tenant_path(*parts, tenant_id) -> 拼子路径
- 默认从 XUANJIAN_TENANT env 读，否则 'default'
- 零外部依赖（仅 pathlib + os.environ）

回滚：XUANJIAN_LEGACY_PATHS=1 走旧 data/ 兼容 v1.6（保留接口，不删旧文件）。

摸底发现：v1.6 全仓 0 命中硬编码 data/output/audit / checklist.json / coverage_ledger.json 路径
（grep -rn 三个关键词 --include='*.py' -> 0 命中），
所以本模块不强制 patch 现有代码；新代码用 tenant_path，旧代码继续工作。
"""
from __future__ import annotations

import os
from pathlib import Path


def _resolve_tid(tenant_id: str | None) -> str:
    """解析 tenant_id：None/空 → env XUANJIAN_TENANT → 'default'。"""
    if tenant_id:
        return tenant_id
    return os.environ.get("XUANJIAN_TENANT") or "default"


def tenant_root(tenant_id: str | None = None) -> Path:
    """解析 tenant 根目录。None = 默认 tenant 'default'。

    回滚到旧路径：XUANJIAN_LEGACY_PATHS=1 时返回 Path('data')。
    """
    if os.environ.get("XUANJIAN_LEGACY_PATHS") == "1":
        return Path("data")
    root = Path(f"data/tenants/{_resolve_tid(tenant_id)}")
    root.mkdir(parents=True, exist_ok=True)
    return root


def tenant_path(*parts: str, tenant_id: str | None = None) -> Path:
    """拼出 tenant 内任意子路径。parts 用 POSIX 风格分隔，自动 Path 化。"""
    root = tenant_root(tenant_id)
    if not parts:
        return root
    joined = root
    for p in parts:
        joined = joined / p
    return joined


# 常用子路径便捷函数（短期 S2 验收点：每个 tenant 下结构清晰）


def audit_dir(tenant_id: str | None = None) -> Path:
    """audit 目录：data/tenants/{tid}/output/audit/。"""
    p = tenant_path("output", "audit", tenant_id=tenant_id)
    p.mkdir(parents=True, exist_ok=True)
    return p


def report_path(tenant_id: str | None = None) -> Path:
    """报告路径：data/tenants/{tid}/output/report.html。"""
    return tenant_path("output", "report.html", tenant_id=tenant_id)


def checklist_path(tenant_id: str | None = None) -> Path:
    """checklist 路径：data/tenants/{tid}/config/checklist.json。"""
    return tenant_path("config", "checklist.json", tenant_id=tenant_id)


def credentials_path(tenant_id: str | None = None) -> Path:
    """凭据路径：data/tenants/{tid}/config/auth_credentials.json。"""
    return tenant_path("config", "auth_credentials.json", tenant_id=tenant_id)


__all__ = [
    "tenant_root",
    "tenant_path",
    "audit_dir",
    "report_path",
    "checklist_path",
    "credentials_path",
]
