"""tests/unit/test_workspace.py — 短期 S2 验收。

按 XUANJIAN_ROADMAP_SHORT_TERM §3.3 3 断言：
1. 默认 tenant 在 env 未设时 = default
2. 自定义 tenant 从 env 读取
3. 两个 tenant 路径不串
"""
from __future__ import annotations

import pathlib

import pytest

from core.workspace import (
    audit_dir,
    checklist_path,
    credentials_path,
    report_path,
    tenant_path,
    tenant_root,
)


def test_default_tenant_when_unset(tmp_path, monkeypatch):
    """env XUANJIAN_TENANT 未设时，默认 'default'。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("XUANJIAN_TENANT", raising=False)
    p = tenant_root()
    assert p == pathlib.Path("data/tenants/default")
    assert p.exists(), "tenant_root 应自动 mkdir"


def test_custom_tenant_from_env(tmp_path, monkeypatch):
    """env XUANJIAN_TENANT=client_acme → 拼出 client_acme 子路径。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XUANJIAN_TENANT", "client_acme")
    p = tenant_path("config", "checklist.json")
    assert "client_acme" in str(p)
    assert p.name == "checklist.json"


def test_two_tenants_isolated(tmp_path, monkeypatch):
    """两个 tenant 写同一相对路径 → 落到不同物理位置。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XUANJIAN_TENANT", "t1")
    p1 = tenant_path("output", "audit", "ledger.json")
    p1.parent.mkdir(parents=True, exist_ok=True)
    p1.write_text("{}", encoding="utf-8")

    monkeypatch.setenv("XUANJIAN_TENANT", "t2")
    p2 = tenant_path("output", "audit", "ledger.json")
    assert not p2.exists(), "t2 路径不应被 t1 占用"
    assert p1.exists(), "t1 文件应仍在"
    assert p1 != p2


def test_explicit_tenant_id_overrides_env(tmp_path, monkeypatch):
    """显式传 tenant_id 覆盖 env。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XUANJIAN_TENANT", "from_env")
    p = tenant_root(tenant_id="explicit")
    assert "explicit" in str(p)
    assert "from_env" not in str(p)


def test_convenience_helpers(tmp_path, monkeypatch):
    """audit_dir / report_path / checklist_path / credentials_path 4 个便捷函数。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XUANJIAN_TENANT", "acme")
    a = audit_dir()
    assert a.exists()
    assert a.name == "audit"
    r = report_path()
    assert r.name == "report.html"
    c = checklist_path()
    assert c.name == "checklist.json"
    cr = credentials_path()
    assert cr.name == "auth_credentials.json"
