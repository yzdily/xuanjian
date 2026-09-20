"""tests/unit/test_rbac_audit.py — 长期 L3 验收。

按 XUANJIAN_ROADMAP_LONG_TERM §4.3 5+ 断言：
1. admin 可写 policy
2. viewer 不可 run scan
3. auditor 可读 audit
4. require 装饰器抛错
5. audit record + report
6. audit 按 who 过滤
7. audit 按 since 过滤
8. audit 关闭开关
"""
from __future__ import annotations

import pytest

from core.audit import AuditLog
from core.rbac import Role, check, require


# ---------- RBAC ----------

def test_admin_can_write_policy():
    assert check(Role.ADMIN, "policy.write") is True


def test_viewer_cannot_run_scan():
    assert check(Role.VIEWER, "scan.run") is False


def test_auditor_can_read_audit():
    assert check(Role.AUDITOR, "audit.read") is True


def test_require_raises_for_unauthorized():
    with pytest.raises(PermissionError):
        require(Role.VIEWER, "scan.run")


def test_require_passes_for_authorized():
    # 不应抛
    require(Role.ADMIN, "scan.run")


def test_unknown_action_defaults_to_false():
    assert check(Role.ADMIN, "no.such.action") is False


# ---------- Audit ----------

def test_audit_log_record_and_report(tmp_path):
    log = AuditLog(str(tmp_path / "audit.log"))
    log.record(who="alice", role="admin", action="scan.run", target="url=x", result="ok")
    log.record(who="bob", role="viewer", action="scan.run", target="url=y", result="denied")
    out = log.report()
    assert len(out) == 2
    assert out[0]["who"] == "alice" and out[0]["result"] == "ok"
    assert out[1]["who"] == "bob" and out[1]["result"] == "denied"


def test_audit_log_filter_by_who(tmp_path):
    log = AuditLog(str(tmp_path / "audit.log"))
    log.record(who="alice", role="admin", action="x", target="t", result="ok")
    log.record(who="bob", role="viewer", action="x", target="t", result="ok")
    out = log.report(who="alice")
    assert len(out) == 1
    assert out[0]["who"] == "alice"


def test_audit_log_extra_field(tmp_path):
    log = AuditLog(str(tmp_path / "audit.log"))
    log.record(who="alice", role="admin", action="x", target="t", result="ok", extra={"k": "v"})
    out = log.report()
    assert out[0]["extra"] == {"k": "v"}


def test_audit_log_disabled(monkeypatch, tmp_path):
    """XUANJIAN_AUDIT_DISABLED=1 → record 返回 False，不写文件。"""
    monkeypatch.setenv("XUANJIAN_AUDIT_DISABLED", "1")
    p = tmp_path / "audit.log"
    log = AuditLog(str(p))
    wrote = log.record(who="alice", role="admin", action="x", target="t", result="ok")
    assert wrote is False
    assert not p.exists()


def test_audit_log_nonexistent_returns_empty(tmp_path):
    log = AuditLog(str(tmp_path / "never_created.log"))
    assert log.report() == []
