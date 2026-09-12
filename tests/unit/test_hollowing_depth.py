"""F8 depth_chain 强制 + 空心化检测单元测试。"""
from __future__ import annotations

from core.session.hollowing import (
    is_hollowed, is_finding_hollowed, FRAMEWORK_TRIGGERS,
)
from core.loops.gates import gate_2_5_depth_check, FRAMEWORK_TRIGGERS as GATE_TRIGGERS
from core.loops.vuln_chain import VulnChainMemory


class TestIsHollowed:
    def test_hollowed_skip_heavy(self):
        assert is_hollowed(real_rate=5.0, skip_rate=80.0, pending_rate=10.0, vuln_count=0, total=100)

    def test_hollowed_pending_heavy(self):
        assert is_hollowed(real_rate=3.0, skip_rate=10.0, pending_rate=75.0, vuln_count=0, total=100)

    def test_not_hollowed_with_vulns(self):
        assert not is_hollowed(real_rate=5.0, skip_rate=80.0, pending_rate=10.0, vuln_count=5, total=100)

    def test_not_hollowed_no_data(self):
        assert not is_hollowed(real_rate=0, skip_rate=0, pending_rate=0, vuln_count=0, total=0)

    def test_not_hollowed_normal(self):
        assert not is_hollowed(real_rate=80.0, skip_rate=10.0, pending_rate=10.0, vuln_count=3, total=100)


class TestIsFindingHollowed:
    def test_framework_finding_no_depth_violates(self):
        findings = [{"id": "f1", "vuln_type": "actuator_exposure"}]
        depth_map = {"actuator_exposure": 0}
        violations = is_finding_hollowed(findings, depth_map)
        assert len(violations) == 1
        assert "actuator_exposure" in violations[0]

    def test_framework_finding_with_depth_passes(self):
        findings = [{"id": "f1", "vuln_type": "actuator_exposure"}]
        depth_map = {"actuator_exposure": 2}
        violations = is_finding_hollowed(findings, depth_map)
        assert violations == []

    def test_non_framework_finding_no_check(self):
        findings = [{"id": "f1", "vuln_type": "sqli"}]
        depth_map = {"sqli": 0}
        violations = is_finding_hollowed(findings, depth_map)
        assert violations == []

    def test_no_depth_map_no_violations(self):
        findings = [{"id": "f1", "vuln_type": "actuator_exposure"}]
        violations = is_finding_hollowed(findings, None)
        assert violations == []


class TestGate25DepthCheck:
    def test_framework_trigger_triggers_gate(self):
        chain = VulnChainMemory()
        findings = [{"id": "f1", "vuln_type": "actuator_exposure"}]
        violations = gate_2_5_depth_check(findings, chain)
        assert len(violations) >= 1
        assert "GATE-2.5" in violations[0]

    def test_framework_trigger_with_depth_passes(self):
        chain = VulnChainMemory()
        chain.append("actuator_exposure", "scan", {"id": "f1"})
        findings = [{"id": "f1", "vuln_type": "actuator_exposure"}]
        violations = gate_2_5_depth_check(findings, chain)
        assert violations == []

    def test_non_framework_finding_no_gate(self):
        chain = VulnChainMemory()
        findings = [{"id": "f1", "vuln_type": "sqli_possible"}]
        violations = gate_2_5_depth_check(findings, chain)
        assert violations == []

    def test_triggers_match_between_modules(self):
        assert FRAMEWORK_TRIGGERS == GATE_TRIGGERS
