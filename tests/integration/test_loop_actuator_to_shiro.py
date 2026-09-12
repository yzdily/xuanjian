"""集成测试：Actuator → heapdump → Shiro RCE 全链 LOOP。

模拟 0902 jingtaituoming 实战场景：从 Actuator 暴露挖到 Shiro RCE 链。
"""
from __future__ import annotations

import asyncio

import pytest

from core.loops.loop_controller import LoopController, Finding
from core.loops.vuln_chain import VulnChainMemory
from core.framework_scan.framework_scan import FrameworkScanner
from core.framework_scan.shiro_detect import detect_shiro_rememberme
from core.framework_scan.heapdump_analyzer import download_and_analyze_heapdump
from core.session.hollowing import is_finding_hollowed


class TestActuatorToShiroChain:
    """模拟 actuator_exposure → heapdump → shiro RCE 全链。"""

    @pytest.mark.asyncio
    async def test_full_chain_executes(self):
        lc = LoopController(vuln_chain=VulnChainMemory())

        step_results = {
            "scan_all_actuator_endpoints": Finding(
                id="f_actuator",
                vuln_type="actuator_exposure",
                severity="Critical",
                detail={"endpoints": ["/actuator/env", "/actuator/heapdump"]},
                extracted_artifacts={"env_url": "/actuator/env", "heapdump_url": "/actuator/heapdump"},
            ),
            "extract_creds_from_env": Finding(
                id="f_env_creds",
                vuln_type="actuator_env_leak",
                severity="Critical",
                detail={"password": "admin123"},
                extracted_artifacts={"db_password": "admin123"},
            ),
            "heapdump_download_extract": Finding(
                id="f_heapdump",
                vuln_type="heapdump_leak",
                severity="Critical",
                detail={"cipherKey": "kPH+bIxk5D2deZiIxcaaaA=="},
                extracted_artifacts={"shiro_key": "kPH+bIxk5D2deZiIxcaaaA=="},
            ),
        }

        async def handler(step, context):
            step_name = step.get("step", "")
            return step_results.get(step_name)

        findings = await lc.execute("actuator_exposure", {}, step_handler=handler)

        # Should have 3 findings (one per step)
        assert len(findings) == 3
        assert findings[0].vuln_type == "actuator_exposure"
        assert findings[2].detail.get("cipherKey") == "kPH+bIxk5D2deZiIxcaaaA=="

        # depth_chain should be >= 3
        assert lc.chain.get_depth("actuator_exposure") >= 3

    @pytest.mark.asyncio
    async def test_chain_termination_on_unreachable(self):
        lc = LoopController(vuln_chain=VulnChainMemory())

        async def handler(step, context):
            step_name = step.get("step", "")
            if step_name == "scan_all_actuator_endpoints":
                context["heapdump_unreachable"] = True
                return Finding(id="f1", vuln_type="actuator_exposure")
            return None

        findings = await lc.execute("actuator_exposure", {}, step_handler=handler)
        # Should terminate after first step
        assert len(findings) == 1
        assert lc.chain.get_depth("actuator_exposure") == 1

    @pytest.mark.asyncio
    async def test_depth_gate_passes_after_chain(self):
        lc = LoopController(vuln_chain=VulnChainMemory())

        async def handler(step, context):
            return Finding(id="f1", vuln_type="actuator_exposure")

        await lc.execute("actuator_exposure", {}, step_handler=handler)

        # After running the chain, depth should be >= 1
        findings = [{"id": "f1", "vuln_type": "actuator_exposure"}]
        depth_map = {"actuator_exposure": lc.chain.get_depth("actuator_exposure")}
        violations = is_finding_hollowed(findings, depth_map)
        assert violations == []  # No violations since depth >= 1

    @pytest.mark.asyncio
    async def test_depth_gate_fails_without_chain(self):
        lc = LoopController(vuln_chain=VulnChainMemory())

        # Don't execute any chain
        findings = [{"id": "f1", "vuln_type": "actuator_exposure"}]
        depth_map = {"actuator_exposure": 0}
        violations = is_finding_hollowed(findings, depth_map)
        assert len(violations) >= 1
        assert "depth" in violations[0].lower()


class TestShiroDetectionChain:
    """Shiro 检测独立验证。"""

    def test_shiro_detect_without_request(self):
        result = detect_shiro_rememberme("http://localhost:8080")
        assert result["status"] == "inactive"

    def test_heapdump_analysis_with_mock(self):
        def mock_download(url):
            return b'cipherKey="kPH+bIxk5D2deZiIxcaaaA=="\npassword="admin123456"'
        result = download_and_analyze_heapdump(
            "http://localhost:8080/actuator",
            download_fn=mock_download,
        )
        assert result["status"] == "ok"
        types = [s["type"] for s in result["secrets"]]
        assert "shiro_key" in types
        assert "password" in types

    def test_framework_scanner_endpoints(self):
        scanner = FrameworkScanner()
        actuator_eps = scanner.endpoints_for("spring_boot_actuator")
        assert "/actuator/env" in actuator_eps
        assert "/actuator/heapdump" in actuator_eps
