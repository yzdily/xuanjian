"""F4 LOOP 引擎单元测试。"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml

from core.loops.loop_controller import LoopController, Finding
from core.loops.vuln_chain import VulnChainMemory


class TestLoopMatrixYaml:
    """F4.1: loop_matrix.yaml schema 校验。"""

    def test_yaml_loads(self):
        path = Path(__file__).parent.parent.parent / "core" / "loops" / "loop_matrix.yaml"
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        assert "loops" in raw
        assert len(raw["loops"]) >= 10

    def test_each_loop_has_required_fields(self):
        path = Path(__file__).parent.parent.parent / "core" / "loops" / "loop_matrix.yaml"
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        for entry in raw["loops"]:
            assert "trigger" in entry, f"missing trigger: {entry}"
            assert "depth_chain" in entry, f"missing depth_chain: {entry.get('trigger')}"
            assert "termination" in entry, f"missing termination: {entry.get('trigger')}"
            assert len(entry["depth_chain"]) >= 1, f"empty depth_chain: {entry['trigger']}"

    def test_waf_bypass_primitives_loads(self):
        path = Path(__file__).parent.parent.parent / "core" / "loops" / "waf_bypass_primitives.yaml"
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        assert "sql_injection_primitives" in raw
        assert len(raw["sql_injection_primitives"]) >= 5
        assert "xss_primitives" in raw
        assert "command_injection_primitives" in raw


class TestLoopController:
    """F4.3: LoopController 引擎。"""

    def test_init_loads_matrix(self):
        lc = LoopController()
        assert lc.has_trigger("actuator_exposure")
        assert lc.has_trigger("shiro_remmeberme_active")
        assert lc.has_trigger("sqli_possible")
        assert not lc.has_trigger("nonexistent_trigger")

    def test_get_trigger_returns_def(self):
        lc = LoopController()
        trigger = lc.get_trigger("actuator_exposure")
        assert trigger is not None
        assert "depth_chain" in trigger
        assert "termination" in trigger

    @pytest.mark.asyncio
    async def test_execute_without_handler_records_chain(self):
        lc = LoopController(vuln_chain=VulnChainMemory())
        findings = await lc.execute("actuator_exposure", {})
        assert len(findings) == 0
        assert lc.chain.get_depth("actuator_exposure") >= 1

    @pytest.mark.asyncio
    async def test_execute_termination_stops_chain(self):
        lc = LoopController(vuln_chain=VulnChainMemory())
        # heapdump_unreachable 终止条件命中
        findings = await lc.execute(
            "actuator_exposure",
            {"heapdump_unreachable": True},
        )
        assert len(findings) == 0
        # chain 应该在第一步就 break

    @pytest.mark.asyncio
    async def test_execute_with_step_handler(self):
        lc = LoopController(vuln_chain=VulnChainMemory())

        async def handler(step, context):
            step_name = step.get("step", "")
            return Finding(
                id=f"f_{step_name}",
                vuln_type="actuator_exposure",
                detail={"step": step_name},
                extracted_artifacts={"secret": "found"},
            )

        findings = await lc.execute("actuator_exposure", {}, step_handler=handler)
        assert len(findings) >= 1
        assert findings[0].vuln_type == "actuator_exposure"
        assert lc.chain.get_depth("actuator_exposure") >= 1


class TestVulnChainMemory:
    """F8: VulnChainMemory。"""

    def test_append_and_depth(self):
        chain = VulnChainMemory()
        chain.append("actuator_exposure", "scan_all", {"finding_id": "f1"})
        chain.append("actuator_exposure", "extract_creds", {"finding_id": "f2"})
        assert chain.get_depth("actuator_exposure") == 2

    def test_get_chain(self):
        chain = VulnChainMemory()
        chain.append("shiro_remmeberme_active", "detect", {})
        steps = chain.get_chain("shiro_remmeberme_active")
        assert len(steps) == 1
        assert steps[0].step == "detect"

    def test_nonexistent_trigger_depth_zero(self):
        chain = VulnChainMemory()
        assert chain.get_depth("nonexistent") == 0
