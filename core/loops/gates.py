"""F8 — GATE-2.5 depth_chain 审计。

对每个框架级漏洞，要求 depth_chain 长度 ≥ 1。
违规时返回违规列表，由 chat_loop 通过 SSE 推送 STEER_REQ。
"""
from __future__ import annotations

from typing import Any

from core.loops.vuln_chain import VulnChainMemory

FRAMEWORK_TRIGGERS = frozenset({
    "actuator_exposure",
    "shiro_remmeberme_active",
    "heapdump_leak",
    "param_config_leak",
    "actuator_env_leak",
    "path_normalization_bypass",
})


def gate_2_5_depth_check(
    findings: list[Any], chain: VulnChainMemory,
) -> list[str]:
    """对每个框架级漏洞，要求 depth_chain 长度 ≥ 1。

    返回违规消息列表；空列表表示全部通过。
    """
    violations: list[str] = []
    for f in findings:
        vuln_type = getattr(f, "vuln_type", None) or (f.get("vuln_type") if isinstance(f, dict) else None)
        if vuln_type in FRAMEWORK_TRIGGERS:
            depth = chain.get_depth(vuln_type)
            if depth < 1:
                finding_id = getattr(f, "id", None) or (f.get("id") if isinstance(f, dict) else "?")
                violations.append(
                    f"GATE-2.5 违反: {finding_id} ({vuln_type}) "
                    f"depth={depth}，必须补测下游路径"
                )
    return violations


__all__ = ["gate_2_5_depth_check", "FRAMEWORK_TRIGGERS"]
