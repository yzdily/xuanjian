"""mcp_servers.bola_mcp — BOLA/IDOR MCP server（短期 S1）。

按 XUANJIAN_ROADMAP_SHORT_TERM §2.3 落地：
- 暴露 mcp__xuanjian__bola_probe / bola_sequence
- 业务委托 core/authz/bola_probe.py
- 缺 mcp 库时 degrade 成 stub
- 零额外依赖

回滚：XUANJIAN_MCP_DISABLED=1 → stub。
"""
from __future__ import annotations

import os

_MCP_DISABLED = os.environ.get("XUANJIAN_MCP_DISABLED") == "1"

try:
    if _MCP_DISABLED:
        raise ImportError("XUANJIAN_MCP_DISABLED=1")
    from mcp.server.fastmcp import FastMCP
    _HAS_MCP = True
except ImportError:
    FastMCP = None  # type: ignore[assignment]
    _HAS_MCP = False


if _HAS_MCP:
    mcp = FastMCP("xuanjian-bola")

    @mcp.tool()
    async def bola_probe(
        resource_id: str,
        cred_a: dict,
        cred_b: dict,
        fetch_url: str,
    ) -> dict:
        """身份 A 取资源 → 身份 B 用同 ID 取，判定 BOLA。"""
        try:
            from core.authz.bola_probe import cross_identity_get
        except Exception as e:  # pragma: no cover
            return {"error": f"core.authz.bola_probe 不可用: {e}", "resource_id": resource_id}
        # 真实 fetch 由调用方注入（避免 mcp 层耦合 httpx/requests）
        async def _stub_fetch(url, rid, auth):
            return {"url": url, "rid": rid, "auth_owner": auth.get("owner", "?")}

        return await cross_identity_get(
            fetch=_stub_fetch,
            resource_id=resource_id,
            cred_a=cred_a,
            cred_b=cred_b,
            base_url=fetch_url,
        )

    @mcp.tool()
    async def bola_sequence(base_id: int, spans: list[int] | None = None) -> list[int]:
        """生成 ±N 遍历序列。默认 spans = [1, 100, 1000]。"""
        try:
            from core.authz.bola_probe import id_sequence
        except Exception as e:  # pragma: no cover
            return [base_id]
        return id_sequence(base_id, spans=tuple(spans) if spans else (1, 100, 1000))

    app = mcp
else:
    async def bola_probe(*args, **kwargs):  # pragma: no cover
        raise RuntimeError("mcp 库缺失或 XUANJIAN_MCP_DISABLED=1；bola_probe 不可用")

    async def bola_sequence(*args, **kwargs):  # pragma: no cover
        raise RuntimeError("mcp 库缺失或 XUANJIAN_MCP_DISABLED=1；bola_sequence 不可用")

    app = None
