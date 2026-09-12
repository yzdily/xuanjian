"""mcp_servers.sqli_mcp — SQLi 扫描 MCP server（短期 S1）。

按 XUANJIAN_ROADMAP_SHORT_TERM §2.3 落地：
- 暴露 mcp__xuanjian__sqli_scan / sqli_verify
- MCP 层只做参数适配，不复制业务逻辑（业务在 core/fuzz/sqli.py）
- 缺 mcp 库时 degrade 成 stub（XUANJIAN_MCP_DISABLED=1 也会退化）
- 零额外依赖（仅 mcp 库已在 pyproject）

回滚：XUANJIAN_MCP_DISABLED=1 → module 退化为 stub，不注册 tools。
"""
from __future__ import annotations

import os

# 缺 mcp 库 / 总闸关 → stub 模式
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
    mcp = FastMCP("xuanjian-sqli")

    @mcp.tool()
    async def sqli_scan(url: str, method: str = "GET", mode: str = "fast") -> dict:
        """对 url 跑 SQLi 扫描（fast/standard/deep 三档）。"""
        # 业务委托到 core/fuzz/sqli.py（不在此层复制）
        try:
            from core.fuzz.sqli import scan_union, scan_boolean, scan_time
        except Exception as e:  # pragma: no cover
            return {"error": f"core.fuzz.sqli 不可用: {e}", "url": url}
        return {
            "union": scan_union(url, method=method, mode=mode),
            "boolean": scan_boolean(url, method=method, mode=mode),
            "time": scan_time(url, method=method, mode=mode),
        }

    @mcp.tool()
    async def sqli_verify(url: str, payload: str, variant: str) -> dict:
        """验证 SQLi 注入 + WAF 绕过是否生效（0827 E7 闭环）。"""
        try:
            from core.fuzz.verify_bypass import classify as classify_bypass
        except Exception as e:  # pragma: no cover
            return {"error": f"verify_bypass 不可用: {e}", "url": url, "variant": variant}
        return classify_bypass(url=url, payload=payload, variant=variant)

    app = mcp  # 别名（测试用 hasattr(mcp, "app") 兼容）
else:
    # stub 模式：只暴露同名函数，调用即 raise
    async def sqli_scan(*args, **kwargs):  # pragma: no cover
        raise RuntimeError("mcp 库缺失或 XUANJIAN_MCP_DISABLED=1；sqli_scan 不可用")

    async def sqli_verify(*args, **kwargs):  # pragma: no cover
        raise RuntimeError("mcp 库缺失或 XUANJIAN_MCP_DISABLED=1；sqli_verify 不可用")

    app = None
