"""
Target MCP — 资产与授权范围管理

核心功能：check_scope — 在 SRC 场景下，
Agent 执行任何攻击前必须调用此函数确认目标在授权范围内。
"""

from __future__ import annotations

from urllib.parse import urlparse
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("target")

# 授权范围（运行时动态添加）
_in_scope: set[str] = set()       # 域名白名单
_out_of_scope: set[str] = set()   # 域名黑名单


@mcp.tool()
async def target_add_scope(domain: str) -> str:
    """将域名添加到授权测试范围。支持通配符如 *.example.com"""
    _in_scope.add(domain.lower().strip())
    return f"已添加到授权范围: {domain}"


@mcp.tool()
async def target_remove_scope(domain: str) -> str:
    """将域名从授权范围移除。"""
    _in_scope.discard(domain.lower().strip())
    _out_of_scope.add(domain.lower().strip())
    return f"已移出授权范围: {domain}"


@mcp.tool()
async def target_check_scope(url: str) -> str:
    """检查 URL 是否在授权测试范围内。

    ⚠️ 在 SRC 模式下，每次攻击前必须调用此函数。
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    host = host.lower()

    # 如果没设 scope，默认放行（非 SRC 场景）
    if not _in_scope:
        return f"✅ {url} — 未设置授权范围限制，默认允许"

    # 检查黑名单
    if host in _out_of_scope:
        return f"❌ {url} — 在排除列表中，禁止测试"

    # 检查白名单
    for scope in _in_scope:
        if scope.startswith("*."):
            # 通配符匹配
            base = scope[2:]
            if host == base or host.endswith("." + base):
                return f"✅ {url} — 在授权范围内 (匹配 {scope})"
        else:
            if host == scope:
                return f"✅ {url} — 在授权范围内"

    return f"❌ {url} — 不在授权范围内，禁止测试。当前范围: {', '.join(_in_scope)}"


@mcp.tool()
async def target_list_scope() -> str:
    """查看当前授权范围。"""
    if not _in_scope:
        return "未设置授权范围限制（所有目标默认允许）"
    lines = ["授权范围:"]
    for s in sorted(_in_scope):
        lines.append(f"  ✅ {s}")
    if _out_of_scope:
        lines.append("排除列表:")
        for s in sorted(_out_of_scope):
            lines.append(f"  ❌ {s}")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
