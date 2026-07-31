"""
Note MCP — 笔记三件套 (info / infer / result)

- info: 资产信息（URL、API、技术栈、Cookie 结构）
- infer: 推理分析（"这个 user_id 可能有越权"）
- result: 漏洞确认（含复现步骤，可直接转报告）
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("note")

NOTE_DIR = Path(os.getenv("NOTE_PATH", "./data/notes"))
NOTE_DIR.mkdir(parents=True, exist_ok=True)


def _get_task_file(note_type: str, task_id: str = "default") -> Path:
    return NOTE_DIR / f"{task_id}-{note_type}.md"


@mcp.tool()
async def note_add(type: str, content: str, task_id: str = "default") -> str:
    """添加一条笔记。
    - type: info（资产信息）/ infer（推理分析）/ result（漏洞确认）
    - content: 笔记内容（支持 Markdown）
    - task_id: 任务 ID
    """
    if type not in ("info", "infer", "result"):
        return f"无效的笔记类型: {type}，应为 info/infer/result"

    filepath = _get_task_file(type, task_id)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    with open(filepath, "a", encoding="utf-8") as f:
        f.write(f"\n## [{timestamp}]\n\n{content}\n\n---\n")

    return f"已记录 [{type}] 笔记到 {filepath}"


@mcp.tool()
async def note_read(type: str, task_id: str = "default") -> str:
    """读取某类笔记的内容（最近 5000 字符）。"""
    filepath = _get_task_file(type, task_id)
    if not filepath.exists():
        return f"暂无 {type} 类型的笔记"
    content = filepath.read_text(encoding="utf-8")
    if len(content) > 5000:
        # 保留最后 5000 字符（最新的记录更重要）
        return f"(笔记共 {len(content)} 字符，显示最近部分)\n\n...{content[-5000:]}"
    return content


@mcp.tool()
async def note_summary(task_id: str = "default") -> str:
    """获取当前任务所有笔记的摘要。"""
    output = []
    for ntype in ("info", "infer", "result"):
        filepath = _get_task_file(ntype, task_id)
        if filepath.exists():
            content = filepath.read_text(encoding="utf-8")
            lines = content.strip().splitlines()
            output.append(f"### {ntype} ({len([l for l in lines if l.startswith('## [')])} 条)")
            # 只显示最后 3 条的标题
            entries = [l for l in lines if l.startswith("## [")]
            for entry in entries[-3:]:
                output.append(f"  {entry}")
        else:
            output.append(f"### {ntype} (0 条)")
    return "\n".join(output)


if __name__ == "__main__":
    mcp.run(transport="stdio")
