"""F12 — 上下文虚拟化（大输出 head+tail + 落盘工作区）。

玄鉴已有 MAX_TOOL_RESULT=6000 硬截断（core/config.py:458 + browse_worker.py:1948）。
本模块作为升级版：超出阈值时保留 head+tail 并落盘到 /workspace/.tool-output/，
而非粗暴切前 N 字符。
"""
from __future__ import annotations

import time
from pathlib import Path

MAX_LINES = 2000
MAX_BYTES = 50 * 1024  # 50KB
HEAD_LINES = 500
TAIL_LINES = 500
OUTPUT_DIR = Path(".tool-output")


def bound_result(tool_name: str, result: str) -> dict[str, str]:
    """大输出 head+tail 切片 + 落盘。

    Args:
        tool_name: 工具名（用于落盘文件名）
        result: 工具返回的原始文本

    Returns:
        {"type": "raw", "content": result} — 未超阈值
        {"type": "truncated", "content": summary, "path": str} — 超阈值
    """
    if not result:
        return {"type": "raw", "content": result}

    lines = result.splitlines()
    if len(lines) <= MAX_LINES and len(result) <= MAX_BYTES:
        return {"type": "raw", "content": result}

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    out_path = OUTPUT_DIR / f"{tool_name}_{ts}.txt"
    out_path.write_text(result, encoding="utf-8", errors="replace")

    head = "\n".join(lines[:HEAD_LINES])
    tail = "\n".join(lines[-TAIL_LINES:])
    truncated_count = max(len(lines) - HEAD_LINES - TAIL_LINES, 0)

    summary = (
        f"{head}\n\n"
        f"... [TRUNCATED {truncated_count} lines, "
        f"{len(result) - len(head) - len(tail)} bytes] ...\n\n"
        f"{tail}\n\n"
        f"FULL OUTPUT saved to: {out_path}\n"
    )
    return {"type": "truncated", "content": summary, "path": str(out_path)}


def truncate_tool_result(tool_name: str, result: str, max_chars: int = 6000) -> str:
    """与 core/browse_worker.py 的硬截断兼容的接口。

    若 result 超过 max_chars，调用 bound_result 做 head+tail+落盘。
    若 bound_result 认为不需要截断（行数/字节数未超阈值），
    则直接用 max_chars 做前缀截断 + 标记。
    """
    if len(result) <= max_chars:
        return result
    bounded = bound_result(tool_name, result)
    if bounded["type"] == "truncated":
        return bounded["content"]
    # bound_result 未截断但 result 仍超 max_chars → 用 head+tail 手动截断
    head = result[:max_chars // 2]
    tail = result[-max_chars // 2:]
    return (
        f"{head}\n\n"
        f"... [TRUNCATED {len(result) - max_chars} bytes] ...\n\n"
        f"{tail}\n\n"
        f"FULL OUTPUT saved by output_store\n"
    )


__all__ = ["bound_result", "truncate_tool_result"]
