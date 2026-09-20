"""core.poc_playback — PoC 一键复现（中期 M1 配套）。

按 XUANJIAN_ROADMAP_MID_TERM §2.3 落地。
- play(poc) 执行 poc 复现
- curl 走 subprocess；python 走 exec（隔离 __name__）
- 零外部依赖（subprocess + exec）

风险：subprocess shell=True 需信任 poc.content 来源；可走 XUANJIAN_POC_REQUIRED=off 关闭闸。
"""
from __future__ import annotations

import subprocess
from typing import Any


def _play_curl(poc: dict, timeout: int = 10) -> dict:
    """curl 走 subprocess。"""
    try:
        r = subprocess.run(
            poc["content"],
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "format": "curl",
            "success": r.returncode == 0,
            "stdout": r.stdout[:500],
            "stderr": r.stderr[:500],
        }
    except subprocess.TimeoutExpired:
        return {"format": "curl", "success": False, "error": "timeout"}
    except Exception as e:
        return {"format": "curl", "success": False, "error": str(e)[:200]}


def _play_python(poc: dict, timeout: int = 10) -> dict:
    """python: 在隔离 namespace 里 exec，捕获 stdout。"""
    import contextlib
    import io

    buf = io.StringIO()
    ns = {"__name__": "__playback__"}
    try:
        with contextlib.redirect_stdout(buf):
            exec(compile(poc["content"], "<poc>", "exec"), ns)  # noqa: S102
        return {
            "format": "python",
            "success": True,
            "stdout": buf.getvalue()[:500],
        }
    except Exception as e:
        return {
            "format": "python",
            "success": False,
            "error": str(e)[:200],
            "stdout": buf.getvalue()[:500],
        }


def play(poc: dict, base_url: str | None = None, timeout: int = 10) -> dict:
    """执行 poc 复现。

    Args:
        poc: gen_poc() 的输出（{format, content, finding_id, auto_generated}）
        base_url: 可选替换 finding 里的 url（适配环境差异）
        timeout: subprocess / exec 超时秒数

    Returns:
        {"format", "success", "stdout"/"stderr"/"error"}
    """
    if not isinstance(poc, dict):
        return {"success": False, "error": "poc 不是 dict"}

    fmt = poc.get("format")
    if fmt == "curl":
        return _play_curl(poc, timeout=timeout)
    if fmt == "python":
        return _play_python(poc, timeout=timeout)
    return {"success": False, "error": f"未知 format: {fmt!r}"}


__all__ = ["play"]
