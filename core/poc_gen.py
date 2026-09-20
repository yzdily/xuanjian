"""core.poc_gen — Finding 自动生成 PoC（中期 M1）。

按 XUANJIAN_ROADMAP_MID_TERM §2.3 落地：
- gen_curl: 生成 curl 复现脚本
- gen_python: 生成 Python requests 复现脚本
- gen_poc: auto 模式按 method 选最佳格式
- 所有 PoC 必带 finding_id 用于回溯

零外部依赖（用 stdlib json + textwrap）。
"""
from __future__ import annotations

import json
import textwrap
from typing import Literal


def _url_of(finding: dict) -> str:
    return finding.get("url") or finding.get("endpoint") or ""


def _method_of(finding: dict) -> str:
    return (finding.get("method") or "GET").upper()


def _headers_of(finding: dict) -> dict:
    return finding.get("request_headers") or {}


def _body_of(finding: dict):
    return finding.get("request_body")


def gen_curl(finding: dict) -> str:
    """生成 curl 复现脚本。"""
    url = _url_of(finding)
    method = _method_of(finding)
    headers = _headers_of(finding)
    body = _body_of(finding)

    lines = [f"curl -X {method} '{url}'"]
    for k, v in headers.items():
        # 转义单引号
        v_esc = str(v).replace("'", "'\\''")
        lines.append(f"  -H '{k}: {v_esc}'")
    if body is not None:
        if isinstance(body, (dict, list)):
            body_str = json.dumps(body, ensure_ascii=False)
        else:
            body_str = str(body)
        body_esc = body_str.replace("'", "'\\''")
        lines.append(f"  -d '{body_esc}'")
    return " \\\n".join(lines) + "\n"


def gen_python(finding: dict) -> str:
    """生成 Python requests 复现脚本。"""
    url = _url_of(finding)
    method = _method_of(finding).lower()
    headers = _headers_of(finding)
    body = _body_of(finding)

    return textwrap.dedent(f"""
        import requests

        resp = requests.{method}(
            url={json.dumps(url)},
            headers={json.dumps(headers, ensure_ascii=False)},
            json={json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else 'None'},
            timeout=10,
        )
        print(f"[{{resp.status_code}}] {{resp.text[:500]}}")
    """).strip() + "\n"


def gen_poc(
    finding: dict,
    fmt: Literal["curl", "python", "auto"] = "auto",
) -> dict:
    """auto 模式：GET → curl，其他 → python。

    Returns:
        {"format": str, "content": str, "finding_id": str, "auto_generated": True}
        或 finding 缺 url/endpoint 时返回 {"format": None, "content": "", "error": ...}
    """
    if fmt == "auto":
        fmt = "curl" if _method_of(finding) == "GET" else "python"

    url = _url_of(finding)
    if not url:
        return {
            "format": None,
            "content": "",
            "finding_id": finding.get("id"),
            "auto_generated": True,
            "error": "finding 缺 url/endpoint，无法生成 PoC",
        }

    content = {"curl": gen_curl, "python": gen_python}[fmt](finding)
    return {
        "format": fmt,
        "content": content,
        "finding_id": finding.get("id"),
        "auto_generated": True,
    }


__all__ = ["gen_curl", "gen_python", "gen_poc"]
