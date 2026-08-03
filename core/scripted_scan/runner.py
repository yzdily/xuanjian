"""Runner for optional external scripted scanners."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from dataclasses import asdict
from pathlib import Path

from core.packet_merger import merge_packets
from core.scripted_scan.export_openapi import export_openapi
from core.scripted_scan.types import dedup_findings, normalize_finding


def _build_auth_env(session_info: dict | None) -> dict:
    """从 session_info 提取认证信息，构造传给外部进程的环境变量。

    外部脚本扫描器（如 api-pentest-extension）通过 PENTEST_TOKEN / PENTEST_COOKIES
    环境变量获取认证信息，与玄鉴 session_info 解耦。
    """
    env = dict(os.environ)  # 继承当前环境
    if not session_info:
        return env
    headers = session_info.get("headers") or {}
    if not isinstance(headers, dict):
        return env
    auth = headers.get("Authorization", "") or headers.get("authorization", "")
    if auth:
        # 去掉 "Bearer " 前缀，api-pentest-extension 的 Config 会自动加回
        token = auth[7:] if auth.lower().startswith("bearer ") else auth
        env["PENTEST_TOKEN"] = token
    cookie = headers.get("Cookie", "") or headers.get("cookie", "")
    if cookie:
        env["PENTEST_COOKIES"] = cookie
    return env


async def _run_command(command: list[str], cwd: Path | None, timeout: float,
                       env: dict | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd) if cwd else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 124, "", "scripted scan timeout"
    return proc.returncode or 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")


def _load_jsonl(path: Path) -> list[dict]:
    findings: list[dict] = []
    if not path.exists():
        return findings
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            findings.append(item)
    return findings


def _drop_expired_auth_findings(findings: list[dict]) -> list[dict]:
    result = []
    for finding in findings:
        response = str(finding.get("evidence_response") or finding.get("response") or finding.get("raw_response") or "")
        status_code = str(finding.get("status_code") or "")
        if status_code in {"401", "403"} or response.startswith("HTTP/1.1 401") or response.startswith("HTTP/1.1 403"):
            continue
        result.append(finding)
    return result


async def run_scripted_scan(sitemap, session_info: dict | None = None) -> tuple[list[dict], dict]:
    """Export current packets, run optional external scanner, return normalized findings.

    Configure the external scanner with XUANJIAN_SCRIPTED_SCAN_CMD. The command may contain
    {api_file} and {output_file}; if omitted, they are appended as --api-file/--output.
    """
    command_template = os.getenv("XUANJIAN_SCRIPTED_SCAN_CMD", "").strip()
    if not command_template:
        return [], {"enabled": False, "reason": "XUANJIAN_SCRIPTED_SCAN_CMD not set"}

    task_id = getattr(sitemap, "task_id", "default") or "default"
    base_dir = Path("data/tasks") / task_id / "scripted_scan"
    api_file = base_dir / "openapi.json"
    output_file = base_dir / "raw_findings.jsonl"

    sitemap_data = {
        "task_id": task_id,
        "target": getattr(sitemap, "target", ""),
        "api_samples": getattr(sitemap, "api_samples", {}) or {},
        "features": {
            key: asdict(feature) if hasattr(feature, "__dataclass_fields__") else getattr(feature, "__dict__", {})
            for key, feature in (getattr(sitemap, "features", {}) or {}).items()
        },
        "extra_scope": getattr(sitemap, "extra_scope", []) or [],
    }
    merged = merge_packets(sitemap_data, target_host=getattr(sitemap, "target", ""))
    packets = merged.get("packets", [])
    export_openapi(packets, api_file)

    rendered = command_template.format(api_file=str(api_file), output_file=str(output_file))
    command = shlex.split(rendered, posix=False)
    if "{api_file}" not in command_template and "--api-file" not in command:
        command.extend(["--api-file", str(api_file)])
    if "{output_file}" not in command_template and "--output" not in command:
        command.extend(["--output", str(output_file)])

    timeout = float(os.getenv("XUANJIAN_SCRIPTED_SCAN_TIMEOUT", "300"))
    auth_env = _build_auth_env(session_info)
    returncode, stdout, stderr = await _run_command(command, cwd=None, timeout=timeout, env=auth_env)

    raw_findings = _load_jsonl(output_file)
    if not raw_findings and stdout.strip():
        for line in stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                raw_findings.append(item)

    raw_findings = _drop_expired_auth_findings(raw_findings)
    normalized = []
    for index, raw in enumerate(raw_findings):
        finding = normalize_finding(raw, index=index)
        if finding:
            normalized.append(finding)

    stats = {
        "enabled": True,
        "returncode": returncode,
        "packets": len(packets),
        "raw_findings": len(raw_findings),
        "findings": len(normalized),
        "api_file": str(api_file),
        "output_file": str(output_file),
        "stderr": stderr[-1000:],
    }
    return dedup_findings(normalized), stats
