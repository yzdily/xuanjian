#!/usr/bin/env python3
"""
dirsearch_only_wrapper.py — 玄鉴 × api-pentest-extension dirsearch 专用桥接脚本

方案 A（适配版）：不新建 dirsearch 实现，而是直接调用已有的
dirsearch_scanner.py（位于 api-pentest-extension/skills/content-discovery-dirsearch/），
仅运行目录/文件内容发现，不运行其他 50 个脚本。

适用于：
  - 目标不可达时的被动侦察（目录爆破）
  - 需要快速目录扫描的场景
  - 作为 XUANJIAN_SCRIPTED_SCAN_CMD 的轻量替代（只跑 dirsearch）

用法（由玄鉴 scripted_scan runner 自动调用）：
    python external/dirsearch_only_wrapper.py --api-file openapi.json --output findings.jsonl

也可直接指定 target（绕过 OpenAPI）：
    python external/dirsearch_only_wrapper.py --target https://api.example.com --output findings.jsonl

环境变量（由玄鉴 runner 注入）：
    PENTEST_TOKEN        — Bearer token / Authorization 值
    PENTEST_COOKIES      — Cookie 字符串
    PENTEST_PROXY        — 代理地址（可选）
    PENTEST_SKILLS_DIR   — skills 目录路径（默认: D:\\qianwencode\\api-pentest-extension\\skills）
    DIRSEARCH_THREADS    — 并发线程数（默认: 15）
    DIRSEARCH_RECURSIVE  — 是否递归扫描（"1"/"true" 启用）
    DIRSEARCH_MAX_DEPTH  — 递归深度（默认: 2）
    DIRSEARCH_EXTENSIONS — 文件扩展名（逗号分隔，如 php,bak,json）
    DIRSEARCH_WORDLIST   — 外部字典文件路径
    DIRSEARCH_TIMEOUT    — 单请求超时秒数（默认: 10）
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

# ── 默认 skills 目录（用户本地 api-pentest-extension 路径）──
DEFAULT_SKILLS_DIR = r"D:\qianwencode\api-pentest-extension\skills"

# ── dirsearch 脚本在 registry 中的定位 ──
DIRSEARCH_SKILL = "content-discovery-dirsearch"
DIRSEARCH_SCRIPT = "dirsearch_scanner.py"
DIRSEARCH_OUTPUT_FILE = "dirsearch_findings.json"

# ── 漏洞类型映射（从路径推导中文漏洞类型）──
# 用于 normalize_finding 的 vuln_type 字段
CRITICAL_PATTERNS = [
    ".env", ".git/head", ".git/config", ".svn/", ".hg/",
    "private.key", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "backup.sql", "dump.sql", "db.sql", "database.sql",
    "backup.zip", "site.zip", "www.zip", "source.zip",
    "credentials", "secrets.json", "secrets.yml", "secrets.yaml",
    "shadow", "passwd", "terraform.tfstate",
    "authorized_keys", "keystore.jks",
    "actuator/heapdump", "actuator/env",
    ".bash_history", ".zsh_history",
]

HIGH_PATTERNS = [
    "admin", "wp-admin", "phpmyadmin", "adminer", "administrator",
    "actuator", "actuator/", "jolokia", "debug/pprof",
    "phpinfo", "info.php",
    "web.config", "application.properties", "application.yml",
    "wp-config.php", "config.php", "database.yml", "db.yml",
    "appsettings.json", "connectionstring",
    ".htpasswd", "nginx.conf", "httpd.conf", "php.ini",
    "my.cnf", "redis.conf", "mongod.conf",
    "pg_hba.conf", "postgresql.conf",
    "elasticsearch", "kibana", "grafana",
    "jenkinsfile", "jenkins", "Jenkins",
    "private_key", "secret.key",
]


def classify_vuln_type(path: str) -> str:
    """从路径推导中文漏洞类型，供 normalize_finding 使用。

    分类优先级：critical > high > medium > 默认
    """
    path_lower = path.lower()

    # ── 精确匹配（优先级最高）──
    if any(p in path_lower for p in [".env", "credentials", "secrets.json",
                                     "secrets.yml", "secrets.yaml",
                                     "private.key", "private_key",
                                     "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                                     "shadow", "passwd"]):
        return "敏感信息泄露"
    if any(p in path_lower for p in [".git/", ".svn/", ".hg/", ".bzr/", ".cvs/"]):
        return "源代码泄露"
    if any(p in path_lower for p in ["actuator/env", "actuator/heapdump",
                                     "actuator/configprops", "actuator/beans",
                                     "actuator/mappings", "actuator/threaddump"]):
        return "Actuator端点暴露"
    if any(p in path_lower for p in ["actuator"]):
        return "调试端点暴露"
    if any(p in path_lower for p in ["admin", "wp-admin", "phpmyadmin",
                                     "adminer", "administrator", "admin-panel"]):
        return "管理面板暴露"
    if any(p in path_lower for p in ["swagger", "openapi", "api-docs",
                                     "graphiql", "voyager", "playground"]):
        return "API文档泄露"
    if any(p in path_lower for p in ["backup", ".sql", ".zip", ".tar",
                                     ".bak", ".old", "dump"]):
        return "备份文件泄露"
    if any(p in path_lower for p in ["debug", "pprof", "jolokia",
                                     "trace", "dump/"]):
        return "调试端点暴露"
    if any(p in path_lower for p in [".htaccess", ".htpasswd", "config.php",
                                     "wp-config", "database.yml", "db.yml",
                                     "application.properties", "application.yml",
                                     "appsettings.json", "connectionstring",
                                     "nginx.conf", "httpd.conf", "php.ini",
                                     "my.cnf", "redis.conf"]):
        return "配置文件泄露"
    if any(p in path_lower for p in ["log", ".log", "access.log",
                                     "error.log", "app.log", "server.log"]):
        return "日志文件泄露"
    if any(p in path_lower for p in ["robots.txt", "sitemap.xml",
                                     "crossdomain.xml", "security.txt"]):
        return "信息泄露"
    if any(p in path_lower for p in ["readme", "changelog", "license",
                                     "package.json", "composer.json",
                                     "requirements.txt", "dockerfile",
                                     "docker-compose"]):
        return "信息泄露"

    return "信息泄露"


def classify_severity(path: str) -> str:
    """从路径推导严重级别（与 dirsearch_scanner.py 一致）。"""
    path_lower = path.lower()
    for pattern in CRITICAL_PATTERNS:
        if pattern in path_lower:
            return "critical"
    for pattern in HIGH_PATTERNS:
        if pattern in path_lower:
            return "high"
    return "medium"


def extract_target_from_openapi(api_file: Path) -> str:
    """从 OpenAPI 文件提取 target URL。"""
    try:
        data = json.loads(api_file.read_text(encoding="utf-8"))
    except Exception:
        return ""
    servers = data.get("servers", [])
    if servers:
        url = servers[0].get("url", "")
        if url:
            return url.rstrip("/")
    return ""


def locate_dirsearch_script(skills_dir: Path) -> Path | None:
    """定位 dirsearch_scanner.py。"""
    script_path = skills_dir / DIRSEARCH_SKILL / "scripts" / DIRSEARCH_SCRIPT
    if script_path.exists():
        return script_path
    return None


def run_dirsearch(
    script_path: Path,
    target: str,
    output_dir: Path,
    timeout: int = 300,
) -> tuple[int, str, str]:
    """运行 dirsearch_scanner.py 子进程。

    根据 CLI 参数和环境变量构建命令，传递认证信息。
    """
    cmd = [sys.executable, str(script_path),
           "--target", target,
           "--output-dir", str(output_dir)]

    # ── 可选参数（从环境变量读取）──
    threads = os.environ.get("DIRSEARCH_THREADS", "15")
    cmd.extend(["--threads", threads])

    recursive = os.environ.get("DIRSEARCH_RECURSIVE", "").lower() in ("1", "true", "yes")
    if recursive:
        cmd.append("--recursive")
        max_depth = os.environ.get("DIRSEARCH_MAX_DEPTH", "2")
        cmd.extend(["--max-depth", max_depth])

    extensions = os.environ.get("DIRSEARCH_EXTENSIONS", "")
    if extensions:
        cmd.extend(["--extensions", extensions])

    wordlist = os.environ.get("DIRSEARCH_WORDLIST", "")
    if wordlist:
        cmd.extend(["--wordlist", wordlist])

    req_timeout = os.environ.get("DIRSEARCH_TIMEOUT", "10")
    cmd.extend(["--timeout", req_timeout])

    # ── 认证信息 ──
    token = os.environ.get("PENTEST_TOKEN", "")
    cookies = os.environ.get("PENTEST_COOKIES", "")
    if token:
        cmd.extend(["--token", token])
    if cookies:
        cmd.extend(["--cookies", cookies])

    proxy = os.environ.get("PENTEST_PROXY", "")
    if proxy:
        cmd.extend(["--proxy", proxy])

    print(f"  [dirsearch] cmd: {' '.join(cmd[:6])}...", file=sys.stderr)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(script_path.parent),
        )
    except subprocess.TimeoutExpired:
        print(f"  [dirsearch] timeout (>{timeout}s)", file=sys.stderr)
        return 124, "", "dirsearch timeout"
    except Exception as e:
        print(f"  [dirsearch] error: {e}", file=sys.stderr)
        return 1, "", str(e)

    return result.returncode or 0, result.stdout, result.stderr


def _make_request_text(url: str) -> str:
    """构造 HTTP 请求文本（用于 evidence_request）。"""
    parsed = urlparse(url or "")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines = [f"GET {path} HTTP/1.1"]
    if parsed.netloc:
        lines.append(f"Host: {parsed.netloc}")
    lines.append("User-Agent: ApiPentestWorkflow/1.0")
    lines.append("")
    return "\n".join(lines)


def _make_response_text(evidence: dict) -> str:
    """从 evidence dict 构造 HTTP 响应文本（用于 evidence_response）。"""
    if not isinstance(evidence, dict):
        return str(evidence) if evidence else ""

    status = evidence.get("status", 200)
    content_type = evidence.get("content_type", "")
    content_length = evidence.get("content_length", 0)
    body_preview = evidence.get("body_preview", "")

    lines = [f"HTTP/1.1 {status}"]
    if content_type:
        lines.append(f"Content-Type: {content_type}")
    if content_length:
        lines.append(f"Content-Length: {content_length}")
    lines.append("")
    if body_preview:
        lines.append(body_preview)
    return "\n".join(lines)


def convert_findings_to_jsonl(
    findings: list[dict],
    target: str,
) -> list[dict]:
    """将 dirsearch Finding dict 列表转换为 normalize_finding 兼容的 JSONL。

    normalize_finding（types.py）期望的字段：
      - url / endpoint / target  → URL
      - method / http_method     → HTTP 方法（默认 GET）
      - vuln_type / type / name  → 漏洞类型
      - severity / severity_original → 严重级别
      - title                    → 标题
      - detail / description     → 详情
      - evidence_request / request → 请求证据
      - evidence_response / response / evidence → 响应证据
      - payload / attack         → Payload（目录扫描无 payload）
      - fix_suggestion / remediation / recommendation → 修复建议
      - phase / stage            → 阶段

    本函数补充 normalize_finding 无法自动推导的字段：
      - vuln_type（从路径推导中文类型）
      - method = "GET"
      - url（显式设置 = endpoint）
      - evidence_request（构造 HTTP 请求文本）
      - evidence_response（从 evidence dict 构造 HTTP 响应文本）
    """
    converted = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        endpoint = finding.get("endpoint", "")
        evidence = finding.get("evidence", {})
        path = ""
        if isinstance(evidence, dict):
            path = evidence.get("path", "")
        if not path and endpoint:
            parsed = urlparse(endpoint)
            path = parsed.path or "/"

        vuln_type = classify_vuln_type(path)
        severity = finding.get("severity", classify_severity(path))

        # 构造 evidence_request / evidence_response
        evidence_request = _make_request_text(endpoint)
        evidence_response = _make_response_text(evidence)

        item = {
            "vuln_id": f"DIRSEARCH-{len(converted) + 1:04d}",
            "source": "dirsearch",
            "phase": finding.get("phase", "recon"),
            "title": finding.get("title", f"Discovered: {path}"),
            "vuln_type": vuln_type,
            "method": "GET",
            "url": endpoint,
            "severity": severity,
            "severity_original": severity,
            "detail": finding.get("description", ""),
            "evidence_request": evidence_request,
            "evidence_response": evidence_response,
            "fix_suggestion": finding.get("recommendation", ""),
            "confidence": 80 if severity in ("critical", "high") else 60,
            "candidate_level": "suspected",
        }
        converted.append(item)

    return converted


def dedup_findings(findings: list[dict]) -> list[dict]:
    """按 method + url_path + vuln_type 去重。"""
    seen: set[str] = set()
    result: list[dict] = []
    for finding in findings:
        parsed = urlparse(finding.get("url", ""))
        path = (parsed.path or finding.get("url", "")).rstrip("/")
        key = "|".join([
            finding.get("method", "").upper(),
            path.lower(),
            finding.get("vuln_type", "").lower(),
        ])
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="dirsearch-only wrapper for 玄鉴 (方案 A 适配版)")
    parser.add_argument("--api-file", default=None,
                        help="OpenAPI 文件路径（由 runner 传入，用于提取 target）")
    parser.add_argument("--output", required=True,
                        help="JSONL 输出路径")
    parser.add_argument("--target", default=None,
                        help="直接指定 target URL（绕过 OpenAPI）")
    parser.add_argument("--skills-dir", default=None,
                        help=f"skills 目录路径（默认: {DEFAULT_SKILLS_DIR}）")
    parser.add_argument("--timeout", type=int, default=300,
                        help="dirsearch 整体超时秒数（默认 300）")
    args = parser.parse_args()

    output_file = Path(args.output)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # ── 定位 skills 目录 ──
    skills_dir_str = args.skills_dir or os.environ.get(
        "PENTEST_SKILLS_DIR", DEFAULT_SKILLS_DIR)
    skills_dir = Path(skills_dir_str)

    if not skills_dir.exists():
        output_file.write_text("", encoding="utf-8")
        print(f"[dirsearch-wrapper] skills 目录不存在: {skills_dir}", file=sys.stderr)
        print(f"  请确认 api-pentest-extension 已 clone 到正确位置", file=sys.stderr)
        return 0

    # ── 定位 dirsearch_scanner.py ──
    script_path = locate_dirsearch_script(skills_dir)
    if not script_path:
        output_file.write_text("", encoding="utf-8")
        print(f"[dirsearch-wrapper] 未找到 {DIRSEARCH_SCRIPT}", file=sys.stderr)
        print(f"  预期路径: {skills_dir / DIRSEARCH_SKILL / 'scripts' / DIRSEARCH_SCRIPT}",
              file=sys.stderr)
        return 0

    # ── 确定 target ──
    target = args.target
    if not target and args.api_file:
        target = extract_target_from_openapi(Path(args.api_file))
    if not target:
        target = os.environ.get("PENTEST_TARGET", "")
    if not target:
        output_file.write_text("", encoding="utf-8")
        print("[dirsearch-wrapper] 无法确定 target URL"
              "（--target / --api-file / PENTEST_TARGET 均未提供）", file=sys.stderr)
        return 0

    print(f"[dirsearch-wrapper] target: {target}", file=sys.stderr)
    print(f"  script: {script_path}", file=sys.stderr)

    # ── 运行 dirsearch ──
    output_dir = output_file.parent / "_dirsearch_tmp"
    output_dir.mkdir(parents=True, exist_ok=True)

    returncode, stdout, stderr = run_dirsearch(
        script_path, target, output_dir, timeout=args.timeout,
    )

    if returncode != 0:
        print(f"  [dirsearch] exit={returncode}", file=sys.stderr)
        if stderr:
            print(f"  [dirsearch] stderr: {stderr[:500]}", file=sys.stderr)

    # ── 读取 dirsearch_findings.json ──
    findings_file = output_dir / DIRSEARCH_OUTPUT_FILE
    raw_findings: list[dict] = []
    if findings_file.exists():
        try:
            data = json.loads(findings_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                raw_findings = [f for f in data if isinstance(f, dict)]
            elif isinstance(data, dict):
                raw_findings = [data]
        except Exception as e:
            print(f"  [dirsearch] 读取 findings 失败: {e}", file=sys.stderr)

    # ── 转换 + 去重 ──
    converted = convert_findings_to_jsonl(raw_findings, target)
    deduped = dedup_findings(converted)

    # ── 输出 JSONL ──
    with open(output_file, "w", encoding="utf-8") as f:
        for finding in deduped:
            f.write(json.dumps(finding, ensure_ascii=False) + "\n")

    # ── 统计 ──
    by_sev: dict[str, int] = {}
    for f in deduped:
        sev = f.get("severity", "unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    print(f"[dirsearch-wrapper] 完成: {len(deduped)} 条 findings"
          f"（原始 {len(raw_findings)}，去重后 {len(deduped)}）",
          file=sys.stderr)
    if by_sev:
        sev_summary = ", ".join(f"{k}: {v}" for k, v in
                                sorted(by_sev.items(),
                                       key=lambda x: ["critical", "high",
                                                      "medium", "low",
                                                      "info"].index(x[0])
                                       if x[0] in ["critical", "high",
                                                   "medium", "low", "info"] else 99))
        print(f"  严重级别: {sev_summary}", file=sys.stderr)

    # ── 清理临时目录 ──
    import shutil
    shutil.rmtree(output_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
