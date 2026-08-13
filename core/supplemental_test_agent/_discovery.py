"""SupplementalTestAgent — L1 自动发现层。

包含 _DiscoveredAPI 数据结构、discover_new_apis_from_flows（被动流量扫描）、
discover_apis_from_dirscan（主动目录爆破）及相关过滤辅助函数。
从原 core/supplemental_test_agent.py 抽取，行为不变。
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

from core.log import get_logger
from core.sitemap import Sitemap

from ._constants import _THIRD_PARTY_BLACKLIST

log = get_logger("supplemental")


# ============================================================
# 数据结构
# ============================================================

class _DiscoveredAPI:
    """从 flows.jsonl 扫出来的待补测 API。"""

    __slots__ = ("method", "url", "host", "path", "status_code",
                 "response_body_preview", "content_type", "timestamp",
                 "flow_id", "request_body")

    def __init__(self, flow: dict):
        self.method = (flow.get("method") or "").upper()
        self.url = flow.get("url") or ""
        parsed = urlparse(self.url)
        self.host = parsed.netloc.lower()
        self.path = parsed.path or "/"
        self.status_code = int(flow.get("status_code") or 0)
        self.response_body_preview = (flow.get("response_body") or "")[:200]
        self.content_type = flow.get("content_type") or ""
        self.timestamp = float(flow.get("timestamp") or 0)
        self.flow_id = flow.get("id", "")
        self.request_body = (flow.get("request_body") or "")[:500]

    @property
    def key(self) -> str:
        """归一化键：METHOD host+path（去 query）。"""
        return f"{self.method} {self.host}{self.path}"


# ============================================================
# L1: 自动发现层 — 从 flows.jsonl 扫描新 API
# ============================================================

def discover_new_apis_from_flows(
    sitemap: Sitemap,
    target_url: str,
    phase2_started_at: float,
    flows_path: Path | None = None,
    task_id: str | None = None,
) -> tuple[list[_DiscoveredAPI], dict[str, int]]:
    """从 flows.jsonl 扫出 Phase 2 期间产生的、scope 内的、2xx 响应的、
    且不在 sitemap.apis 里的新 API。

    Args:
        task_id: 可选，如果指定则只保留归属该任务的流量（避免跨任务污染）。

    Returns:
        (apis, stats)：apis 是去重后的新 API 列表，stats 是过滤统计信息。
    """
    stats = {
        "total_scanned": 0,
        "before_phase2": 0,
        "other_task": 0,
        "out_of_scope": 0,
        "third_party": 0,
        "not_2xx": 0,
        "non_business": 0,
        "already_known": 0,
        "duplicate": 0,
        "kept": 0,
        "flow_file": "",
    }

    if flows_path is None:
        flows_path = Path(
            os.getenv("PROXY_FLOW_FILE",
                      "data/pentest_agent_flows.jsonl")
        )
    stats["flow_file"] = str(flows_path)

    if not flows_path.exists():
        log.warning("supplemental: flows.jsonl 不存在: %s", flows_path)
        stats["flow_file_missing"] = 1
        return [], stats

    # 计算 scope
    target_host = urlparse(target_url).netloc.lower() if target_url else ""
    extra_scope = set()
    try:
        ex = getattr(sitemap, "extra_scope", None)
        if ex:
            extra_scope = {d.lower().lstrip(".") for d in ex if d}
    except Exception:
        pass
    in_scope_hosts = ({target_host} | extra_scope) if target_host else extra_scope

    # 计算已知 API 集合（用于 dedup）
    known_keys: set[str] = set()
    try:
        for api_key in (sitemap.apis or {}).keys():
            # api_key 格式 "METHOD url"，取 method + host+path
            parts = api_key.split(" ", 1)
            if len(parts) == 2:
                m = parts[0].upper()
                u = parts[1].strip()
                pu = urlparse(u)
                if pu.netloc:
                    known_keys.add(f"{m} {pu.netloc.lower()}{pu.path}")
                else:
                    # 只有 path
                    known_keys.add(f"{m} {pu.path}")
    except Exception:
        pass

    seen: dict[str, _DiscoveredAPI] = {}

    try:
        # ★ 使用 errors="replace" 容错：flows.jsonl 可能因 mitmproxy 写入时
        # 含非 UTF-8 字节（如二进制响应体被误记），不能因一行解码失败
        # 就放弃整个文件，导致 Phase 2.55 补测全部跳过。
        with open(flows_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                stats["total_scanned"] += 1
                try:
                    flow = json.loads(line)
                except Exception:
                    # 单行 JSON 解析失败（可能因 errors=replace 引入的 U+FFFD）
                    # 跳过这一行继续，而不是整体抛出
                    stats.setdefault("parse_failed", 0)
                    stats["parse_failed"] = stats.get("parse_failed", 0) + 1
                    continue

                ts = float(flow.get("timestamp") or 0)
                if ts < phase2_started_at:
                    stats["before_phase2"] += 1
                    continue

                # ★ 2026-05-29: 按 task_id 过滤，避免跨任务污染
                if task_id:
                    flow_task_id = flow.get("task_id", "")
                    if flow_task_id and flow_task_id != task_id:
                        stats["other_task"] += 1
                        continue

                api = _DiscoveredAPI(flow)

                # scope 过滤
                if not api.host:
                    stats["out_of_scope"] += 1
                    continue
                if not _host_in_scope(api.host, in_scope_hosts):
                    stats["out_of_scope"] += 1
                    continue
                # 第三方黑名单
                if _is_third_party(api.host):
                    stats["third_party"] += 1
                    continue

                # 仅 2xx 响应
                if not (200 <= api.status_code < 300):
                    stats["not_2xx"] += 1
                    continue

                # 排除静态资源、非业务路径
                if _is_non_business_path(api.path):
                    stats["non_business"] += 1
                    continue

                # 已知 API（带 host+path 的精确归一化键）
                norm_key = f"{api.method} {api.host}{api.path}"
                if norm_key in known_keys:
                    stats["already_known"] += 1
                    continue
                # 兼容只存 path 的旧 key
                path_only_key = f"{api.method} {api.path}"
                if path_only_key in known_keys:
                    stats["already_known"] += 1
                    continue

                # 去重（同一新 API 多次出现只保留第一条 2xx）
                if api.key in seen:
                    stats["duplicate"] += 1
                    continue

                seen[api.key] = api
                stats["kept"] += 1
    except OSError as e:
        # 仅捕获文件级 IO 错误（文件不存在/权限等），其他异常向上抛出
        # 触发任务级告警，避免因单点异常导致 Phase 2.55 补测全部静默跳过。
        log.warning("supplemental: 读取 flows.jsonl IO 错误: %s", e)
        stats["io_error"] = str(e)[:200]
        return list(seen.values()), stats
    except Exception as e:
        # 非预期异常：记录详细堆栈并向上抛出，由调用方决定是否终止 Phase 2.55
        log.exception("supplemental: 扫描 flows.jsonl 发生非预期异常（已收集 %d 条）", len(seen))
        stats["unexpected_error"] = str(e)[:200]
        # 返回已收集的部分结果，而非空列表，最大限度保留补测数据
        return list(seen.values()), stats

    return list(seen.values()), stats


def _host_in_scope(host: str, in_scope_hosts: set[str]) -> bool:
    """host 是否落在 scope 内（精确或后缀匹配）。"""
    if not host:
        return False
    if host in in_scope_hosts:
        return True
    # 后缀匹配（如 in_scope = {jd.com}，host=qw.jd.com → 命中）
    for sc in in_scope_hosts:
        if sc and (host == sc or host.endswith("." + sc)):
            return True
    return False


def _is_third_party(host: str) -> bool:
    host = (host or "").lower().lstrip(".")
    for bl in _THIRD_PARTY_BLACKLIST:
        if host == bl or host.endswith("." + bl):
            return True
    return False


_NON_BUSINESS_PATH_SUFFIXES = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
)
_NON_BUSINESS_PATH_SEGMENTS = (
    "/assets/", "/static/", "/dist/", "/_next/static/", "/_nuxt/",
)

# ---- 敏感/基础设施路径 ----
# 这些路径已被 FastScanner._check_info_disclosure（SENSITIVE_PATHS）和
# dirscan 的敏感文件检测覆盖。若把它们创建为业务 feature 并跑全量 14 条
# 漏洞规则（SQLi/XSS/XXE/CORS…），不仅浪费请求，还会触发 WAF 封禁。
# 匹配方式：
#   - _SENSITIVE_DIR_SEGMENTS: 路径中包含该段即命中（如 /console/.svn/entries）
#   - _SENSITIVE_FILE_SUFFIXES: 路径等于或以该后缀结尾（如 /.env、/api/.env）
#   - _SENSITIVE_ENDPOINT_PREFIXES: 路径等于该前缀或以 前缀/ 开头（避免 /manage 误匹配 /manager）
_SENSITIVE_DIR_SEGMENTS = (
    "/.svn/", "/.git/", "/.hg/", "/.bzr/",
    "/.idea/", "/.vscode/",
    "/web-inf/", "/meta-inf/",
)
_SENSITIVE_FILE_SUFFIXES = (
    # VCS / dotfiles
    "/.svn", "/.svn/entries", "/.svn/wc.db",
    "/.git", "/.git/config", "/.git/head", "/.git/index",
    "/.hg", "/.bzr",
    "/.env", "/.env.local", "/.env.production", "/.env.bak",
    "/.ds_store", "/.htaccess", "/.htpasswd",
    # Config files
    "/web.config", "/config.php.bak", "/config.yml", "/config.yaml", "/config.json",
    "/application.yml", "/application.yaml", "/application.properties",
    "/bootstrap.yml", "/bootstrap.properties",
    "/docker-compose.yml", "/dockerfile", "/.dockerignore",
    # Backup / database dumps
    "/backup.sql", "/db.sql", "/database.sql", "/dump.sql", "/data.sql",
    "/backup.zip", "/backup.tar.gz", "/www.zip", "/web.zip", "/site.zip",
    "/backup.rar",
    # Build / dependency files
    "/package.json", "/composer.json", "/requirements.txt", "/pom.xml", "/makefile",
    "/webpack.config.js", "/.babelrc",
    # PHP info / shells
    "/phpinfo.php", "/info.php", "/test.php",
    "/shell.php", "/cmd.php", "/eval.php",
    # Server status
    "/server-status", "/server-info",
    # API documentation endpoints (not business APIs to test for vulns)
    "/swagger-ui.html", "/swagger-ui/", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/openapi.json", "/openapi.yaml", "/api/swagger",
    "/swagger.json", "/swagger.yaml",
)
_SENSITIVE_ENDPOINT_PREFIXES = (
    "/actuator", "/manage", "/management",
    "/jolokia", "/eureka", "/hystrix",
    "/druid", "/h2-console", "/phpmyadmin", "/pma", "/adminer",
)

# ---- 管理后台 & 认证路径（DirScan 字典猜测） ----
# 这些路径是 dirscan 字典中的高频猜测项（/dashboard、/login 等），
# 在 wildcard 站点上会全部命中 200，导致创建大量无效 feature。
# 它们应由 FastScanner 的 info_disclosure 规则检测，而非创建业务 feature 跑全量漏洞测试。
# 匹配方式：精确匹配 或 路径前缀匹配
_ADMIN_PANEL_PATHS = (
    "/admin", "/administrator", "/administrator/",
    "/backend", "/cpanel", "/control", "/cp",
    "/dashboard", "/manager", "/webadmin",
)
# ★ /login /signin 已从过滤列表移除：登录页是主要测试目标，应使用
# LOGIN_PAGE_CHECKLIST 专用检测（验证码绕过/弱口令/SQL注入等），
# 而非被当作"非业务路径"过滤掉。
# 保留 /register /signup /sso /oauth /logout 过滤：这些是次要认证路径，
# 仍需过滤防止 wildcard 站点 feature 爆炸。
_AUTH_PATH_PREFIXES = (
    "/register", "/signup",
    "/sso", "/oauth", "/logout",
)


def _is_non_business_path(path: str) -> bool:
    """判断路径是否为非业务路径（静态资源或敏感/基础设施路径）。

    敏感路径（/.svn/entries、/.git/config、/actuator/env 等）已由 FastScanner
    的 _check_info_disclosure 和 dirscan 的敏感文件检测覆盖，不应创建为业务
    feature 并跑全量漏洞规则。

    2026-08-08：新增管理后台/认证路径过滤——这些是 dirscan 字典高频猜测项，
    在 wildcard 站点上全部返回 200，导致 feature 爆炸（8921 checklist）。
    改为直接在 DirScan 摘要中记录，不创建业务 feature。
    """
    p = (path or "").lower().rstrip("/")
    if not p:
        return False
    # 静态资源后缀
    if any(p.endswith(s) for s in _NON_BUSINESS_PATH_SUFFIXES):
        return True
    # 静态资源路径段
    if any(seg in p for seg in _NON_BUSINESS_PATH_SEGMENTS):
        return True
    # 敏感目录段（VCS、IDE、框架配置目录）
    if any(seg in p for seg in _SENSITIVE_DIR_SEGMENTS):
        return True
    # 敏感文件（精确或后缀匹配，后缀含 / 前缀避免误匹配）
    if any(p == s or p.endswith(s) for s in _SENSITIVE_FILE_SUFFIXES):
        return True
    # 敏感端点前缀（精确或 path 前缀匹配，避免 /manage 误匹配 /manager）
    if any(p == pre or p.startswith(pre + "/") for pre in _SENSITIVE_ENDPOINT_PREFIXES):
        return True
    # ★ 管理后台精确匹配（字典猜测项，不应创建 feature）
    if p in _ADMIN_PANEL_PATHS:
        return True
    # ★ 认证路径精确或前缀匹配（字典猜测项，不应创建 feature）
    if any(p == pre or p.startswith(pre + "/") for pre in _AUTH_PATH_PREFIXES):
        return True
    return False


# ============================================================
# L1b: 主动目录爆破发现新 API（dirsearch 风格）
# ============================================================

async def discover_apis_from_dirscan(
    sitemap: Sitemap,
    target_url: str,
    auth_headers: dict | None = None,
    existing_apis: list[_DiscoveredAPI] | None = None,
) -> tuple[list[_DiscoveredAPI], dict[str, int]]:
    """使用 DirectoryScanner 主动爆破目标，发现 sitemap 中没有的 API 端点。

    与 discover_new_apis_from_flows 互补：
    - flows 扫描依赖被动流量（mitmproxy 记录），代理不可用时为空
    - dirscan 主动发请求探测，不依赖代理

    Args:
        existing_apis: 已从 flows 发现的 API，用于去重（避免重复）。

    Returns:
        (apis, stats): apis 是新发现的 API 列表，stats 是统计信息。
    """
    stats = {
        "dirscan_total": 0,
        "dirscan_discovered": 0,
        "dirscan_sensitive": 0,
        "dirscan_already_known": 0,
        "dirscan_duplicate": 0,
        "dirscan_error": "",
    }

    if not target_url:
        return [], stats

    try:
        from core.dir_scanner import DirectoryScanner
    except ImportError:
        stats["dirscan_error"] = "DirectoryScanner 导入失败"
        return [], stats

    # 计算已知 API 集合（用于 dedup）
    known_keys: set[str] = set()
    try:
        for api_key in (sitemap.apis or {}).keys():
            parts = api_key.split(" ", 1)
            if len(parts) == 2:
                m = parts[0].upper()
                u = parts[1].strip()
                pu = urlparse(u)
                if pu.netloc:
                    known_keys.add(f"{m} {pu.netloc.lower()}{pu.path}")
                else:
                    known_keys.add(f"{m} {pu.path}")
    except Exception:
        pass

    # 已从 flows 发现的 API 也加入去重集合
    if existing_apis:
        for api in existing_apis:
            known_keys.add(api.key)

    target_host = urlparse(target_url).netloc.lower()

    try:
        scanner = DirectoryScanner(
            max_workers=20,
            timeout=8.0,
            recursive=True,
            max_depth=2,
        )
        dir_result = await scanner.scan(
            target_url,
            auth_headers=auth_headers,
        )
    except Exception as e:
        log.warning("supplemental: dirscan 失败（非致命）: %s", e)
        stats["dirscan_error"] = f"{type(e).__name__}: {str(e)[:120]}"
        return [], stats

    stats["dirscan_total"] = dir_result.total_requests
    stats["dirscan_sensitive"] = dir_result.sensitive_count

    # 把目录扫描发现的存活路径转换为 _DiscoveredAPI
    discovered: list[_DiscoveredAPI] = []
    for entry in dir_result.entries:
        # 跳过非业务路径
        if _is_non_business_path(entry.path):
            continue

        # 构造 _DiscoveredAPI（复用 flows 的数据结构）
        flow_like = {
            "method": "GET",
            "url": entry.url,
            "status_code": entry.status,
            "response_body": "",
            "content_type": entry.content_type,
            "timestamp": time.time(),
            "id": f"dirscan_{entry.path}",
            "request_body": "",
        }
        api = _DiscoveredAPI(flow_like)

        # scope 过滤
        if api.host != target_host and not _host_in_scope(api.host, {target_host} | {
            d.lower().lstrip(".") for d in (getattr(sitemap, "extra_scope", None) or []) if d
        }):
            continue

        # 已知 API 去重
        if api.key in known_keys:
            stats["dirscan_already_known"] += 1
            continue

        # 与已有发现去重
        if any(a.key == api.key for a in discovered):
            stats["dirscan_duplicate"] += 1
            continue

        known_keys.add(api.key)
        discovered.append(api)

    # 把敏感路径发现也记录到 stats（供报告体现）
    if dir_result.findings:
        stats["dirscan_sensitive_findings"] = [
            {"vuln_type": f.vuln_type, "severity": f.severity, "url": f.url}
            for f in dir_result.findings
        ]

    stats["dirscan_discovered"] = len(discovered)
    log.info(
        "supplemental: dirscan 完成 — 请求 %d, 发现 %d 个新 API, %d 个敏感泄露",
        dir_result.total_requests, len(discovered), dir_result.sensitive_count,
    )
    return discovered, stats
