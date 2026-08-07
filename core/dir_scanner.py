"""
DirectoryScanner — dirsearch 风格的目录/文件爆破模块。

当目标根路径不可达（5xx / 超时）或仅做被动侦察时，对目标主机进行
基于字典的目录与文件枚举，发现存活端点、敏感文件与信息泄露。

设计参考：https://github.com/maurosoria/dirsearch

核心能力：
- 内置精简字典（管理后台 / 配置 / 备份 / 调试 / Swagger / Actuator 等）
- 并发请求 + 信号量限流
- 通配符 / 软 404 假阳性过滤（随机路径基线对比，dirsearch 同款思路）
- 状态码白名单过滤
- 主机可达性预检（连接级失败立即中止，避免对死主机打满字典）
- WAF / 超时熔断（连续拦截或超时即降速或中止）
- 可选递归（深度受限 + 候选目录白名单，请求量可控）
- 可选扩展名追加（备份文件发现）
- 发现结果回写 sitemap（add_page / add_api）并产出 info_disclosure 发现
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import re
import string
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlparse

import httpx

from core.log import get_logger

log = get_logger("dir_scanner")


# ============================================================
# 内置精简字典（~190 条，覆盖渗透高频路径）
# 字典项不含前导斜杠；含子路径的用 "/" 分隔（如 "actuator/health"）
# ============================================================

DEFAULT_WORDLIST: list[str] = [
    # ---- 管理后台 / 控制台 ----
    "admin", "administrator", "manage", "management", "manager", "backend",
    "console", "dashboard", "control", "panel", "cp", "cpanel", "webadmin",
    "admin.php", "admin.html", "admin/login", "admin/index",
    "pma", "phpmyadmin", "adminer", "adminer.php", "dbadmin",
    # ---- 认证 / 账号 ----
    "login", "signin", "signup", "register", "oauth", "sso", "cas", "logout",
    "auth", "sso/login", "login.html", "login.php",
    # ---- API / 接口文档 ----
    "api", "apis", "rest", "graphql", "graphiql", "api/v1", "api/v2",
    "swagger", "swagger-ui", "swagger-ui.html", "swagger-ui/index.html",
    "swagger.json", "swagger.yaml", "v2/api-docs", "v3/api-docs",
    "openapi.json", "openapi.yaml", "api-docs", "api/help", "api/docs",
    # ---- 配置 / 敏感文件 ----
    ".env", ".env.local", ".env.production", ".env.bak",
    ".git/config", ".git/HEAD", ".git/index", ".svn/entries", ".svn/wc.db",
    ".DS_Store", ".htaccess", ".htpasswd", "web.config",
    "config.json", "config.yaml", "config.yml", "config.php", "config.bak",
    "application.yml", "application.yaml", "application.properties",
    "bootstrap.yml", "bootstrap.properties",
    # ---- 备份 / 数据库 ----
    "backup", "backup.zip", "backup.sql", "backup.tar.gz", "backup.rar",
    "db.sql", "database.sql", "dump.sql", "data.sql",
    "www.zip", "web.zip", "site.zip", "wwwroot.zip", "1.zip", "bak",
    "backup.zip.bak", "db.bak",
    # ---- Spring Boot Actuator 全端点（高危信息泄露 + RCE）----
    "actuator", "actuator/health", "actuator/env", "actuator/info",
    "actuator/heapdump", "actuator/mappings", "actuator/beans",
    "actuator/configprops", "actuator/trace", "actuator/httptrace",
    "actuator/loggers", "actuator/threaddump", "actuator/metrics",
    "actuator/auditevents", "actuator/scheduledtasks",
    "actuator/refresh", "actuator/restart", "actuator/shutdown",
    "actuator/sessions", "actuator/prometheus", "actuator/logfile",
    "actuator/conditions", "actuator/caches", "actuator/startup",
    "actuator/flyway", "actuator/liquibase", "actuator/integrationgraph",
    "actuator/jolokia", "actuator/jolokia/list",
    # Actuator 1.x context-path 变体
    "manage", "manage/health", "manage/env", "manage/heapdump",
    "manage/refresh", "manage/jolokia",
    "management", "management/health", "management/env",
    # Spring Cloud Gateway（CVE-2022-22947 SpEL RCE）
    "actuator/gateway/routes", "actuator/gateway/refresh",
    "actuator/gateway/globalfilters", "actuator/gateway/routefilters",
    "gateway/actuator", "gateway/actuator/gateway/routes",
    # Spring Cloud Function（CVE-2022-22963 SpEL RCE）
    "functionRouter",
    # Spring Cloud Config Server（信息泄露）
    "application/default", "application/default/master",
    "application-dev.yml", "application-prod.yml",
    "application-dev.properties", "application-prod.properties",
    # Spring Cloud Eureka（未授权 → 内网服务列表）
    "eureka", "eureka/apps", "eureka/lastn", "eureka/v2/apps",
    # Spring Cloud Hystrix（Dashboard + 监控流）
    "hystrix", "hystrix.stream", "hystrix/monitor",
    # Spring Boot Admin（未授权管理面板）
    "instances", "instances/applications", "applications",
    # Jolokia（JMX over HTTP → JNDI RCE）
    "jolokia", "jolokia/list", "jolokia/version", "jolokia/read",
    "jolokia/exec", "jolokia/search",
    # Spring 路径穿越绕过变体
    ";/actuator/env", "..;/actuator/env", ";/actuator",
    # ---- Java / 中间件默认后台 ----
    "manager", "manager/html", "manager/status", "host-manager",
    "jmx-console", "jmx-console/", "jenkins", "struts",
    "weblogic", "console", "ibm/console", "solr", "solr/admin",
    # Spring Boot 静态资源 / 配置泄露
    "application.yml", "application.yaml", "application.properties",
    "bootstrap.yml", "bootstrap.properties",
    "WEB-INF/web.xml", "WEB-INF/classes/application.yml",
    "META-INF/MANIFEST.MF", "META-INF/spring.factories",
    # ---- PHP / CMS ----
    "wp-admin", "wp-login.php", "wp-config.php", "wp-config.php.bak",
    "xmlrpc.php", "install.php", "info.php", "phpinfo.php", "test.php",
    "wp-content", "wp-content/uploads", "wp-content/debug.log",
    # ---- .NET ----
    "elmah.axd", "trace.axd", "aspnet_client", "web.config.bak",
    # ---- 调试 / 监控 / 健康检查 ----
    "debug", "debug/pprof", "debug/vars", "_debug", "__debug__",
    "metrics", "health", "healthz", "readyz", "status", "ping", "info",
    "pprof", "pprof/goroutine", "prometheus",
    # ---- 服务状态 / 元信息 ----
    "server-status", "server-info", "status.php", "status.json",
    ".well-known/security.txt", ".well-known/openid-configuration",
    ".well-known/apple-app-site-association",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    # ---- 文档 ----
    "docs", "documentation", "doc", "help", "readme", "readme.md",
    "readme.txt", "changelog", "changelog.md", "CHANGELOG",
    # ---- 上传 / 下载 / 静态 ----
    "upload", "uploads", "files", "file", "download", "downloads",
    "static", "assets", "public", "images", "img", "media", "attachment",
    # ---- 源码 / 版本控制 / CI ----
    ".gitignore", ".gitattributes", "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile", "package.json", "package-lock.json", "composer.json",
    "composer.lock", "yarn.lock", ".eslintrc", ".dockerenv", "Makefile",
    # ---- 通用目录 ----
    "index", "home", "main", "app", "application", "src", "dist", "build",
    "lib", "libs", "js", "css", "bin", "scripts", "tools", "util", "utils",
    "tmp", "temp", "log", "logs", "cache", "data", "db", "sql", "test",
    "tests", "config", "conf", "etc", "var", "run", "common", "system",
    # ---- 云 / 存储 / 其他 ----
    "s3", ".aws", "firebase", "storage", "oss", "minio", "buckets",
    ".svn", ".hg", ".bzr", ".git",
    "phpunit", "phpunit.xml", "composer.json.bak", "vendor", "vendor/composer",
]

# 递归候选目录白名单：只对这些目录做二级爆破，控制请求量
RECURSE_CANDIDATES: set[str] = {
    "admin", "api", "config", "backup", "debug", "actuator", "manage",
    "management", "console", "swagger", "docs", "static", "upload",
    "uploads", "files", "test", "app", "application", "manager",
    "wp-admin", "wp-content", "server", "system", "public", "assets",
    "eureka", "jolokia", "gateway", "instances",
}

# 默认收录的状态码（排除 404；含重定向/认证/方法不允许/服务端错误）
DEFAULT_INCLUDE_STATUS: set[int] = {
    200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 501,
}

# 敏感路径 → 信息泄露分类（命中即产出 finding）
SENSITIVE_PATTERNS: list[tuple[str, str, str]] = [
    # (路径关键字(小写), 漏洞类型, 严重度)
    (".git", "源码泄露(.git)", "high"),
    (".svn", "源码泄露(.svn)", "high"),
    (".hg", "源码泄露(.hg)", "high"),
    (".env", "环境配置泄露(.env)", "high"),
    (".ds_store", "目录列举(.DS_Store)", "medium"),
    (".htaccess", "配置文件泄露(.htaccess)", "medium"),
    (".htpasswd", "凭证泄露(.htpasswd)", "high"),
    ("web.config", "配置文件泄露(web.config)", "medium"),
    ("backup", "备份文件泄露", "high"),
    (".sql", "数据库备份泄露", "high"),
    (".zip", "压缩包泄露", "medium"),
    (".tar.gz", "压缩包泄露", "medium"),
    (".rar", "压缩包泄露", "medium"),
    (".bak", "备份文件泄露", "medium"),
    ("actuator/env", "Actuator 环境信息泄露", "high"),
    ("actuator/heapdump", "Actuator 堆转储泄露", "critical"),
    ("actuator/trace", "Actuator 请求追踪泄露", "high"),
    ("actuator/httptrace", "Actuator 请求追踪泄露", "high"),
    ("actuator/loggers", "Actuator 日志配置泄露", "medium"),
    ("actuator/threaddump", "Actuator 线程转储泄露", "medium"),
    ("actuator/configprops", "Actuator 配置泄露", "high"),
    ("actuator/mappings", "Actuator 路由映射泄露", "medium"),
    ("actuator/beans", "Actuator Bean 信息泄露", "medium"),
    ("actuator/refresh", "Actuator 配置刷新(可触发JNDI)", "critical"),
    ("actuator/restart", "Actuator 应用重启(DoS+RCE触发)", "critical"),
    ("actuator/jolokia", "Actuator Jolokia JMX 未授权(JNDI RCE)", "critical"),
    ("actuator/gateway", "Spring Cloud Gateway 路由(SpEL RCE)", "critical"),
    ("actuator/shutdown", "Actuator 关闭应用(DoS)", "critical"),
    ("manage/env", "Actuator 1.x 环境信息泄露", "high"),
    ("manage/heapdump", "Actuator 1.x 堆转储泄露", "critical"),
    ("manage/refresh", "Actuator 1.x 配置刷新(可触发JNDI)", "critical"),
    ("eureka/apps", "Eureka 注册中心未授权(内网服务列表)", "high"),
    ("eureka", "Eureka 注册中心未授权", "medium"),
    ("hystrix", "Hystrix Dashboard 未授权", "medium"),
    ("jolokia", "Jolokia JMX 未授权(JNDI RCE)", "critical"),
    ("functionrouter", "Spring Cloud Function(SpEL RCE)", "critical"),
    ("application/default", "Spring Cloud Config 配置泄露", "high"),
    ("swagger", "API 文档泄露(Swagger)", "medium"),
    ("api-docs", "API 文档泄露", "medium"),
    ("openapi", "API 文档泄露(OpenAPI)", "medium"),
    ("phpinfo", "PHP 信息泄露(phpinfo)", "medium"),
    ("info.php", "PHP 信息泄露", "medium"),
    ("server-status", "Apache server-status 泄露", "medium"),
    ("server-info", "Apache server-info 泄露", "medium"),
    ("jmx-console", "JMX 控制台未授权", "high"),
    ("manager/html", "Tomcat Manager 未授权", "high"),
    ("jenkins", "Jenkins 未授权访问", "high"),
    ("heapdump", "堆转储泄露", "critical"),
    ("pprof", "pprof 调试接口泄露", "high"),
    ("debug/vars", "Go expvar 调试接口泄露", "medium"),
    ("wp-config", "WordPress 配置泄露", "high"),
    ("xmlrpc.php", "WordPress XMLRPC 暴露", "low"),
    ("application.yml", "应用配置泄露(application.yml)", "high"),
    ("application.properties", "应用配置泄露(application.properties)", "high"),
    (".dockerenv", "容器环境标识泄露", "low"),
    ("composer.json", "PHP 依赖配置泄露", "low"),
    ("package.json", "Node 依赖配置泄露", "low"),
]

# 备份扩展名：当启用扩展追加时，对每个字典项尝试这些后缀
DEFAULT_EXTENSIONS: list[str] = [".bak", ".old", ".orig", ".swp", ".save"]

# ★ 关键路径子集：基线失败（主机可能不可达）时 best-effort 探测这些高频路径。
# 排序按"最可能独立存活"优先（API 文档 / 调试端点 / 管理后台 / 配置泄露）。
CRITICAL_PATHS: list[str] = [
    "robots.txt", "sitemap.xml",
    "swagger-ui.html", "swagger.json", "v2/api-docs", "v3/api-docs",
    "openapi.json", "api-docs",
    "actuator", "actuator/health", "actuator/env", "actuator/heapdump",
    "actuator/info", "actuator/mappings",
    "api", "api/v1", "api/v2",
    "admin", "login", "console", "manager/html",
    ".env", ".git/config", ".git/HEAD",
    "web.config", "application.yml", "application.properties",
    "backup.zip", "db.sql", "www.zip",
    "health", "healthz", "metrics", "info", "status", "ping",
    "server-status", "phpinfo.php", "info.php",
    "graphql", "graphiql",
    "debug", "debug/pprof", "pprof",
    "jenkins", "jmx-console",
    ".well-known/security.txt",
]

# 默认 UA（dirsearch 风格，避免被基础 WAF 按 UA 拦截）
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; DirScanner/1.0; +pentest-recon)"


# ============================================================
# 数据模型
# ============================================================

@dataclass
class DirEntry:
    """单个目录/文件探测结果。"""
    path: str               # 相对路径，如 "/admin" 或 "/actuator/env"
    url: str                # 完整 URL
    status: int             # HTTP 状态码
    length: int             # 响应体字节数
    content_type: str       # Content-Type
    redirect: str           # Location 头（无则空）
    is_directory: bool      # 推测是否为目录
    title: str              # 从 HTML <title> 提取的标题（无则空）
    body_hash: str          # 响应体哈希（用于通配符对比）


@dataclass
class DirFinding:
    """目录扫描产出的漏洞/信息泄露发现。"""
    vuln_type: str
    severity: str
    url: str
    detail: str
    evidence: str = ""


@dataclass
class DirScanResult:
    """目录扫描汇总结果。"""
    target: str
    entries: list[DirEntry] = field(default_factory=list)
    findings: list[DirFinding] = field(default_factory=list)
    total_requests: int = 0
    elapsed: float = 0.0
    host_unreachable: bool = False
    wildcard_detected: bool = False
    waf_blocked: bool = False
    timeout_blocked: bool = False
    recursed_dirs: int = 0
    # ★ 诊断字段：连接失败 / 超时次数（供前端判断"为什么 0 请求"）
    connect_errors: int = 0
    timeout_errors: int = 0
    # ★ 标记是否走了"关键路径兜底"（基线失败后仍 best-effort 探测高频路径）
    critical_path_fallback: bool = False

    @property
    def discovered_count(self) -> int:
        return len(self.entries)

    @property
    def sensitive_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "host_unreachable": self.host_unreachable,
            "wildcard_detected": self.wildcard_detected,
            "total_requests": self.total_requests,
            "elapsed": round(self.elapsed, 2),
            "discovered_count": self.discovered_count,
            "sensitive_count": self.sensitive_count,
            "recursed_dirs": self.recursed_dirs,
            "connect_errors": self.connect_errors,
            "timeout_errors": self.timeout_errors,
            "critical_path_fallback": self.critical_path_fallback,
            "entries": [
                {
                    "path": e.path, "url": e.url, "status": e.status,
                    "length": e.length, "content_type": e.content_type,
                    "redirect": e.redirect, "title": e.title,
                }
                for e in self.entries
            ],
            "findings": [
                {
                    "vuln_type": f.vuln_type, "severity": f.severity,
                    "url": f.url, "detail": f.detail, "evidence": f.evidence[:300],
                }
                for f in self.findings
            ],
        }


# ============================================================
# DirectoryScanner
# ============================================================

class DirectoryScanner:
    """dirsearch 风格的目录/文件爆破器。

    用法::

        scanner = DirectoryScanner(max_workers=20, recursive=True, max_depth=2)
        result = await scanner.scan("https://example.com/", auth_headers={...})
        for entry in result.entries:
            print(entry.status, entry.url)
    """

    def __init__(
        self,
        max_workers: int = 20,
        timeout: float = 8.0,
        extensions: list[str] | None = None,
        recursive: bool = True,
        max_depth: int = 2,
        max_recursed_dirs: int = 12,
        include_status: set[int] | None = None,
        wordlist: list[str] | None = None,
        extra_paths: list[str] | None = None,
        proxy: str | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        # 熔断阈值
        waf_block_threshold: int = 25,
        timeout_block_threshold: int = 15,
    ):
        self.max_workers = max(1, max_workers)
        self.timeout = timeout
        # 扩展追加：None/[] 表示不追加（仅按字典原文探测）
        self.extensions = list(extensions) if extensions else []
        self.recursive = recursive
        self.max_depth = max(1, max_depth)
        self.max_recursed_dirs = max_recursed_dirs
        self.include_status = include_status or DEFAULT_INCLUDE_STATUS
        # 合并字典：去重保序
        wl = list(wordlist) if wordlist else list(DEFAULT_WORDLIST)
        if extra_paths:
            wl.extend(extra_paths)
        seen: set[str] = set()
        self.wordlist: list[str] = []
        for w in wl:
            w = w.strip().lstrip("/")
            if w and w not in seen:
                seen.add(w)
                self.wordlist.append(w)
        self.proxy = proxy
        self.user_agent = user_agent
        self.waf_block_threshold = waf_block_threshold
        self.timeout_block_threshold = timeout_block_threshold

        # 运行态（每次 scan 重置）
        self._client: httpx.AsyncClient | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._total_requests = 0
        self._consecutive_timeout = 0
        self._consecutive_block = 0
        self._waf_blocked = False
        self._timeout_blocked = False
        # ★ 诊断计数器
        self._connect_errors = 0
        self._timeout_errors = 0
        # 通配符基线签名集合：{(status, length)}
        self._wildcard_sigs: set[tuple[int, int]] = set()
        self._wildcard_hashes: set[str] = set()

    # ---------- 公共入口 ----------

    async def scan(
        self,
        base_url: str,
        auth_headers: dict | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> DirScanResult:
        """对 base_url 执行目录/文件爆破。

        Args:
            base_url: 目标根 URL，如 "https://example.com/"。
            auth_headers: 可选认证头（Cookie/Authorization）。
            on_progress: 可选进度回调（接收日志字符串）。
        """
        base_url = self._normalize_base(base_url)
        result = DirScanResult(target=base_url)
        t0 = time.time()
        headers = self._build_headers(auth_headers)

        try:
            self._client = self._make_client()
            self._semaphore = asyncio.Semaphore(self.max_workers)

            # 1) 主机可达性预检 + 通配符基线（含重试）
            baseline_ok = await self._establish_baseline(
                base_url, headers, result, on_progress,
            )

            if baseline_ok:
                # 2a) 主机可达 → 全量字典爆破
                await self._scan_level(
                    base_url=base_url, headers=headers,
                    level=1, result=result, on_progress=on_progress,
                )

                # 3) 递归：对命中目录的子目录做二级爆破
                if self.recursive and self.max_depth >= 2 and not self._waf_blocked:
                    await self._recurse(base_url, headers, result, on_progress)
            else:
                # 2b) ★ 基线失败（主机可能不可达）→ 关键路径兜底
                # 不完全跳过：目标可能只是根路径 5xx / TLS 不稳定，
                # 子路径（/actuator/env, /swagger-ui.html 等）可能独立存活。
                # 关键路径请求也会快速 ConnectError，不会浪费太多时间。
                result.critical_path_fallback = True
                await self._scan_critical_paths(
                    base_url, headers, result, on_progress,
                )

        except Exception as e:
            log.warning("[DirScan] 扫描异常: %s", e, exc_info=True)
        finally:
            if self._client and not self._client.is_closed:
                try:
                    await self._client.aclose()
                except Exception:
                    pass

        result.elapsed = time.time() - t0
        # 标记熔断状态 + 诊断计数
        result.waf_blocked = self._waf_blocked
        result.timeout_blocked = self._timeout_blocked
        result.connect_errors = self._connect_errors
        result.timeout_errors = self._timeout_errors
        result.total_requests = self._total_requests
        log.info(
            "[DirScan] 完成: target=%s 请求=%d 发现=%d 敏感=%d 递归目录=%d "
            "耗时=%.1fs host_unreachable=%s wildcard=%s waf=%s timeout=%s "
            "connect_err=%d timeout_err=%d fallback=%s",
            base_url, self._total_requests, result.discovered_count,
            result.sensitive_count, result.recursed_dirs, result.elapsed,
            result.host_unreachable, result.wildcard_detected,
            result.waf_blocked, result.timeout_blocked,
            result.connect_errors, result.timeout_errors,
            result.critical_path_fallback,
        )
        return result

    # ---------- 内部：客户端与请求 ----------

    def _make_client(self) -> httpx.AsyncClient:
        kwargs = {
            "timeout": httpx.Timeout(self.timeout),
            "follow_redirects": False,  # 不跟随重定向，以便记录 301/302
            "verify": False,
            "limits": httpx.Limits(max_connections=self.max_workers * 2),
            "headers": {"User-Agent": self.user_agent},
        }
        if self.proxy:
            kwargs["proxy"] = self.proxy
        return httpx.AsyncClient(**kwargs)

    def _build_headers(self, auth_headers: dict | None) -> dict:
        h = {"User-Agent": self.user_agent}
        if auth_headers:
            for k, v in auth_headers.items():
                if v:
                    h[k] = v
        return h

    @staticmethod
    def _normalize_base(base_url: str) -> str:
        p = urlparse(base_url)
        # 保留 scheme + netloc，丢弃 path/query
        base = f"{p.scheme}://{p.netloc}"
        return base.rstrip("/") + "/"

    async def _establish_baseline(
        self, base_url: str, headers: dict,
        result: DirScanResult, on_progress,
    ) -> bool:
        """主机可达性预检 + 软 404 通配符基线。

        每个随机路径最多重试 ``baseline_retries`` 次，避免瞬时网络抖动误判。
        全部重试均失败才判定主机不可达。

        Returns:
            True 表示主机可达，可继续全量扫描；
            False 表示连接级不可达（调用方应走关键路径兜底）。
        """
        baseline_retries = 2
        if on_progress:
            on_progress("目录扫描: 主机可达性预检...")
        # 两个随机路径探测通配符
        rand_paths = [
            "/" + "".join(random.choices(string.ascii_lowercase, k=16)),
            "/" + "".join(random.choices(string.ascii_lowercase, k=16)),
        ]
        for rp in rand_paths:
            entry = None
            for attempt in range(baseline_retries):
                entry = await self._probe(
                    urljoin(base_url, rp), headers, tag="baseline")
                if entry is not None:
                    break
                # 基线单次失败，短暂等待后重试
                if attempt < baseline_retries - 1:
                    await asyncio.sleep(1.0)

            if entry is None:
                # 连接级失败（ConnectError/超时等）→ 主机不可达
                if on_progress:
                    on_progress(
                        f"目录扫描: 基线探测失败（{baseline_retries} 次重试均失败），"
                        f"主机可能不可达，切换关键路径兜底模式"
                    )
                result.host_unreachable = True
                return False
            # 非 404 响应 → 可能存在软 404 / 通配符
            if entry.status != 404:
                self._wildcard_sigs.add((entry.status, entry.length))
                self._wildcard_hashes.add(entry.body_hash)
                result.wildcard_detected = True

        if result.wildcard_detected and on_progress:
            on_progress(
                f"目录扫描: 检测到软 404/通配符（基线状态 "
                f"{[s for s,_ in self._wildcard_sigs]}），启用假阳性过滤"
            )
        return True

    async def _scan_critical_paths(
        self, base_url: str, headers: dict,
        result: DirScanResult, on_progress,
    ) -> None:
        """关键路径兜底：基线失败后 best-effort 探测高频路径。

        目标可能只是根路径 5xx / TLS 不稳定，子路径（/actuator/env、
        /swagger-ui.html 等）可能独立存活。关键路径请求也会快速
        ConnectError，不会浪费太多时间。
        """
        paths = CRITICAL_PATHS
        if on_progress:
            on_progress(
                f"目录扫描: 关键路径兜底 — best-effort 探测 {len(paths)} 个高频路径"
            )

        tasks = [
            self._probe_entry(base_url, "", word, headers, result)
            for word in paths
        ]
        for chunk in self._chunked(tasks, self.max_workers * 2):
            await asyncio.gather(*chunk, return_exceptions=True)

        if on_progress:
            on_progress(
                f"目录扫描: 关键路径兜底完成 — 请求 {self._total_requests} 次, "
                f"发现 {result.discovered_count} 个存活路径"
            )

    async def _scan_level(
        self, base_url: str, headers: dict, level: int,
        result: DirScanResult, on_progress,
        sub_prefix: str = "",
    ) -> None:
        """对单层目录执行字典爆破。

        Args:
            base_url: 站点根 URL（含尾斜杠）。
            sub_prefix: 子目录前缀，如 "admin/"（相对根）。
        """
        if self._waf_blocked or self._timeout_blocked:
            return

        # 构造待探测路径列表（应用扩展追加）
        candidates = self._build_candidates()
        total = len(candidates)
        if on_progress and level == 1:
            on_progress(f"目录扫描: 开始爆破 {total} 条路径（{self.max_workers} 并发）")

        # 并发探测
        tasks = [
            self._probe_entry(base_url, sub_prefix, word, headers, result)
            for word in candidates
        ]
        # 分批 gather 避免一次性创建超大协程列表（字典较小，直接 gather 也可）
        for chunk in self._chunked(tasks, self.max_workers * 4):
            await asyncio.gather(*chunk, return_exceptions=True)

    def _build_candidates(self) -> list[str]:
        """生成字典候选（含扩展追加）。"""
        out: list[str] = []
        for w in self.wordlist:
            out.append(w)
            for ext in self.extensions:
                if not w.lower().endswith(ext):
                    out.append(f"{w}{ext}")
        return out

    async def _probe_entry(
        self, base_url: str, sub_prefix: str, word: str,
        headers: dict, result: DirScanResult,
    ) -> None:
        if self._waf_blocked or self._timeout_blocked:
            return
        path = f"/{sub_prefix}{word}" if sub_prefix else f"/{word}"
        url = urljoin(base_url, path.lstrip("/"))
        entry = await self._probe(url, headers, tag=word)
        if entry is None:
            return
        # 状态码白名单过滤
        if entry.status not in self.include_status:
            return
        # 软 404 / 通配符过滤
        if self._is_wildcard(entry):
            return
        result.entries.append(entry)
        # 敏感路径分类
        for keyword, vtype, severity in SENSITIVE_PATTERNS:
            if keyword in entry.path.lower():
                result.findings.append(DirFinding(
                    vuln_type=vtype, severity=severity, url=entry.url,
                    detail=f"目录扫描发现敏感路径: {entry.path} "
                           f"(HTTP {entry.status}, {entry.length}B, {entry.content_type})",
                    evidence=f"GET {entry.url} -> {entry.status} "
                             f"{entry.content_type} | title={entry.title or '-'}",
                ))
                break

    async def _probe(self, url: str, headers: dict, tag: str = "") -> DirEntry | None:
        """发送单个 GET 请求，返回 DirEntry。失败/熔断返回 None。"""
        if self._waf_blocked or self._timeout_blocked:
            return None
        async with self._semaphore:
            if self._waf_blocked or self._timeout_blocked:
                return None
            try:
                resp = await self._client.get(url, headers=headers)
            except httpx.ConnectError as e:
                # 连接级失败：计数，但不计入超时熔断（连接拒绝≠超时）
                self._connect_errors += 1
                log.debug("[DirScan] %s connect error: %s", tag, str(e)[:120])
                return None
            except httpx.TimeoutException:
                self._timeout_errors += 1
                self._consecutive_timeout += 1
                if (self._consecutive_timeout >= self.timeout_block_threshold
                        and not self._timeout_blocked):
                    self._timeout_blocked = True
                    log.warning(
                        "[DirScan] 超时熔断：连续超时 %d 次，中止剩余请求",
                        self._consecutive_timeout,
                    )
                return None
            except Exception as e:
                log.debug("[DirScan] %s request fail: %s", tag, str(e)[:120])
                return None

            self._consecutive_timeout = 0
            self._total_requests += 1
            status = resp.status_code
            body = resp.content or b""
            length = len(body)

            # WAF 拦截计数（429/503 视为限流/拦截；403 单独累计）
            if status in (429, 503):
                self._consecutive_block += 1
                if (self._consecutive_block >= self.waf_block_threshold
                        and not self._waf_blocked):
                    self._waf_blocked = True
                    log.warning(
                        "[DirScan] WAF 限流熔断：连续 %d 次 429/503，中止剩余请求",
                        self._consecutive_block,
                    )
            else:
                self._consecutive_block = 0

            content_type = resp.headers.get("content-type", "").split(";")[0].strip()
            redirect = resp.headers.get("location", "")
            body_text = body.decode("utf-8", errors="ignore")[:8192]
            title = self._extract_title(body_text)
            is_dir = (
                status in (301, 302, 307, 308)
                and redirect.rstrip("/").endswith(url.rstrip("/") + "/")
            ) or (status == 200 and url.endswith("/"))
            body_hash = hashlib.md5(body[:4096]).hexdigest()
            return DirEntry(
                path="/" + urlparse(url).path.lstrip("/"),
                url=url, status=status, length=length,
                content_type=content_type, redirect=redirect,
                is_directory=is_dir, title=title, body_hash=body_hash,
            )

    # ---------- 内部：递归 ----------

    async def _recurse(
        self, base_url: str, headers: dict,
        result: DirScanResult, on_progress,
    ) -> None:
        """对命中的目录做受限递归。"""
        # 选取候选目录：命中 + 在白名单 + 像目录
        recurse_targets: list[str] = []
        seen_dirs: set[str] = set()
        for e in list(result.entries):
            base_name = e.path.strip("/").split("/")[-1].lower()
            if not base_name:
                continue
            # 仅对顶层目录递归（避免过深）
            if e.path.count("/") > 1:
                continue
            if base_name not in RECURSE_CANDIDATES:
                continue
            dir_key = e.path.rstrip("/") + "/"
            if dir_key in seen_dirs:
                continue
            seen_dirs.add(dir_key)
            recurse_targets.append(dir_key)
            if len(recurse_targets) >= self.max_recursed_dirs:
                break

        if not recurse_targets:
            return
        if on_progress:
            on_progress(
                f"目录扫描: 递归探测 {len(recurse_targets)} 个目录 "
                f"(最大深度 {self.max_depth})"
            )

        # 各子目录可能有不同软 404，重置基线后重新建立
        for sub in recurse_targets:
            if self._waf_blocked or self._timeout_blocked:
                break
            # 子目录基线：保留顶层基线，额外追加子目录随机探测
            sub_url = urljoin(base_url, sub.lstrip("/"))
            rand_entry = await self._probe(
                urljoin(sub_url, "".join(random.choices(string.ascii_lowercase, k=12))),
                headers, tag=f"recurse-baseline:{sub}",
            )
            if rand_entry is not None and rand_entry.status != 404:
                self._wildcard_sigs.add(
                    (rand_entry.status, rand_entry.length))
                self._wildcard_hashes.add(rand_entry.body_hash)

            await self._scan_level(
                base_url=base_url, headers=headers, level=2,
                result=result, on_progress=None, sub_prefix=sub,
            )
            result.recursed_dirs += 1

    # ---------- 内部：过滤工具 ----------

    def _is_wildcard(self, entry: DirEntry) -> bool:
        """判断响应是否匹配通配符/软 404 基线。

        匹配条件（任一即判为假阳性）：
        - body_hash 命中基线（响应体完全相同 → 经典软 404，最可靠）
        - (status, 精确 length) 命中基线（dirsearch 风格状态码+长度匹配）

        无基线时返回 False（正常 404 已由状态码白名单排除）。
        注意：对"回显请求路径"的动态软 404（body 随路径变化）存在漏判，
        这是 dirsearch 同款已知局限，需 --bf 级暴力才完全覆盖。
        """
        if not self._wildcard_sigs and not self._wildcard_hashes:
            return False
        if (entry.status, entry.length) in self._wildcard_sigs:
            return True
        if entry.body_hash in self._wildcard_hashes:
            return True
        return False

    @staticmethod
    def _extract_title(html: str) -> str:
        if not html:
            return ""
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        return ""

    @staticmethod
    def _chunked(items: list, size: int):
        """将列表切成指定大小的块。"""
        for i in range(0, len(items), size):
            yield items[i:i + size]


# ============================================================
# 便捷入口
# ============================================================

async def scan_directories(
    base_url: str,
    auth_headers: dict | None = None,
    max_workers: int = 20,
    recursive: bool = True,
    extensions: list[str] | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> DirScanResult:
    """一键目录爆破入口。

    用法::

        result = await scan_directories("https://example.com/")
        print(result.discovered_count, result.sensitive_count)
    """
    scanner = DirectoryScanner(
        max_workers=max_workers,
        recursive=recursive,
        extensions=extensions,
    )
    return await scanner.scan(base_url, auth_headers=auth_headers, on_progress=on_progress)
