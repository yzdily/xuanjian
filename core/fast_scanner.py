"""
FastScanner — 本地快速规则引擎

不依赖 LLM，基于预定义规则并发检测常见漏洞。
检测速度比 LLM 快 100 倍以上。

支持规则类型：
- SQL 注入（基于报错/布尔/时间盲注）
- XSS（反射型检测）
- 信息泄露（敏感路径/文件/响应头）
- 未授权访问（去认证对比）
- 弱口令（常见默认凭据）
- 目录穿越
- 命令注入
- SSRF
- CORS 配置错误
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin

import httpx

from core.log import get_logger

log = get_logger("fast_scanner")


# ============================================================
# 数据模型
# ============================================================

@dataclass
class VulnFinding:
    """漏洞发现结果"""
    vuln_type: str
    severity: str  # critical / high / medium / low / info
    url: str
    method: str
    detail: str
    evidence: str = ""
    payload: str = ""
    fix_suggestion: str = ""
    # ★ 证据质量（供 harm_validation 二次裁决参考）：
    #   header_only   = 仅根据响应头判定，无响应体敏感数据佐证（最易误报）
    #   body_confirmed = 响应体已确认含敏感数据特征
    #   content_match = 敏感路径/文件内容特征已匹配预期
    evidence_quality: str = ""


@dataclass
class ScanTarget:
    """单个扫描目标"""
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: str = ""
    params: dict = field(default_factory=dict)
    auth_headers: dict = field(default_factory=dict)  # 认证头（用于去认证对比）


@dataclass
class ScanResult:
    """扫描结果汇总"""
    target_url: str
    findings: list[VulnFinding] = field(default_factory=list)
    elapsed: float = 0.0
    total_requests: int = 0
    rules_run: int = 0
    blocked_count: int = 0
    timeout_count: int = 0
    error_count: int = 0

    @property
    def vuln_count(self) -> int:
        return len(self.findings)

    @property
    def high_severity_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in ("critical", "high"))

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "vuln_count": self.vuln_count,
            "high_severity_count": self.high_severity_count,
            "elapsed": round(self.elapsed, 2),
            "total_requests": self.total_requests,
            "rules_run": self.rules_run,
            "blocked_count": self.blocked_count,
            "timeout_count": self.timeout_count,
            "error_count": self.error_count,
            "findings": [
                {
                    "vuln_type": f.vuln_type,
                    "severity": f.severity,
                    "url": f.url,
                    "method": f.method,
                    "detail": f.detail,
                    "evidence": f.evidence[:500],
                    "payload": f.payload,
                    "fix_suggestion": f.fix_suggestion,
                }
                for f in self.findings
            ],
        }


# ============================================================
# 规则定义
# ============================================================

# SQL 注入报错特征
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"check the manual that corresponds to your MySQL",
    r"ORA-\d{5}", r"Oracle error", r"Oracle.*Driver",
    r"Microsoft SQL Server.*\d", r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver", r"macromedia.*sql",
    r"PostgreSQL.*ERROR", r"Warning.*\bpg_",
    r"valid PostgreSQL result", r"Npgsql\.",
    r"DB2 SQL error", r"SQLSTATE\[",
    r"SQLite3?::query", r"SQLite/JDBCDriver",
    r"SQLiteException", r"Warning.*sqlite_",
    r"Warning.*SQLite3",
    r"Unclosed quotation mark after the character string",
    r"Incorrect syntax near",
    r"Syntax error.*SQL",
    r"syntax error at or near",
]

# XSS 反射检测特征
XSS_REFLECT_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"<img[^>]+src[^>]+onerror",
    r"<svg[^>]+onload",
    r"<iframe[^>]*>",
]

# 敏感路径/文件
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/web.config", "/config.php.bak", "/config.yml",
    "/backup.sql", "/db.sql", "/database.sql",
    "/dump.sql", "/data.sql", "/backup.zip",
    "/backup.tar.gz", "/www.zip", "/web.zip",
    "/wp-config.php.bak", "/application.yml",
    "/swagger-ui.html", "/swagger-ui/", "/v2/api-docs",
    "/api-docs", "/openapi.json", "/api/swagger",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/heapdump", "/actuator/mappings",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/WEB-INF/web.xml", "/META-INF/",
    "/WEB-INF/classes/",
    "/druid/index.html", "/druid/login.html",
    "/console", "/h2-console", "/adminer.php",
    "/phpmyadmin/", "/pma/", "/mysql/",
    "/.idea/", "/.vscode/",
    "/package.json", "/composer.json",
    "/webpack.config.js", "/.babelrc",
    "/source.map", "/app.js.map", "/main.js.map",
    "/docker-compose.yml", "/Dockerfile",
    "/.dockerignore", "/Makefile",
    "/requirements.txt", "/pom.xml",
    "/shell.php", "/cmd.php", "/eval.php",
]

# 默认弱口令
WEAK_CREDENTIALS = [
    ("admin", "admin"), ("admin", "123456"), ("admin", "admin123"),
    ("admin", "password"), ("admin", "admin@123"),
    ("root", "root"), ("root", "123456"), ("root", "password"),
    ("test", "test"), ("test", "123456"),
    ("guest", "guest"), ("user", "user"),
    ("administrator", "administrator"),
    ("admin", "P@ssw0rd"), ("admin", "Passw0rd"),
    ("sa", "sa"), ("sa", "123456"),
    ("postgres", "postgres"), ("postgres", "123456"),
    ("oracle", "oracle"),
]

# 命令注入特征
CMD_INJECTION_PATTERNS = [
    r"uid=\d+\(.*\)\s+gid=\d+",
    r"root:.*:0:0:",
    r"total \d+",  # ls -la 输出
    r"Volume Serial Number",
    r"Directory of ",
    r"COMMAND\s+PID\s+USER",
    r"/bin/(ba)?sh",
    r"whoami",
]

# CORS 错误配置检测
CORS_VULN_HEADERS = {
    "access-control-allow-origin": ["*", "null"],
    "access-control-allow-credentials": ["true"],
}

# 信息泄露响应头：仅当值含具体版本号时才视为有价值的泄露。
# 纯 banner（如 "nginx"、"Express" 无版本号）几乎所有站点都有，不构成可被 SRC 收录的漏洞。
INFO_LEAK_HEADERS = {
    "x-powered-by": r".+",
    "server": r".+",
    "x-aspnet-version": r".+",
    "x-generator": r".+",
}

# 版本号特征：匹配 "nginx/1.2.3"、"Apache/2.4.1 (Ubuntu)"、"Microsoft-HTTPAPI/2.0"、
# "Express/4.18.2"、"(ASP.NET 4.0.30319)" 等。纯产品名不带版本号（如 "nginx"、"cloudflare"）不算。
_HEADER_VERSION_RE = re.compile(
    r"/?\s*v?\d+(?:\.\d+){1,3}"          # 1.2 / 1.2.3 / 1.2.3.4
    r"|"                                  # 或
    r"\(\s*[A-Za-z.\s]+\s*\d+(?:\.\d+)+\s*\)",  # (ASP.NET 4.0.30319)
    re.IGNORECASE,
)


# ============================================================
# 多因素判定辅助：响应体敏感数据 / 公开数据特征
# （用于未授权访问、CORS、信息泄露等多因素验证，避免"只看响应头/长度"误报）
# ============================================================

# 敏感数据特征：响应体出现这些才认为"真有危害"
SENSITIVE_DATA_PATTERNS = [
    r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)"
    r"\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{6,}",          # 密钥/令牌赋值
    r"\b\d{15,18}\b",                                    # 身份证号
    r"\b1[3-9]\d{9}\b",                                  # 中国手机号
    r"\b4\d{15}\b|\b5[1-5]\d{14}\b",                     # 银行卡号
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",  # 邮箱（批量出现才算）
    r"\"(?:user|admin|account|order|balance|idcard|phone|email|address)\"\s*:\s*",
    # JSON 字段暴露用户/账户/订单等私有数据
    r"<(?:userList|userInfo|accountList|orderList|user_list|admin_list)\b",
    r"(?:jdbc:|mysql://|postgresql://|redis://|mongodb://)",  # 数据库连接串
    r"(?:access_key|secret_key|accesskeyid|secretaccesskey)\s*[:=]",
    r"AKIA[0-9A-Z]{16}",                                 # AWS Access Key
    r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----",          # 私钥
    r"stack[_-]?trace|exception\s+(?:in|at)\s+",         # 错误堆栈
    r"/home/\w+|/var/\w+|C:\\\\(Users|inetpub|wwwroot)",  # 服务器内部路径
    r"phpinfo|PHP_VERSION|DOCUMENT_ROOT",                # phpinfo 泄露
]

# 公开数据特征：响应体是这些内容时，即使无需认证也不算漏洞
PUBLIC_DATA_PATTERNS = [
    r"<title>\s*(?:example|test|hello|welcome|首页|登录|home)\b",
    r"<!doctype html>[\s\S]{0,300}<html",                # 普通 HTML 壳/落地页
    r"<div id=\"(?:root|app|app-root)\"",                # SPA 空壳
    r"(?:公告|通知|新闻|帮助|faq|about|contact)\s*[:：]?",
    r"(?:price|product|商品|价格|费率|利率|限额|杠杆)\s*[:：]",  # 交易参数（面向公众）
    r"(?:version|copyright|license)\s*[:：]",            # 版本/版权声明
]

# 公开/无害 Content-Type：这类响应体一般不含敏感数据
_PUBLIC_CONTENT_TYPES = ("text/html", "text/css", "application/javascript",
                         "image/", "font/", "text/plain")


def _body_contains_sensitive_data(text: str) -> bool:
    """检测响应体是否包含真实敏感数据特征。

    用于未授权访问/CORS/信息泄露的多因素验证：只有响应体确实含敏感数据，
    才认为该漏洞有实际危害，避免只看响应头/状态码就判漏洞。
    """
    if not text or len(text) < 5:
        return False
    # 邮箱需要批量出现才算（单个邮箱可能是示例）
    email_count = len(re.findall(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", text))
    for pat in SENSITIVE_DATA_PATTERNS:
        if "email" in pat.lower():
            continue
        if re.search(pat, text, re.IGNORECASE):
            return True
    if email_count >= 3:
        return True
    return False


def _is_public_data(text: str, content_type: str = "") -> bool:
    """检测响应体是否属于公开/无害数据。

    用于未授权访问/CORS 判定：如果响应体是公开数据（公告、商品、SPA 壳等），
    即使无需认证也不应判为漏洞。
    """
    if not text:
        return True
    ct = (content_type or "").lower()
    # 纯静态资源一般不含敏感业务数据
    if any(ct.startswith(p) for p in ("image/", "font/", "text/css",
                                       "application/javascript", "text/plain")):
        if len(text) < 200:
            return True
    for pat in PUBLIC_DATA_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def _header_value_leaks_version(val: str) -> bool:
    """判断响应头值是否泄露了具体版本号。

    纯产品名（如 "nginx"、"cloudflare"、"Express" 无版本）不算泄露，
    因为无法据版本号匹配已知 CVE。
    """
    if not val:
        return False
    return bool(_HEADER_VERSION_RE.search(val))


# 敏感路径内容指纹：path 后缀/关键字 → 预期内容特征（命中才算真泄露，避免 SPA 兜底 200 误报）
SENSITIVE_PATH_FINGERPRINTS = {
    # 配置文件类：应含键值对
    ".env": [r"^[A-Z_]+\s*=", r"\b(?:DB_|APP_|SECRET|API_|TOKEN)"],
    "config.yml": [r"^\s*\w+:\s*", r"(?:database|server|port|host)\s*:"],
    "application.yml": [r"^\s*\w+:\s*", r"(?:spring|datasource|server)\s*:"],
    "web.config": [r"<configuration", r"<connectionStrings"],
    "config.php.bak": [r"<\?php", r"\$(?:db|config|host|pass)"],
    ".htaccess": [r"RewriteRule", r"Allow(?:From|Override)"],
    ".htpasswd": [r"^[^:]+:\$[0-9a-z]\$", r"\$2[aby]\$"],
    # Git/SVN
    ".git/config": [r"\[core\]", r"\[remote\b"],
    ".git/head": [r"^ref:\s*refs/"],
    ".svn/entries": [r"^\d+\n", r"svn://", r"dir\n"],
    # API 文档
    "swagger-ui.html": [r"swagger", r"SwaggerUI"],
    "api-docs": [r'"swagger"\s*:', r'"paths"\s*:', r'"openapi"\s*:'],
    "openapi.json": [r'"openapi"\s*:', r'"paths"\s*:'],
    "v2/api-docs": [r'"swagger"\s*:', r'"paths"\s*:', r'"basePath"\s*:'],
    # Spring Actuator
    "actuator": [r'"_links"', r'"diskSpace"', r'"health"'],
    "actuator/env": [r'"propertySources"', r'"property"', r'"configName"'],
    "actuator/heapdump": [r"^\x00", r"JAVA PROFILE"],  # 二进制
    "actuator/mappings": [r'"handler"', r'"mappings"'],
    # 数据库备份
    ".sql": [r"CREATE TABLE", r"INSERT INTO", r"^--\s*-{2,}"],
    ".zip": [r"^PK\x03\x04"],  # ZIP 魔数
    # phpinfo
    "phpinfo.php": [r"PHP Version", r"phpinfo"],
    "info.php": [r"PHP Version", r"phpinfo"],
    "test.php": [r"PHP Version", r"phpinfo", r"<\?php"],
    # 开发工具
    "druid/index.html": [r"Druid", r"StatView"],
    "druid/login.html": [r"Druid", r"login"],
    "h2-console": [r"H2 Console", r"h2"],
    "server-status": [r"Apache Status", r"Server uptime"],
    # 依赖/清单
    "package.json": [r'"name"\s*:', r'"dependencies"\s*:'],
    "composer.json": [r'"name"\s*:', r'"require"\s*:'],
}


def _verify_sensitive_path_content(path: str, text: str) -> tuple[bool, str]:
    """验证敏感路径响应体是否匹配预期内容特征。

    Returns:
        (matched, evidence_quality):
        - (True, "content_match")  路径有指纹且内容命中 → 强证据
        - (True, "header_only")     路径无指纹但 200 + 内容较大 → 弱证据（可能误报）
        - (False, "")               路径有指纹但内容未命中 → 跳过（多为 SPA 兜底）
    """
    if not text:
        return False, ""
    path_lower = path.lower()
    # 查找匹配的指纹（按 path 后缀/子串匹配）
    # ★ 按长度降序迭代：让更具体的 key（如 "actuator/env"）先于
    #   更宽泛的 key（如 "actuator"）匹配，避免误用错误指纹导致漏判。
    for key in sorted(SENSITIVE_PATH_FINGERPRINTS, key=len, reverse=True):
        patterns = SENSITIVE_PATH_FINGERPRINTS[key]
        if key in path_lower:
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    return True, "content_match"
            # 有指纹但都没命中 → 大概率是 SPA 兜底页/默认页，跳过
            return False, ""
    # 无指纹的路径（少数）：仅当内容足够大且非 HTML 壳时给弱证据
    if len(text) > 50 and not re.search(r"<(?:html|!doctype|div id=\"(?:root|app))",
                                         text, re.IGNORECASE):
        return True, "header_only"
    return False, ""


# ============================================================
# 规则引擎
# ============================================================

class FastScanner:
    """本地快速规则引擎，并发检测多种漏洞类型。"""

    def __init__(
        self,
        max_workers: int = 20,
        timeout: float = 10.0,
        proxy: str | None = None,
    ):
        self.max_workers = max_workers
        self.timeout = timeout
        self.proxy = proxy
        self._client: httpx.AsyncClient | None = None
        self._total_requests = 0
        self._blocked_count = 0
        self._timeout_count = 0
        self._error_count = 0
        self._lock = asyncio.Lock()
        # ★ WAF 封禁标志：连续被拦截超过阈值后置 True，所有规则检测提前退出
        # 避免对已被 WAF 全量拦截的目标继续打数千次无效请求（实测 zzidc.com 拦截 1737 次仍在打）
        self._waf_blocked = False
        self._waf_block_threshold = 20  # 连续 20 次 403/418/429/503 即判定 WAF 封禁
        # ★ 超时熔断：连续超时达到阈值后置 True，避免对不可达目标继续打无效请求
        self._consecutive_timeout_count = 0
        self._timeout_blocked = False
        self._timeout_block_threshold = 10  # 连续 10 次超时即熔断
        # ★ 并发信号量：限制同时在途的 HTTP 请求数，避免 gather 一次性创建数百协程
        # 当 WAF/超时熔断后，等待中的协程进入 _request 时会看到标志位并直接返回 None
        self._semaphore: asyncio.Semaphore | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            kwargs = {
                "timeout": httpx.Timeout(self.timeout),
                "follow_redirects": True,
                "verify": False,
                "limits": httpx.Limits(max_connections=self.max_workers * 2),
            }
            if self.proxy:
                kwargs["proxy"] = self.proxy
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        content: str | None = None,
        drop_auth: bool = False,
        rule_tag: str = "",
        payload_tag: str = "",
    ) -> httpx.Response | None:
        """发送 HTTP 请求，返回响应对象。失败返回 None。

        ★ WAF 自适应：被拦截时自动降速，避免触发 IP 封禁。
          深度绕过（编码/分块/注释变体）由 WAFBypassFuzzer 负责，
          本引擎仅做快速规则检测 + 限速保护。
        """
        # ★ WAF / 超时熔断早退：一旦全局封禁标志置位，后续所有请求直接返回 None
        if self._waf_blocked or self._timeout_blocked:
            return None

        # ★ 并发信号量：限制同时在途的 HTTP 请求数
        # gather 创建的协程在此排队，进入后才检查熔断标志，避免数百请求同时发出
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_workers)
        async with self._semaphore:
            # 二次检查：排队期间可能已被熔断
            if self._waf_blocked or self._timeout_blocked:
                return None

            client = await self._get_client()
            # 去认证：移除 Cookie / Authorization
            req_headers = dict(headers) if headers else {}
            if drop_auth:
                req_headers.pop("Cookie", None)
                req_headers.pop("cookie", None)
                req_headers.pop("Authorization", None)
                req_headers.pop("authorization", None)

            try:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=req_headers,
                    content=content,
                )

                _need_sleep = 0.0
                async with self._lock:
                    self._total_requests += 1
                    # 请求成功，重置连续超时计数
                    self._consecutive_timeout_count = 0
                    # WAF 拦截检测
                    if resp.status_code in (403, 418, 429, 503):
                        self._blocked_count += 1
                        # ★ WAF 日志指数退避采样：仅在 3/10/30/100/300/1000 次时输出
                        # 原逻辑每 3 次输出一条，拦截 576 次产生 192 条几乎相同的 WARNING
                        _log_milestones = {3, 10, 30, 100, 300, 1000, 3000}
                        if self._blocked_count in _log_milestones:
                            delay = min(2.0, 0.5 * (self._blocked_count // 3))
                            log.warning("[SCAN] WAF 拦截 %d 次，降速 %0.1fs",
                                        self._blocked_count, delay)
                            _need_sleep = delay
                        # ★ WAF 全局封禁早退：拦截次数达到阈值，置全局标志中止所有后续请求
                        if self._blocked_count >= self._waf_block_threshold and not self._waf_blocked:
                            self._waf_blocked = True
                            log.warning(
                                "[SCAN] WAF 封禁：连续被拦截 %d 次（阈值 %d），中止该目标所有后续 payload",
                                self._blocked_count, self._waf_block_threshold
                            )

                # ★ sleep 移到锁外执行，避免持锁期间阻塞其他协程
                if _need_sleep > 0:
                    await asyncio.sleep(_need_sleep)

                log.info("[SCAN] %s | %s %s | payload=%s | => %d %s | body=%d",
                         rule_tag, method, url, payload_tag,
                         resp.status_code, resp.reason_phrase, len(resp.content))
                return resp
            except httpx.TimeoutException:
                async with self._lock:
                    self._timeout_count += 1
                    self._consecutive_timeout_count += 1
                    # ★ 超时熔断：连续超时达到阈值，中止该目标所有后续请求
                    if (self._consecutive_timeout_count >= self._timeout_block_threshold
                            and not self._timeout_blocked):
                        self._timeout_blocked = True
                        log.warning(
                            "[SCAN] 超时熔断：连续超时 %d 次（阈值 %d），中止该目标所有后续 payload",
                            self._consecutive_timeout_count, self._timeout_block_threshold
                        )
                log.warning("[SCAN] %s | %s %s | payload=%s | => TIMEOUT",
                            rule_tag, method, url, payload_tag)
                return None
            except httpx.HTTPStatusError as e:
                log.warning("[SCAN] %s | %s %s | payload=%s | => HTTP_ERR %s",
                            rule_tag, method, url, payload_tag, e.response.status_code)
                return e.response
            except Exception as e:
                async with self._lock:
                    self._error_count += 1
                log.debug("[SCAN] %s | %s %s | payload=%s | => FAIL %s",
                          rule_tag, method, url, payload_tag, e)
                return None

    async def scan_target(
        self,
        target: ScanTarget,
        enabled_rules: list[str] | None = None,
    ) -> ScanResult:
        """对单个目标执行快速扫描。

        Args:
            target: 扫描目标
            enabled_rules: 启用的规则类型列表，None 表示全部
        """
        all_rules = enabled_rules or [
            "sql_injection", "xss", "info_disclosure",
            "unauthorized", "weak_password", "cors",
            "path_traversal", "command_injection", "ssrf",
        ]

        t0 = time.time()
        self._total_requests = 0
        self._blocked_count = 0
        self._waf_blocked = False  # ★ 每个目标重置 WAF 封禁标志
        self._consecutive_timeout_count = 0
        self._timeout_blocked = False  # ★ 每个目标重置超时熔断标志
        self._semaphore = asyncio.Semaphore(self.max_workers)  # ★ 每个目标重建信号量
        findings: list[VulnFinding] = []

        # ★ 分批执行规则：每批 max_workers 个规则，批次间检查熔断标志
        # 原逻辑一次性 gather 所有规则，每条规则内部又 gather 数十 payload，
        # 导致数百协程同时在途，WAF 封禁后仍有大量在途请求返回 403 并刷日志
        all_handlers = []
        for rule in all_rules:
            handler = getattr(self, f"_check_{rule}", None)
            if handler:
                all_handlers.append(handler)

        batch_size = min(3, len(all_handlers)) if all_handlers else 1
        for i in range(0, len(all_handlers), batch_size):
            # 批次间检查熔断标志，跳过剩余规则
            if self._waf_blocked:
                log.info("[SCAN] WAF 已封禁，跳过剩余 %d 个规则", len(all_handlers) - i)
                break
            if self._timeout_blocked:
                log.info("[SCAN] 超时已熔断，跳过剩余 %d 个规则", len(all_handlers) - i)
                break

            batch = all_handlers[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    log.warning("规则执行异常: %s", result)

        elapsed = time.time() - t0
        await self._close()

        return ScanResult(
            target_url=target.url,
            findings=findings,
            elapsed=elapsed,
            total_requests=self._total_requests,
            rules_run=len(all_handlers),
            blocked_count=self._blocked_count,
            timeout_count=self._timeout_count,
            error_count=self._error_count,
        )

    async def scan_targets(
        self,
        targets: list[ScanTarget],
        enabled_rules: list[str] | None = None,
    ) -> list[ScanResult]:
        """批量扫描多个目标。"""
        results = []
        # 分批并发，避免连接爆炸
        batch_size = self.max_workers
        for i in range(0, len(targets), batch_size):
            batch = targets[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[self.scan_target(t, enabled_rules) for t in batch],
                return_exceptions=True,
            )
            for r in batch_results:
                if isinstance(r, ScanResult):
                    results.append(r)
                elif isinstance(r, Exception):
                    log.warning("目标扫描异常: %s", r)
                    results.append(ScanResult(
                        target_url="unknown", elapsed=0,
                        total_requests=0, rules_run=0,
                    ))
        return results

    def get_accumulated_stats(self) -> dict:
        """获取累计的请求统计（供 orchestrator 收集写入报告）。"""
        return {
            "total_requests": self._total_requests,
            "blocked": self._blocked_count,
            "timeout": self._timeout_count,
            "error": self._error_count,
            "waf_blocked": self._waf_blocked,
            "timeout_blocked": self._timeout_blocked,
        }

    async def _close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ============================================================
    # 规则实现
    # ============================================================

    async def _check_sql_injection(self, target: ScanTarget) -> list[VulnFinding]:
        """SQL 注入检测：报错注入 + 布尔盲注 + 时间盲注

        支持 GET 参数、POST 表单 body、POST JSON body 三种注入点。
        """
        findings = []
        test_payloads = [
            ("'", "报错注入"),
            ("' OR '1'='1", "布尔注入"),
            ("' OR '1'='1' --", "布尔注入"),
            ("1' AND '1'='1", "布尔注入"),
            ("1' AND '1'='2", "布尔注入-False"),
            ("1 UNION SELECT NULL--", "UNION注入"),
            ("1; WAITFOR DELAY '0:0:3'--", "时间盲注"),
        ]

        # 获取基线响应
        baseline = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body,
        )
        if not baseline:
            return []

        baseline_text = baseline.text
        baseline_len = len(baseline_text)

        # === GET 参数注入 ===
        for param_name, param_val in target.params.items():
            for payload, inj_type in test_payloads:
                # 构造注入请求
                test_params = dict(target.params)
                test_params[param_name] = param_val if param_val else payload
                test_url = self._build_url(target.url, test_params)

                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="SQLi", payload_tag=f"{param_name}={payload}",
                )
                if not resp:
                    continue

                # 报错注入检测
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append(VulnFinding(
                            vuln_type="SQL注入",
                            severity="critical",
                            url=test_url,
                            method="GET",
                            detail=f"参数 '{param_name}' 存在 SQL 注入（{inj_type}），"
                                   f"响应中匹配到数据库报错特征: {pattern}",
                            evidence=resp.text[:500],
                            payload=payload,
                            fix_suggestion="使用参数化查询/预编译语句，禁止拼接SQL",
                        ))
                        break  # 一个payload命中即可，不重复报

                # 布尔盲注检测：' OR '1'='1 vs ' OR '1'='2
                if "布尔注入" in inj_type and "False" not in inj_type:
                    false_params = dict(target.params)
                    false_params[param_name] = "' OR '1'='2"
                    false_url = self._build_url(target.url, false_params)
                    false_resp = await self._request(
                        "GET", false_url,
                        headers={**target.auth_headers, **target.headers},
                        rule_tag="SQLi", payload_tag=f"{param_name}=false_condition",
                    )
                    if false_resp and resp:
                        # True 条件响应与基线相似，False 条件响应不同
                        true_len = len(resp.text)
                        false_len = len(false_resp.text)
                        if abs(true_len - baseline_len) < 50 and abs(false_len - baseline_len) > 200:
                            findings.append(VulnFinding(
                                vuln_type="SQL注入",
                                severity="critical",
                                url=test_url,
                                method="GET",
                                detail=f"参数 '{param_name}' 存在布尔盲注，"
                                       f"True条件响应长度={true_len}，False条件={false_len}，基线={baseline_len}",
                                evidence=f"True: {resp.text[:200]}\nFalse: {false_resp.text[:200]}",
                                payload=payload,
                                fix_suggestion="使用参数化查询，对用户输入进行严格过滤",
                            ))

        # === POST 表单 body 注入 ===
        if target.method == "POST" and target.body and "=" in target.body:
            form_params = {}
            for pair in target.body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    form_params[k] = v

            for param_name in form_params:
                for payload, inj_type in test_payloads:
                    test_form = dict(form_params)
                    test_form[param_name] = payload
                    test_body = "&".join(f"{k}={v}" for k, v in test_form.items())
                    resp = await self._request(
                        "POST", target.url,
                        headers={**target.auth_headers, **target.headers,
                                 "Content-Type": "application/x-www-form-urlencoded"},
                        content=test_body,
                        rule_tag="SQLi-POST", payload_tag=f"{param_name}={payload}",
                    )
                    if not resp:
                        continue
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            findings.append(VulnFinding(
                                vuln_type="SQL注入",
                                severity="critical",
                                url=target.url,
                                method="POST",
                                detail=f"POST 参数 '{param_name}' 存在 SQL 注入（{inj_type}），"
                                       f"响应中匹配到数据库报错特征: {pattern}",
                                evidence=resp.text[:500],
                                payload=payload,
                                fix_suggestion="使用参数化查询/预编译语句，禁止拼接SQL",
                            ))
                            break

        # === POST JSON body 注入 ===
        if target.method == "POST" and target.body and target.body.strip().startswith("{"):
            try:
                json_body = json.loads(target.body)
                if isinstance(json_body, dict):
                    for field_name, field_val in list(json_body.items()):
                        if not isinstance(field_val, str):
                            continue
                        for payload, inj_type in test_payloads:
                            test_json = dict(json_body)
                            test_json[field_name] = payload
                            test_body = json.dumps(test_json, ensure_ascii=False)
                            resp = await self._request(
                                "POST", target.url,
                                headers={**target.auth_headers, **target.headers,
                                         "Content-Type": "application/json"},
                                content=test_body,
                                rule_tag="SQLi-JSON", payload_tag=f"{field_name}={payload}",
                            )
                            if not resp:
                                continue
                            for pattern in SQL_ERROR_PATTERNS:
                                if re.search(pattern, resp.text, re.IGNORECASE):
                                    findings.append(VulnFinding(
                                        vuln_type="SQL注入",
                                        severity="critical",
                                        url=target.url,
                                        method="POST",
                                        detail=f"JSON 字段 '{field_name}' 存在 SQL 注入（{inj_type}），"
                                               f"响应中匹配到数据库报错特征: {pattern}",
                                        evidence=resp.text[:500],
                                        payload=payload,
                                        fix_suggestion="使用参数化查询/预编译语句，禁止拼接SQL",
                                    ))
                                    break
            except (json.JSONDecodeError, ValueError):
                pass

        return findings

    async def _check_xss(self, target: ScanTarget) -> list[VulnFinding]:
        """XSS 反射型检测"""
        findings = []
        xss_probe = 'xuanjianxss<>"\''

        for param_name in target.params:
            test_params = dict(target.params)
            test_params[param_name] = xss_probe
            test_url = self._build_url(target.url, test_params)

            resp = await self._request(
                "GET", test_url,
                headers={**target.auth_headers, **target.headers},
                rule_tag="XSS", payload_tag=f"{param_name}={xss_probe}",
            )
            if not resp:
                continue

            # 检查 probe 是否原样反射
            if xss_probe in resp.text:
                # 检查是否被编码
                encoded = resp.text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")
                if xss_probe in encoded:
                    # 未编码，存在 XSS
                    findings.append(VulnFinding(
                        vuln_type="XSS",
                        severity="high",
                        url=test_url,
                        method="GET",
                        detail=f"参数 '{param_name}' 存在反射型 XSS，输入的探测字符串被原样反射到页面中",
                        evidence=resp.text[:500],
                        payload=xss_probe,
                        fix_suggestion="对用户输入进行HTML编码，使用CSP策略",
                    ))

        # POST 表单 XSS
        if target.method == "POST" and target.body and "=" in target.body:
            form_params = {}
            for pair in target.body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    form_params[k] = v
            for param_name in form_params:
                test_form = dict(form_params)
                test_form[param_name] = xss_probe
                xss_body = "&".join(f"{k}={v}" for k, v in test_form.items())
                resp = await self._request(
                    "POST", target.url,
                    headers={**target.auth_headers, **target.headers, "Content-Type": "application/x-www-form-urlencoded"},
                    content=xss_body,
                    rule_tag="XSS-POST", payload_tag=f"{param_name}={xss_probe}",
                )
                if resp and xss_probe in resp.text:
                    encoded = resp.text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")
                    if xss_probe in encoded:
                        findings.append(VulnFinding(
                            vuln_type="XSS",
                            severity="high",
                            url=target.url,
                            method="POST",
                            detail=f"POST 参数 '{param_name}' 存在反射型 XSS",
                            evidence=resp.text[:500],
                            payload=xss_probe,
                            fix_suggestion="对用户输入进行HTML编码",
                        ))

        return findings

    async def _check_info_disclosure(self, target: ScanTarget) -> list[VulnFinding]:
        """信息泄露检测：敏感路径 + 响应头"""
        findings = []
        # ★ 使用站点根 URL 而非完整页面 URL 作为 base_url
        # 原逻辑 target.url 可能是 https://example.com/Login/logout，
        # 拼接 /.DS_Store 会得到 https://example.com/Login/logout/.DS_Store（无意义路径）
        from urllib.parse import urlparse
        parsed = urlparse(target.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 基线预检：先请求 target.url 本身，若基线就 5xx/404，说明该 base 路径已坏，
        # 后续拼接的所有敏感路径必然同样失败，整批跳过（原实现对 /Content/setting 等
        # 报 500 的 base 仍并发打满 SENSITIVE_PATHS，单 target 即浪费数十次请求）
        baseline = await self._request("GET", target.url, headers=target.auth_headers)
        if not baseline:
            return findings

        # 响应头信息泄露（基线已拿到，复用）
        # ★ 多因素验证：纯 banner（无版本号）几乎所有站点都有，不构成可被 SRC 收录的漏洞，
        #    不再产出 VulnFinding。只有泄露了具体版本号、且响应体也含敏感信息时才报告。
        if baseline.status_code < 500:
            baseline_text = baseline.text or ""
            baseline_ct = baseline.headers.get("content-type", "")
            body_sensitive = _body_contains_sensitive_data(baseline_text)
            for header in INFO_LEAK_HEADERS:
                val = baseline.headers.get(header, "")
                if not val:
                    continue
                # 因素1：响应头值必须含具体版本号才视为有价值的泄露
                if not _header_value_leaks_version(val):
                    continue
                # 因素2：响应体也泄露敏感信息（phpinfo/堆栈/密钥等）→ 升级 medium
                if body_sensitive:
                    findings.append(VulnFinding(
                        vuln_type="信息泄露",
                        severity="medium",
                        url=target.url,
                        method="GET",
                        detail=(f"响应头 {header} 泄露版本号({val})，且响应体含敏感数据，"
                                f"可据版本号匹配已知 CVE"),
                        evidence=f"{header}: {val}\n响应体片段: {baseline_text[:200]}",
                        fix_suggestion=f"移除或混淆 {header} 响应头，清理响应体敏感信息",
                        evidence_quality="body_confirmed",
                    ))
                else:
                    # 仅版本号泄露、无响应体佐证 → 标 header_only，留给二次裁决
                    findings.append(VulnFinding(
                        vuln_type="信息泄露",
                        severity="low",
                        url=target.url,
                        method="GET",
                        detail=(f"响应头 {header} 泄露版本号: {val}（仅响应头证据，"
                                f"需结合已知 CVE 才有实际危害）"),
                        evidence=f"{header}: {val}",
                        fix_suggestion=f"移除或混淆 {header} 响应头",
                        evidence_quality="header_only",
                    ))

        # 基线 500/404 → base 路径失效，跳过敏感路径批量探测
        # （403 不跳过：目录被禁但子路径敏感文件可能因配置错误可访问）
        if baseline.status_code in (500, 404):
            log.warning("[SCAN] InfoLeak | 基线 %d，跳过 %d 条敏感路径探测: %s",
                        baseline.status_code, len(SENSITIVE_PATHS), target.url)
            return findings

        # 并发检测敏感路径
        async def check_path(path: str) -> VulnFinding | None:
            url = base_url + path
            resp = await self._request("GET", url, headers=target.auth_headers,
                                       rule_tag="InfoLeak", payload_tag=path)
            if not resp:
                return None
            # ★ 多因素验证：仅看 200 不够，必须内容匹配预期指纹才算真泄露
            if resp.status_code == 200 and len(resp.text) > 10:
                matched, quality = _verify_sensitive_path_content(path, resp.text)
                if not matched:
                    # 内容未匹配指纹 → 多为 SPA 兜底页/默认页，跳过
                    return None
                severity = "medium" if quality == "content_match" else "low"
                return VulnFinding(
                    vuln_type="信息泄露",
                    severity=severity,
                    url=url,
                    method="GET",
                    detail=(f"敏感路径可访问: {path}（内容指纹"
                            f"{'已确认' if quality == 'content_match' else '未匹配，弱证据'}）"),
                    evidence=f"HTTP {resp.status_code}, Content-Length: {len(resp.text)}\n"
                             f"响应体片段: {resp.text[:200]}",
                    payload="",
                    fix_suggestion=f"限制对 {path} 的访问，添加访问控制",
                    evidence_quality=quality,
                )
            return None

        tasks = [check_path(p) for p in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, VulnFinding):
                findings.append(r)

        # 源码映射文件
        for map_path in ["/app.js.map", "/main.js.map", "/bundle.js.map", "/app.min.js.map"]:
            # 从页面中提取 JS 文件路径再检测 .map
            pass  # 已在 SENSITIVE_PATHS 中覆盖

        return findings

    async def _check_unauthorized(self, target: ScanTarget) -> list[VulnFinding]:
        """未授权访问检测：去认证后请求对比"""
        findings = []

        # 带认证请求（基线）
        auth_resp = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body,
            rule_tag="Unauth", payload_tag="with_auth",
        )
        if not auth_resp:
            return []

        # 去认证请求
        noauth_resp = await self._request(
            target.method, target.url,
            headers=target.headers,
            content=target.body,
            drop_auth=True,
            rule_tag="Unauth", payload_tag="no_auth",
        )
        if not noauth_resp:
            return []

        # 如果去认证后仍返回 200 且内容相似 → 疑似未授权访问
        if noauth_resp.status_code == 200 and auth_resp.status_code == 200:
            auth_len = len(auth_resp.text)
            noauth_len = len(noauth_resp.text)
            noauth_ct = noauth_resp.headers.get("content-type", "")
            # 内容相似度 > 80%
            if abs(auth_len - noauth_len) < max(auth_len * 0.2, 100):
                noauth_text = noauth_resp.text or ""
                # ★ 多因素验证：只看长度/状态码会大量误报公开接口
                if _is_public_data(noauth_text, noauth_ct):
                    # 公开数据（公告/商品/SPA 壳/静态资源）→ 不算漏洞
                    log.info("[SCAN] Unauth | 去认证 200 但响应体为公开数据，跳过: %s", target.url)
                    pass
                elif _body_contains_sensitive_data(noauth_text):
                    # 响应体确实含敏感数据（PII/密钥/用户列表）→ 高危，强证据
                    findings.append(VulnFinding(
                        vuln_type="未授权访问",
                        severity="high",
                        url=target.url,
                        method=target.method,
                        detail=(f"去除认证头后仍返回 200，且响应体含敏感数据，"
                                f"响应长度对比: 认证={auth_len} / 去认证={noauth_len}"),
                        evidence=f"无认证响应: {noauth_text[:300]}",
                        fix_suggestion="添加认证中间件，对所有 API 请求强制鉴权",
                        evidence_quality="body_confirmed",
                    ))
                else:
                    # 既非明显公开也非含敏感数据 → 弱证据，留二次裁决
                    findings.append(VulnFinding(
                        vuln_type="未授权访问",
                        severity="medium",
                        url=target.url,
                        method=target.method,
                        detail=(f"去除认证头后仍返回 200（仅状态码+长度证据，"
                                f"响应体未确认含敏感数据）: "
                                f"认证={auth_len} / 去认证={noauth_len}"),
                        evidence=f"无认证响应: {noauth_text[:300]}",
                        fix_suggestion="添加认证中间件，并对接口返回数据做最小化",
                        evidence_quality="header_only",
                    ))

        # 去认证后返回 401/403 → 正常（有鉴权）
        if noauth_resp.status_code in (401, 403):
            pass  # 安全

        return findings

    async def _check_weak_password(self, target: ScanTarget) -> list[VulnFinding]:
        """弱口令检测：对登录接口尝试默认凭据"""
        findings = []

        # 只对登录相关 URL 检测
        url_lower = target.url.lower()
        if not any(kw in url_lower for kw in ["login", "signin", "auth", "登录", "api/auth"]):
            return []

        # 端点存活性预检：首个请求若返回 404/410，说明登录 URL 不存在，
        # 后续凭据爆破全是无效请求，提前退出（原实现对失效端点会空打 42 次）
        for cred_idx, (username, password) in enumerate(WEAK_CREDENTIALS):
            # JSON 登录
            login_data = json.dumps({"username": username, "password": password})
            resp = await self._request(
                "POST", target.url,
                headers={**target.headers, "Content-Type": "application/json"},
                content=login_data,
                rule_tag="WeakPwd", payload_tag=f"{username}:{password}",
            )
            if not resp:
                continue

            # 失效端点早退：404/410 表示该 URL 根本不是有效登录接口
            if resp.status_code in (404, 410):
                log.warning("[SCAN] WeakPwd | 登录端点失效 (%d)，跳过剩余 %d 组凭据: %s",
                            resp.status_code, len(WEAK_CREDENTIALS) - cred_idx - 1, target.url)
                return findings

            resp_text = resp.text.lower()
            # 成功登录的特征
            success_indicators = ["token", "access_token", "session", "login success",
                                  "登录成功", '"code":0', '"code": 0', '"success":true', "success"]
            failure_indicators = ["error", "fail", "invalid", "wrong", "incorrect",
                                  "失败", "错误", "密码不正确"]

            is_success = any(ind in resp_text for ind in success_indicators)
            is_failure = any(ind in resp_text for ind in failure_indicators)

            if is_success and not is_failure:
                findings.append(VulnFinding(
                    vuln_type="弱口令",
                    severity="high",
                    url=target.url,
                    method="POST",
                    detail=f"使用默认凭据 {username}/{password} 成功登录",
                    evidence=resp.text[:500],
                    payload=f"{username}:{password}",
                    fix_suggestion="强制密码复杂度策略，禁用默认凭据",
                ))
                break  # 一个成功即可

            # 也尝试表单提交
            form_data = f"username={username}&password={password}"
            resp2 = await self._request(
                "POST", target.url,
                headers={**target.headers, "Content-Type": "application/x-www-form-urlencoded"},
                content=form_data,
                rule_tag="WeakPwd", payload_tag=f"{username}:{password}_form",
            )
            if resp2:
                if resp2.status_code in (404, 410):
                    log.warning("[SCAN] WeakPwd | 登录端点失效 (%d)，跳过剩余 %d 组凭据: %s",
                                resp2.status_code, len(WEAK_CREDENTIALS) - cred_idx - 1, target.url)
                    return findings
                if any(ind in resp2.text.lower() for ind in success_indicators):
                    findings.append(VulnFinding(
                        vuln_type="弱口令",
                        severity="high",
                        url=target.url,
                        method="POST",
                        detail=f"使用默认凭据 {username}/{password} 成功登录（表单提交）",
                        evidence=resp2.text[:500],
                        payload=f"{username}:{password}",
                        fix_suggestion="强制密码复杂度策略，禁用默认凭据",
                    ))
                    break

        return findings

    async def _check_cors(self, target: ScanTarget) -> list[VulnFinding]:
        """CORS 配置错误检测"""
        findings = []

        # 发送 Origin 头看是否反射
        evil_origin = "https://evil-xuanjian.example.com"
        resp = await self._request(
            "GET", target.url,
            headers={**target.auth_headers, "Origin": evil_origin},
            rule_tag="CORS", payload_tag=f"Origin={evil_origin}",
        )
        if not resp:
            return []

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        # 先判定 CORS 头是否配置错误
        cors_misconfigured = False
        misconfig_desc = ""
        if acao == "*" and acac.lower() == "true":
            cors_misconfigured = True
            misconfig_desc = "CORS 允许任意来源 (*) 且允许携带凭据"
        elif acao == evil_origin:
            cors_misconfigured = True
            misconfig_desc = "CORS 反射任意 Origin"
        elif acao == "null" and acac.lower() == "true":
            cors_misconfigured = True
            misconfig_desc = "CORS 允许 null Origin 且允许凭据"

        if not cors_misconfigured:
            return findings

        # ★ 多因素验证：CORS 配置错误只有当接口确实返回敏感数据才有实际危害。
        #    公开数据/静态资源即使 CORS 宽松也无法窃取有价值信息。
        resp_text = resp.text or ""
        resp_ct = resp.headers.get("content-type", "")
        if _body_contains_sensitive_data(resp_text):
            findings.append(VulnFinding(
                vuln_type="CORS配置错误",
                severity="high",
                url=target.url,
                method="GET",
                detail=(f"{misconfig_desc}，且响应体含敏感数据，"
                        f"可被恶意网站跨域读取"),
                evidence=f"ACAO: {acao}, ACAC: {acac}\n响应体片段: {resp_text[:200]}",
                fix_suggestion="限制 CORS 允许的来源白名单，不要使用 * 或反射 Origin",
                evidence_quality="body_confirmed",
            ))
        elif _is_public_data(resp_text, resp_ct):
            # 公开数据/静态资源 → CORS 宽松无实际危害，降级为 low
            findings.append(VulnFinding(
                vuln_type="CORS配置错误",
                severity="low",
                url=target.url,
                method="GET",
                detail=(f"{misconfig_desc}，但响应体为公开数据/静态资源，"
                        f"无实际跨域窃取价值"),
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                fix_suggestion="仍建议收紧 CORS 来源白名单",
                evidence_quality="header_only",
            ))
        else:
            # 数据敏感性未知 → 中危，留二次裁决实测
            findings.append(VulnFinding(
                vuln_type="CORS配置错误",
                severity="medium",
                url=target.url,
                method="GET",
                detail=(f"{misconfig_desc}（仅响应头证据，响应体未确认含敏感数据，"
                        f"需实测跨域读取是否真能拿到敏感信息）"),
                evidence=f"ACAO: {acao}, ACAC: {acac}\n响应体片段: {resp_text[:200]}",
                fix_suggestion="限制 CORS 允许的来源白名单，不要使用 * 或反射 Origin",
                evidence_quality="header_only",
            ))

        return findings

    async def _check_path_traversal(self, target: ScanTarget) -> list[VulnFinding]:
        """目录穿越检测"""
        findings = []
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]

        passwd_patterns = [r"root:.*:0:0:", r"\[fonts\]"]
        winini_patterns = [r"\[fonts\]", r"\[extensions\]"]

        for param_name in target.params:
            for payload in payloads:
                test_params = dict(target.params)
                test_params[param_name] = payload
                test_url = self._build_url(target.url, test_params)

                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="PathTraversal", payload_tag=f"{param_name}={payload}",
                )
                if not resp:
                    continue

                for pattern in passwd_patterns + winini_patterns:
                    if re.search(pattern, resp.text):
                        findings.append(VulnFinding(
                            vuln_type="目录穿越",
                            severity="critical",
                            url=test_url,
                            method="GET",
                            detail=f"参数 '{param_name}' 存在目录穿越，成功读取系统文件",
                            evidence=resp.text[:300],
                            payload=payload,
                            fix_suggestion="对文件路径参数进行严格白名单校验",
                        ))
                        break

        return findings

    async def _check_command_injection(self, target: ScanTarget) -> list[VulnFinding]:
        """命令注入检测"""
        findings = []
        payloads = [
            ";id",
            "|id",
            "`id`",
            "$(id)",
            "&&id",
            "; whoami",
            "| whoami",
        ]

        for param_name in target.params:
            for payload in payloads:
                test_params = dict(target.params)
                test_params[param_name] = payload
                test_url = self._build_url(target.url, test_params)

                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="CmdInjection", payload_tag=f"{param_name}={payload}",
                )
                if not resp:
                    continue

                for pattern in CMD_INJECTION_PATTERNS:
                    if re.search(pattern, resp.text):
                        findings.append(VulnFinding(
                            vuln_type="命令注入",
                            severity="critical",
                            url=test_url,
                            method="GET",
                            detail=f"参数 '{param_name}' 存在命令注入，响应中匹配到命令执行特征",
                            evidence=resp.text[:300],
                            payload=payload,
                            fix_suggestion="禁止直接拼接系统命令，使用安全的 API 调用",
                        ))
                        break

        return findings

    async def _check_ssrf(self, target: ScanTarget) -> list[VulnFinding]:
        """SSRF 检测：对 URL 参数注入内网地址"""
        findings = []
        ssrf_targets = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
        ]

        url_params = [k for k in target.params if any(kw in k.lower() for kw in ["url", "link", "redirect", "callback", "proxy", "fetch", "src"])]

        for param_name in url_params:
            for payload in ssrf_targets:
                test_params = dict(target.params)
                test_params[param_name] = payload
                test_url = self._build_url(target.url, test_params)

                resp = await self._request(
                    "GET", test_url,
                    headers={**target.auth_headers, **target.headers},
                    rule_tag="SSRF", payload_tag=f"{param_name}={payload}",
                )
                if not resp:
                    continue

                # AWS metadata 特征
                if "ami-id" in resp.text or "instance-id" in resp.text:
                    findings.append(VulnFinding(
                        vuln_type="SSRF",
                        severity="critical",
                        url=test_url,
                        method="GET",
                        detail=f"参数 '{param_name}' 存在 SSRF，成功读取云服务元数据",
                        evidence=resp.text[:500],
                        payload=payload,
                        fix_suggestion="对 URL 参数进行白名单校验，禁止访问内网地址",
                    ))
                elif "root:.*:0:0:" in resp.text:
                    findings.append(VulnFinding(
                        vuln_type="SSRF",
                        severity="critical",
                        url=test_url,
                        method="GET",
                        detail=f"参数 '{param_name}' 存在 SSRF，成功读取本地文件",
                        evidence=resp.text[:300],
                        payload=payload,
                        fix_suggestion="对 URL 参数进行白名单校验，禁止 file:// 协议",
                    ))
                elif resp.status_code == 200 and len(resp.text) > 100:
                    # 检查是否返回了内网信息
                    if "127.0.0.1" in resp.text or "localhost" in resp.text:
                        if payload not in resp.text:  # 不是反射
                            findings.append(VulnFinding(
                                vuln_type="SSRF",
                                severity="high",
                                url=test_url,
                                method="GET",
                                detail=f"参数 '{param_name}' 疑似 SSRF，响应中包含内网信息",
                                evidence=resp.text[:300],
                                payload=payload,
                                fix_suggestion="对 URL 参数进行白名单校验",
                            ))

        return findings

    async def scan_sitemap_features(
        self,
        features: list,
        session_info: dict | None = None,
        sitemap=None,
    ) -> list[VulnFinding]:
        """扫描 sitemap 中的功能点（供 orchestrator 调用）。

        Args:
            features: FeaturePoint 列表（来自 sitemap）
            session_info: 包含 headers 等信息的 dict
            sitemap: Sitemap 实例（可选），用于补充未覆盖的 API
        """
        findings: list[VulnFinding] = []
        auth_headers = (session_info or {}).get("headers", {})

        # 收集所有已扫描的 API key（"METHOD url" 格式），用于去重
        scanned_api_keys: set[str] = set()
        targets: list[ScanTarget] = []

        # ---- 1. 从功能点的 related_apis 生成扫描目标 ----
        # related_apis 格式: ["GET /api/users", "POST /api/login", ...]
        for fp in features:
            for api in getattr(fp, "related_apis", []):
                if isinstance(api, str):
                    # "METHOD url" 格式
                    parts = api.split(" ", 1)
                    if len(parts) == 2:
                        method, api_url = parts
                    else:
                        method, api_url = "GET", api
                elif isinstance(api, dict):
                    method = api.get("method", "GET")
                    api_url = api.get("url", "")
                else:
                    continue

                if not api_url:
                    continue

                # 跳过非 HTTP URL（如 mailto:, javascript:）
                if api_url.startswith(("mailto:", "javascript:", "tel:", "#")):
                    continue

                api_key = f"{method} {api_url}"
                if api_key in scanned_api_keys:
                    continue
                scanned_api_keys.add(api_key)

                # 从 sitemap.api_samples 提取请求样本（body/params）
                body = ""
                params = {}
                if sitemap:
                    body, params = self._extract_sample_from_sitemap(
                        sitemap, method, api_url, auth_headers
                    )

                targets.append(ScanTarget(
                    url=api_url,
                    method=method,
                    params=params,
                    body=body,
                    auth_headers=auth_headers,
                ))

            # 如果功能点没有 related_apis，用 page_url 兜底
            if not getattr(fp, "related_apis", []):
                fp_url = getattr(fp, "page_url", "") or getattr(fp, "url", "")
                if fp_url and fp_url.startswith("http"):
                    targets.append(ScanTarget(url=fp_url, auth_headers=auth_headers))

        # ---- 2. 从 sitemap.apis 补充未被功能点覆盖的 API ----
        if sitemap and hasattr(sitemap, "apis"):
            for api_key, api_endpoint in sitemap.apis.items():
                if api_key in scanned_api_keys:
                    continue
                scanned_api_keys.add(api_key)

                api_url = getattr(api_endpoint, "url", "")
                method = getattr(api_endpoint, "method", "GET")
                if not api_url:
                    continue

                # 从 api_samples 提取请求样本
                body = getattr(api_endpoint, "request_body_sample", "") or ""
                params = {}
                param_names = getattr(api_endpoint, "params", [])
                if param_names and isinstance(param_names, list):
                    params = {p: "" for p in param_names}

                body2, params2 = self._extract_sample_from_sitemap(
                    sitemap, method, api_url, auth_headers
                )
                if body2:
                    body = body2
                if params2:
                    params = params2

                targets.append(ScanTarget(
                    url=api_url,
                    method=method,
                    params=params,
                    body=body,
                    auth_headers=auth_headers,
                ))

        if not targets:
            log.warning("FastScanner: 无可扫描目标（功能点和 sitemap.apis 均为空）")
            return []

        log.info("FastScanner: 扫描 %d 个目标 (功能点 %d + sitemap.apis 补充)",
                 len(targets), len(features))

        # 批量扫描
        results = await self.scan_targets(targets)

        # 收集发现
        for result in results:
            findings.extend(result.findings)

        return findings

    @staticmethod
    def _extract_sample_from_sitemap(
        sitemap, method: str, api_url: str, auth_headers: dict
    ) -> tuple[str, dict]:
        """从 sitemap.api_samples 提取请求样本，返回 (body, params)。"""
        body = ""
        params = {}

        if not hasattr(sitemap, "api_samples"):
            return body, params

        # api_samples 的 key 格式: "METHOD host/path|param_fingerprint"
        from urllib.parse import urlparse
        parsed = urlparse(api_url)
        path = parsed.path or api_url

        for skey, sample in sitemap.api_samples.items():
            if not isinstance(sample, dict):
                continue
            # 匹配 method + path
            s_parts = skey.split(" ", 1)
            s_method = s_parts[0] if len(s_parts) == 2 else ""
            s_url_part = s_parts[1] if len(s_parts) == 2 else skey
            s_base = s_url_part.split("|")[0]

            if s_method.upper() != method.upper():
                continue
            # 路径匹配（s_base 可能是 host/path 或 /path）
            if path not in s_base and s_base not in path:
                continue

            # 提取 body
            req_body = sample.get("request_body") or sample.get("body") or ""
            if req_body:
                body = req_body
            # 提取 params
            req_params = sample.get("params") or sample.get("query_params") or {}
            if isinstance(req_params, dict):
                params = req_params
            break

        return body, params

    # ============================================================
    # 辅助方法
    # ============================================================

    @staticmethod
    def _build_url(base_url: str, params: dict) -> str:
        """构造带参数的 URL"""
        if not params:
            return base_url
        sep = "&" if "?" in base_url else "?"
        return base_url + sep + urlencode(params)


# ============================================================
# 从 YAML 规则文件加载（可选）
# ============================================================

def load_rules_from_yaml(rules_dir: str = "rules") -> list[dict]:
    """从 rules/ 目录加载 YAML 格式的规则文件。

    规则格式：
        name: SQL注入检测
        type: sql_injection
        severity: critical
        match:
          - pattern: "SQL syntax.*MySQL"
            in: body
          - pattern: "ORA-\\d{5}"
            in: body
        payloads:
          - "'"
          - "' OR '1'='1"
    """
    rules = []
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        return rules

    try:
        import yaml
    except ImportError:
        log.warning("PyYAML 未安装，跳过 YAML 规则加载")
        return rules

    for yml_file in rules_path.glob("*.yaml"):
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                rules.extend(data)
            elif isinstance(data, dict):
                rules.append(data)
        except Exception as e:
            log.warning("加载规则文件 %s 失败: %s", yml_file, e)

    log.info("从 %s 加载了 %d 条规则", rules_dir, len(rules))
    return rules


# ============================================================
# 快速入口
# ============================================================

async def quick_scan(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    params: dict | None = None,
    auth_headers: dict | None = None,
    proxy: str | None = None,
    max_workers: int = 20,
    enabled_rules: list[str] | None = None,
) -> ScanResult:
    """快速扫描入口函数。

    用法:
        result = await quick_scan(
            url="http://example.com/api/users",
            params={"id": "1"},
            auth_headers={"Cookie": "session=xxx"},
        )
        print(f"发现 {result.vuln_count} 个漏洞")
    """
    target = ScanTarget(
        url=url,
        method=method,
        headers=headers or {},
        params=params or {},
        auth_headers=auth_headers or {},
    )
    scanner = FastScanner(max_workers=max_workers, proxy=proxy)
    return await scanner.scan_target(target, enabled_rules=enabled_rules)


async def batch_quick_scan(
    urls: list[str],
    auth_headers: dict | None = None,
    proxy: str | None = None,
    max_workers: int = 20,
) -> list[ScanResult]:
    """批量快速扫描多个 URL"""
    targets = [
        ScanTarget(url=url, auth_headers=auth_headers or {})
        for url in urls
    ]
    scanner = FastScanner(max_workers=max_workers, proxy=proxy)
    return await scanner.scan_targets(targets)


# ============================================================
# 结果转换工具（供 orchestrator 集成）
# ============================================================

def convert_findings_to_checklist_results(
    findings: list[VulnFinding],
) -> list[dict]:
    """将 FastScanner 的发现转换为 checklist 结果格式。

    供 orchestrator 回写到 sitemap 使用。
    """
    results = []
    for f in findings:
        results.append({
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "url": f.url,
            "method": f.method,
            "detail": f.detail,
            "evidence": f.evidence[:500] if f.evidence else "",
            "evidence_request": f.payload,
            "evidence_response": f.evidence[:500] if f.evidence else "",
            "fix_suggestion": f.fix_suggestion,
            "source": "fast_scanner",
        })
    return results
