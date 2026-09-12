"""fast_scanner 常量定义（从原 fast_scanner.py 机械拆分，内容逐字保留）。"""

from __future__ import annotations

import re

from core.log import get_logger

log = get_logger("fast_scanner")


DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36 Edg/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
]

# ★ 移动端 UA 池：WAF 拦截桌面 UA 时切换移动 UA 绕过
# （infer.md 发现 Jiasule WAF 可用移动 UA 绕过）
MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 "
    "Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 "
    "Mobile Safari/537.36",
]


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
    "/actuator/refresh", "/actuator/restart", "/actuator/jolokia",
    "/actuator/gateway/routes", "/actuator/gateway/refresh",
    "/actuator/configprops", "/actuator/beans", "/actuator/loggers",
    "/actuator/httptrace", "/actuator/threaddump", "/actuator/env",
    # Spring Boot 1.x context-path 变体
    "/manage", "/manage/env", "/manage/heapdump", "/manage/refresh",
    "/management", "/management/env",
    # Spring Cloud（Eureka / Hystrix / Config / Function）
    "/eureka/apps", "/hystrix", "/hystrix.stream",
    "/application/default", "/functionRouter",
    # Jolokia（JMX → JNDI RCE）
    "/jolokia", "/jolokia/list", "/jolokia/exec",
    # Spring 路径穿越绕过变体
    "/;/actuator/env", "/..;/actuator/env",
    # Spring Boot 配置文件
    "/application.yml", "/bootstrap.yml",
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

# 命令注入特征（★ P2 收紧：移除 whoami/total 等过于宽泛的通用词）
CMD_INJECTION_PATTERNS = [
    r"uid=\d+\(.*\)\s+gid=\d+",      # id 命令输出
    r"root:.*:0:0:",                  # /etc/passwd 内容
    r"Volume Serial Number is",       # Windows vol 命令
    r"Directory of\s+[A-Z]:\\",       # Windows dir 命令
    r"COMMAND\s+PID\s+USER",          # ps 命令输出
    r"[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+", # whoami 输出域名格式（非通用词）
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


# ============================================================
# ★ 假阳性过滤辅助（借鉴 api-pentest-extension 铁律框架）
# ============================================================

# 业务层拒绝特征：HTTP 200 但响应体含业务错误码 → 业务层已鉴权/已拒绝，
# 不应判为未授权访问。这是历史报告中 ≥90% 误报的根因。
BUSINESS_DENY_PATTERNS = [
    # 业务码 401/403/500 + 未登录/未授权 message
    r'"code"\s*:\s*(401|403|500|40100|40300|40001|40003)\b',
    r'"(errorCode|errcode|err_code|status_code)"\s*:\s*(401|403|500)\b',
    # 中英文拒绝消息
    r'"(message|msg|errMsg|errmsg|error_msg)"\s*:\s*"(?:[^"]*?)'
    r'(?:未登录|未授权|无权限|请登录|登录失效|身份验证失败|token无效|token已过期|'
    r'权限不足|没有权限|access denied|unauthorized|please login|not authenticated|'
    r'permission denied|token expired|invalid token|authentication failed)"',
    r'"(success|status)"\s*:\s*false',
    r'"(success|status)"\s*:\s*"false"',
    r'\bcode["\']?\s*[:=]\s*["\']?(401|403)\b',  # 通用 code:401/403
]

# 空 data 特征：响应返回 200 但 data 为空 → 无实际数据泄露，不应判为未授权访问
EMPTY_DATA_PATTERNS = [
    r'"data"\s*:\s*null\b',
    r'"data"\s*:\s*\[\s*\]',
    r'"data"\s*:\s*""',
    r'"data"\s*:\s*\{\s*\}',
    r'"result"\s*:\s*null\b',
    r'"result"\s*:\s*\[\s*\]',
    r'"result"\s*:\s*""',
    r'"records"\s*:\s*\[\s*\]',
    r'"rows"\s*:\s*\[\s*\]',
    r'"list"\s*:\s*\[\s*\]',
]

# WAF 拦截页特征：403/418/429/503 + 这些关键词 → 不算漏洞（WAF 拦截而非真实响应）
WAF_BLOCK_KEYWORDS = [
    "blocked", "firewall", "waf", "security", "intercepted",
    "denied by", "request blocked", "已被拦截", "安全拦截",
    "访问被拒绝", "已被防火墙", "拦截", "规则拦截",
]


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
    "actuator/refresh": [r'"context"', r'"refresh"'],
    "actuator/restart": [r'"context"', r'restart'],
    "actuator/jolokia": [r'"jolokia"', r'"mbean"', r'"JmxAgent"'],
    "actuator/gateway/routes": [r'"route_id"', r'"filters"', r'"uri"'],
    "actuator/configprops": [r'"prefix"', r'"properties"'],
    "actuator/beans": [r'"bean"', r'"scope"', r'"type"'],
    "actuator/loggers": [r'"configuredLevel"', r'"effectiveLevel"'],
    "actuator/httptrace": [r'"exchanges"', r'"request"', r'"response"'],
    "actuator/threaddump": [r'"threadName"', r'"threadState"'],
    # Spring Cloud
    "eureka/apps": [r'"application"', r'"instance"', r'"hostName"'],
    "eureka": [r'"applications"', r'"eureka"'],
    "hystrix.stream": [r'"type"', r'"ping"', r"data:"],
    "jolokia": [r'"jolokia"', r'"request"', r'"mbean"'],
    "jolokia/list": [r'"java.lang"', r'"mbean"'],
    "manage/env": [r'"propertySources"', r'"property"'],
    "manage/heapdump": [r"^\x00", r"JAVA PROFILE"],
    "application/default": [r'"propertySources"', r'"name"', r'"source"'],
    "functionrouter": [r'"function"', r'"routing"', r'"error"'],
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
    # 源码映射文件（source map）：泄露原始源码/文件路径，属内容级强证据
    # 命中 version + sources/mappings/sourcesContent 即为真泄露，避免 SPA 兜底 200 误报
    ".js.map": [r'"version"\s*:\s*3\b', r'"sources"\s*:', r'"mappings"\s*:', r'"sourcesContent"\s*:'],
    "source.map": [r'"version"\s*:\s*3\b', r'"sources"\s*:', r'"mappings"\s*:'],
}
