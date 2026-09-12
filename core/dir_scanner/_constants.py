"""DirectoryScanner 常量 — 从 core/dir_scanner.py 抽取，行为不变。"""

from __future__ import annotations

import re


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
# ★ 技术栈感知字典分类
# 将 DEFAULT_WORDLIST 按技术栈相关性分组，扫描时根据目标技术栈
# 动态选择字典，避免对 Java 站点扫 PHP 路径（backup.zip 等），
# 也避免对 SPA 站点扫静态资源路径（/static, /assets 等）。
# ============================================================

# 通用路径 — 任何技术栈都值得探测（API 文档 / 配置 / 调试 / 元信息）
UNIVERSAL_PATHS: list[str] = [
    # API / 接口文档
    "api", "api/v1", "api/v2", "api/v3",
    "swagger", "swagger-ui", "swagger-ui.html", "swagger-ui/index.html",
    "swagger.json", "swagger.yaml", "v2/api-docs", "v3/api-docs",
    "openapi.json", "openapi.yaml", "api-docs", "api/help", "api/docs",
    "graphql", "graphiql",
    # 通用配置 / 敏感文件
    ".env", ".env.local", ".env.production", ".env.bak",
    ".git/config", ".git/HEAD", ".git/index",
    ".gitignore", ".gitattributes", ".dockerenv",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    "config.json", "config.yaml", "config.yml", "config.bak",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    ".well-known/security.txt", ".well-known/openid-configuration",
    ".well-known/apple-app-site-association",
    "crossdomain.xml", "clientaccesspolicy.xml",
    # 通用调试 / 健康检查
    "debug", "debug/pprof", "debug/vars",
    "metrics", "health", "healthz", "readyz", "status", "ping", "info",
    "pprof", "pprof/goroutine", "prometheus",
    # 通用管理 / 认证
    "admin", "login", "console", "dashboard", "backend",
    "logout", "auth", "register",
    # 通用备份
    "backup", "backup.sql",
    # 通用文档
    "docs", "documentation", "doc", "help", "readme", "readme.md",
    # 通用上传
    "upload", "uploads", "files",
]

# Java / Spring 专属路径
JAVA_PATHS: list[str] = [
    # Spring Boot Actuator 全端点
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
    # Spring Cloud
    "actuator/gateway/routes", "actuator/gateway/refresh",
    "actuator/gateway/globalfilters", "actuator/gateway/routefilters",
    "gateway/actuator", "gateway/actuator/gateway/routes",
    "functionRouter",
    "application/default", "application/default/master",
    "application-dev.yml", "application-prod.yml",
    "application-dev.properties", "application-prod.properties",
    "eureka", "eureka/apps", "eureka/lastn", "eureka/v2/apps",
    "hystrix", "hystrix.stream", "hystrix/monitor",
    "instances", "instances/applications", "applications",
    # Jolokia
    "jolokia", "jolokia/list", "jolokia/version", "jolokia/read",
    "jolokia/exec", "jolokia/search",
    # Spring 路径穿越绕过
    ";/actuator/env", "..;/actuator/env", ";/actuator",
    # Java 配置 / 中间件
    "application.yml", "application.yaml", "application.properties",
    "bootstrap.yml", "bootstrap.properties",
    "WEB-INF/web.xml", "WEB-INF/classes/application.yml",
    "META-INF/MANIFEST.MF", "META-INF/spring.factories",
    "manager", "manager/html", "manager/status", "host-manager",
    "jmx-console", "jmx-console/", "jenkins", "struts",
    "weblogic", "ibm/console", "solr", "solr/admin",
]

# PHP 专属路径
PHP_PATHS: list[str] = [
    "admin.php", "admin.html", "admin/login", "admin/index",
    "pma", "phpmyadmin", "adminer", "adminer.php", "dbadmin",
    "login.php", "login.html",
    "wp-admin", "wp-login.php", "wp-config.php", "wp-config.php.bak",
    "xmlrpc.php", "install.php", "info.php", "phpinfo.php", "test.php",
    "wp-content", "wp-content/uploads", "wp-content/debug.log",
    "phpunit", "phpunit.xml", "composer.json", "composer.json.bak",
    "composer.lock", "vendor", "vendor/composer",
    "backup.zip", "backup.tar.gz", "backup.rar",
    "www.zip", "web.zip", "site.zip", "wwwroot.zip", "1.zip",
    "db.sql", "database.sql", "dump.sql", "data.sql",
    "db.bak", "backup.zip.bak",
    "server-status", "server-info", "status.php", "status.json",
    "config.php", ".htaccess", ".htpasswd",
]

# .NET 专属路径
DOTNET_PATHS: list[str] = [
    "elmah.axd", "trace.axd", "aspnet_client",
    "web.config", "web.config.bak",
]

# Node.js 专属路径
NODE_PATHS: list[str] = [
    "package.json", "package-lock.json", "yarn.lock",
    ".eslintrc", "Makefile",
    "debug/vars",  # expvar
]

# Python 专属路径
PYTHON_PATHS: list[str] = [
    "admin",  # Django admin
    "manage.py",
]

# 静态资源路径 — SPA 站点跳过这些（会被 catch-all 路由返回 index.html）
STATIC_RESOURCE_PATHS: set[str] = {
    "static", "assets", "public", "images", "img", "media",
    "attachment", "css", "js", "lib", "libs", "dist", "build",
    "src", "bin", "scripts", "tools", "util", "utils",
    "tmp", "temp", "log", "logs", "cache", "data", "db", "sql",
    "test", "tests", "config", "conf", "etc", "var", "run",
    "common", "system", "home", "main", "app", "application",
    "index", "download", "downloads", "file",
}

# API 优先关键词 — 含这些关键词的路径优先探测
API_PRIORITY_KEYWORDS: tuple[str, ...] = (
    "api", "swagger", "openapi", "graphql", "graphiql",
    "actuator", "api-docs", "v1/", "v2/", "v3/", "rest",
    "manage", "management", "jolokia", "eureka", "hystrix",
    "instances", "functionrouter", "gateway",
    "health", "healthz", "metrics", "status", "ping", "info",
    "debug", "pprof", "prometheus", ".env", ".git",
    "application.yml", "application.properties", "application.yaml",
    "bootstrap.yml", "bootstrap.properties",
    "config.json", "config.yaml", "config.yml",
    "web.config", "WEB-INF", "META-INF",
    "robots.txt", "sitemap.xml", "security.txt",
    ".well-known", "swagger.json", "openapi.json",
)

# SPA 空壳页面特征正则 — 基线响应匹配则判定为 SPA
_SPA_SHELL_PATTERN = re.compile(
    r'<div\s+id\s*=\s*["\'](?:root|app|app-root)["\']'
    r'|<!doctype html>[\s\S]{0,500}<script[^>]*src\s*=\s*["\'][^"\']*\.js["\']'
    r'|<title>\s*</title>\s*</head>',  # 空标题 + 闭 head → 典型 SPA 壳
    re.IGNORECASE,
)

# 技术栈关键词 → 对应路径集映射
_TECH_PATH_MAP: list[tuple[tuple[str, ...], list[str]]] = [
    (("java", "spring", "jvm", "tomcat", "jboss", "weblogic", "kotlin", "groovy"), JAVA_PATHS),
    (("php", "wordpress", "wp", "laravel", "thinkphp", "yii", "composer"), PHP_PATHS),
    ((".net", "asp", "dotnet", "c#", "iis", "azure"), DOTNET_PATHS),
    (("node", "express", "koa", "nest", "npm", "yarn"), NODE_PATHS),
    (("python", "django", "flask", "fastapi", "tornado"), PYTHON_PATHS),
]

