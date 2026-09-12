"""公共路径过滤器 — 统一初始 dirscan、探索 dirscan 和补测 dirscan 的路径过滤标准。

提取自 supplemental_test_agent.py，避免路径过滤逻辑分散在多个模块中。
"""

# ---- 静态资源后缀 / 路径段 ----
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
    # ★ 通用 PHP/WordPress 工具路径（OPT5: 防止 dirscan 字典污染 sitemap）
    "/adminer.php", "/admin.php",
    "/wp-login.php", "/wp-config.php", "/wp-admin",
    "/wp-content", "/wp-includes",
    "/xmlrpc.php", "/install.php", "/setup.php",
    "/phpmyadmin", "/pma", "/adminer",
    "/license.php", "/license.txt",
    "/readme.html", "/readme.txt",
    "/change log.txt", "/changelog.txt",
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


def is_non_business_path(path: str) -> bool:
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
