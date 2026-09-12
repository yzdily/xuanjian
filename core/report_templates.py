"""
ReportTemplates — FAST 模式本地模板归因（P2-B）

为 FAST 模式报告阶段提供基于预置模板的风险归因，
不依赖 LLM，根据漏洞类型自动拼接风险描述和修复步骤。

使用方式：
    from core.report_templates import generate_fast_report_attribution
    attribution = generate_fast_report_attribution(sitemap)
"""

from __future__ import annotations

from typing import Any

from core.log import get_logger

log = get_logger("report_templates")


# ============================================================
# 漏洞类型 → 风险描述 + 修复步骤模板
# ============================================================

_VULN_TEMPLATES: dict[str, dict[str, str]] = {
    "sql_injection": {
        "name": "SQL 注入",
        "risk": "攻击者可通过注入恶意 SQL 语句，读取、修改或删除数据库中的敏感数据，"
                "甚至获取数据库服务器权限，导致数据泄露或完全控制服务器。",
        "impact": "高危 — 可导致全库数据泄露、篡改或删除",
        "fix": (
            "1. 使用参数化查询（PreparedStatement / ORM），禁止拼接 SQL\n"
            "2. 对所有用户输入进行严格过滤和类型校验\n"
            "3. 数据库账户使用最小权限原则，禁止应用账户使用 DBA 权限\n"
            "4. 部署 WAF 规则拦截常见注入 payload"
        ),
        "owasp": "A03:2021 - Injection",
    },
    "xss": {
        "name": "跨站脚本攻击（XSS）",
        "risk": "攻击者可注入恶意 JavaScript 代码，在受害者浏览器中执行，"
                "窃取 Cookie/Session、劫持用户操作或进行钓鱼攻击。",
        "impact": "中高危 — 可导致会话劫持、敏感信息窃取",
        "fix": (
            "1. 所有输出到 HTML 的内容必须进行 HTML 实体编码\n"
            "2. 对 JavaScript 上下文中的数据使用 JSON.stringify + 转义\n"
            "3. 设置 Content-Security-Policy 头限制脚本来源\n"
            "4. Cookie 设置 HttpOnly 和 Secure 属性"
        ),
        "owasp": "A03:2021 - Injection",
    },
    "info_disclosure": {
        "name": "敏感信息泄露",
        "risk": "系统暴露了敏感信息（如堆栈跟踪、内部路径、版本号、密钥等），"
                "攻击者可利用这些信息制定更精准的攻击计划。",
        "impact": "中危 — 辅助攻击者了解系统内部结构",
        "fix": (
            "1. 生产环境关闭调试模式和详细错误信息\n"
            "2. 自定义错误页面，不暴露堆栈跟踪\n"
            "3. 检查所有 API 响应，移除不必要的内部字段\n"
            "4. 配置服务器隐藏版本号和 banner 信息"
        ),
        "owasp": "A01:2021 - Broken Access Control",
    },
    "unauthorized": {
        "name": "未授权访问",
        "risk": "API 或功能点缺少认证校验，攻击者可直接访问本应需要登录的接口，"
                "获取敏感数据或执行敏感操作。",
        "impact": "高危 — 可导致越权访问和数据泄露",
        "fix": (
            "1. 所有敏感接口必须强制认证校验（中间件/装饰器统一拦截）\n"
            "2. 实现基于角色的访问控制（RBAC）\n"
            "3. 对每个 API 端点进行权限矩阵审查\n"
            "4. 定期进行越权测试"
        ),
        "owasp": "A01:2021 - Broken Access Control",
    },
    "weak_password": {
        "name": "弱口令",
        "risk": "系统存在弱口令账户，攻击者可通过暴力破解或字典攻击获取账户权限，"
                "进而以合法用户身份访问系统。",
        "impact": "中高危 — 可导致账户被接管",
        "fix": (
            "1. 强制密码复杂度要求（至少 8 位，包含大小写+数字+特殊字符）\n"
            "2. 登录失败次数限制 + 账户锁定机制\n"
            "3. 启用验证码防止自动化暴力破解\n"
            "4. 定期审计弱口令账户"
        ),
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "cors": {
        "name": "CORS 配置不当",
        "risk": "跨域资源共享（CORS）配置过于宽松，允许任意来源读取响应，"
                "攻击者可构造恶意页面窃取已登录用户的数据。",
        "impact": "中危 — 可导致跨域数据窃取",
        "fix": (
            "1. 避免 Access-Control-Allow-Origin: *，使用白名单机制\n"
            "2. 不要将 Origin 头直接反射到 ACAO 头\n"
            "3. 敏感接口关闭 CORS 或仅允许可信域\n"
            "4. Access-Control-Allow-Credentials: true 时禁止使用通配符"
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
    },
    "path_traversal": {
        "name": "路径穿越",
        "risk": "攻击者可通过 ../ 等路径穿越字符访问服务器上的任意文件，"
                "读取配置文件、源代码或系统敏感文件。",
        "impact": "高危 — 可导致任意文件读取",
        "fix": (
            "1. 对所有文件路径参数进行规范化（realpath）和边界检查\n"
            "2. 使用白名单限制可访问的目录范围\n"
            "3. 禁止用户输入直接拼接文件路径\n"
            "4. 应用以最小权限账户运行"
        ),
        "owasp": "A01:2021 - Broken Access Control",
    },
    "command_injection": {
        "name": "命令注入",
        "risk": "攻击者可通过注入系统命令，在服务器上执行任意命令，"
                "完全控制服务器，导致数据泄露、服务中断或横向渗透。",
        "impact": "严重 — 可导致服务器完全被控",
        "fix": (
            "1. 避免直接调用系统命令，使用语言内置库替代\n"
            "2. 如必须调用命令，使用参数化 API（如 subprocess.run(list)）\n"
            "3. 对输入进行严格白名单过滤\n"
            "4. 命令执行使用最小权限账户"
        ),
        "owasp": "A03:2021 - Injection",
    },
    "ssrf": {
        "name": "服务端请求伪造（SSRF）",
        "risk": "攻击者可让服务器发起任意网络请求，访问内网服务、云元数据接口"
                "或其他受限资源，导致内网信息泄露或远程命令执行。",
        "impact": "高危 — 可导致内网穿透和云资源接管",
        "fix": (
            "1. 对所有外部请求 URL 进行白名单校验\n"
            "2. 禁止访问内网 IP 段（10.x / 172.16-31.x / 192.168.x）\n"
            "3. 禁止访问云元数据接口（169.254.169.254）\n"
            "4. DNS 解析后校验 IP 是否为内网地址"
        ),
        "owasp": "A10:2021 - Server-Side Request Forgery",
    },
}


def generate_fast_report_attribution(sitemap: Any) -> str:
    """根据 sitemap 中的扫描结果生成本地模板归因报告。

    不依赖 LLM，纯本地模板拼接，为 FAST 模式提供有意义的报告输出。

    Args:
        sitemap: Sitemap 实例，包含 features 和 checklist 结果

    Returns:
        Markdown 格式的归因报告字符串
    """
    if sitemap is None:
        return "⚠️ 无扫描数据可用"

    # 收集所有漏洞
    vulns_by_type: dict[str, list[dict]] = {}
    total_features = 0
    tested_features = 0
    total_checks = 0
    vuln_checks = 0
    safe_checks = 0
    # ★ OPT2-P0: 统计跳过/待测数，计算真实完成率
    skipped_checks = 0
    pending_checks = 0

    try:
        from core.sitemap import CheckResult

        features = getattr(sitemap, "features", {}) or {}
        total_features = len(features)

        for fp in features.values():
            if getattr(fp, "deferred", False):
                continue
            checklist = getattr(fp, "checklist", []) or []
            if checklist:
                tested_features += 1
            for c in checklist:
                total_checks += 1
                if c.result == CheckResult.VULN:
                    vuln_checks += 1
                    vuln_type = getattr(c, "vuln_type", "unknown")
                    if vuln_type not in vulns_by_type:
                        vulns_by_type[vuln_type] = []
                    vulns_by_type[vuln_type].append({
                        "feature": getattr(fp, "name", ""),
                        "url": getattr(c, "evidence_request", "") or "",
                        "detail": getattr(c, "detail", ""),
                        "severity": getattr(c, "severity", "medium"),
                    })
                elif c.result == CheckResult.SAFE:
                    safe_checks += 1
                elif c.result == CheckResult.SKIPPED:
                    skipped_checks += 1
                elif c.result == CheckResult.PENDING:
                    pending_checks += 1
    except Exception as e:
        log.warning("generate_fast_report_attribution 收集漏洞失败: %s", e)

    # ★ OPT2-P0: 计算真实完成率
    real_done = vuln_checks + safe_checks
    real_rate = round(real_done / total_checks * 100, 1) if total_checks > 0 else 0.0
    skip_rate = round(skipped_checks / total_checks * 100, 1) if total_checks > 0 else 0.0

    # 构建 Markdown 报告
    lines = []
    lines.append("## FAST 模式扫描报告（本地模板归因）\n")
    lines.append(f"**扫描模式**: FAST（本地规则引擎）\n")

    # 模式升降级信息
    lines.append(f"**测试功能点**: {tested_features}/{total_features}")
    lines.append(f"**检查项总数**: {total_checks}")
    lines.append(f"**发现漏洞**: {vuln_checks} 个")
    lines.append(f"**安全项**: {safe_checks} 个")
    # ★ OPT2-P0: 显示真实完成率而非含跳过的完成率
    lines.append(f"**真实完成率**: {real_rate}%（{real_done}/{total_checks} 项真实执行）")
    if skip_rate > 0:
        lines.append(f"**跳过率**: {skip_rate}%（{skipped_checks} 项跳过 LLM 分析）")
    lines.append("")

    # ★ OPT2-P0: 空心化告警
    if total_checks > 0 and real_rate < 10.0 and skip_rate > 70.0 and vuln_checks == 0:
        lines.append("> ## ⚠️ 测试过程疑似空心化告警\n")
        lines.append(f"> 真实完成率仅 **{real_rate}%**，跳过率 **{skip_rate}%**，漏洞数 **0**。\n")
        lines.append("> 报告完成率数字不能反映真实测试覆盖度。\n")
        lines.append("> 建议：检查目标是否为 SPA 单页应用，或切换到标准/深度模式重新扫描。\n")

    if not vulns_by_type:
        lines.append("\n### ✅ 未发现漏洞\n")
        lines.append("FAST 模式扫描未发现已知漏洞模式。请注意：")
        lines.append("- FAST 模式仅运行本地规则引擎，不包含 LLM 深度分析")
        lines.append("- 业务逻辑漏洞、复杂越权等需切换到标准/深度模式检测")
        lines.append("- 建议定期使用标准模式进行全面扫描\n")
        return "\n".join(lines)

    # 按漏洞类型输出归因
    lines.append("\n### 📋 漏洞详情与修复建议\n")
    for vuln_type, findings in sorted(vulns_by_type.items(), key=lambda x: -len(x[1])):
        template = _VULN_TEMPLATES.get(vuln_type, {})
        name = template.get("name", vuln_type)
        risk = template.get("risk", "该漏洞类型暂无预置风险描述。")
        impact = template.get("impact", "")
        fix = template.get("fix", "请参考 OWASP 官方文档获取修复建议。")
        owasp = template.get("owasp", "")

        lines.append(f"\n#### {name} ({len(findings)} 个)\n")
        if owasp:
            lines.append(f"**OWASP 分类**: {owasp}\n")
        lines.append(f"**风险描述**: {risk}\n")
        if impact:
            lines.append(f"**影响等级**: {impact}\n")
        lines.append(f"**修复建议**:\n```\n{fix}\n```\n")

        # 列出具体发现
        lines.append("**发现位置**:\n")
        for f in findings[:5]:  # 最多展示 5 个
            feat = f.get("feature", "")
            url = f.get("url", "")[:100]
            lines.append(f"- {feat}: `{url}`")
        if len(findings) > 5:
            lines.append(f"- ... 及其他 {len(findings) - 5} 个\n")

    lines.append("\n---")
    lines.append("*本报告由 FAST 模式本地模板自动生成，不含 LLM 分析。")
    lines.append("如需深度分析、业务逻辑测试或漏洞危害验证，请切换到标准或深度模式重新扫描。*")

    return "\n".join(lines)
