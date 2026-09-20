"""§4 Phase 2 item 4：知识包化 — 五段 markdown 模板 + 按 risk_domain 按需注入。

设计目标：
- 降低 token 成本：不同 risk_domain 只注入该域相关的五段方法论，而非全量 SKILL。
- 五段结构（与 api-pentest-extension 方法论骨架对齐）：
    1. 概述（overview）       — 漏洞原理 + 典型场景
    2. 检测步骤（steps）      — 可执行的检测流程
    3. 绕过技巧（bypass）     — WAF/过滤器绕过要点
    4. 误报判断（fp_control） — 确认条件，避免假阳
    5. 报告要点（report）     — 报告撰写要点
- ``load_skill_sections(domain)`` 返回五段拼装的 markdown 字符串。
- ``DOMAIN_TO_SECTIONS`` 是 8 个 risk_domain 到五段内容的映射。

零外部依赖（纯 stdlib）。
"""
from __future__ import annotations

from typing import Iterable

# 8 个 risk_domain（与 core.endpoint.risk_domain.RISK_DOMAIN_RULES 对齐）
DOMAINS = (
    "upload", "ssrf", "injection", "authz",
    "csrf", "file", "business", "config",
)

# 五段结构定义
SECTION_NAMES = ("overview", "steps", "bypass", "fp_control", "report")

# 各域五段内容（精简但可用，避免超长 token）
_DOMAIN_SECTIONS: dict[str, dict[str, str]] = {
    "upload": {
        "overview": "文件上传漏洞：攻击者通过上传点植入恶意文件（webshell/解析漏洞），"
                    "最终实现 RCE 或存储型 XSS。",
        "steps": "1. 探测上传点（/upload、/avatar、/import）\n"
                 "2. 尝试扩展名绕过（大小写/双写/::$DATA/分号截断）\n"
                 "3. 验证解析（Nginx/Apache/IIS 解析漏洞）\n"
                 "4. 直链未授权三态：无 token/正确 sign/错误 sign\n"
                 "5. 重放篡改 sign 比对签名是否真生效",
        "bypass": "- Content-Type 伪造（image/png 内容含 webshell）\n"
                  "- 图片马（GIF89a + PHP）\n"
                  "- 解析漏洞（.php.jpg、.php%00.jpg）",
        "fp_control": "确认条件：上传后文件可被服务器解析执行，或直链可下载未授权资源。"
                      "仅 '上传成功' 不构成漏洞。",
        "report": "报告需包含：上传点 URL、绕过手法、解析路径、直链三态对比表、签名验证结果。",
    },
    "ssrf": {
        "overview": "SSRF 服务端请求伪造：服务器根据用户输入发起内部请求，可探测内网、"
                    "读取云元数据（169.254.169.254）、攻击内部服务。",
        "steps": "1. 识别可控 URL 参数（url/urlfetch/webhook/preview）\n"
                 "2. 尝试内网地址（127.0.0.1、10.x、169.254.169.254）\n"
                 "3. DNS rebinding / 302 跳转绕过 IP 黑名单\n"
                 "4. 协议变种（gopher/file/dict）",
        "bypass": "- 十进制/八进制/十六进制 IP\n"
                  "- @ 符号绕过（http://evil@internal）\n"
                  "- DNS rebinding",
        "fp_control": "确认条件：响应内容包含内网服务响应（如云元数据、Redis 响应）。"
                      "仅 '请求被转发' 不构成漏洞。",
        "report": "报告需包含：注入点、可达内网服务清单、读取的敏感数据、云元数据验证。",
    },
    "injection": {
        "overview": "注入类漏洞（SQL/NoSQL/SSTI/命令注入等）：用户输入未过滤直接拼入"
                    "后端解析器，导致代码执行或数据泄露。",
        "steps": "1. 识别输入点（query/body/header/cookie）\n"
                 "2. 单引号/括号探测语法错误\n"
                 "3. 布尔盲注（TRUE/FALSE 响应差异）\n"
                 "4. 时间盲注（sleep）\n"
                 "5. 报错注入（extractvalue/updatexml）",
        "bypass": "- 注释符（-- # /* */）\n"
                  "- 编码（URL/Unicode/Hex）\n"
                  "- 大小写混合（SeLeCt）\n"
                  "- 等价函数（concat 转 ||）",
        "fp_control": "确认条件：能从数据库读取非预期数据或修改数据。"
                      "仅 '响应延迟' 需排除网络抖动。",
        "report": "报告需包含：注入点、payload、回显数据、数据库类型推断。",
    },
    "authz": {
        "overview": "越权/鉴权漏洞（IDOR/垂直越权）：低权限用户可访问高权限资源或"
                    "他人资源。核心是资源标识符未鉴权。",
        "steps": "1. 识别资源标识符（id/order_id/user_id）\n"
                 "2. 替换 ID 为他人值，观察响应\n"
                 "3. CRUD 全覆盖（GET/POST/PUT/DELETE）\n"
                 "4. 跨租户 BOLA：tenant-A token 访问 tenant-B 资源\n"
                 "5. 签名真生效验证",
        "bypass": "- 参数污染（id=1&id=2）\n"
                  "- JSON 嵌套（{\"user\":{\"id\":1}}）\n"
                  "- 数组注入（id[]=1）\n"
                  "- Base64/hex/UUID v1 预测",
        "fp_control": "确认条件：响应数据长度/内容随 ID 变化且返回他人数据。"
                      "仅 '200 OK' 不构成越权（可能返回空）。",
        "report": "报告需包含：端点、ID 替换对比表（A/B 响应 diff）、"
                  "跨租户验证结果、签名验证结果。",
    },
    "csrf": {
        "overview": "CSRF 跨站请求伪造：诱导已登录用户在恶意站点发起请求，"
                    "利用浏览器自动携带 Cookie 完成越权操作。",
        "steps": "1. 识别状态改变端点（POST 修改操作）\n"
                 "2. 检查是否有 CSRF Token/Referer/Origin 校验\n"
                 "3. 构造跨站请求表单\n"
                 "4. 验证 SameSite Cookie",
        "bypass": "- 缺 CSRF Token\n"
                  "- Referer 校验可绕过（空 Referer、子域）\n"
                  "- SameSite=None",
        "fp_control": "确认条件：去掉 Token 后请求仍被服务器接受并执行。"
                      "需验证是真实执行而非仅返回 200。",
        "report": "报告需包含：漏洞端点、PoC HTML、Cookie 属性、防护缺失点。",
    },
    "file": {
        "overview": "文件读取/下载漏洞（路径穿越 LFI）：通过 ../ 或编码绕过路径限制，"
                    "读取任意文件（/etc/passwd、配置文件、源码）。",
        "steps": "1. 识别文件读取参数（path/file/name）\n"
                 "2. 尝试 ../../etc/passwd\n"
                 "3. 编码绕过（%2e%2e/、....//、/..;/）\n"
                 "4. Null byte 截断（%00，老版本 PHP）\n"
                 "5. 目标：配置文件/日志/密钥",
        "bypass": "- 双写 ....// -> ../\n"
                  "- URL 二次编码\n"
                  "- Windows ::$DATA",
        "fp_control": "确认条件：响应内容包含目标文件内容（/etc/passwd 的 root 行）。"
                      "仅 '文件下载成功' 需确认是否越权路径。",
        "report": "报告需包含：读取参数、payload、读取的文件内容片段。",
    },
    "business": {
        "overview": "业务逻辑漏洞：利用业务流程缺陷（金额篡改/状态篡改/竞态条件/重复使用），"
                    "造成经济损失或权限提升。",
        "steps": "1. 识别业务流程（下单/支付/提现/优惠券）\n"
                 "2. 金额篡改（price=0.01、amount=-1）\n"
                 "3. 状态篡改（status=paid）\n"
                 "4. 竞态条件（并发请求，信号量竞争）\n"
                 "5. 重复使用（一次性券码重复领取）",
        "bypass": "- 负金额 / 大数溢出\n"
                  "- 状态机跳步\n"
                  "- 并发重复提交",
        "fp_control": "确认条件：业务实际执行异常结果（0 元下单成功、重复领取成功）。"
                      "需核实服务端是否真正落库。",
        "report": "报告需包含：业务流程、篡改点、异常结果对比、影响金额估算。",
    },
    "config": {
        "overview": "配置/信息泄露：通过 Actuator/Swagger/heapdump/debug 端点"
                    "获取系统配置、密钥、环境变量。",
        "steps": "1. 探测常见端点（/actuator、/swagger-ui、/env、/heapdump）\n"
                 "2. 检查默认凭据（actuator 免登录）\n"
                 "3. 从配置中提取密钥/数据库连接串\n"
                 "4. heapdump 内存分析（Java）",
        "bypass": "- /actuator/heapdump\n"
                  "- /actuator/env 泄露密钥\n"
                  "- /swagger-resources",
        "fp_control": "确认条件：端点返回真实配置数据（含密钥/IP/账号）。"
                      "仅 '端点存在' 不构成泄露。",
        "report": "报告需包含：泄露端点 URL、泄露的敏感数据（脱敏）、影响范围。",
    },
}

# 未知域的通用兜底段
_GENERIC_SECTIONS: dict[str, str] = {
    "overview": "通用漏洞检测：根据端点特性选择对应检测策略。",
    "steps": "1. 识别输入点与鉴权方式\n2. 逐项验证 OWASP Top 10\n3. 关注业务逻辑异常",
    "bypass": "参考对应漏洞类型的绕过方法论。",
    "fp_control": "确认条件：能证明漏洞可被利用产生实际危害。",
    "report": "报告需包含：漏洞点、PoC、影响、修复建议。",
}


def get_sections(domain: str) -> dict[str, str]:
    """获取指定 risk_domain 的五段内容。未知域返回通用兜底。"""
    return _DOMAIN_SECTIONS.get(domain, _GENERIC_SECTIONS)


def load_skill_sections(domain: str, include: Iterable[str] | None = None) -> str:
    """拼装五段 markdown 字符串。

    Args:
        domain: risk_domain 名称（upload/ssrf/injection/authz/csrf/file/business/config）
        include: 仅包含指定段名（默认全部五段），用于按需注入降 token

    Returns:
        拼装后的 markdown 字符串。
    """
    sections = get_sections(domain)
    if include:
        names = [n for n in include if n in SECTION_NAMES]
    else:
        names = list(SECTION_NAMES)
    out = [f"## {domain} 方法论"]
    for name in names:
        out.append(f"\n### {_SECTION_TITLES[name]}\n{sections[name]}")
    return "\n".join(out)


_SECTION_TITLES: dict[str, str] = {
    "overview": "概述",
    "steps": "检测步骤",
    "bypass": "绕过技巧",
    "fp_control": "误报判断",
    "report": "报告要点",
}


def available_domains() -> list[str]:
    """返回所有已注册的 risk_domain。"""
    return list(DOMAINS)


def token_estimate(domain: str, include: Iterable[str] | None = None) -> int:
    """估算拼装内容的 token 数（按字符数 / 4 粗估，用于按需注入决策）。"""
    text = load_skill_sections(domain, include)
    return len(text) // 4
