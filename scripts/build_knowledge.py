"""scripts/build_knowledge.py — 一次性生成离线知识库骨架（中期 M4）。

按 XUANJIAN_ROADMAP_MID_TERM §5.3 Step 1 落地。
- 生成 data/knowledge/owasp/A01-A10.md
- 复制 core/cwe_dict.py 到 data/knowledge/cwe/cwe_dict.py
- 生成 data/knowledge/remediation/template_{python,java,go,node}.md

幂等：可重复执行；覆盖旧文件。
零外部依赖。
"""
from __future__ import annotations

import pathlib
import shutil

ROOT = pathlib.Path("data/knowledge")

OWASP_DESCS: dict[str, str] = {
    "A01": "Broken Access Control：访问控制缺陷，含 IDOR / 越权 / 路径遍历。\n\n"
           "**修复方向**：\n- 强制鉴权中间件覆盖所有受保护路由\n"
           "- 资源 owner 校验（防止水平越权）\n- 路径规范化 + 白名单",
    "A02": "Cryptographic Failures：加密失效。\n\n"
           "**修复方向**：\n- TLS 1.2+ 强制\n- 敏感字段（密码 / token / 身份证）加密存储\n"
           "- 不使用自实现加密算法",
    "A03": "Injection：注入类（SQLi / XSS / SSTI / 命令注入）。\n\n"
           "**修复方向**：\n- 参数化查询（不要字符串拼接 SQL）\n- 输出编码（HTML / JS / URL）\n"
           "- ORM + 白名单过滤",
    "A04": "Insecure Design：不安全设计。\n\n"
           "**修复方向**：\n- 威胁建模（STRIDE / LINDDUN）\n- 安全开发生命周期（SDLC）\n"
           "- 关键业务流程加风控",
    "A05": "Security Misconfiguration：配置错误。\n\n"
           "**修复方向**：\n- 最小权限原则\n- 默认安全配置（关闭调试模式 / 默认账户）\n"
           "- 定期配置基线核查",
    "A06": "Vulnerable Components：组件漏洞。\n\n"
           "**修复方向**：\n- SCA 扫描（pip-audit / npm audit）\n- 及时升级到最新稳定版\n"
           "- 供应链 SBOM 管理",
    "A07": "Authentication Failures：认证失败。\n\n"
           "**修复方向**：\n- 多因素认证（MFA）\n- 强密码策略 + 密码哈希（bcrypt / argon2）\n"
           "- 登录限速 + 失败锁定",
    "A08": "Software & Data Integrity：完整性失效。\n\n"
           "**修复方向**：\n- CI/CD 加签名验证\n- 反序列化白名单\n"
           "- 不信任客户端传入的更新包",
    "A09": "Logging Failures：日志不足。\n\n"
           "**修复方向**：\n- 关键操作（登录 / 支付 / 权限变更）全审计\n- 告警规则（异常登录 / 批量失败）\n"
           "- 日志完整性保护（防篡改）",
    "A10": "SSRF：服务端请求伪造。\n\n"
           "**修复方向**：\n- URL 白名单（仅允许已知外部域）\n- 屏蔽内网段（127.0.0.0/8、10.0.0.0/8、172.16/12、192.168/16）\n"
           "- DNS 解析结果二次校验（防止 rebinding）",
}

REMEDIATION_TEMPLATES: dict[str, str] = {
    "python": """# Python 修复模板

## 1. 输入校验
- 使用 pydantic / marshmallow 做 schema 校验
- 路径参数白名单 + 长度限制

## 2. 输出编码
- Jinja2 autoescape=True（防 XSS）
- SQLAlchemy 参数化查询（防 SQLi）

## 3. 鉴权中间件
- FastAPI Depends(get_current_user)
- 资源 owner 校验（防 IDOR）

## 4. 日志记录
- logging JSON 输出
- 关键操作审计 + 告警
""",
    "java": """# Java 修复模板

## 1. 输入校验
- Bean Validation (jakarta.validation)
- OWASP Java Encoder

## 2. 输出编码
- Thymeleaf 自动转义
- PreparedStatement 参数化

## 3. 鉴权中间件
- Spring Security FilterChain
- @PreAuthorize 资源级控制

## 4. 日志记录
- Logback JSON encoder
- MDC 追踪 + 告警
""",
    "go": """# Go 修复模板

## 1. 输入校验
- go-playground/validator
- net/url 严格解析

## 2. 输出编码
- html/template（自动转义）
- database/sql 参数化

## 3. 鉴权中间件
- gin / chi 中间件
- 资源 owner 校验

## 4. 日志记录
- zap JSON 输出
- 关键操作审计
""",
    "node": """# Node.js 修复模板

## 1. 输入校验
- joi / zod schema 校验
- express-validator

## 2. 输出编码
- EJS / Pug 默认转义
- mysql2 参数化

## 3. 鉴权中间件
- passport.js
- express-jwt

## 4. 日志记录
- pino JSON 输出
- 关键操作审计 + 告警
""",
}


def build() -> dict:
    """生成知识库。返回 {files, root}。"""
    (ROOT / "owasp").mkdir(parents=True, exist_ok=True)
    (ROOT / "cwe").mkdir(parents=True, exist_ok=True)
    (ROOT / "remediation").mkdir(parents=True, exist_ok=True)

    file_count = 0

    # OWASP 10 项
    for k, v in OWASP_DESCS.items():
        (ROOT / "owasp" / f"{k}.md").write_text(
            f"# {k}\n\n{v}\n\n修复建议请参考本地 `remediation/template_<lang>.md` 模板。\n",
            encoding="utf-8",
        )
        file_count += 1

    # CWE 字典（从 core 复制，保留单源）
    src = pathlib.Path("core/cwe_dict.py")
    if src.exists():
        shutil.copy(src, ROOT / "cwe" / "cwe_dict.py")
        file_count += 1

    # 修复模板 4 份
    for lang, body in REMEDIATION_TEMPLATES.items():
        (ROOT / "remediation" / f"template_{lang}.md").write_text(body, encoding="utf-8")
        file_count += 1

    return {"root": str(ROOT), "files": file_count}


if __name__ == "__main__":
    import json

    out = build()
    print(json.dumps(out, ensure_ascii=False, indent=2))
