"""fast_scanner 认证类漏洞检测 mixin（从原 fast_scanner.py 机械拆分，方法体逐字保留）。"""
# noqa: giant  — 历史存量：认证类检测规则集中，D6 Stage 2-4 逐步消化

from __future__ import annotations

import asyncio
import json
import re

import httpx

from core.log import get_logger

from ._constants import WEAK_CREDENTIALS
from ._fp_filters import (
    _is_business_deny,
    _is_empty_data,
    _is_waf_block_page,
    _normalize_body,
    _bodies_similar,
    _body_contains_sensitive_data,
    _is_public_data,
    _is_auth_wall_page,
)
from ._models import VulnFinding, ScanTarget

log = get_logger("fast_scanner")


# ============================================================
# §2.8 P1 全类别补检（0918 技术方案 §3.12.2 / §3.12.3）
# ============================================================

# 403 绕过探测技术（CWE-425 / CWE-284）
BYPASS_PROBES = ["大小写", "..;/", "%2e", "X-Original-URL", "X-Forwarded-For", "X-Rewrite-URL"]

# 验证码端点关键词（CWE-804 / CWE-200）
CAPTCHA_ENDPOINT_KEYWORDS = ["captcha", "verify", "getcode", "randpic", "kaptcha",
                             "seccode", "vcode", "slider", "slide", "puzzle"]
CAPTCHA_ANSWER_LEAK_FIELDS = ["y", "array", "answer", "solution", "offset", "position",
                              "gap", "result", "correct", "code", "value", "x_offset",
                              "y_offset", "slide_x", "distance", "target"]

# 批量赋值注入字段（CWE-915）
MASS_ASSIGNMENT_FIELDS = [
    ("role", "admin"), ("is_admin", "true"), ("admin", "true"),
    ("isAdmin", "true"), ("isadmin", "1"), ("user_type", "admin"),
    ("permission", "admin"), ("role_id", "1"), ("is_superuser", "true"),
]

# 频控缺失检测并发数（红线：仅检测，不真发轰炸）
RATE_LIMIT_PROBE_COUNT = 5


class _ChecksAuth:
    """认证类漏洞检测方法（未授权 / 越权矩阵 / IDOR / 弱口令 / CORS / CSRF / JWT）。"""

    async def _check_unauthorized(self, target: ScanTarget) -> list[VulnFinding]:
        """未授权访问检测：去认证后请求对比"""
        findings = []

        # ★ P0 防误报：登录/认证提交接口本身就是匿名可访问的（用户在认证前提交凭据），
        # 去认证后返回 200 属正常行为，不应报未授权访问。
        _url_lower = target.url.lower()
        _LOGIN_AUTH_ENDPOINTS = (
            "/login", "/signin", "/auth", "/login_psw", "/login_auth",
            "/login_cert", "/logon", "/authenticate", "/sso/login",
            "/api/auth", "/oauth/token", "/session",
        )
        if any(ep in _url_lower for ep in _LOGIN_AUTH_ENDPOINTS):
            log.info("[SCAN] Unauth | 登录/认证接口本身允许匿名访问，跳过未授权检测: %s", target.url)
            return []

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
            noauth_text = noauth_resp.text or ""
            # ★ P0 防误报铁律1：业务层拒绝 → HTTP 200 但响应体含
            # "code:500, message:用户未登录" 等业务拒绝码 → 业务层已鉴权，不是未授权访问
            if _is_business_deny(noauth_text):
                log.info("[SCAN] Unauth | 去认证 200 但响应体为业务层拒绝(已鉴权)，跳过: %s", target.url)
                pass
            # ★ P0 防误报铁律2：空 data → 200 但 data:null/[] → 无数据泄露，不算漏洞
            elif _is_empty_data(noauth_text):
                log.info("[SCAN] Unauth | 去认证 200 但响应体为空 data，跳过: %s", target.url)
                pass
            # 内容相似度 > 80%（归一化后比较）
            elif abs(auth_len - noauth_len) < max(auth_len * 0.2, 100):
                # ★ 多因素验证：只看长度/状态码会大量误报公开接口
                if _is_public_data(noauth_text, noauth_ct):
                    # 公开数据（公告/商品/SPA 壳/静态资源）→ 不算漏洞
                    log.info("[SCAN] Unauth | 去认证 200 但响应体为公开数据，跳过: %s", target.url)
                    pass
                # ★ 优化.md 建议1 缺口：去认证后返回登录/认证墙页面（含密码输入框+登录特征）
                #   登录页天然含 password 字段，会被敏感数据检测误判 → 提前剔除
                elif _is_auth_wall_page(noauth_text):
                    log.info("[SCAN] Unauth | 去认证 200 但响应体为登录/认证墙页面，跳过: %s", target.url)
                    pass
                # ★ 认证/去认证响应归一化后完全一致 → 无鉴权差异（公开页或统一兜底页）
                elif _normalize_body(auth_resp.text) == _normalize_body(noauth_text):
                    log.info("[SCAN] Unauth | 认证与去认证响应归一化后一致，无鉴权差异，跳过: %s", target.url)
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

    async def _check_auth_matrix(self, target: ScanTarget) -> list[VulnFinding]:
        """★ 优化.md 建议4：三身份认证对照（Auth Matrix）。

        对每个接口执行三身份请求矩阵：
          1. 无凭证请求 → 记录状态码 + 响应体
          2. 认证请求（现有 auth_headers） → 记录状态码 + 响应体
          3. IDOR 探测：修改 URL 中的资源 ID，用认证身份请求他人资源

        判定规则：
          - 无凭证 200 且响应 == 认证响应 → 公开接口，降级为 Info（不算漏洞）
          - 无凭证 200 且响应含敏感数据 ≠ 认证响应 → 未授权访问（已被 _check_unauthorized 覆盖，此处补矩阵证据）
          - IDOR 探测成功（认证身份访问到他人资源） → High/Critical
          - 仅有无凭证 200 但无对照证据 → 不定 High/Critical（降级为 Medium）

        与 _check_unauthorized 的区别：
          - _check_unauthorized 是二元对比（auth vs no-auth），只看是否泄露
          - _check_auth_matrix 是三元矩阵 + IDOR 探测，记录结构化对照证据
        """
        findings = []

        # 跳过登录/认证接口（本身允许匿名访问）
        _url_lower = target.url.lower()
        _LOGIN_AUTH_ENDPOINTS = (
            "/login", "/signin", "/auth", "/login_psw", "/login_auth",
            "/login_cert", "/logon", "/authenticate", "/sso/login",
            "/api/auth", "/oauth/token", "/session",
        )
        if any(ep in _url_lower for ep in _LOGIN_AUTH_ENDPOINTS):
            return []

        # ── 身份1：无凭证请求 ──
        noauth_resp = await self._request(
            target.method, target.url,
            headers=target.headers,
            content=target.body,
            drop_auth=True,
            rule_tag="AuthMatrix", payload_tag="no_cred",
        )

        # ── 身份2：认证请求（基线） ──
        auth_resp = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body,
            rule_tag="AuthMatrix", payload_tag="with_auth",
        )

        if not noauth_resp or not auth_resp:
            return []

        noauth_text = noauth_resp.text or ""
        auth_text = auth_resp.text or ""
        noauth_status = noauth_resp.status_code
        auth_status = auth_resp.status_code

        # ── 矩阵判定1：无凭证 200 且 == 认证响应 → 公开接口，降级 ──
        # 优化.md：仅无凭证200 但高权限响应相同 → 可能本来就是公开接口，降级
        if (noauth_status == 200 and auth_status == 200
                and _normalize_body(noauth_text) == _normalize_body(auth_text)):
            log.info("[SCAN] AuthMatrix | 无凭证与认证响应一致，判定为公开接口: %s", target.url)
            # 不产生漏洞，但记录矩阵结果供报告溯源
            return []

        # ── 矩阵判定2：IDOR 探测 ──
        # 提取 URL 中的资源 ID（/api/users/123, ?id=123, ?userId=456）
        idor_findings = await self._probe_idor(target, auth_resp)
        findings.extend(idor_findings)

        # ── 矩阵判定3：无凭证 200 且含敏感数据（补矩阵证据） ──
        # _check_unauthorized 已覆盖此场景，此处仅当未检出时补一条带矩阵证据的发现
        if (noauth_status == 200 and auth_status == 200
                and not _is_business_deny(noauth_text)
                and not _is_empty_data(noauth_text)
                and not _is_auth_wall_page(noauth_text)
                and _body_contains_sensitive_data(noauth_text)
                and _normalize_body(noauth_text) != _normalize_body(auth_text)):
            # 确认不是公开接口（响应不同）且含敏感数据 → 未授权访问
            # 记录三身份矩阵作为对照证据
            matrix_detail = (
                f"三身份认证对照检出未授权访问：\n"
                f"  无凭证: HTTP {noauth_status}, body={len(noauth_text)}字符\n"
                f"  认证用户: HTTP {auth_status}, body={len(auth_text)}字符\n"
                f"  对照结论: 无凭证可获取与认证用户不同的敏感数据"
            )
            findings.append(VulnFinding(
                vuln_type="未授权访问",
                severity="high",
                url=target.url,
                method=target.method,
                detail=matrix_detail,
                evidence=f"无凭证响应: {noauth_text[:300]}\n---\n认证响应: {auth_text[:300]}",
                fix_suggestion="添加认证中间件，对所有 API 请求强制鉴权；对敏感数据接口实施最小权限原则",
                evidence_quality="body_confirmed",
                rule_tag="AuthMatrix",
            ))

        return findings

    async def _probe_idor(self, target: ScanTarget, auth_resp: httpx.Response) -> list[VulnFinding]:
        """★ 优化.md 建议4：IDOR 探测 — 修改 URL 中的资源 ID 尝试越权访问。

        检测逻辑：
        1. 从 URL 中提取数字型/UUID 型资源 ID
        2. 用相邻 ID（id±1, id+100）重发请求
        3. 如果获取到不同的数据 → IDOR（越权访问他人资源）
        4. 仅当认证身份能访问到不同资源时才定 High/Critical
        """
        import re as _re
        findings = []

        # 从 URL path 和 query 中提取资源 ID
        url = target.url
        id_candidates: list[tuple[str, str, str]] = []  # (full_match, id_value, location)

        # path 中的数字 ID: /api/users/123, /api/orders/456
        for m in _re.finditer(r'/(?:users?|orders?|accounts?|items?|products?|docs?|records?|files?|tasks?|projects?)/(\d+)', url, _re.I):
            id_candidates.append((m.group(0), m.group(1), "path"))

        # query 中的 ID 参数: ?id=123, ?userId=456, ?orderId=789
        for m in _re.finditer(r'[?&](\w*(?:[Ii]d|ID))=(\d+)', url):
            id_candidates.append((m.group(0), m.group(2), f"query:{m.group(1)}"))

        if not id_candidates:
            return []

        auth_text = auth_resp.text or ""
        auth_len = len(auth_text)

        for _, id_str, location in id_candidates[:2]:  # 最多测 2 个 ID 参数
            try:
                id_val = int(id_str)
            except ValueError:
                continue

            # 尝试相邻 ID
            for offset in (1, -1, 100):
                new_id = id_val + offset
                if new_id <= 0:
                    continue
                new_url = url.replace(id_str, str(new_id), 1)
                if new_url == url:
                    continue

                idor_resp = await self._request(
                    target.method, new_url,
                    headers={**target.auth_headers, **target.headers},
                    content=target.body,
                    rule_tag="AuthMatrix", payload_tag=f"idor_{location}={new_id}",
                )
                if not idor_resp or idor_resp.status_code != 200:
                    continue

                idor_text = idor_resp.text or ""
                idor_len = len(idor_text)

                # 跳过：空数据、业务拒绝、与原始响应完全一致（同一资源或统一兜底）
                if _is_empty_data(idor_text) or _is_business_deny(idor_text):
                    continue
                if _normalize_body(idor_text) == _normalize_body(auth_text):
                    continue  # 相同数据，可能没有越权

                # 响应不同且含数据 → 疑似 IDOR
                if _body_contains_sensitive_data(idor_text):
                    findings.append(VulnFinding(
                        vuln_type="IDOR",
                        severity="high",
                        url=new_url,
                        method=target.method,
                        detail=(
                            f"三身份认证对照 IDOR 探测：\n"
                            f"  原始资源 ID={id_val}: HTTP 200, body={auth_len}字符\n"
                            f"  越权 ID={new_id}: HTTP 200, body={idor_len}字符\n"
                            f"  对照结论: 认证用户可访问 ID={new_id} 的他人资源，响应含敏感数据\n"
                            f"  证据来源: {location}"
                        ),
                        evidence=f"越权响应: {idor_text[:400]}",
                        fix_suggestion=(
                            "1. 对每个资源访问实施对象级授权检查（OWASP A01）\n"
                            "2. 验证当前用户是否有权访问目标资源 ID\n"
                            "3. 使用间接引用映射（如 session→resource_id）替代直接暴露 ID"
                        ),
                        evidence_quality="body_confirmed",
                        rule_tag="AuthMatrix",
                    ))
                    break  # 一个 ID 越权成功即可，不重复测
            else:
                continue
            break

        return findings

    async def _check_weak_password(self, target: ScanTarget) -> list[VulnFinding]:
        """弱口令检测：对登录接口尝试默认凭据

        凭据来源：硬编码 WEAK_CREDENTIALS（兜底）+ YAML 规则文件（rules/weak_password.yaml）
        """
        findings = []

        # ★ 合并硬编码凭据 + YAML 规则凭据
        weak_credentials = list(WEAK_CREDENTIALS)  # 复制一份
        yaml_creds = self._get_yaml_credentials()
        for cred in yaml_creds:
            if cred not in weak_credentials:
                weak_credentials.append(cred)

        # 只对登录相关 URL 检测
        url_lower = target.url.lower()
        if not any(kw in url_lower for kw in ["login", "signin", "auth", "登录", "api/auth"]):
            return []

        # 端点存活性预检：首个请求若返回 404/410，说明登录 URL 不存在，
        # 后续凭据爆破全是无效请求，提前退出（原实现对失效端点会空打 42 次）
        for cred_idx, (username, password) in enumerate(weak_credentials):
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
                            resp.status_code, len(weak_credentials) - cred_idx - 1, target.url)
                return findings

            resp_text = resp.text.lower()
            # ★ 收紧成功判定指标：使用带赋值格式避免误匹配失败响应
            #   原 "token"/"session"/"success" 裸词会匹配 {"error":"invalid token","success":false}
            #   现改为 "token":"  /  "access_token":"  等带引号赋值格式，排除 false 响应
            success_indicators = ['"token":', '"access_token":', '"sessionid":',
                                  '"session_id":', "login success", "登录成功",
                                  '"code":0', '"code": 0', '"success":true',
                                  '"status":"ok"', '"result":"success"']
            failure_indicators = ["error", "fail", "invalid", "wrong", "incorrect",
                                  "失败", "错误", "密码不正确"]

            is_success = any(ind in resp_text for ind in success_indicators)
            is_failure = any(ind in resp_text for ind in failure_indicators)

            # ★ P1 防误报：排除 "error":null / "error":"" 等空 error 字段误匹配
            #   原逻辑 {"error":null,"token":"xxx"} 会因 "error" 命中 failure_indicators 而漏报
            if is_failure:
                # 检查 error 是否实际为空值（null/""/0/false）
                if re.search(r'"error"\s*:\s*(?:null|""|0|false)', resp_text):
                    is_failure = False

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
                    evidence_quality="body_confirmed",
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
                                resp2.status_code, len(weak_credentials) - cred_idx - 1, target.url)
                    return findings
                # ★ 与 JSON 路径对齐：同时检查 success / failure 指标
                resp2_text = resp2.text.lower()
                is_success2 = any(ind in resp2_text for ind in success_indicators)
                is_failure2 = any(ind in resp2_text for ind in failure_indicators)
                if is_failure2 and re.search(r'"error"\s*:\s*(?:null|""|0|false)', resp2_text):
                    is_failure2 = False
                if is_success2 and not is_failure2:
                    findings.append(VulnFinding(
                        vuln_type="弱口令",
                        severity="high",
                        url=target.url,
                        method="POST",
                        detail=f"使用默认凭据 {username}/{password} 成功登录（表单提交）",
                        evidence=resp2.text[:500],
                        payload=f"{username}:{password}",
                        fix_suggestion="强制密码复杂度策略，禁用默认凭据",
                        evidence_quality="body_confirmed",
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

        # ★ 补充 OPTIONS 预检请求：部分服务器仅在 OPTIONS 响应中返回 CORS 头，
        # GET 请求不返回 CORS 头会导致漏报
        if not acao:
            options_resp = await self._request(
                "OPTIONS", target.url,
                headers={**target.auth_headers, "Origin": evil_origin,
                         "Access-Control-Request-Method": "GET"},
                rule_tag="CORS", payload_tag=f"OPTIONS Origin={evil_origin}",
            )
            if options_resp:
                acao = options_resp.headers.get("access-control-allow-origin", "")
                acac = options_resp.headers.get("access-control-allow-credentials", "")
                if acao:
                    log.info("[SCAN] CORS | GET 无 CORS 头，OPTIONS 预检发现 CORS 配置: %s", target.url)
                    resp = options_resp  # 使用 OPTIONS 响应做后续分析

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
        # ★ P0 防误报：业务层拒绝 / 空 data → 即使 CORS 宽松也无实际危害
        if _is_business_deny(resp_text) or _is_empty_data(resp_text):
            log.info("[SCAN] CORS | CORS 配置错误但响应体为业务拒绝/空 data，跳过: %s", target.url)
            return findings
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

    # ============================================================
    # 新增漏洞检测规则：CSRF, XXE, SSTI, File Upload
    # ============================================================

    async def _check_csrf(self, target: ScanTarget) -> list[VulnFinding]:
        """CSRF 漏洞检测

        检测原理：
        1. 检查请求是否包含 CSRF token（常见名称）
        2. 对于无 CSRF token 的状态变更请求，尝试无 Cookie 重放
        3. 如果重放成功，则可能存在 CSRF 漏洞
        """
        findings = []

        # 只检查状态变更方法
        if target.method.upper() not in ("POST", "PUT", "DELETE", "PATCH"):
            return findings

        # 检查是否存在 CSRF token
        has_csrf_token = self._check_csrf_token_presence(target)
        if has_csrf_token:
            return findings

        # 尝试无认证重放
        result = await self._test_csrf_replay(target)
        if result:
            findings.append(VulnFinding(
                vuln_type="CSRF",
                severity="medium",
                url=target.url,
                method=target.method,
                detail=f"{target.method} 请求缺少 CSRF token 且可重放，可能存在跨站请求伪造漏洞",
                evidence="请求缺少 CSRF token 且可重放",
                payload="",
                fix_suggestion="添加 CSRF token（如 csrfmiddlewaretoken、_token、authenticity_token），验证 Referer/Origin 头",
                evidence_quality="body_confirmed",
            ))

        return findings

    def _check_csrf_token_presence(self, target: ScanTarget) -> bool:
        """检查是否存在 CSRF token"""
        csrf_token_names = [
            "csrf_token", "csrfmiddlewaretoken", "_token", "token",
            "__RequestVerificationToken", "anti_forgery_token",
            "xsrf_token", "_csrf", "authenticity_token",
            "csrf", "nonce", "anticsrf",
            # ★ P0 防误报：Sangfor/深信服 VPN 使用 anti_replay + CSRF_RAND_CODE 双提交
            "anti_replay", "csrf_rand_code", "anti_csrf",
            "request_id", "req_id", "x_request_id",
        ]

        body = target.body or ""
        headers = target.headers or {}
        params = target.params or {}

        # Check body (表单或 JSON)
        body_lower = body.lower()
        for name in csrf_token_names:
            if name.lower() in body_lower:
                return True

        # Check headers
        for header_name, header_value in headers.items():
            header_name_lower = header_name.lower()
            header_value_str = str(header_value).lower()
            for name in csrf_token_names:
                if name.lower() in header_name_lower or name.lower() in header_value_str:
                    return True

        # Check params
        for param_name in params.keys():
            param_name_lower = param_name.lower()
            for name in csrf_token_names:
                if name.lower() in param_name_lower:
                    return True

        return False

    async def _test_csrf_replay(self, target: ScanTarget) -> bool:
        """测试 CSRF 重放（无认证重放）"""
        # 构造无认证请求头（移除 Cookie 和 Authorization）
        replay_headers = dict(target.headers)
        replay_headers.pop("Cookie", None)
        replay_headers.pop("cookie", None)
        replay_headers.pop("Authorization", None)
        replay_headers.pop("authorization", None)

        resp = await self._request(
            target.method,
            target.url,
            headers=replay_headers,
            content=target.body,
            rule_tag="CSRF",
            payload_tag="replay_without_auth",
        )

        if resp and resp.status_code in (200, 201, 204, 302):
            # 检查是否是 WAF 拦截页
            if not _is_waf_block_page(resp):
                return True

        return False

    async def _check_jwt(self, target: ScanTarget) -> list[VulnFinding]:
        """JWT 安全检测

        检测原理：
        1. 从认证头 / Cookie / 响应体中提取 JWT
        2. 解码 header，检测 alg=none（critical，可绕过签名校验）
        3. 解码 payload，检测弱配置（无 exp / 弱密钥泄露 / 敏感信息）
        4. 检测弱算法（HS256 + 短密钥可爆破）

        纯被动分析，不发送额外请求。
        """
        import base64
        import json as _json

        findings: list[VulnFinding] = []

        def _decode_jwt_segment(seg: str) -> dict | None:
            """解码 JWT 的一个 base64url 段"""
            # 补齐 padding
            padding = 4 - len(seg) % 4
            if padding != 4:
                seg += "=" * padding
            try:
                decoded = base64.urlsafe_b64decode(seg)
                return _json.loads(decoded)
            except Exception:
                return None

        # 收集所有可能的 JWT 来源
        jwt_candidates: list[str] = []
        # 1. 认证头
        for h_name in ("Authorization", "authorization", "X-Auth-Token",
                        "X-Access-Token", "Bearer"):
            val = (target.auth_headers or {}).get(h_name, "")
            if val:
                token = _extract_jwt(val) or (val if val.startswith("eyJ") else "")
                if token:
                    jwt_candidates.append(token)
        # 2. Cookie
        cookie = (target.headers or {}).get("Cookie", "") or (target.headers or {}).get("cookie", "")
        if cookie:
            token = _extract_jwt(cookie)
            if token:
                jwt_candidates.append(token)
        # 3. 请求参数
        for v in target.params.values():
            if v and isinstance(v, str):
                token = _extract_jwt(v)
                if token:
                    jwt_candidates.append(token)

        if not jwt_candidates:
            return findings

        for jwt in jwt_candidates[:5]:  # 最多分析 5 个
            parts = jwt.split(".")
            if len(parts) < 2:
                continue
            header = _decode_jwt_segment(parts[0]) or {}
            payload = _decode_jwt_segment(parts[1]) or {}

            if not header:
                continue

            # 检测1: alg=none（critical）
            alg = (header.get("alg") or "").lower()
            if alg == "none":
                findings.append(VulnFinding(
                    vuln_type="JWT 安全漏洞",
                    severity="critical",
                    url=target.url,
                    method=target.method,
                    detail="JWT 使用 none 算法，可绕过签名校验构造任意 payload",
                    evidence=f"Header: {_json.dumps(header)}\nPayload: {_json.dumps(payload)}",
                    payload=jwt[:100] + "...",
                    fix_suggestion="禁止 none 算法，服务端必须校验签名算法白名单",
                    evidence_quality="content_match",
                    rule_tag="JWT",
                ))
                continue  # none 算法已是最严重，不再检查其他项

            # 检测2: 无 exp（high，token 永不过期）
            if "exp" not in payload:
                findings.append(VulnFinding(
                    vuln_type="JWT 安全漏洞",
                    severity="high",
                    url=target.url,
                    method=target.method,
                    detail="JWT payload 无 exp 字段，token 永不过期",
                    evidence=f"Payload: {_json.dumps(payload)}",
                    payload=jwt[:100] + "...",
                    fix_suggestion="JWT 必须包含 exp 字段，设置合理过期时间（建议 ≤2h）",
                    evidence_quality="content_match",
                    rule_tag="JWT",
                ))

            # 检测3: 弱算法 HS256 + 短 payload（medium，可能爆破密钥）
            if alg == "hs256" and len(parts[2]) < 20:
                findings.append(VulnFinding(
                    vuln_type="JWT 安全漏洞",
                    severity="medium",
                    url=target.url,
                    method=target.method,
                    detail="JWT 使用 HS256 且签名较短，密钥可能可被爆破",
                    evidence=f"Header: {_json.dumps(header)}\n签名长度: {len(parts[2])}",
                    payload=jwt[:100] + "...",
                    fix_suggestion="使用足够长的随机密钥（≥32 字节），或改用 RS256/ES256 非对称算法",
                    evidence_quality="header_only",
                    rule_tag="JWT",
                ))

            # 检测4: payload 含敏感信息（密码/密钥等）
            sensitive_keys = ("password", "secret", "key", "passwd", "pwd", "apikey", "api_key")
            for k, v in payload.items():
                if any(sk in k.lower() for sk in sensitive_keys) and v:
                    findings.append(VulnFinding(
                        vuln_type="JWT 安全漏洞",
                        severity="medium",
                        url=target.url,
                        method=target.method,
                        detail=f"JWT payload 包含敏感字段: {k}",
                        evidence=f"Payload: {_json.dumps(payload)}",
                        payload=jwt[:100] + "...",
                        fix_suggestion="JWT payload 不应包含敏感信息，只放必要的身份标识",
                        evidence_quality="content_match",
                        rule_tag="JWT",
                    ))
                    break

        return findings

    # ============================================================
    # §2.8 P1 全类别补检（0918 §3.12.2 / §3.12.3）
    # ============================================================

    async def _check_403_bypass(self, target: ScanTarget) -> list[VulnFinding]:
        """403 绕过检测（CWE-425 / CWE-284）

        复用 _check_unauthorized 的 noauth 请求；先确认基线 401/403 再探测。
        探测技术：大小写 / ..;/ / %2e / X-Original-URL / X-Forwarded-For / X-Rewrite-URL。
        断言：任一绕过返回 200 且响应含业务数据 → 报。
        """
        findings = []
        base_resp = await self._request(
            target.method, target.url,
            headers=target.headers,
            content=target.body,
            drop_auth=True,
            rule_tag="403Bypass", payload_tag="baseline",
        )
        if not base_resp or base_resp.status_code not in (401, 403):
            return findings

        for variant in self._build_403_variants(target):
            resp = await self._request(
                variant["method"], variant["url"],
                headers={**target.headers, **variant.get("headers", {})},
                content=variant.get("content") or target.body,
                rule_tag="403Bypass", payload_tag=variant["tag"],
            )
            if not resp or resp.status_code != 200:
                continue
            if (_is_waf_block_page(resp) or _is_business_deny(resp.text)
                    or _is_auth_wall_page(resp.text) or _is_empty_data(resp.text)):
                continue
            text = resp.text or ""
            ct = resp.headers.get("content-type", "")
            if _body_contains_sensitive_data(text):
                quality, sev, note = "body_confirmed", "high", "且响应体含敏感数据"
            elif not _is_public_data(text, ct):
                quality, sev, note = "header_only", "medium", "（响应体非公开壳，需二次确认）"
            else:
                continue
            findings.append(VulnFinding(
                vuln_type="403绕过",
                severity=sev,
                url=variant["url"],
                method=variant["method"],
                detail=f"基线 401/403，使用 '{variant['technique']}' 绕过后返回 200{note}",
                evidence=f"Technique: {variant['technique']}\n响应体片段: {text[:300]}",
                payload=variant["technique"],
                fix_suggestion="对敏感路径实施服务端统一鉴权，避免依赖 Web 容器/网关的路径匹配",
                evidence_quality=quality,
                rule_tag="403Bypass",
            ))
            break  # 一个变体命中即可
        return findings

    def _build_403_variants(self, target: ScanTarget) -> list[dict]:
        """构造 403 绕过变体列表。"""
        from urllib.parse import urlparse
        parsed = urlparse(target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        path_upper = path.upper()
        variants: list[dict] = []
        # 1. 大小写：路径转大写（部分容器大小写敏感路径匹配）
        if path != path_upper:
            variants.append({"method": "GET", "url": base + path_upper,
                             "technique": "大小写", "tag": "case_upper"})
        # 2. ..;/ 路径归一化绕过（Spring/Tomcat）
        variants.append({"method": "GET", "url": base + "/..;/" + path.lstrip("/"),
                         "technique": "..;/", "tag": "dotdot_semi"})
        variants.append({"method": "GET", "url": base + path + "/..;/",
                         "technique": "..;/", "tag": "dotdot_semi_tail"})
        # 3. %2e 编码点（/./ 与 /%2e/）
        variants.append({"method": "GET", "url": base + "/./" + path.lstrip("/"),
                         "technique": "%2e", "tag": "dot_slash"})
        variants.append({"method": "GET", "url": base + "/%2e/" + path.lstrip("/"),
                         "technique": "%2e", "tag": "enc_dot"})
        # 4-5. 头部转发绕过（X-Original-URL / X-Rewrite-URL / X-Forwarded-For）
        for hname in ("X-Original-URL", "X-Rewrite-URL"):
            variants.append({"method": target.method, "url": target.url,
                             "headers": {hname: path}, "technique": hname, "tag": hname})
        variants.append({"method": target.method, "url": target.url,
                         "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
                         "technique": "X-Forwarded-For", "tag": "xff"})
        return variants

    async def _check_user_enum(self, target: ScanTarget) -> list[VulnFinding]:
        """用户枚举（CWE-204）+ 频率限制缺失检测（CWE-307）

        复用 _check_weak_password 骨架：仅测登录/注册/找回类端点。
        枚举：存在用户 vs 不存在用户响应可区分（状态码/长度/内容）→ 报。
        频控：并发 count=5 全成功且无 429/Retry-After → 报频控缺失（红线：不真发轰炸）。
        """
        findings = []
        url_lower = target.url.lower()
        if not any(kw in url_lower for kw in
                   ("login", "signin", "register", "signup", "forgot", "reset",
                    "找回", "注册", "登录", "checkuser", "check_user")):
            return findings

        base_headers = {**target.headers, "Content-Type": "application/json"}
        existing_user = "admin"
        non_user = "xuanjian_nosuchuser_9f8e7c"

        async def _login_as(user: str):
            return await self._request(
                "POST", target.url,
                headers=base_headers,
                content=json.dumps({"username": user, "password": "Xj@wrong#pwd1"}),
                rule_tag="UserEnum", payload_tag=f"user={user}",
            )

        resp_exist = await _login_as(existing_user)
        resp_none = await _login_as(non_user)
        if resp_exist and resp_none:
            t_exist, t_none = resp_exist.text or "", resp_none.text or ""
            status_diff = resp_exist.status_code != resp_none.status_code
            len_diff = abs(len(t_exist) - len(t_none)) > 20
            content_diff = (not _bodies_similar(t_exist, t_none, threshold=0.95) and any(
                kw in (t_exist + t_none) for kw in ("不存在", "无此用户", "用户不存在",
                                                    "not found", "no such user")))
            if status_diff or len_diff or content_diff:
                findings.append(VulnFinding(
                    vuln_type="用户枚举",
                    severity="medium",
                    url=target.url,
                    method="POST",
                    detail=(f"登录接口存在用户枚举（CWE-204）：用户 '{existing_user}' 与不存在用户响应可区分\n"
                            f"  存在用户: HTTP {resp_exist.status_code}, {len(t_exist)} 字符\n"
                            f"  不存在用户: HTTP {resp_none.status_code}, {len(t_none)} 字符"),
                    evidence=f"存在: {t_exist[:200]}\n不存在: {t_none[:200]}",
                    payload=existing_user,
                    fix_suggestion="登录失败统一返回相同错误（状态码/文案/耗时），避免暴露账号是否存在",
                    evidence_quality="body_confirmed" if content_diff else "header_only",
                    rule_tag="UserEnum",
                ))

        # 频率限制缺失检测（并发 5 次，仅检测不轰炸）
        rate_missing, rate_resps = await check_rate_limit(self, target.url, method="POST",
                                                          count=RATE_LIMIT_PROBE_COUNT)
        if rate_missing and len([r for r in rate_resps if r is not None]) >= 3:
            statuses = [r.status_code for r in rate_resps if r is not None]
            findings.append(VulnFinding(
                vuln_type="频控缺失",
                severity="medium",
                url=target.url,
                method="POST",
                detail=(f"登录接口无频率限制（CWE-307）：并发 {RATE_LIMIT_PROBE_COUNT} 次请求"
                        f"均未被限流，无 429/Retry-After"),
                evidence=f"并发 {len(statuses)} 次状态码: {statuses}",
                fix_suggestion="对登录/注册/找回接口实施频率限制与账号锁定策略",
                evidence_quality="header_only",
                rule_tag="UserEnum",
            ))
        return findings

    async def _check_captcha_leak(self, target: ScanTarget) -> list[VulnFinding]:
        """验证码答案泄露检测（CWE-804 / CWE-200）

        复用 core/captcha_solver 端点识别思路（关键词匹配）。
        断言：验证码响应含答案字段 → 报；不含 → 不报。
        红线：只检测响应是否泄露答案，不做识别/绕过。
        """
        findings = []
        url_lower = target.url.lower()
        if not any(kw in url_lower for kw in CAPTCHA_ENDPOINT_KEYWORDS):
            return findings

        resp = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body,
            rule_tag="CaptchaLeak", payload_tag="probe",
        )
        if not resp or resp.status_code != 200:
            return findings

        leaked = self._extract_captcha_answer_fields(resp.text or "")
        if leaked:
            findings.append(VulnFinding(
                vuln_type="验证码答案泄露",
                severity="high",
                url=target.url,
                method=target.method,
                detail=(f"验证码接口响应直接泄露答案字段（CWE-804/200）: "
                        f"{'、'.join(leaked[:8])}"),
                evidence=resp.text[:400],
                payload=",".join(leaked[:8]),
                fix_suggestion="验证码答案必须只存服务端会话，接口响应仅返回图片/题目标识，严禁返回答案字段",
                evidence_quality="body_confirmed",
                rule_tag="CaptchaLeak",
            ))
        return findings

    def _extract_captcha_answer_fields(self, text: str) -> list[str]:
        """递归扫描验证码响应中的答案字段（JSON 键 + 文本特征）。

        ★ 防误报：code/result/value 等通用字段排除纯成功标记（0/1/200/ok/true/false），
          只认短值（≤12 字符），避免 {"code":0} 状态码被误判为答案。
        """
        found: list[str] = []
        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            obj = None
        if isinstance(obj, dict):
            found.extend(self._walk_captcha_fields(obj))
        if not found:
            _success_markers = {"0", "1", "200", "ok", "true", "false", "success", "successful"}
            for pat in (r'"(?:answer|solution|result|correct|value|code)"\s*:\s*"?([0-9A-Za-z_\-]{1,12})"?',
                        r'"(?:x|y|offset|position|gap|distance|target)"\s*:\s*(\d{1,4})'):
                for m in re.finditer(pat, text):
                    val = m.group(1)
                    # 排除纯成功标记（{"code":0} 等状态码不是验证码答案）
                    if val.lower() not in _success_markers and val not in found:
                        found.append(val)
        return list(dict.fromkeys(found))[:16]

    def _walk_captcha_fields(self, node, depth: int = 0) -> list[str]:
        """递归遍历 JSON 节点，收集命中答案字段名的非空值。"""
        if depth > 6:
            return []
        found: list[str] = []
        _success_markers = {"0", "1", "200", "ok", "true", "false", "success", "successful"}
        if isinstance(node, dict):
            for k, v in node.items():
                kl = str(k).lower()
                if (any(f in kl for f in CAPTCHA_ANSWER_LEAK_FIELDS)
                        and v is not None and v != "" and v != [] and v != {}):
                    if isinstance(v, (str, int, float)) and str(v).strip():
                        sval = str(v).strip()
                        # 排除纯成功标记（code/result/value 等通用字段的常见 FP 源）
                        if sval.lower() not in _success_markers and len(sval) <= 12:
                            found.append(f"{k}={sval}")
                    elif isinstance(v, list) and v:
                        found.append(f"{k}=[{len(v)}items]")
                else:
                    found.extend(self._walk_captcha_fields(v, depth + 1))
        elif isinstance(node, list):
            for item in node[:10]:
                found.extend(self._walk_captcha_fields(item, depth + 1))
        return found

    async def _check_mass_assignment(self, target: ScanTarget) -> list[VulnFinding]:
        """批量赋值检测（CWE-915）：注入 role / is_admin 等权限字段

        复用 _check_auth_matrix 思路：基线请求对比注入后的响应。
        断言：注入权限字段后响应出现越权特征（基线业务拒绝→注入后成功，
        或响应含管理员数据且与基线显著不同）→ 报。
        """
        findings = []
        url_lower = target.url.lower()
        if any(ep in url_lower for ep in ("/login", "/signin", "/auth", "/oauth/token", "/logon")):
            return findings

        baseline = await self._request(
            target.method, target.url,
            headers={**target.auth_headers, **target.headers},
            content=target.body,
            rule_tag="MassAssign", payload_tag="baseline",
        )
        if not baseline:
            return []
        baseline_text = baseline.text or ""
        baseline_deny = _is_business_deny(baseline_text)

        for field, value in MASS_ASSIGNMENT_FIELDS:
            body, headers, params = self._inject_mass_field(target, field, value)
            if params and body == (target.body or ""):
                test_url = self._build_url(target.url, params)
                resp = await self._request(
                    "GET", test_url,
                    headers=headers,
                    rule_tag="MassAssign", payload_tag=f"{field}={value}",
                )
            else:
                resp = await self._request(
                    target.method, target.url,
                    headers=headers,
                    content=body,
                    rule_tag="MassAssign", payload_tag=f"{field}={value}",
                )
            if not resp or resp.status_code != 200 or _is_waf_block_page(resp):
                continue
            text = resp.text or ""
            if not text:
                continue
            # 场景A：基线业务拒绝，注入权限字段后成功 → 越权提升
            if baseline_deny and not _is_business_deny(text):
                findings.append(VulnFinding(
                    vuln_type="批量赋值",
                    severity="high",
                    url=target.url,
                    method=target.method,
                    detail=(f"注入权限字段 {field}={value} 后响应由业务拒绝变为成功，"
                            f"疑似批量赋值越权（CWE-915）"),
                    evidence=f"基线: {baseline_text[:200]}\n注入后: {text[:200]}",
                    payload=f"{field}={value}",
                    fix_suggestion="服务端必须显式声明可绑定字段白名单（DTO/视图模型），禁止直接绑定用户可控字段到实体",
                    evidence_quality="body_confirmed",
                    rule_tag="MassAssign",
                ))
                break
            # 场景B：注入后响应含敏感数据且与基线显著不同
            if _body_contains_sensitive_data(text) and not _bodies_similar(text, baseline_text):
                findings.append(VulnFinding(
                    vuln_type="批量赋值",
                    severity="medium",
                    url=target.url,
                    method=target.method,
                    detail=(f"注入权限字段 {field}={value} 后响应出现敏感数据且与基线不同，"
                            f"疑似批量赋值（CWE-915）"),
                    evidence=f"注入后响应: {text[:300]}",
                    payload=f"{field}={value}",
                    fix_suggestion="服务端必须显式声明可绑定字段白名单（DTO/视图模型）",
                    evidence_quality="body_confirmed",
                    rule_tag="MassAssign",
                ))
                break
        return findings

    def _inject_mass_field(self, target: ScanTarget, field: str, value: str) -> tuple[str, dict, dict]:
        """把权限字段注入到请求体/参数，返回 (body, headers, params)。"""
        body = target.body or ""
        headers = {**target.auth_headers, **target.headers}
        if target.method.upper() in ("POST", "PUT", "PATCH") and body:
            if body.strip().startswith("{"):
                try:
                    obj = json.loads(body)
                    if isinstance(obj, dict):
                        obj[field] = value
                        return (json.dumps(obj, ensure_ascii=False),
                                {**headers, "Content-Type": "application/json"},
                                dict(target.params))
                except (json.JSONDecodeError, ValueError):
                    pass
            elif "=" in body:
                return (body + f"&{field}={value}",
                        {**headers, "Content-Type": "application/x-www-form-urlencoded"},
                        dict(target.params))
        # 兜底：GET 参数注入
        params = dict(target.params)
        params[field] = value
        return body, headers, params


# --- hoisted from _check_jwt (A-grade, no local capture) ---
def _extract_jwt(s: str) -> str | None:
    """从字符串中提取 JWT（匹配 eyJ... 格式）"""
    # JWT 格式: header.payload.signature，三段 base64url
    m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', s)
    return m.group(0) if m else None


async def check_rate_limit(client, url: str, method: str = "POST",
                           count: int = 5) -> tuple[bool, list]:
    """并发发送 count 次请求，检测是否无频率限制（CWE-307）。

    client: 具有 async _request(method, url, headers, content, ...) 的扫描器实例。
    返回 (rate_limit_missing, responses)。
    红线：仅检测，不真发轰炸（count 固定且小）。
    """
    headers = {"Content-Type": "application/json"}
    content = json.dumps({"username": "admin", "password": "Xj@wrong#pwd1"})

    async def send():
        return await client._request(
            method, url, headers=headers, content=content,
            rule_tag="UserEnum", payload_tag="rate_check",
        )

    responses = await asyncio.gather(
        *[send() for _ in range(max(1, count))], return_exceptions=True)
    responses = [r for r in responses if not isinstance(r, BaseException)]

    rate_limited = any(
        r is not None and (
            r.status_code == 429
            or r.status_code == 403
            or "retry-after" in {str(k).lower() for k in (r.headers or {})}
        )
        for r in responses
    )
    return (not rate_limited), responses
