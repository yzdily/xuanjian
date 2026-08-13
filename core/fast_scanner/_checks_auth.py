"""fast_scanner 认证类漏洞检测 mixin（从原 fast_scanner.py 机械拆分，方法体逐字保留）。"""

from __future__ import annotations

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
    _body_contains_sensitive_data,
    _is_public_data,
    _is_auth_wall_page,
)
from ._models import VulnFinding, ScanTarget

log = get_logger("fast_scanner")


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

        def _extract_jwt(s: str) -> str | None:
            """从字符串中提取 JWT（匹配 eyJ... 格式）"""
            # JWT 格式: header.payload.signature，三段 base64url
            m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', s)
            return m.group(0) if m else None

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
