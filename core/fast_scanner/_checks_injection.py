"""fast_scanner 注入类检测 mixin（从原 fast_scanner.py 机械拆分，方法体逐字保留）。"""

from __future__ import annotations

import json
import re
import time

from core.log import get_logger

from ._constants import SQL_ERROR_PATTERNS, CMD_INJECTION_PATTERNS
from ._fp_filters import (
    _normalize_body,
    _bodies_similar,
    _is_waf_block_page,
    _is_xss_executable_context,
)
from ._models import VulnFinding, ScanTarget

log = get_logger("fast_scanner")


class _ChecksInjection:
    """注入类漏洞检测方法（SQLi / XSS / 路径穿越 / 命令注入）。"""

    async def _check_sql_injection(self, target: ScanTarget) -> list[VulnFinding]:
        """SQL 注入检测：报错注入 + 布尔盲注 + 时间盲注

        支持 GET 参数、POST 表单 body、POST JSON body 三种注入点。
        Payload 来源：硬编码默认值 + YAML 规则文件（rules/sql_injection.yaml）
        """
        findings = []
        # ★ 硬编码默认 payloads（兜底）
        test_payloads = [
            ("'", "报错注入"),
            ("' OR '1'='1", "布尔注入"),
            ("' OR '1'='1' --", "布尔注入"),
            ("1' AND '1'='1", "布尔注入"),
            ("1' AND '1'='2", "布尔注入-False"),
            ("1 UNION SELECT NULL--", "UNION注入"),
            ("1; WAITFOR DELAY '0:0:3'--", "时间盲注"),
        ]
        # ★ 从 YAML 规则扩展 payloads
        yaml_payloads = self._get_yaml_payloads("sql_injection")
        for p in yaml_payloads:
            if isinstance(p, str) and p not in [t[0] for t in test_payloads]:
                test_payloads.append((p, "YAML规则"))

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
                            evidence_quality="body_confirmed",
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
                        # ★ P1 防误报：归一化后比较，剥离时间戳/CSRF token/JWT 等动态内容
                        true_norm = _normalize_body(resp.text)
                        false_norm = _normalize_body(false_resp.text)
                        baseline_norm = _normalize_body(baseline_text)
                        true_len = len(true_norm)
                        false_len = len(false_norm)
                        baseline_len_n = len(baseline_norm)
                        # True 条件响应与基线相似，False 条件响应不同
                        true_similar = _bodies_similar(resp.text, baseline_text)
                        false_similar = _bodies_similar(resp.text, false_resp.text)
                        if true_similar and not false_similar:
                            # ★ 铁律2：True/False 响应必须有差异（状态码或归一化长度差 > 10）
                            if (resp.status_code != false_resp.status_code
                                    or abs(true_len - false_len) > 10):
                                # ★ P0 防误报：True≈基线说明参数被忽略（静态端点），
                                # False 不同很可能是因为 payload 中的特殊字符(单引号等)
                                # 触发了 WAF 拦截/路由错误/服务端异常，而非 SQL 逻辑差异。
                                # 真正的布尔盲注：False 返回空结果集（长度接近但略短），
                                # 而非极短的错误页/WAF 拦截页。
                                _is_false_waf_or_error = (
                                    _is_waf_block_page(false_resp)
                                    or false_len < max(baseline_len_n * 0.1, 10)
                                    or false_resp.status_code in (403, 404, 418, 429, 500, 502, 503)
                                )
                                # ★ 如果 False 也≈基线（参数被忽略），说明端点完全无视参数
                                _false_similar_baseline = _bodies_similar(
                                    false_resp.text, baseline_text)
                                if _false_similar_baseline:
                                    # True≈基线 + False≈基线 → 参数完全被忽略，不是注入
                                    pass
                                elif _is_false_waf_or_error:
                                    # True≈基线 + False 是 WAF/错误页 → 特殊字符触发防护，不是注入
                                    log.info("[SCAN] SQLi | True≈基线(参数被忽略) + False=WAF/错误页，跳过: %s?%s=%s",
                                             target.url, param_name, payload)
                                else:
                                    findings.append(VulnFinding(
                                        vuln_type="SQL注入",
                                        severity="critical",
                                        url=test_url,
                                        method="GET",
                                        detail=f"参数 '{param_name}' 存在布尔盲注，"
                                               f"True条件响应与基线相似(归一化)，False条件不同，"
                                               f"True长度={true_len}，False长度={false_len}，基线={baseline_len_n}",
                                        evidence=f"True: {resp.text[:200]}\nFalse: {false_resp.text[:200]}",
                                        payload=payload,
                                        fix_suggestion="使用参数化查询，对用户输入进行严格过滤",
                                        evidence_quality="body_confirmed",
                                    ))

                # ★ P1 时间盲注检测：测量响应延迟，延迟≥4s 且二次复现才算确认
                if "时间盲注" in inj_type:
                    time_payloads = [
                        ("1; WAITFOR DELAY '0:0:4'--", "MSSQL"),
                        ("1' AND SLEEP(4)-- -", "MySQL"),
                        ("1' AND pg_sleep(4)--", "PostgreSQL"),
                    ]
                    for time_payload, db_type in time_payloads:
                        t_params = dict(target.params)
                        t_params[param_name] = time_payload
                        t_url = self._build_url(target.url, t_params)
                        t0_req = time.time()
                        t_resp = await self._request(
                            "GET", t_url,
                            headers={**target.auth_headers, **target.headers},
                            rule_tag="SQLi-Time", payload_tag=f"{param_name}={time_payload}",
                        )
                        if not t_resp:
                            continue
                        elapsed1 = time.time() - t0_req
                        if elapsed1 >= 3.5:
                            # ★ 铁律3：二次复现，排除网络抖动
                            t0_replay = time.time()
                            t_resp2 = await self._request(
                                "GET", t_url,
                                headers={**target.auth_headers, **target.headers},
                                rule_tag="SQLi-Time-replay", payload_tag=f"{param_name}={time_payload}",
                            )
                            elapsed2 = time.time() - t0_replay
                            if t_resp2 and elapsed2 >= 3.5:
                                findings.append(VulnFinding(
                                    vuln_type="SQL注入",
                                    severity="critical",
                                    url=test_url,
                                    method="GET",
                                    detail=f"参数 '{param_name}' 存在时间盲注（{db_type}），"
                                           f"延时 payload 两次请求分别耗时 {elapsed1:.1f}s / {elapsed2:.1f}s（≥3.5s）",
                                    evidence=f"Payload: {time_payload}\n"
                                             f"第一次延迟: {elapsed1:.1f}s\n第二次延迟: {elapsed2:.1f}s",
                                    payload=time_payload,
                                    fix_suggestion="使用参数化查询，禁止拼接SQL",
                                    evidence_quality="body_confirmed",
                                ))
                                break  # 一个 DB 类型命中即可

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
                                evidence_quality="body_confirmed",
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
                                        evidence_quality="body_confirmed",
                                    ))
                                    break
            except (json.JSONDecodeError, ValueError):
                pass

        # === POST 参数布尔盲注检测 ===
        if target.method == "POST" and target.body:
            # 处理表单数据
            if "=" in target.body and not target.body.strip().startswith("{"):
                form_params = {}
                for pair in target.body.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        form_params[k] = v

                for param_name, param_val in form_params.items():
                    # 布尔盲注：True 条件 vs False 条件
                    true_payloads = [
                        f"{param_val}' AND '1'='1",
                        f'{param_val}" AND "1"="1',
                    ]
                    false_payloads = [
                        f"{param_val}' AND '1'='2",
                        f'{param_val}" AND "1"="2',
                    ]

                    for true_payload, false_payload in zip(true_payloads, false_payloads):
                        # 发送 True 条件请求
                        test_form_true = dict(form_params)
                        test_form_true[param_name] = true_payload
                        test_body_true = "&".join(f"{k}={v}" for k, v in test_form_true.items())
                        true_resp = await self._request(
                            "POST", target.url,
                            headers={**target.auth_headers, **target.headers,
                                     "Content-Type": "application/x-www-form-urlencoded"},
                            content=test_body_true,
                            rule_tag="SQLi-POST-Bool", payload_tag=f"{param_name}={true_payload}",
                        )
                        if not true_resp:
                            continue

                        # 发送 False 条件请求
                        test_form_false = dict(form_params)
                        test_form_false[param_name] = false_payload
                        test_body_false = "&".join(f"{k}={v}" for k, v in test_form_false.items())
                        false_resp = await self._request(
                            "POST", target.url,
                            headers={**target.auth_headers, **target.headers,
                                     "Content-Type": "application/x-www-form-urlencoded"},
                            content=test_body_false,
                            rule_tag="SQLi-POST-Bool", payload_tag=f"{param_name}={false_payload}",
                        )
                        if not false_resp:
                            continue

                        # 比较 True/False 响应差异
                        true_norm = _normalize_body(true_resp.text)
                        false_norm = _normalize_body(false_resp.text)
                        baseline_norm = _normalize_body(baseline_text)
                        true_len = len(true_norm)
                        false_len = len(false_norm)
                        baseline_len_n = len(baseline_norm)

                        true_similar = _bodies_similar(true_resp.text, baseline_text)
                        false_similar = _bodies_similar(true_resp.text, false_resp.text)

                        if true_similar and not false_similar:
                            if (true_resp.status_code != false_resp.status_code
                                    or abs(true_len - false_len) > 10):
                                # ★ P0 防误报（与 GET 路径对齐）：
                                # False 不同很可能是因为 payload 中的特殊字符触发了
                                # WAF 拦截/路由错误/服务端异常，而非 SQL 逻辑差异。
                                _is_false_waf_or_error = (
                                    _is_waf_block_page(false_resp)
                                    or false_len < max(baseline_len_n * 0.1, 10)
                                    or false_resp.status_code in (403, 404, 418, 429, 500, 502, 503)
                                )
                                _false_similar_baseline = _bodies_similar(
                                    false_resp.text, baseline_text)
                                if _false_similar_baseline:
                                    # True≈基线 + False≈基线 → 参数完全被忽略，不是注入
                                    pass
                                elif _is_false_waf_or_error:
                                    log.info("[SCAN] SQLi-POST | True≈基线 + False=WAF/错误页，跳过: %s param=%s",
                                             target.url, param_name)
                                else:
                                    findings.append(VulnFinding(
                                        vuln_type="SQL注入",
                                        severity="critical",
                                        url=target.url,
                                        method="POST",
                                        detail=f"POST 参数 '{param_name}' 存在布尔盲注，"
                                               f"True条件响应与基线相似(归一化)，False条件不同，"
                                               f"True长度={true_len}，False长度={false_len}，基线={baseline_len_n}",
                                        evidence=f"True: {true_resp.text[:200]}\nFalse: {false_resp.text[:200]}",
                                        payload=true_payload,
                                        fix_suggestion="使用参数化查询，对用户输入进行严格过滤",
                                        evidence_quality="body_confirmed",
                                    ))
                                    break  # 一个参数命中即可

            # 处理 JSON 数据
            if target.body.strip().startswith("{"):
                try:
                    json_body = json.loads(target.body)
                    if isinstance(json_body, dict):
                        for field_name, field_val in list(json_body.items()):
                            if not isinstance(field_val, str):
                                continue

                            # 布尔盲注：True 条件 vs False 条件
                            true_payloads = [
                                f"{field_val}' AND '1'='1",
                                f'{field_val}" AND "1"="1',
                            ]
                            false_payloads = [
                                f"{field_val}' AND '1'='2",
                                f'{field_val}" AND "1"="2',
                            ]

                            for true_payload, false_payload in zip(true_payloads, false_payloads):
                                test_json_true = dict(json_body)
                                test_json_true[field_name] = true_payload
                                test_body_true = json.dumps(test_json_true, ensure_ascii=False)
                                true_resp = await self._request(
                                    "POST", target.url,
                                    headers={**target.auth_headers, **target.headers,
                                             "Content-Type": "application/json"},
                                    content=test_body_true,
                                    rule_tag="SQLi-JSON-Bool", payload_tag=f"{field_name}={true_payload}",
                                )
                                if not true_resp:
                                    continue

                                test_json_false = dict(json_body)
                                test_json_false[field_name] = false_payload
                                test_body_false = json.dumps(test_json_false, ensure_ascii=False)
                                false_resp = await self._request(
                                    "POST", target.url,
                                    headers={**target.auth_headers, **target.headers,
                                             "Content-Type": "application/json"},
                                    content=test_body_false,
                                    rule_tag="SQLi-JSON-Bool", payload_tag=f"{field_name}={false_payload}",
                                )
                                if not false_resp:
                                    continue

                                true_norm = _normalize_body(true_resp.text)
                                false_norm = _normalize_body(false_resp.text)
                                baseline_norm = _normalize_body(baseline_text)
                                true_len = len(true_norm)
                                false_len = len(false_norm)
                                baseline_len_n = len(baseline_norm)

                                true_similar = _bodies_similar(true_resp.text, baseline_text)
                                false_similar = _bodies_similar(true_resp.text, false_resp.text)

                                if true_similar and not false_similar:
                                    if (true_resp.status_code != false_resp.status_code
                                            or abs(true_len - false_len) > 10):
                                        # ★ P0 防误报（与 GET / POST-form 路径对齐）：
                                        _is_false_waf_or_error = (
                                            _is_waf_block_page(false_resp)
                                            or false_len < max(baseline_len_n * 0.1, 10)
                                            or false_resp.status_code in (403, 404, 418, 429, 500, 502, 503)
                                        )
                                        _false_similar_baseline = _bodies_similar(
                                            false_resp.text, baseline_text)
                                        if _false_similar_baseline:
                                            pass
                                        elif _is_false_waf_or_error:
                                            log.info("[SCAN] SQLi-JSON | True≈基线 + False=WAF/错误页，跳过: %s field=%s",
                                                     target.url, field_name)
                                        else:
                                            findings.append(VulnFinding(
                                                vuln_type="SQL注入",
                                                severity="critical",
                                                url=target.url,
                                                method="POST",
                                                detail=f"JSON 字段 '{field_name}' 存在布尔盲注，"
                                                       f"True条件响应与基线相似(归一化)，False条件不同，"
                                                       f"True长度={true_len}，False长度={false_len}，基线={baseline_len_n}",
                                                evidence=f"True: {true_resp.text[:200]}\nFalse: {false_resp.text[:200]}",
                                                payload=true_payload,
                                                fix_suggestion="使用参数化查询，对用户输入进行严格过滤",
                                                evidence_quality="body_confirmed",
                                            ))
                                            break
                except (json.JSONDecodeError, ValueError):
                    pass

        # === POST 参数时间盲注检测 ===
        if target.method == "POST" and target.body:
            time_payloads = [
                ("1; WAITFOR DELAY '0:0:4'--", "MSSQL"),
                ("1' AND SLEEP(4)-- -", "MySQL"),
                ("1' AND pg_sleep(4)--", "PostgreSQL"),
            ]

            # 处理表单数据
            if "=" in target.body and not target.body.strip().startswith("{"):
                form_params = {}
                for pair in target.body.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        form_params[k] = v

                for param_name in form_params:
                    for time_payload, db_type in time_payloads:
                        test_form = dict(form_params)
                        test_form[param_name] = time_payload
                        test_body = "&".join(f"{k}={v}" for k, v in test_form.items())

                        t0_req = time.time()
                        t_resp = await self._request(
                            "POST", target.url,
                            headers={**target.auth_headers, **target.headers,
                                     "Content-Type": "application/x-www-form-urlencoded"},
                            content=test_body,
                            rule_tag="SQLi-POST-Time", payload_tag=f"{param_name}={time_payload}",
                        )
                        if not t_resp:
                            continue
                        elapsed1 = time.time() - t0_req

                        if elapsed1 >= 3.5:
                            # 二次复现
                            t0_replay = time.time()
                            t_resp2 = await self._request(
                                "POST", target.url,
                                headers={**target.auth_headers, **target.headers,
                                         "Content-Type": "application/x-www-form-urlencoded"},
                                content=test_body,
                                rule_tag="SQLi-POST-Time-replay", payload_tag=f"{param_name}={time_payload}",
                            )
                            elapsed2 = time.time() - t0_replay
                            if t_resp2 and elapsed2 >= 3.5:
                                findings.append(VulnFinding(
                                    vuln_type="SQL注入",
                                    severity="critical",
                                    url=target.url,
                                    method="POST",
                                    detail=f"POST 参数 '{param_name}' 存在时间盲注（{db_type}），"
                                           f"延时 payload 两次请求分别耗时 {elapsed1:.1f}s / {elapsed2:.1f}s（≥3.5s）",
                                    evidence=f"Payload: {time_payload}\n"
                                             f"第一次延迟: {elapsed1:.1f}s\n第二次延迟: {elapsed2:.1f}s",
                                    payload=time_payload,
                                    fix_suggestion="使用参数化查询，禁止拼接SQL",
                                    evidence_quality="body_confirmed",
                                ))
                                break  # 一个 DB 类型命中即可

            # 处理 JSON 数据
            if target.body.strip().startswith("{"):
                try:
                    json_body = json.loads(target.body)
                    if isinstance(json_body, dict):
                        for field_name, field_val in list(json_body.items()):
                            if not isinstance(field_val, str):
                                continue

                            for time_payload, db_type in time_payloads:
                                test_json = dict(json_body)
                                test_json[field_name] = time_payload
                                test_body = json.dumps(test_json, ensure_ascii=False)

                                t0_req = time.time()
                                t_resp = await self._request(
                                    "POST", target.url,
                                    headers={**target.auth_headers, **target.headers,
                                             "Content-Type": "application/json"},
                                    content=test_body,
                                    rule_tag="SQLi-JSON-Time", payload_tag=f"{field_name}={time_payload}",
                                )
                                if not t_resp:
                                    continue
                                elapsed1 = time.time() - t0_req

                                if elapsed1 >= 3.5:
                                    t0_replay = time.time()
                                    t_resp2 = await self._request(
                                        "POST", target.url,
                                        headers={**target.auth_headers, **target.headers,
                                                 "Content-Type": "application/json"},
                                        content=test_body,
                                        rule_tag="SQLi-JSON-Time-replay", payload_tag=f"{field_name}={time_payload}",
                                    )
                                    elapsed2 = time.time() - t0_replay
                                    if t_resp2 and elapsed2 >= 3.5:
                                        findings.append(VulnFinding(
                                            vuln_type="SQL注入",
                                            severity="critical",
                                            url=target.url,
                                            method="POST",
                                            detail=f"JSON 字段 '{field_name}' 存在时间盲注（{db_type}），"
                                                   f"延时 payload 两次请求分别耗时 {elapsed1:.1f}s / {elapsed2:.1f}s（≥3.5s）",
                                            evidence=f"Payload: {time_payload}\n"
                                                     f"第一次延迟: {elapsed1:.1f}s\n第二次延迟: {elapsed2:.1f}s",
                                            payload=time_payload,
                                            fix_suggestion="使用参数化查询，禁止拼接SQL",
                                            evidence_quality="body_confirmed",
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
                    # ★ P1：确定证据质量——检查是否在可执行上下文中（HTML/JS），还是被注释/JSON 包裹
                    is_exec_context = _is_xss_executable_context(resp.text, xss_probe)
                    findings.append(VulnFinding(
                        vuln_type="XSS",
                        severity="high",
                        url=test_url,
                        method="GET",
                        detail=f"参数 '{param_name}' 存在反射型 XSS，输入的探测字符串被原样反射到页面中",
                        evidence=resp.text[:500],
                        payload=xss_probe,
                        fix_suggestion="对用户输入进行HTML编码，使用CSP策略",
                        evidence_quality="body_confirmed" if is_exec_context else "header_only",
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
                        is_exec_context = _is_xss_executable_context(resp.text, xss_probe)
                        findings.append(VulnFinding(
                            vuln_type="XSS",
                            severity="high",
                            url=target.url,
                            method="POST",
                            detail=f"POST 参数 '{param_name}' 存在反射型 XSS",
                            evidence=resp.text[:500],
                            payload=xss_probe,
                            fix_suggestion="对用户输入进行HTML编码",
                            evidence_quality="body_confirmed" if is_exec_context else "header_only",
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

        # ★ P2：收紧特征——[fonts] 同时出现在两个列表中导致歧义，改用更精确的指纹
        passwd_patterns = [r"root:.*:0:0:", r"bin:.*:1:1:", r"daemon:.*:2:2:"]
        winini_patterns = [r"\[fonts\]", r"\[extensions\]", r"for 16-bit"]

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
                # ★ P2：WAF 拦截页 → 跳过
                if _is_waf_block_page(resp):
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
                            evidence_quality="body_confirmed",
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
                # ★ P2：WAF 拦截页 → 跳过，不算命令执行
                if _is_waf_block_page(resp):
                    continue

                # ★ P2：收紧特征——要求 payload 命令输出特征，而非仅匹配通用词
                # 原逻辑 whoami/total/bin/sh 等过于宽泛，正常文档页会误匹配
                for pattern in CMD_INJECTION_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        # ★ 铁律1：仅 payload 原样反射（无命令输出）= 假阳性
                        # 必须有命令执行输出特征，而非 payload 本身被回显
                        cmd_output = re.search(pattern, resp.text, re.IGNORECASE)
                        if cmd_output and cmd_output.group(0) in payload:
                            # 匹配到的是 payload 本身，不是命令输出 → 跳过
                            continue
                        findings.append(VulnFinding(
                            vuln_type="命令注入",
                            severity="critical",
                            url=test_url,
                            method="GET",
                            detail=f"参数 '{param_name}' 存在命令注入，响应中匹配到命令执行特征: {pattern}",
                            evidence=resp.text[:300],
                            payload=payload,
                            fix_suggestion="禁止直接拼接系统命令，使用安全的 API 调用",
                            evidence_quality="body_confirmed",
                        ))
                        break

        return findings
