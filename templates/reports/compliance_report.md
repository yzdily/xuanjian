# 安全评估报告

## 1. 概述

**评估目标**: {{target_url}}
**评估时间**: {{scan_time}}
**评估人员**: {{scanner}}

## 2. 风险摘要

| 风险等级 | 数量 |
|----------|------|
| 严重 (Critical) | {{critical_count}} |
| 高危 (High) | {{high_count}} |
| 中危 (Medium) | {{medium_count}} |
| 低危 (Low) | {{low_count}} |
| 信息 (Info) | {{info_count}} |

**总风险评分**: {{risk_score}}/100

## 3. 漏洞详情

### 3.1 严重漏洞

{% for vuln in critical_vulns %}
#### {{vuln.name}}

- **类型**: {{vuln.type}}
- **URL**: {{vuln.url}}
- **描述**: {{vuln.description}}
- **证据**: 
  ```
  {{vuln.evidence}}
  ```
- **修复建议**: {{vuln.remediation}}

{% endfor %}

### 3.2 高危漏洞

{% for vuln in high_vulns %}
#### {{vuln.name}}

- **类型**: {{vuln.type}}
- **URL**: {{vuln.url}}
- **描述**: {{vuln.description}}
- **证据**: 
  ```
  {{vuln.evidence}}
  ```
- **修复建议**: {{vuln.remediation}}

{% endfor %}

## 4. OWASP Top 10 合规检查

| OWASP 类别 | 状态 | 发现数量 |
|------------|------|----------|
| A01: Broken Access Control | {{a01_status}} | {{a01_count}} |
| A02: Cryptographic Failures | {{a02_status}} | {{a02_count}} |
| A03: Injection | {{a03_status}} | {{a03_count}} |
| A04: Insecure Design | {{a04_status}} | {{a04_count}} |
| A05: Security Misconfiguration | {{a05_status}} | {{a05_count}} |
| A06: Vulnerable Components | {{a06_status}} | {{a06_count}} |
| A07: Authentication Failures | {{a07_status}} | {{a07_count}} |
| A08: Software and Data Integrity | {{a08_status}} | {{a08_count}} |
| A09: Security Logging Failures | {{a09_status}} | {{a09_count}} |
| A10: Server-Side Request Forgery | {{a10_status}} | {{a10_count}} |

## 5. 修复优先级

{% for item in priority_list %}
{{item.priority}}. **{{item.vuln_type}}** - {{item.url}}
   - 风险: {{item.severity}}
   - 预计修复时间: {{item.estimated_effort}}
{% endfor %}

## 6. 附录

### 6.1 扫描配置

- 扫描模式: {{scan_mode}}
- 扫描深度: {{scan_depth}}
- 爬取页面数: {{pages_crawled}}
- API 端点数: {{apis_discovered}}

### 6.2 免责声明

本报告仅供授权的安全评估使用。未经授权使用本报告进行任何形式的攻击行为均属违法。