"""fast_scanner 数据模型（从原 fast_scanner.py 机械拆分，内容逐字保留）。"""

from __future__ import annotations

from dataclasses import dataclass, field


# ============================================================
# 数据模型
# ============================================================

@dataclass
class VulnFinding:
    """漏洞发现结果"""
    vuln_type: str
    severity: str  # critical / high / medium / low / info
    url: str
    method: str
    detail: str
    evidence: str = ""
    payload: str = ""
    fix_suggestion: str = ""
    # ★ 证据质量（供 harm_validation 二次裁决参考）：
    #   header_only   = 仅根据响应头判定，无响应体敏感数据佐证（最易误报）
    #   body_confirmed = 响应体已确认含敏感数据特征
    #   content_match = 敏感路径/文件内容特征已匹配预期
    evidence_quality: str = ""
    # ★ 优化.md 建议6：日志→报告溯源 ID
    # 每条发现生成唯一 trace_id，可在 agent.log/agent.jsonl 中检索对应请求/响应日志
    trace_id: str = ""
    # 发现该漏洞的规则标签（如 SQLi / Unauth / IDOR / XSS），用于溯源
    rule_tag: str = ""
    # ★ skill 引导：该发现由哪个 SKILL 治理（确定性映射，fast 模式在 ScanExecutor 回填）
    skill: str = ""
    skill_path: str = ""


@dataclass
class ScanTarget:
    """单个扫描目标"""
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: str = ""
    params: dict = field(default_factory=dict)
    auth_headers: dict = field(default_factory=dict)  # 认证头（用于去认证对比）
    # ★ Fix4（优先级感知调度）：目标优先级，从 FeaturePoint.priority 透传。
    #   取值 critical / high / medium / low；scan_targets 据此排序，
    #   并决定 WAF/超时封禁后是继续尝试还是跳过该目标。
    priority: str = "medium"


@dataclass
class ScanResult:
    """扫描结果汇总"""
    target_url: str
    findings: list[VulnFinding] = field(default_factory=list)
    elapsed: float = 0.0
    total_requests: int = 0
    rules_run: int = 0
    blocked_count: int = 0
    timeout_count: int = 0
    error_count: int = 0
    log_suppressed_count: int = 0
    # ★ 封禁/熔断标志：标记本次扫描是否因 WAF/超时而提前终止
    waf_blocked: bool = False
    timeout_blocked: bool = False

    @property
    def vuln_count(self) -> int:
        return len(self.findings)

    @property
    def high_severity_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in ("critical", "high"))

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "vuln_count": self.vuln_count,
            "high_severity_count": self.high_severity_count,
            "elapsed": round(self.elapsed, 2),
            "total_requests": self.total_requests,
            "rules_run": self.rules_run,
            "blocked_count": self.blocked_count,
            "timeout_count": self.timeout_count,
            "error_count": self.error_count,
            "log_suppressed_count": self.log_suppressed_count,
            # ★ 封禁/熔断标志：让报告能展示扫描是否因 WAF/超时而受限
            "waf_blocked": getattr(self, "waf_blocked", False),
            "timeout_blocked": getattr(self, "timeout_blocked", False),
            "findings": [
                {
                    "vuln_type": f.vuln_type,
                    "severity": f.severity,
                    "url": f.url,
                    "method": f.method,
                    "detail": f.detail,
                    "evidence": f.evidence[:500],
                    "payload": f.payload,
                    "fix_suggestion": f.fix_suggestion,
                    "trace_id": f.trace_id,
                    "rule_tag": f.rule_tag,
                    "skill": f.skill,
                    "skill_path": f.skill_path,
                }
                for f in self.findings
            ],
        }
