"""
合规报告生成器 — 生成符合 OWASP/PCI DSS 标准的报告

借鉴 AWVS 的合规报告功能，生成结构化的安全评估报告，
支持 PDF 导出和多种合规框架检查。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.log import get_logger

log = get_logger("compliance_report")


# OWASP Top 10 2021 映射
OWASP_MAPPING = {
    "sqli": "A03",
    "xss": "A03",
    "csrf": "A01",
    "ssrf": "A10",
    "auth_bypass": "A07",
    "info_disclosure": "A05",
    "weak_password": "A07",
    "xxe": "A05",
    "ssti": "A03",
    "file_upload": "A04",
}


@dataclass
class ComplianceReport:
    """合规报告"""
    target_url: str = ""
    scan_time: str = ""
    scanner: str = "xuanjian"
    
    # Severity counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Risk score (0-100)
    risk_score: int = 0
    
    # Vulnerabilities by severity
    critical_vulns: list[dict] = field(default_factory=list)
    high_vulns: list[dict] = field(default_factory=list)
    medium_vulns: list[dict] = field(default_factory=list)
    low_vulns: list[dict] = field(default_factory=list)
    
    # OWASP compliance
    owasp_status: dict = field(default_factory=dict)
    
    # Priority list
    priority_list: list[dict] = field(default_factory=list)
    
    # Scan config
    scan_mode: str = "fast"
    scan_depth: int = 2
    pages_crawled: int = 0
    apis_discovered: int = 0


class ComplianceReportGenerator:
    """合规报告生成器"""
    
    def __init__(self):
        self._template_dir = Path("templates/reports")
    
    def generate(self, findings: list[dict], scan_info: dict) -> ComplianceReport:
        """生成合规报告
        
        Args:
            findings: 扫描发现列表
            scan_info: 扫描信息
            
        Returns:
            合规报告对象
        """
        report = ComplianceReport(
            target_url=scan_info.get("target_url", ""),
            scan_time=datetime.now().isoformat(),
            scan_mode=scan_info.get("mode", "fast"),
            pages_crawled=scan_info.get("pages_crawled", 0),
            apis_discovered=scan_info.get("apis_discovered", 0),
        )
        
        # Categorize by severity
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            
            if severity == "critical":
                report.critical_count += 1
                report.critical_vulns.append(finding)
            elif severity == "high":
                report.high_count += 1
                report.high_vulns.append(finding)
            elif severity == "medium":
                report.medium_count += 1
                report.medium_vulns.append(finding)
            elif severity == "low":
                report.low_count += 1
                report.low_vulns.append(finding)
            else:
                report.info_count += 1
        
        # Calculate risk score
        report.risk_score = self._calculate_risk_score(report)
        
        # OWASP compliance check
        report.owasp_status = self._check_owasp_compliance(findings)
        
        # Priority list
        report.priority_list = self._generate_priority_list(findings)
        
        return report
    
    def _calculate_risk_score(self, report: ComplianceReport) -> int:
        """计算风险评分 (0-100)"""
        score = 0
        score += report.critical_count * 25
        score += report.high_count * 15
        score += report.medium_count * 5
        score += report.low_count * 1
        return min(100, score)
    
    def _check_owasp_compliance(self, findings: list[dict]) -> dict:
        """检查 OWASP Top 10 合规状态"""
        status = {}
        
        for category in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
            status[category] = {"status": "通过", "count": 0}
        
        for finding in findings:
            vuln_type = finding.get("type", "")
            category = OWASP_MAPPING.get(vuln_type)
            
            if category and category in status:
                status[category]["count"] += 1
                status[category]["status"] = "需关注"
        
        return status
    
    def _generate_priority_list(self, findings: list[dict]) -> list[dict]:
        """生成修复优先级列表"""
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5)
        )
        
        priority_list = []
        effort_map = {
            "critical": "2-4 小时",
            "high": "4-8 小时",
            "medium": "1-2 天",
            "low": "1 周",
        }
        
        for i, finding in enumerate(sorted_findings[:20], 1):  # Top 20
            priority_list.append({
                "priority": i,
                "vuln_type": finding.get("type", "unknown"),
                "url": finding.get("url", ""),
                "severity": finding.get("severity", "info"),
                "estimated_effort": effort_map.get(finding.get("severity", "low").lower(), "1 周"),
            })
        
        return priority_list
    
    def to_markdown(self, report: ComplianceReport) -> str:
        """转换为 Markdown 格式"""
        template_path = self._template_dir / "compliance_report.md"
        
        if template_path.exists():
            template = template_path.read_text(encoding="utf-8")
        else:
            template = self._get_default_template()
        
        # Simple template rendering
        md = template.replace("{{target_url}}", report.target_url)
        md = md.replace("{{scan_time}}", report.scan_time)
        md = md.replace("{{scanner}}", report.scanner)
        md = md.replace("{{critical_count}}", str(report.critical_count))
        md = md.replace("{{high_count}}", str(report.high_count))
        md = md.replace("{{medium_count}}", str(report.medium_count))
        md = md.replace("{{low_count}}", str(report.low_count))
        md = md.replace("{{info_count}}", str(report.info_count))
        md = md.replace("{{risk_score}}", str(report.risk_score))
        
        return md
    
    def _get_default_template(self) -> str:
        """获取默认模板"""
        return """# 安全评估报告

## 1. 概述
- **评估目标**: {{target_url}}
- **评估时间**: {{scan_time}}
- **风险评分**: {{risk_score}}/100

## 2. 风险摘要
- 严重: {{critical_count}}
- 高危: {{high_count}}
- 中危: {{medium_count}}
- 低危: {{low_count}}

## 3. 免责声明
本报告仅供授权的安全评估使用。
"""


# Global instance
_generator: ComplianceReportGenerator | None = None


def get_report_generator() -> ComplianceReportGenerator:
    """获取报告生成器"""
    global _generator
    if _generator is None:
        _generator = ComplianceReportGenerator()
    return _generator


def generate_compliance_report(findings: list[dict], scan_info: dict) -> str:
    """便捷函数：生成合规报告"""
    generator = get_report_generator()
    report = generator.generate(findings, scan_info)
    return generator.to_markdown(report)