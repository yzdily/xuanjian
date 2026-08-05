"""
POC 模板生成器 — 快速构建标准化验证模板

借鉴 Venom 的 POC 模板生成设计，生成 Nuclei 兼容的 YAML 模板，
支持一键导出和分享。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from core.log import get_logger

log = get_logger("poc_generator")


class Severity(str, Enum):
    """漏洞严重级别"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MatchCondition(str, Enum):
    """匹配条件"""
    STATUS = "status"
    WORDS = "words"
    REGEX = "regex"
    BODY = "body"
    HEADER = "header"


@dataclass
class RequestSpec:
    """请求规格"""
    method: str = "GET"
    path: list[str] = field(default_factory=lambda: ["{{BaseURL}}"])
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: str = ""  # 完整原始请求


@dataclass  
class Matcher:
    """匹配器"""
    condition: MatchCondition = MatchCondition.STATUS
    values: list[str] = field(default_factory=list)
    negative: bool = False
    part: str = "body"  # body, header, all


@dataclass
class Extractor:
    """提取器"""
    name: str = ""
    part: str = "body"
    regex: list[str] = field(default_factory=list)
    group: int = 1


@dataclass
class POCSpec:
    """POC 规格"""
    id: str = ""
    name: str = ""
    author: str = "xuanjian"
    severity: Severity = Severity.MEDIUM
    description: str = ""
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    classification: dict = field(default_factory=dict)
    request: RequestSpec = field(default_factory=RequestSpec)
    matchers: list[Matcher] = field(default_factory=list)
    extractors: list[Extractor] = field(default_factory=list)


class POCGenerator:
    """POC 模板生成器"""
    
    def __init__(self):
        self._templates: dict[str, POCSpec] = {}
    
    def generate_http_poc(
        self,
        vuln_type: str,
        request_method: str,
        request_path: str,
        request_headers: dict[str, str] = None,
        request_body: str = "",
        match_status: int = 200,
        match_words: list[str] = None,
        match_regex: list[str] = None,
        severity: str = "medium",
        description: str = "",
        tags: list[str] = None,
    ) -> str:
        """生成 HTTP 类型 POC 模板
        
        Args:
            vuln_type: 漏洞类型（如 sqli, xss, ssrf）
            request_method: 请求方法
            request_path: 请求路径
            request_headers: 请求头
            request_body: 请求体
            match_status: 匹配状态码
            match_words: 匹配关键词
            match_regex: 匹配正则
            severity: 严重级别
            description: 描述
            tags: 标签
            
        Returns:
            YAML 格式的 POC 模板
        """
        import uuid
        
        poc_id = f"{vuln_type}-{uuid.uuid4().hex[:8]}"
        
        # Build request
        request = RequestSpec(
            method=request_method.upper(),
            path=[request_path],
            headers=request_headers or {},
            body=request_body,
        )
        
        # Build matchers
        matchers = []
        
        if match_status:
            matchers.append(Matcher(
                condition=MatchCondition.STATUS,
                values=[str(match_status)],
            ))
        
        if match_words:
            matchers.append(Matcher(
                condition=MatchCondition.WORDS,
                values=match_words,
                part="body",
            ))
        
        if match_regex:
            matchers.append(Matcher(
                condition=MatchCondition.REGEX,
                values=match_regex,
                part="body",
            ))
        
        # Build POC spec
        spec = POCSpec(
            id=poc_id,
            name=f"{vuln_type.upper()} 漏洞检测",
            severity=Severity(severity.lower()),
            description=description or f"检测 {vuln_type} 漏洞",
            tags=tags or [vuln_type],
            request=request,
            matchers=matchers,
        )
        
        return self._to_yaml(spec)
    
    def generate_from_finding(self, finding: dict) -> str:
        """从扫描发现生成 POC
        
        Args:
            finding: 扫描发现结果
            
        Returns:
            YAML 格式的 POC 模板
        """
        vuln_type = finding.get("type", "unknown")
        url = finding.get("url", "")
        method = finding.get("method", "GET")
        body = finding.get("body", "")
        evidence = finding.get("evidence", "")
        severity = finding.get("severity", "medium")
        
        # Extract path from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        
        return self.generate_http_poc(
            vuln_type=vuln_type,
            request_method=method,
            request_path=path,
            request_body=body,
            match_words=[evidence] if evidence else None,
            severity=severity,
            description=f"自动生成自扫描发现: {evidence}",
        )
    
    def _to_yaml(self, spec: POCSpec) -> str:
        """将 POC 规格转换为 YAML
        
        Args:
            spec: POC 规格
            
        Returns:
            YAML 字符串
        """
        lines = []
        
        # Header
        lines.append(f"id: {spec.id}")
        lines.append(f"name: {spec.name}")
        lines.append(f"author: {spec.author}")
        lines.append(f"severity: {spec.severity.value}")
        lines.append(f"description: {spec.description}")
        
        if spec.reference:
            lines.append("reference:")
            for ref in spec.reference:
                lines.append(f"  - {ref}")
        
        if spec.tags:
            lines.append(f"tags: {','.join(spec.tags)}")
        
        if spec.classification:
            lines.append("classification:")
            for key, value in spec.classification.items():
                lines.append(f"  {key}: {value}")
        
        # Requests
        lines.append("requests:")
        lines.append("  - method: {{method}}".replace("{{method}}", spec.request.method))
        
        lines.append("    path:")
        for path in spec.request.path:
            lines.append(f"      - \"{path}\"")
        
        if spec.request.headers:
            lines.append("    headers:")
            for key, value in spec.request.headers.items():
                lines.append(f"      {key}: \"{value}\"")
        
        if spec.request.body:
            lines.append(f"    body: \"{spec.request.body}\"")
        
        # Matchers
        if spec.matchers:
            lines.append("    matchers-condition: and")
            lines.append("    matchers:")
            for matcher in spec.matchers:
                lines.append(f"      - type: {matcher.condition.value}")
                lines.append(f"        {matcher.condition.value}:")
                for value in matcher.values:
                    lines.append(f"          - \"{value}\"")
                if matcher.part != "body":
                    lines.append(f"        part: {matcher.part}")
                if matcher.negative:
                    lines.append("        negative: true")
        
        # Extractors
        if spec.extractors:
            lines.append("    extractors:")
            for ext in spec.extractors:
                lines.append(f"      - name: {ext.name}")
                lines.append(f"        type: regex")
                lines.append(f"        part: {ext.part}")
                lines.append("        regex:")
                for regex in ext.regex:
                    lines.append(f"          - \"{regex}\"")
        
        return "\n".join(lines)


# 全局生成器实例
_generator: POCGenerator | None = None


def get_poc_generator() -> POCGenerator:
    """获取 POC 生成器实例"""
    global _generator
    if _generator is None:
        _generator = POCGenerator()
    return _generator


def generate_poc(finding: dict) -> str:
    """便捷函数：从发现生成 POC"""
    return get_poc_generator().generate_from_finding(finding)