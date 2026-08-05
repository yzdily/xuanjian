"""
误报管理器 — 用户标记误报并学习规则

借鉴 AWVS 的误报标记机制，用户可以标记漏洞为误报，
系统自动生成过滤规则，后续扫描自动排除类似误报。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from core.log import get_logger

log = get_logger("false_positive")


@dataclass
class FalsePositiveRule:
    """误报规则"""
    id: str = ""
    vuln_type: str = ""
    pattern: str = ""  # URL pattern or response pattern
    reason: str = ""
    created_at: str = ""
    created_by: str = "user"
    hit_count: int = 0


class FalsePositiveManager:
    """误报管理器"""
    
    def __init__(self, db_path: str = "data/false_positives.json"):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._rules: list[FalsePositiveRule] = []
        self._load_rules()
    
    def _load_rules(self) -> None:
        """加载规则"""
        if self._db_path.exists():
            try:
                with open(self._db_path, encoding="utf-8") as f:
                    data = json.load(f)
                self._rules = [FalsePositiveRule(**r) for r in data.get("rules", [])]
                log.info(f"加载 {len(self._rules)} 条误报规则")
            except Exception as e:
                log.warning(f"加载误报规则失败: {e}")
    
    def _save_rules(self) -> None:
        """保存规则"""
        try:
            data = {
                "rules": [r.__dict__ for r in self._rules],
                "updated_at": datetime.now().isoformat(),
            }
            with open(self._db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.error(f"保存误报规则失败: {e}")
    
    def mark_as_false_positive(
        self,
        vuln_type: str,
        url_pattern: str,
        reason: str = "",
        response_pattern: str = "",
    ) -> FalsePositiveRule:
        """标记为误报
        
        Args:
            vuln_type: 漏洞类型
            url_pattern: URL 匹配模式（支持正则）
            reason: 误报原因
            response_pattern: 响应体匹配模式
            
        Returns:
            新创建的误报规则
        """
        import uuid
        
        rule = FalsePositiveRule(
            id=f"fp-{uuid.uuid4().hex[:8]}",
            vuln_type=vuln_type,
            pattern=url_pattern or response_pattern,
            reason=reason,
            created_at=datetime.now().isoformat(),
        )
        
        self._rules.append(rule)
        self._save_rules()
        
        log.info(f"新增误报规则: {rule.id} ({vuln_type}) - {reason}")
        return rule
    
    def is_false_positive(self, finding: dict) -> bool:
        """检查是否为已知误报
        
        Args:
            finding: 扫描发现
            
        Returns:
            True = 是误报，应排除
        """
        url = finding.get("url", "")
        vuln_type = finding.get("type", "") or finding.get("vuln_type", "")
        
        for rule in self._rules:
            if rule.vuln_type != vuln_type:
                continue
            
            # URL pattern match
            try:
                if re.search(rule.pattern, url, re.IGNORECASE):
                    rule.hit_count += 1
                    log.debug(f"命中误报规则: {rule.id} - {url}")
                    return True
            except re.error:
                # Not a valid regex, try simple match
                if rule.pattern in url:
                    rule.hit_count += 1
                    return True
        
        return False
    
    def get_rules(self, vuln_type: str = None) -> list[FalsePositiveRule]:
        """获取规则列表"""
        if vuln_type:
            return [r for r in self._rules if r.vuln_type == vuln_type]
        return list(self._rules)
    
    def delete_rule(self, rule_id: str) -> bool:
        """删除规则"""
        for i, rule in enumerate(self._rules):
            if rule.id == rule_id:
                self._rules.pop(i)
                self._save_rules()
                log.info(f"删除误报规则: {rule_id}")
                return True
        return False


# Global instance
_fp_manager: FalsePositiveManager | None = None


def get_fp_manager() -> FalsePositiveManager:
    """获取误报管理器实例"""
    global _fp_manager
    if _fp_manager is None:
        _fp_manager = FalsePositiveManager()
    return _fp_manager


def is_false_positive(finding: dict) -> bool:
    """便捷函数：检查是否为误报"""
    return get_fp_manager().is_false_positive(finding)