"""
误报管理器 — 用户标记误报并学习规则

借鉴 AWVS 的误报标记机制，用户可以标记漏洞为误报，
系统自动生成过滤规则，后续扫描自动排除类似误报。

生产级重构要点（2026-08-07）：
- 存储与逻辑解耦：规则持久化收敛到 `RuleStore` 协议，
  `JsonFileRuleStore`（默认，向后兼容 `data/false_positives.json`）
  与 `MemoryRuleStore`（测试用，零 I/O）可互换。
- 依赖注入：构造函数接受 `store` 与 `clock`，测试可在不触碰文件系统、
  不依赖系统时间的前提下确定性地验证持久化 / 命中计数 / 过期等行为。
- 向后兼容：`FalsePositiveManager()` 不传参时行为与旧版完全一致；
  `get_fp_manager()` 全局单例不变。
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

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


@runtime_checkable
class RuleStore(Protocol):
    """规则存储协议：加载 / 保存规则列表。"""

    def load(self) -> list[FalsePositiveRule]:
        ...

    def save(self, rules: list[FalsePositiveRule]) -> None:
        ...


class MemoryRuleStore:
    """内存存储：测试与无持久化场景使用，零副作用。"""

    def __init__(self) -> None:
        self.rules: list[FalsePositiveRule] = []

    def load(self) -> list[FalsePositiveRule]:
        return list(self.rules)

    def save(self, rules: list[FalsePositiveRule]) -> None:
        self.rules = [r for r in rules]


class JsonFileRuleStore:
    """JSON 文件存储：生产默认实现，向后兼容旧路径。"""

    def __init__(self, db_path: str = "data/false_positives.json") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> list[FalsePositiveRule]:
        if self._db_path.exists():
            try:
                with open(self._db_path, encoding="utf-8") as f:
                    data = json.load(f)
                return [FalsePositiveRule(**r) for r in data.get("rules", [])]
            except Exception as e:  # noqa: BLE001 - 损坏文件不应崩溃整个扫描
                log.warning(f"加载误报规则失败: {e}")
        return []

    def save(self, rules: list[FalsePositiveRule]) -> None:
        try:
            data = {
                "rules": [r.__dict__ for r in rules],
                "updated_at": datetime.now().isoformat(),
            }
            with open(self._db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:  # noqa: BLE001
            log.error(f"保存误报规则失败: {e}")


class FalsePositiveManager:
    """误报管理器

    Args:
        store: 规则存储后端。为 None 时回退到 `JsonFileRuleStore(db_path)`，
               保持向后兼容。
        db_path: 仅在 `store=None` 时生效，指定 JSON 文件路径。
        clock: 返回当前时间的可调用对象，默认 `datetime.now`，便于测试注入。
    """

    def __init__(
        self,
        store: RuleStore | None = None,
        *,
        db_path: str = "data/false_positives.json",
        clock: Callable[[], datetime] = datetime.now,
    ) -> None:
        self._clock = clock
        self._store: RuleStore = store if store is not None else JsonFileRuleStore(db_path)
        try:
            self._rules: list[FalsePositiveRule] = self._store.load()
        except Exception as e:  # noqa: BLE001 损坏/不可读的存储应优雅降级为空规则集
            log.warning("误报规则存储加载失败，已降级为空规则集: %s", e)
            self._rules = []

    def _save_rules(self) -> None:
        try:
            self._store.save(self._rules)
        except Exception as e:  # noqa: BLE001
            log.error(f"保存误报规则失败: {e}")

    def mark_as_false_positive(
        self,
        vuln_type: str,
        url_pattern: str,
        reason: str = "",
        response_pattern: str = "",
    ) -> FalsePositiveRule:
        """标记为误报，返回新创建的规则。"""
        rule = FalsePositiveRule(
            id=f"fp-{uuid.uuid4().hex[:8]}",
            vuln_type=vuln_type,
            pattern=url_pattern or response_pattern,
            reason=reason,
            created_at=self._clock().isoformat(),
        )
        self._rules.append(rule)
        self._save_rules()
        log.info(f"新增误报规则: {rule.id} ({vuln_type}) - {reason}")
        return rule

    def is_false_positive(self, finding: dict) -> bool:
        """检查是否为已知误报。命中规则会累加 hit_count 并持久化。"""
        url = finding.get("url", "")
        vuln_type = finding.get("type", "") or finding.get("vuln_type", "")

        for rule in self._rules:
            if rule.vuln_type != vuln_type:
                continue
            try:
                if re.search(rule.pattern, url, re.IGNORECASE):
                    rule.hit_count += 1
                    self._save_rules()
                    log.debug(f"命中误报规则: {rule.id} - {url}")
                    return True
            except re.error:
                if rule.pattern in url:
                    rule.hit_count += 1
                    self._save_rules()
                    return True
        return False

    def get_rules(self, vuln_type: str | None = None) -> list[FalsePositiveRule]:
        if vuln_type:
            return [r for r in self._rules if r.vuln_type == vuln_type]
        return list(self._rules)

    def delete_rule(self, rule_id: str) -> bool:
        for i, rule in enumerate(self._rules):
            if rule.id == rule_id:
                self._rules.pop(i)
                self._save_rules()
                log.info(f"删除误报规则: {rule_id}")
                return True
        return False


# Global instance（向后兼容）
_fp_manager: FalsePositiveManager | None = None


def get_fp_manager() -> FalsePositiveManager:
    """获取误报管理器单例。"""
    global _fp_manager
    if _fp_manager is None:
        _fp_manager = FalsePositiveManager()
    return _fp_manager


def is_false_positive(finding: dict) -> bool:
    """便捷函数：检查是否为误报。"""
    return get_fp_manager().is_false_positive(finding)
