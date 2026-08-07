"""
ScanConfig — 可注入、可测试的扫描配置门面

生产级重构要点（2026-08-07）：
原 `core.config` 把漏洞映射表、优先级、同义词等以**模块级可变全局变量**
暴露，引擎散弹式 `from core.config import X` 引用，导致：
- 无法在测试中替换配置（热重载只能原地修改全局字典，存在引用失效风险）；
- 配置与逻辑耦合，单测难以构造边界用例。

本模块把上述数据收敛为一个 `ScanConfig` 对象，引擎通过依赖注入获取配置，
并用**纯函数**实现去重 / 优先级排序 / Checklist 推导，使其可单元测试、
可替换、可组合。

注意：ScanConfig 默认从 core.config 拷贝真实生产值，因此不会与既有逻辑分叉。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import core.config as _cfg


@dataclass
class ScanConfig:
    # ---- 配置数据（默认拷贝自 core.config，可被测试覆盖） ----
    feature_vuln_mapping: list = field(default_factory=lambda: list(_cfg.FEATURE_VULN_MAPPING))
    vuln_to_skill: dict = field(default_factory=lambda: dict(_cfg.VULN_TO_SKILL))
    vuln_synonyms: dict = field(default_factory=lambda: dict(_cfg.VULN_SYNONYMS))
    vuln_priority: dict = field(default_factory=lambda: dict(_cfg.VULN_PRIORITY))
    vuln_priority_default: int = _cfg.VULN_PRIORITY_DEFAULT
    method_vuln_map: dict = field(default_factory=lambda: dict(_cfg.METHOD_VULN_MAP))
    path_vuln_patterns: list = field(default_factory=lambda: list(_cfg.PATH_VULN_PATTERNS))
    element_vuln_map: dict = field(default_factory=lambda: dict(_cfg.ELEMENT_VULN_MAP))
    max_checklist_per_fp: int = _cfg.MAX_CHECKLIST_PER_FP

    # ============================================================
    # 纯函数
    # ============================================================
    def dedup_vuln_type(self, name: str) -> str:
        """把 LLM / 用户传入的任意命名归一化为系统标准漏洞类型名。

        先精确匹配，再大小写 / 空格归一匹配（覆盖中文带空格、英文混排等变体）。
        """
        if not name:
            return name
        key = name.strip()
        if key in self.vuln_synonyms:
            return self.vuln_synonyms[key]
        # 归一化：同时剥离 空格 / 连字符 / 下划线，兼容 "Horizontal Privilege Escalation"
        # 与 synonyms 表里 "horizontal-privilege-escalation" / "horizontal_privilege_escalation" 等混排写法
        normalized = re.sub(r"[\s_-]+", "", key.lower())
        for k, v in self.vuln_synonyms.items():
            if re.sub(r"[\s_-]+", "", k.lower()) == normalized:
                return v
        return key

    def priority(self, vuln_type: str) -> int:
        """返回漏洞类型的优先级数值（越小越靠前）。"""
        return self.vuln_priority.get(vuln_type, self.vuln_priority_default)

    def derive_path_vulns(self, path: str) -> list[str]:
        """根据 URL 路径特征推导应测试的漏洞类型（去重后的列表）。"""
        out: list[str] = []
        seen: set[str] = set()
        for patterns, types in self.path_vuln_patterns:
            for pat in patterns:
                try:
                    matched = bool(re.search(pat, path))
                except re.error:
                    matched = pat in path
                if matched:
                    for t in types:
                        norm = self.dedup_vuln_type(t)
                        if norm not in seen:
                            seen.add(norm)
                            out.append(norm)
                    break
        return out

    def build_feature_checklist(
        self,
        keywords: list[str],
        method: str | None = None,
        path: str = "",
    ) -> list[str]:
        """推导单个功能点的漏洞测试清单。

        合并来源：功能点关键词映射 + HTTP 方法映射 + 路径特征映射。
        结果按优先级排序，并裁剪到 max_checklist_per_fp（保险丝，防规则爆炸）。

        返回：去重、按优先级排序、已裁剪的漏洞类型列表。
        """
        collected: list[str] = []
        seen: set[str] = set()

        def add(types: list[str]) -> None:
            for t in types:
                norm = self.dedup_vuln_type(t)
                if norm not in seen:
                    seen.add(norm)
                    collected.append(norm)

        kw_lower = [k.lower() for k in keywords]
        for kw_group, types in self.feature_vuln_mapping:
            if any(kw.lower() in kw_lower for kw in kw_group):
                add(types)

        if method:
            add(self.method_vuln_map.get(method.upper(), []))

        if path:
            add(self.derive_path_vulns(path))

        ordered = sorted(collected, key=lambda t: (self.priority(t), t))
        return ordered[: self.max_checklist_per_fp]
