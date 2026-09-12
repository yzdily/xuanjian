"""
skill_router 单元测试（确定性，零 LLM）

验证点：
- lookup_skill_for_vuln_type：命中返回 SkillRoute，未命中返回 None
- build_vuln_to_skill_routes：完整查找表（不截断、不按 SKILL 去重，缺失类型排除）
- route_vuln_types_to_skills：优先级降序排序、同一 SKILL 去重、top_n 截断
- 注入式 registry：纯函数，零网络 / 零文件副作用
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from core.skill_router import (
    SkillRoute,
    build_vuln_to_skill_routes,
    lookup_skill_for_vuln_type,
    route_vuln_types_to_skills,
)


class _FakeRegistry:
    """测试用的极简 registry：name -> entry(path, priority) + vuln_to_skill。"""

    def __init__(self, vuln_to_skill: dict[str, str], skills: dict[str, tuple[str, int]]):
        self.vuln_to_skill = vuln_to_skill
        self.skills = {
            name: SimpleNamespace(name=name, path=Path(path), priority=prio)
            for name, (path, prio) in skills.items()
        }


from pathlib import Path  # noqa: E402  (放这里仅为可读性，避免 import 顺序敏感)


@pytest.fixture
def fake_registry() -> Any:
    # vuln_type -> skill_name
    vts = {
        "SQL注入": "sql-injection",
        "XSS": "xss",
        "IDOR": "idor",
        "信息泄露": "info-leak",
        "CORS配置错误": "cors",
        "命令注入": "command-injection",
    }
    # skill_name -> (path, priority)
    skills = {
        "sql-injection": ("skills_my/sql-injection/SKILL.md", 10),
        "xss": ("skills_my/xss/SKILL.md", 8),
        "idor": ("skills_my/idor/SKILL.md", 9),
        "info-leak": ("skills_my/info-leak/SKILL.md", 5),
        "cors": ("skills_my/cors/SKILL.md", 4),
        "command-injection": ("skills_my/command-injection/SKILL.md", 7),
    }
    return _FakeRegistry(vts, skills)


# ============================================================
# 单类型查表
# ============================================================
class TestLookup:
    def test_hit(self, fake_registry):
        r = lookup_skill_for_vuln_type("SQL注入", fake_registry)
        assert isinstance(r, SkillRoute)
        assert r.skill_name == "sql-injection"
        assert r.priority == 10
        assert r.skill_path.endswith("SKILL.md")

    def test_unknown_returns_none(self, fake_registry):
        assert lookup_skill_for_vuln_type("未知漏洞", fake_registry) is None

    def test_empty_returns_none(self, fake_registry):
        assert lookup_skill_for_vuln_type("", fake_registry) is None


# ============================================================
# 完整查找表
# ============================================================
class TestBuildLookup:
    def test_maps_all_known(self, fake_registry):
        routes = build_vuln_to_skill_routes(
            ["SQL注入", "XSS", "IDOR", "信息泄露"], fake_registry
        )
        assert set(routes.keys()) == {"SQL注入", "XSS", "IDOR", "信息泄露"}
        assert routes["SQL注入"].skill_name == "sql-injection"

    def test_excludes_unknown(self, fake_registry):
        routes = build_vuln_to_skill_routes(["SQL注入", "不存在的类型"], fake_registry)
        assert set(routes.keys()) == {"SQL注入"}

    def test_dedupes_by_vuln_type_not_skill(self, fake_registry):
        # 两个不同 vuln_type 指向同一 SKILL 时，两张都保留
        routes = build_vuln_to_skill_routes(["SQL注入", "SQL注入"], fake_registry)
        assert set(routes.keys()) == {"SQL注入"}


# ============================================================
# 路由选择（排序 / 去重 / 截断）
# ============================================================
class TestRouteSelection:
    def test_sorted_by_priority_desc(self, fake_registry):
        routes = route_vuln_types_to_skills(
            ["XSS", "CORS配置错误", "SQL注入", "信息泄露"], fake_registry
        )
        prios = [r.priority for r in routes]
        assert prios == sorted(prios, reverse=True)
        assert routes[0].skill_name == "sql-injection"  # priority 10

    def test_top_n_truncation(self, fake_registry):
        routes = route_vuln_types_to_skills(
            ["SQL注入", "XSS", "IDOR", "信息泄露", "CORS配置错误", "命令注入"],
            fake_registry,
            top_n=2,
        )
        assert len(routes) == 2
        assert routes[0].skill_name == "sql-injection"
        assert routes[1].skill_name == "idor"

    def test_skips_unknown_types(self, fake_registry):
        routes = route_vuln_types_to_skills(["SQL注入", "ghost"], fake_registry)
        assert len(routes) == 1
        assert routes[0].skill_name == "sql-injection"

    def test_stable_sort_when_same_priority(self, fake_registry):
        # 构造两个相同优先级的 skill，验证按名字升序稳定
        reg = _FakeRegistry(
            {"A型": "skill-a", "B型": "skill-b"},
            {"skill-a": ("p/a.md", 5), "skill-b": ("p/b.md", 5)},
        )
        routes = route_vuln_types_to_skills(["B型", "A型"], reg)
        assert [r.skill_name for r in routes] == ["skill-a", "skill-b"]

    def test_empty_input(self, fake_registry):
        assert route_vuln_types_to_skills([], fake_registry) == []
