"""
SKILL 注册模块测试

覆盖：parse_skill_file、scan_skills、SkillRegistry、_parse_frontmatter、
      _to_str_list、find_skill_path、get_registry、reload_registry
"""

import pytest
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestParseFrontmatter:
    def test_valid_frontmatter(self):
        from core.skill_registry import _parse_frontmatter
        content = """---
name: test-skill
description: "测试技能"
enabled: true
vuln_types:
  - SQL注入
  - 注入漏洞
triggers:
  - 搜索
  - 查询
priority: 8
---

# 正文内容
这是 SKILL 的正文。
"""
        meta, body = _parse_frontmatter(content)
        assert meta["name"] == "test-skill"
        assert meta["description"] == "测试技能"
        assert meta["enabled"] is True
        assert "SQL注入" in meta["vuln_types"]
        assert meta["priority"] == 8
        assert "正文内容" in body

    def test_no_frontmatter(self):
        from core.skill_registry import _parse_frontmatter
        content = "# 没有 frontmatter 的文件\n\n正文内容"
        meta, body = _parse_frontmatter(content)
        assert meta == {}
        assert "正文内容" in body

    def test_empty_frontmatter(self):
        from core.skill_registry import _parse_frontmatter
        content = "---\n---\n\n正文"
        meta, body = _parse_frontmatter(content)
        # 空 YAML 解析为 None，应返回 {}
        assert meta == {} or meta is None


class TestToStrList:
    def test_list_input(self):
        from core.skill_registry import _to_str_list
        assert _to_str_list(["a", "b", "c"]) == ["a", "b", "c"]

    def test_string_input(self):
        from core.skill_registry import _to_str_list
        result = _to_str_list("SQL注入, XSS, SSRF")
        assert "SQL注入" in result
        assert "XSS" in result
        assert "SSRF" in result

    def test_none_input(self):
        from core.skill_registry import _to_str_list
        assert _to_str_list(None) == []

    def test_empty_string(self):
        from core.skill_registry import _to_str_list
        assert _to_str_list("") == []

    def test_single_value(self):
        from core.skill_registry import _to_str_list
        assert _to_str_list(42) == ["42"]


class TestParseSkillFile:
    def test_parse_valid_skill(self):
        from core.skill_registry import parse_skill_file
        tmpdir = Path(tempfile.mkdtemp())
        skill_dir = tmpdir / "test-skill"
        skill_dir.mkdir()
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text("""---
name: test-skill
description: "测试"
vuln_types:
  - XSS
triggers:
  - 搜索
priority: 7
---

# Phase 1
测试步骤
""", encoding="utf-8")
        entry = parse_skill_file(skill_md)
        assert entry is not None
        assert entry.name == "test-skill"
        assert "XSS" in entry.vuln_types
        assert entry.priority == 7
        assert entry.body_size > 0

    def test_parse_no_frontmatter(self):
        from core.skill_registry import parse_skill_file
        tmpdir = Path(tempfile.mkdtemp())
        skill_dir = tmpdir / "bare-skill"
        skill_dir.mkdir()
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text("# 无 frontmatter\n\n正文", encoding="utf-8")
        entry = parse_skill_file(skill_md)
        assert entry is not None
        assert entry.name == "bare-skill"  # 使用目录名

    def test_parse_nonexistent_file(self):
        from core.skill_registry import parse_skill_file
        result = parse_skill_file(Path("/nonexistent/SKILL.md"))
        assert result is None

    def test_parse_with_knowledge_dir(self):
        from core.skill_registry import parse_skill_file
        tmpdir = Path(tempfile.mkdtemp())
        skill_dir = tmpdir / "rich-skill"
        skill_dir.mkdir()
        knowledge_dir = skill_dir / "knowledge"
        knowledge_dir.mkdir()
        (knowledge_dir / "tips.md").write_text("# Tips", encoding="utf-8")
        (knowledge_dir / "examples.md").write_text("# Examples", encoding="utf-8")
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text("---\nname: rich-skill\n---\n\n正文", encoding="utf-8")
        entry = parse_skill_file(skill_md)
        assert len(entry.knowledge_files) == 2
        assert "tips" in entry.knowledge_files
        assert "examples" in entry.knowledge_files


class TestSkillEntry:
    def test_relative_path(self):
        from core.skill_registry import SkillEntry, SKILLS_DIR
        entry = SkillEntry(
            name="test",
            path=SKILLS_DIR.resolve() / "web" / "sql-injection" / "SKILL.md",
        )
        rel = entry.relative_path
        assert "sql-injection" in rel


class TestScanSkills:
    def test_scan_real_skills_dir(self):
        """扫描真实的 skills_my 目录。"""
        from core.skill_registry import scan_skills, SKILLS_DIR
        if not SKILLS_DIR.exists():
            pytest.skip("skills_my 目录不存在")
        registry = scan_skills()
        assert registry.count >= 20  # 当前约 24 个 SKILL
        assert registry.enabled_count >= 20
        assert len(registry.vuln_to_skill) > 0
        assert len(registry.errors) == 0  # 不应有解析错误

    def test_scan_empty_dir(self):
        from core.skill_registry import scan_skills
        tmpdir = Path(tempfile.mkdtemp()) / "empty_skills"
        tmpdir.mkdir()
        registry = scan_skills(tmpdir)
        assert registry.count == 0

    def test_scan_nonexistent_dir(self):
        from core.skill_registry import scan_skills
        registry = scan_skills(Path("/nonexistent/skills"))
        assert registry.count == 0
        assert len(registry.errors) == 1


class TestGetRegistry:
    def test_get_registry_singleton(self):
        from core.skill_registry import get_registry
        r1 = get_registry()
        r2 = get_registry()
        assert r1 is r2

    def test_reload_registry(self):
        from core.skill_registry import get_registry, reload_registry
        r1 = get_registry()
        r2 = reload_registry()
        # reload 后应是新对象
        assert r1 is not r2


class TestFindSkillPath:
    def test_find_existing_skill(self):
        from core.skill_registry import find_skill_path, SKILLS_DIR
        if not SKILLS_DIR.exists():
            pytest.skip("skills_my 目录不存在")
        # 找一个已知存在的 skill
        path = find_skill_path("401-403-bypass")
        if path:
            assert path.exists()
            assert path.name == "SKILL.md"

    def test_find_nonexistent_skill(self):
        from core.skill_registry import find_skill_path
        path = find_skill_path("nonexistent-skill-xyz")
        assert path is None
