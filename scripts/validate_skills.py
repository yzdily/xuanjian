"""
validate_skills — 校验所有 SKILL.md 的 frontmatter 格式

用法：python -m scripts.validate_skills 或 make validate
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


REQUIRED_FIELDS = ["name", "description"]
SEARCH_PATHS = [Path("./skills_my")]


def validate_skill(filepath: Path) -> list[str]:
    """校验单个 SKILL.md，返回错误列表。"""
    errors = []
    content = filepath.read_text(encoding="utf-8")

    # 检查 frontmatter
    if not content.startswith("---"):
        errors.append("缺少 YAML frontmatter (文件应以 --- 开头)")
        return errors

    parts = content.split("---", 2)
    if len(parts) < 3:
        errors.append("YAML frontmatter 格式错误 (需要两个 ---)")
        return errors

    try:
        meta = yaml.safe_load(parts[1])
    except yaml.YAMLError as e:
        errors.append(f"YAML 解析错误: {e}")
        return errors

    if not meta:
        errors.append("frontmatter 为空")
        return errors

    for field in REQUIRED_FIELDS:
        if field not in meta:
            errors.append(f"缺少必填字段: {field}")

    if "description" in meta and len(meta["description"]) < 10:
        errors.append("description 太短（建议至少 10 个字符）")

    # 检查正文是否有内容
    body = parts[2].strip()
    if len(body) < 50:
        errors.append("正文内容过少（建议填写 Phase 1~4）")

    return errors


def main():
    total = 0
    errors_count = 0

    for base in SEARCH_PATHS:
        if not base.exists():
            continue
        for skill_file in base.rglob("SKILL.md"):
            total += 1
            errors = validate_skill(skill_file)
            if errors:
                errors_count += 1
                print(f"\n❌ {skill_file}")
                for e in errors:
                    print(f"   - {e}")
            else:
                print(f"✅ {skill_file}")

    print(f"\n总计: {total} 个 Skill, {errors_count} 个有问题")

    if errors_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
