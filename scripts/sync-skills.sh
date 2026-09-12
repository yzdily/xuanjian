#!/usr/bin/env bash
# sync-skills.sh — 将嵌套的 skills 目录同步为扁平结构
# 用于兼容 Claude Code 的 .claude/skills/<name>/SKILL.md 格式
#
# 用法: bash scripts/sync-skills.sh [--target /path/to/project]

set -euo pipefail

TARGET="${1:-$(pwd)}"
SKILL_OUT="${TARGET}/.claude/skills"

echo "同步 Skills → ${SKILL_OUT}"
mkdir -p "${SKILL_OUT}"

# 清理旧的软链接
find "${SKILL_OUT}" -type l -delete 2>/dev/null || true

sync_dir() {
    local source_dir="$1"
    local label="$2"

    if [ ! -d "${source_dir}" ]; then
        return
    fi

    local count=0
    while IFS= read -r -d '' skill_file; do
        local skill_dir
        skill_dir=$(dirname "${skill_file}")
        local skill_name
        skill_name=$(basename "${skill_dir}")

        # 创建软链接
        local link="${SKILL_OUT}/${skill_name}"
        if [ ! -e "${link}" ]; then
            ln -s "$(cd "${skill_dir}" && pwd)" "${link}"
            count=$((count + 1))
        fi
    done < <(find "${source_dir}" -name "SKILL.md" -print0)

    echo "  ${label}: ${count} 个"
}

# 私有 skills 优先（覆盖同名公共 skill）
sync_dir "./skills_my" "私有 Skills"
sync_dir "./playbooks" "Playbooks"
sync_dir "./knowledge/AboutSecurity/skills" "公共 Skills (AboutSecurity)"

echo "✅ 同步完成"
