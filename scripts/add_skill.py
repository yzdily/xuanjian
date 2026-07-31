"""
add_skill — 交互式创建新的 SKILL.md 骨架

用法：python -m scripts.add_skill 或 make add-skill
"""

from __future__ import annotations

import os
from pathlib import Path


SKILL_TEMPLATE = '''---
name: {name}
description: "{description}"
metadata:
  tags: "{tags}"
  category: "{category}"
---

# {title}

> 简要说明这个方法论解决什么问题。

## Phase 1: 识别攻击面

<!-- 描述什么情况下应该使用这个方法论，怎么判断目标存在这类风险 -->

## Phase 2: 测试方法

<!-- 具体的测试步骤，用 Burp/浏览器 的视角描述 -->

## Phase 3: 验证与利用

<!-- 如何确认漏洞存在，最小化 PoC -->

## Phase 4: 失败恢复

<!-- 测试不成功时的替代思路 -->

## 注意事项

<!-- 合规边界、不该做的事 -->
'''

CATEGORIES = [
    "auth",           # 认证授权（IDOR/越权/未授权）
    "business-logic", # 业务逻辑（支付/优惠券/验证码）
    "web",            # Web 通用（注入/XSS/SSRF/文件上传...）
    "api",            # API 安全（GraphQL/WebSocket/REST）
    "advanced",       # 高级（竞态/HTTP走私/缓存投毒）
    "info-disclosure",# 信息泄露（.git/备份/Swagger/JS泄露）
    "middleware",     # 中间件（Nginx/Tomcat/Redis/Nacos...）
    "cloud",          # 云安全（SSRF 元数据/AKSK/Bucket）
    "tool",           # 工具用法指南
    "core",           # 核心方法论
]


def main():
    print("\n🔧 创建新的 SKILL (你的挖洞经验)\n")

    # 1. 选分类
    print("可用分类:")
    for i, cat in enumerate(CATEGORIES, 1):
        print(f"  {i}. {cat}")
    print(f"  0. 自定义")

    choice = input("\n选择分类 (数字): ").strip()
    if choice == "0":
        category = input("输入自定义分类名 (英文小写连字符): ").strip()
    elif choice.isdigit() and 1 <= int(choice) <= len(CATEGORIES):
        category = CATEGORIES[int(choice) - 1]
    else:
        print("无效选择")
        return

    # 2. Skill 名称
    name = input("Skill 名称 (英文小写连字符, 如 payment-bypass): ").strip()
    if not name:
        print("名称不能为空")
        return

    # 3. 触发场景描述
    description = input("触发场景描述 (什么情况下 Agent 应该加载这个 skill): ").strip()

    # 4. Tags
    tags = input("标签 (逗号分隔, 中英文都行, 如 payment,支付,bypass,绕过): ").strip()

    # 5. 标题
    title = input("方法论标题 (中文, 如 '支付金额篡改方法论'): ").strip() or name

    # 生成文件
    skill_dir = Path(os.getenv("SKILLS_MY_PATH", "./skills_my")) / category / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_file = skill_dir / "SKILL.md"

    if skill_file.exists():
        overwrite = input(f"\n⚠️ {skill_file} 已存在，覆盖? (y/N): ").strip().lower()
        if overwrite != "y":
            print("取消")
            return

    content = SKILL_TEMPLATE.format(
        name=name,
        description=description,
        tags=tags,
        category=category,
        title=title,
    )
    skill_file.write_text(content, encoding="utf-8")

    print(f"\n✅ 已创建: {skill_file}")
    print(f"   请编辑文件，填写 Phase 1~4 的具体内容。")
    print(f"   下次运行 Agent 时会自动加载。\n")


if __name__ == "__main__":
    main()
