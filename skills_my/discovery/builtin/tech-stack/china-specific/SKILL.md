---
name: china-specific
description: "国产组件指纹 + 默认凭据 + 高危路径知识库 — 覆盖致远/通达/泛微/用友/金蝶/蓝凌等国产 OA，Nacos/XXL-JOB/Druid/Apollo 等中间件，RuoYi/JeecgBoot 等国产框架。含指纹识别、默认密码、高危路径、WooYun 高频参数字典。当目标指纹识别出国产组件时自动加载。"
metadata:
  tags: "国产,OA,致远,通达,泛微,用友,金蝶,蓝凌,Nacos,XXL-JOB,Druid,RuoYi,JeecgBoot,默认密码,指纹,中国,SRC,补天"
  category: "recon"
  authority: "reference"
---

# 国产组件安全知识库

> 当目标系统识别出国产组件指纹时，加载本知识库获取：
> - 指纹确认 → 高危路径 → 默认凭据 → 已知漏洞模式
> - WooYun 高频参数字典（提升 fuzzing 命中率）

## 知识库子文件

| 子文件 | 内容 | 加载方式 |
|--------|------|---------|
| 国产组件指纹 + 默认凭据 + 高危路径 | OA/中间件/框架指纹、默认密码、信息泄露路径、高频参数 | `knowledge_load_skill("china-specific/fingerprints")` |

---

## 快速指纹检测清单

发现目标时，先检查以下指纹：

1. **OA 系统**：`/seeyon/`、`/general/`、`/weaver/`、`/oaerp/`、`/kdgs/`
2. **中间件**：`/druid/`、`/nacos/`、`/xxl-job-admin/`、`/jeecg-boot/`
3. **信息泄露**：`/.git/config`、`/wwwroot.rar`、`/phpinfo.php`
4. **API 文档**：`/swagger-ui.html`、`/actuator/`

→ 命中任一指纹，立即加载 `knowledge_load_skill("china-specific/fingerprints")` 获取详细攻击路径。
