"""
Custom Report MCP — 自定义报告模版服务

独立的 MCP 服务，负责自定义报告模版的检测、数据准备和格式化报告保存。
与 report_mcp.py 互补：
- report_mcp: 系统内置模版的简单占位符替换（无自定义模版时使用）
- custom_report_mcp: 自定义模版的 LLM 智能格式化（有自定义模版时使用）

工作流程：
1. Phase 3 开始时，LLM 调用 report_check_template 检查是否有自定义模版
2. 如果有 → 调用 report_format_with_template 获取模版文本 + 结构化数据
3. LLM 按模版格式组织报告内容
4. LLM 调用 report_save_formatted 保存最终报告
5. 如果没有 → 走原有 report_generate 流程（不受影响）
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from mcp.server.fastmcp import FastMCP

from core.config import MAX_REPORT_TEXT_SIZE

mcp = FastMCP("custom_report")

NOTE_DIR = Path(os.getenv("NOTE_PATH", "./data/notes"))
REPORT_DIR = Path(os.getenv("REPORT_PATH", "./data/reports"))
CUSTOM_TEMPLATE_DIR = Path("data/custom_templates")
CUSTOM_TEMPLATE_META = CUSTOM_TEMPLATE_DIR / "_meta.json"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _load_template_meta() -> list[dict]:
    """加载自定义模版元数据。"""
    if not CUSTOM_TEMPLATE_META.exists():
        return []
    try:
        return json.loads(CUSTOM_TEMPLATE_META.read_text(encoding="utf-8"))
    except Exception:
        return []


def _get_active_template() -> dict | None:
    """获取当前启用的自定义模版信息。返回 {id, name, content} 或 None。"""
    meta = _load_template_meta()
    for item in meta:
        if item.get("enabled"):
            text_path = CUSTOM_TEMPLATE_DIR / f"{item['id']}.extracted.txt"
            if text_path.exists():
                return {
                    "id": item["id"],
                    "name": item["name"],
                    "content": text_path.read_text(encoding="utf-8")[:MAX_REPORT_TEXT_SIZE],
                }
    return None


@mcp.tool()
async def report_check_template(task_id: str = "default") -> str:
    """检查是否有启用的自定义报告模版。

    在 Phase 3 报告生成前调用此工具：
    - 如果返回 has_template=true，则应调用 report_format_with_template 获取模版和数据，
      按模版格式组织报告后调用 report_save_formatted 保存。
    - 如果返回 has_template=false，则直接调用 report_generate 走内置模版流程。
    """
    tpl = _get_active_template()
    if tpl:
        return (
            f"has_template=true\n"
            f"template_name={tpl['name']}\n"
            f"template_id={tpl['id']}\n\n"
            f"检测到用户自定义报告模版「{tpl['name']}」已启用。\n"
            f"请调用 report_format_with_template 获取模版内容和测试数据，"
            f"然后按照模版的格式和结构组织报告内容，最后调用 report_save_formatted 保存。"
        )
    else:
        return (
            "has_template=false\n\n"
            "未检测到自定义报告模版（或所有模版已禁用）。\n"
            "请直接调用 report_generate 使用系统内置模版生成报告。"
        )


@mcp.tool()
async def report_format_with_template(task_id: str = "default") -> str:
    """获取自定义模版内容和测试数据，供 LLM 按模版格式组织报告。

    返回内容包含：
    1. 用户上传的报告模版原文（LLM 需理解其结构、章节、格式）
    2. 本次测试的结构化数据（漏洞列表、资产信息等）

    LLM 收到后应该：
    1. 理解模版的章节结构、排版风格、固定文案
    2. 将测试数据按模版格式填入对应位置
    3. 保留模版中的固定内容（如公司名、免责声明、封面信息等）
    4. 将组织好的完整报告通过 report_save_formatted 保存
    """
    tpl = _get_active_template()
    if not tpl:
        return "错误：没有启用的自定义模版。请直接使用 report_generate。"

    # 收集测试数据
    result_file = NOTE_DIR / f"{task_id}-result.md"
    results = result_file.read_text(encoding="utf-8") if result_file.exists() else "暂无漏洞记录"

    info_file = NOTE_DIR / f"{task_id}-info.md"
    info_content = info_file.read_text(encoding="utf-8") if info_file.exists() else "无"

    # 尝试从 sitemap 获取更多结构化数据
    sitemap_summary = _get_sitemap_summary(task_id)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    return (
        f"# 自定义报告模版格式化任务\n\n"
        f"## 📐 用户的报告模版\n\n"
        f"以下是用户上传的报告模版原文。请**严格按照此模版的格式、章节结构、排版风格**来组织报告。\n"
        f"保留模版中的固定文案（如公司名称、免责声明、版权信息等），用实际测试数据替换占位内容。\n\n"
        f"```\n{tpl['content']}\n```\n\n"
        f"---\n\n"
        f"## 📊 本次测试数据\n\n"
        f"### 基本信息\n"
        f"- 任务 ID: {task_id}\n"
        f"- 生成时间: {timestamp}\n\n"
        f"### 资产信息\n\n{info_content}\n\n"
        f"### 漏洞发现\n\n{results}\n\n"
        f"{sitemap_summary}\n\n"
        f"---\n\n"
        f"## ✍️ 你的任务\n\n"
        f"1. 仔细阅读上面的「用户报告模版」，理解其结构\n"
        f"2. 将「本次测试数据」中的内容，按照模版的格式重新组织\n"
        f"3. 模版中有固定文案的地方保留原文，有占位内容的地方用实际数据填充\n"
        f"4. 如果模版中某些章节在本次测试中没有对应数据，写明「本次测试未涉及」\n"
        f"5. 将最终组织好的完整报告内容，调用 report_save_formatted 保存\n"
    )


@mcp.tool()
async def report_save_formatted(
    task_id: str = "default",
    content: str = "",
    report_type: str = "custom",
) -> str:
    """保存 LLM 按自定义模版格式化后的报告。

    - task_id: 任务 ID
    - content: LLM 按模版格式组织好的完整报告内容（Markdown）
    - report_type: 报告类型标识，默认 "custom"
    """
    if not content.strip():
        return "错误：报告内容为空，请先按模版格式组织报告内容再保存。"

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # ★ 写盘前强制替换占位符，防止 LLM 直接把模板原文（含 {{CRITICAL_COUNT}} 等）
    # 写入报告文件。复用 report_mcp._force_replace_placeholders 的幂等逻辑。
    try:
        from mcp_servers.report_mcp import _force_replace_placeholders
        # 读取 result/info 笔记供占位符替换使用
        result_file = NOTE_DIR / f"{task_id}-result.md"
        info_file = NOTE_DIR / f"{task_id}-info.md"
        results_text = result_file.read_text(encoding="utf-8") if result_file.exists() else ""
        info_text = info_file.read_text(encoding="utf-8") if info_file.exists() else ""
        content = _force_replace_placeholders(
            content, task_id=task_id,
            results=results_text, info_content=info_text,
        )
    except Exception as e:
        # 占位符替换失败不阻塞写盘，但记录警告
        import logging
        logging.getLogger("mcp.custom_report").warning(
            "report_save_formatted: 占位符强制替换失败（非致命）: %s", e
        )

    # 保存为主报告（覆盖 realtime-report，这样前端能直接看到）
    main_report_path = REPORT_DIR / f"{task_id}-realtime-report.md"
    main_report_path.write_text(content, encoding="utf-8")

    # 同时保存一份带时间戳的快照
    snapshot_path = REPORT_DIR / f"{task_id}-custom-{int(time.time() * 1000)}.md"
    snapshot_path.write_text(content, encoding="utf-8")

    # 获取模版名称
    tpl = _get_active_template()
    tpl_name = tpl["name"] if tpl else "自定义模版"

    return (
        f"✅ 报告已按自定义模版「{tpl_name}」格式保存\n"
        f"- 主报告: {main_report_path}\n"
        f"- 历史快照: {snapshot_path}\n"
        f"- 内容长度: {len(content)} 字符\n\n"
        f"用户可在「报告管理」页面查看。"
    )


def _get_sitemap_summary(task_id: str) -> str:
    """尝试从 sitemap 获取测试覆盖率等结构化摘要。"""
    sitemap_path = Path("data/tasks") / f"{task_id}-sitemap.json"
    if not sitemap_path.exists():
        return ""

    try:
        data = json.loads(sitemap_path.read_text(encoding="utf-8"))
        target = data.get("target", "")
        features = data.get("features", {})
        total_features = len(features) if isinstance(features, dict) else 0

        vuln_count = 0
        tested_count = 0
        vuln_list = []
        if isinstance(features, dict):
            for fp_id, fp in features.items():
                checklist = fp.get("checklist", []) or []
                has_tested = False
                for c in checklist:
                    result = c.get("result", "")
                    if result and result != "pending":
                        has_tested = True
                    if result == "vulnerable":
                        vuln_count += 1
                        vuln_list.append({
                            "feature": fp.get("name", fp_id),
                            "vuln_type": c.get("vuln_type", ""),
                            "severity": c.get("severity", "medium"),
                            "detail": (c.get("detail") or "")[:200],
                        })
                if has_tested:
                    tested_count += 1

        lines = ["### 测试覆盖摘要\n"]
        lines.append(f"- 目标: {target}")
        lines.append(f"- 功能点总数: {total_features}")
        lines.append(f"- 已测试: {tested_count}")
        lines.append(f"- 发现漏洞: {vuln_count} 个")
        lines.append("")

        if vuln_list:
            lines.append("### 漏洞清单\n")
            lines.append("| # | 功能点 | 漏洞类型 | 严重等级 | 描述 |")
            lines.append("|---|--------|---------|---------|------|")
            for i, v in enumerate(vuln_list[:50], 1):
                lines.append(
                    f"| {i} | {v['feature']} | {v['vuln_type']} | "
                    f"{v['severity']} | {v['detail'][:100]} |"
                )
            lines.append("")

        # 危害验证结果
        hv = data.get("harm_validation", {})
        if hv and hv.get("status") == "ok":
            verdicts = hv.get("verdicts", []) or []
            accepted = [v for v in verdicts if v.get("verdict") == "accepted"]
            if accepted:
                lines.append(f"### 已证明漏洞（{len(accepted)} 个）\n")
                for i, v in enumerate(accepted, 1):
                    orig = v.get("_original", {}) or {}
                    lines.append(
                        f"**{i}. [{v.get('platform_level', 'medium')}] "
                        f"{orig.get('title', v.get('vuln_id', ''))}**"
                    )
                    if v.get("harm_story"):
                        lines.append(f"  - 危害: {v['harm_story'][:200]}")
                    lines.append("")

        return "\n".join(lines)
    except Exception:
        return ""


if __name__ == "__main__":
    mcp.run(transport="stdio")
