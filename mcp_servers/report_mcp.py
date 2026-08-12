"""
Report MCP — 报告生成

读取 note 笔记中的 result 条目，结合内置模板生成 SRC / PT 报告。
自定义模版由独立的 custom_report_mcp.py 处理。
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from mcp.server.fastmcp import FastMCP

from core.log import get_logger

log = get_logger("mcp.report")

mcp = FastMCP("report")

NOTE_DIR = Path(os.getenv("NOTE_PATH", "./data/notes"))
REPORT_DIR = Path(os.getenv("REPORT_PATH", "./data/reports"))
TEMPLATE_DIR = Path("templates/reports")

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _latest_path(task_id: str, report_type: str) -> Path:
    """主报告路径：始终覆盖为最新版，供追问后增量更新使用。"""
    return REPORT_DIR / f"{task_id}-{report_type}-latest.md"


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:12]


# ★ 占位符强制替换上下文（用于 _force_replace_placeholders）
import re as _re_module

_PLACEHOLDER_RE = _re_module.compile(r"\{\{[A-Z_]+\}\}")


def _force_replace_placeholders(
    text: str,
    task_id: str = "",
    results: str = "",
    info_content: str = "",
    timestamp: str = "",
) -> str:
    """强制替换所有已知的模板占位符，防止 LLM 手工拼装模板文本时残留占位符。

    此函数幂等，可安全多次调用。任何写 *-latest.md / realtime-report.md 的
    代码路径都应在 write_text 之前调用一次。
    """
    if not timestamp:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # 计算 vuln_counts（失败时用全 0 默认值）
    try:
        vuln_counts = _count_vulns_by_severity(task_id, results)
    except Exception as e:
        log.warning("_force_replace_placeholders: _count_vulns_by_severity 失败: %s", e)
        vuln_counts = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0,
            "suspected_critical": 0, "suspected_high": 0,
            "suspected_medium": 0, "suspected_low": 0, "suspected_total": 0,
            "skipped": 0, "tested": 0, "pending": 0,
            "fallback_notes": [], "skipped_items": [], "source": "text",
        }

    coverage_total = (vuln_counts["tested"]
                      + vuln_counts["skipped"]
                      + vuln_counts["pending"])
    coverage_pct = (
        f"{(vuln_counts['tested'] / coverage_total * 100):.1f}%"
        if coverage_total else "0.0%"
    )

    replacements = {
        "{{TIMESTAMP}}": timestamp,
        "{{TASK_ID}}": task_id,
        "{{ASSET_INFO}}": info_content,
        "{{VULNERABILITIES}}": results,
        "{{CRITICAL_COUNT}}": str(vuln_counts["critical"]),
        "{{HIGH_COUNT}}": str(vuln_counts["high"]),
        "{{MEDIUM_COUNT}}": str(vuln_counts["medium"]),
        "{{LOW_COUNT}}": str(vuln_counts["low"]),
        "{{TOTAL_COUNT}}": str(vuln_counts["total"]),
        # ★ 疑似项（needs_review）统计：避免 22 个待确认项被完全隐藏在摘要里，
        # 用户看"合计 0"误以为无任何发现。现在摘要和评级表都展示疑似数。
        "{{SUSPECTED_CRITICAL}}": str(vuln_counts.get("suspected_critical", 0)),
        "{{SUSPECTED_HIGH}}": str(vuln_counts.get("suspected_high", 0)),
        "{{SUSPECTED_MEDIUM}}": str(vuln_counts.get("suspected_medium", 0)),
        "{{SUSPECTED_LOW}}": str(vuln_counts.get("suspected_low", 0)),
        "{{SUSPECTED_TOTAL}}": str(vuln_counts.get("suspected_total", 0)),
        "{{TESTED_COUNT}}": str(vuln_counts["tested"]),
        "{{SKIPPED_COUNT}}": str(vuln_counts["skipped"]),
        "{{PENDING_COUNT}}": str(vuln_counts["pending"]),
        "{{COVERAGE_PERCENT}}": coverage_pct,
        "{{DATA_SOURCE}}": vuln_counts["source"],
        "{{SKIPPED_SECTION}}": _render_skipped_section(vuln_counts["skipped_items"]),
        "{{FALLBACK_SECTION}}": _render_fallback_section(vuln_counts["fallback_notes"]),
    }
    for ph, val in replacements.items():
        text = text.replace(ph, val)

    # 检查是否还有未知占位符残留
    leftovers = _PLACEHOLDER_RE.findall(text)
    if leftovers:
        unique = sorted(set(leftovers))
        log.warning(
            "_force_replace_placeholders: 仍有 %d 个未知占位符未替换 %s",
            len(leftovers), unique,
        )
        # 把未知占位符替换为空字符串，避免用户看到 {{XXX}} 字面量
        text = _PLACEHOLDER_RE.sub("", text)

    return text


def _compute_real_completion_from_sitemap(task_id: str) -> dict | None:
    """★ OPT2-P0: 从 sitemap JSON 计算真实完成率与空心化检测。

    返回:
        {
            real_done, skipped, pending, total, real_rate, skip_rate,
            hollowing: None | {reasons, real_rate, skip_rate, vuln_count}
        }
        若 sitemap 不存在返回 None。
    """
    try:
        sitemap_path = Path(f"data/tasks/{task_id}-sitemap.json")
        if not sitemap_path.exists():
            return None
        import json as _json
        data = _json.loads(sitemap_path.read_text(encoding="utf-8"))
        features = data.get("features", {})

        real_done = 0
        skipped = 0
        pending = 0
        total = 0
        vuln_count = 0
        for fp in features.values():
            for check in (fp.get("checklist") or []):
                total += 1
                result = check.get("result", "")
                if result == "skipped":
                    skipped += 1
                elif result == "pending":
                    pending += 1
                else:
                    real_done += 1
                    if result == "vulnerable":
                        vuln_count += 1

        real_rate = round(real_done / total * 100, 1) if total > 0 else 0.0
        skip_rate = round(skipped / total * 100, 1) if total > 0 else 0.0

        hollowing = None
        if total > 0 and real_rate < 10.0 and skip_rate > 70.0 and vuln_count == 0:
            reasons = []
            if skip_rate > 80.0:
                reasons.append(f"跳过率极高（{skip_rate}%）— 大量检测项被跳过而非真实执行")
            elif skip_rate > 70.0:
                reasons.append(f"跳过率偏高（{skip_rate}%）— 超过半数检测项被跳过")
            if real_rate < 5.0:
                reasons.append(f"真实完成率极低（{real_rate}%）— 几乎无检测项被真正执行")
            if pending > total * 0.3:
                reasons.append(f"大量检查项仍处于待测状态（{pending}/{total}）")
            hollowing = {
                "real_rate": real_rate,
                "skip_rate": skip_rate,
                "real_done": real_done,
                "total": total,
                "vuln_count": vuln_count,
                "reasons": reasons,
            }

        return {
            "real_done": real_done,
            "skipped": skipped,
            "pending": pending,
            "total": total,
            "real_rate": real_rate,
            "skip_rate": skip_rate,
            "vuln_count": vuln_count,
            "hollowing": hollowing,
        }
    except Exception:
        return None


def _render_hollowing_alert(rc: dict) -> str:
    """★ OPT2-P0: 渲染空心化告警 Markdown 片段。"""
    h = rc.get("hollowing")
    if not h:
        return ""

    lines = [
        "\n---\n",
        "> ## ⚠️ 测试过程疑似空心化告警\n",
        f"> \n> 报告显示的完成率数字 **不能反映真实测试覆盖度**。\n",
        f"> \n> | 指标 | 数值 | 说明 |\n",
        f"> |---|---|---|\n",
        f"> | 报告完成率 | 可能显示 > 70% | 包含大量跳过项，数字虚高 |\n",
        f"> | **真实完成率** | **{h['real_rate']}%** | 仅计真实执行检测（{h['real_done']}/{h['total']} 项）|\n",
        f"> | 跳过率 | {h['skip_rate']}% | 被跳过的检测项占比 |\n",
        f"> | 发现漏洞数 | {h['vuln_count']} | 空心化扫描通常 0 漏洞 |\n",
        f">\n> **根因诊断：**\n",
    ]
    for reason in h["reasons"]:
        lines.append(f"> - {reason}\n")
    lines.append(">\n> **建议：** 请检查目标是否为 SPA 单页应用（路由全前端处理，API 无法被爬虫发现），\n")
    lines.append("> 或检查扫描模式是否过低（如 FAST 模式跳过了 LLM 分析）。建议切换到标准/深度模式重新扫描。\n")
    return "".join(lines)


def _count_vulns_by_severity(task_id: str, results_text: str) -> dict:
    """统计漏洞等级数量。

    优先从 sitemap 的 coverage 获取准确数据，
    如果 sitemap 不可用则从 result 笔记文本中用正则推导。

    ★ #13/#18: 返回字段统一包含：
      - critical/high/medium/low/total: 漏洞计数
      - skipped: 跳过的检查项数（不适用/不在 scope）
      - tested: 已完成的检查项数（不含 skipped）
      - pending: 未完成的检查项数
      - fallback_notes: 使用了降级/兜底逻辑的检查项详情（#19）
      - skipped_items: 跳过的检查项详情（#14）
      - source: 数据来源（sitemap/text），便于报告口径溯源
    """
    counts = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0,
        # ★ 疑似漏洞计数（needs_review）：避免「0 已确认」被误读为「空报告」
        "suspected_critical": 0, "suspected_high": 0,
        "suspected_medium": 0, "suspected_low": 0,
        "suspected_total": 0,
        "skipped": 0, "tested": 0, "pending": 0,
        "fallback_notes": [], "skipped_items": [],
        "source": "text",
    }

    # 方案 1: 从 sitemap 获取准确数据
    try:
        sitemap_path = Path(f"data/tasks/{task_id}-sitemap.json")
        if sitemap_path.exists():
            import json as _json
            data = _json.loads(sitemap_path.read_text(encoding="utf-8"))
            features = data.get("features", {})
            for fp in features.values():
                fp_name = fp.get("name", fp.get("id", ""))
                fp_url = fp.get("page_url", "")
                for check in (fp.get("checklist") or []):
                    result = check.get("result", "")
                    if result == "vulnerable":
                        sev = (check.get("severity") or "").lower()
                        if sev in ("critical", "high", "medium", "low"):
                            counts[sev] += 1
                        elif sev == "info":
                            counts["low"] += 1
                        else:
                            # 无 severity 的默认按功能点优先级
                            prio = (fp.get("priority") or "").lower()
                            if prio == "critical":
                                counts["critical"] += 1
                            elif prio == "high":
                                counts["high"] += 1
                            elif prio == "medium":
                                counts["medium"] += 1
                            else:
                                counts["low"] += 1
                        counts["tested"] += 1
                    elif result == "not_vuln":
                        counts["tested"] += 1
                    elif result == "needs_review":
                        counts["tested"] += 1
                        # ★ #19: 标记降级项（needs_review 通常是降级兜底产生）
                        detail = check.get("detail", "")
                        counts["fallback_notes"].append({
                            "feature": fp_name,
                            "vuln_type": check.get("vuln_type", ""),
                            "url": fp_url,
                            "reason": detail or "needs_review（降级为待人工确认）",
                        })
                        # ★ 报告空问题修复：同时计入疑似漏洞统计
                        sev = (check.get("severity") or "").lower()
                        if sev not in ("critical", "high", "medium", "low"):
                            prio = (fp.get("priority") or "").lower()
                            sev = prio if prio in ("critical", "high", "medium", "low") else "low"
                        counts[f"suspected_{sev}"] += 1
                        counts["suspected_total"] += 1
                    elif result == "skipped":
                        counts["skipped"] += 1
                        # ★ #14: 收集跳过项详情
                        counts["skipped_items"].append({
                            "feature": fp_name,
                            "vuln_type": check.get("vuln_type", ""),
                            "url": fp_url,
                            "reason": check.get("detail", "未提供原因"),
                        })
                    elif result == "pending":
                        counts["pending"] += 1
            counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low"))
            counts["source"] = "sitemap"
            return counts
    except Exception:
        pass

    # 方案 2: 从 result 文本中用结构化标记推导
    # ★ 修复：之前对每行检查"严重/高危"关键词，但 result.md 里这些词常出现在
    # 描述性文本中（如"未发现严重漏洞"），导致误计数。现在改为：
    # 1. 优先匹配 LLM 可能写入的结构化计数标记（如"严重: 3 个"）
    # 2. 没有结构化标记时保持 0，标注 source="text_fallback" 让报告明确显示数据不可靠
    import re
    # 匹配形如 "严重: 3" / "Critical: 3" / "严重漏洞：3个" 的计数行
    sev_patterns = {
        "critical": r"(?:严重|critical)[^\d]*?(\d+)\s*个?",
        "high": r"(?:高危|high)[^\d]*?(\d+)\s*个?",
        "medium": r"(?:中危|medium)[^\d]*?(\d+)\s*个?",
        "low": r"(?:低危|low)[^\d]*?(\d+)\s*个?",
    }
    found_any = False
    for sev, pat in sev_patterns.items():
        m = re.search(pat, results_text, re.IGNORECASE)
        if m:
            try:
                counts[sev] = int(m.group(1))
                found_any = True
            except ValueError:
                pass
    if found_any:
        counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low"))
        counts["source"] = "text"
    else:
        # 无结构化标记，明确标注数据不可靠
        counts["source"] = "text_fallback"
    return counts


def _render_skipped_section(skipped_items: list) -> str:
    """★ #14/#18: 渲染跳过测试项的独立章节。

    skipped_items: [{"feature", "vuln_type", "url", "reason"}, ...]
    """
    if not skipped_items:
        return ""
    lines = [
        "",
        "---",
        "",
        "## 附录 A：跳过的测试项（共 {} 项）".format(len(skipped_items)),
        "",
        "> 以下检查项在测试过程中被标记为「跳过」，不计入漏洞统计，",
        "> 也不计入「已测试」基数。跳过原因通常是：不适用 / 不在 scope / 预算耗尽。",
        "",
        "| # | 功能点 | 漏洞类型 | URL | 跳过原因 |",
        "|---|--------|----------|-----|----------|",
    ]
    for i, item in enumerate(skipped_items, 1):
        feat = (item.get("feature") or "-").replace("|", "\\|")
        vt = (item.get("vuln_type") or "-").replace("|", "\\|")
        url = (item.get("url") or "-").replace("|", "\\|")
        reason = (item.get("reason") or "未提供原因").replace("|", "\\|")
        # 限制单格长度，避免表格被撑爆
        if len(reason) > 80:
            reason = reason[:77] + "..."
        lines.append(f"| {i} | {feat} | {vt} | `{url}` | {reason} |")
    lines.append("")
    return "\n".join(lines)


def _render_fallback_section(fallback_notes: list) -> str:
    """★ #19: 渲染降级/兜底标注章节。

    fallback_notes: [{"feature", "vuln_type", "url", "reason"}, ...]
    """
    if not fallback_notes:
        return ""
    lines = [
        "",
        "---",
        "",
        "## 附录 B：降级处理的检查项（共 {} 项）".format(len(fallback_notes)),
        "",
        "> 以下检查项在自动化判定中触发了降级逻辑（如未实测就被判 accepted → 自动降级为 borderline），",
        "> 需要安全人员人工复核。降级原因已在「说明」列标注。",
        "",
        "| # | 功能点 | 漏洞类型 | URL | 说明 |",
        "|---|--------|----------|-----|------|",
    ]
    for i, item in enumerate(fallback_notes, 1):
        feat = (item.get("feature") or "-").replace("|", "\\|")
        vt = (item.get("vuln_type") or "-").replace("|", "\\|")
        url = (item.get("url") or "-").replace("|", "\\|")
        reason = (item.get("reason") or "").replace("|", "\\|")
        if len(reason) > 80:
            reason = reason[:77] + "..."
        lines.append(f"| {i} | {feat} | {vt} | `{url}` | {reason} |")
    lines.append("")
    return "\n".join(lines)


def _auto_generate_results_from_sitemap(task_id: str) -> str:
    """★ 当 result.md 缺失/为空时，自动从 sitemap 生成漏洞摘要。

    复用 _render_vuln_details_from_sitemap 的提取逻辑，并补充 FastScanner 孤儿发现，
    生成一份可读的 result 内容，让 report_generate 流程能继续，而非直接拒绝。
    明确标注"系统自动生成"，便于用户区分 LLM 手写 vs 系统兜底。
    """
    # 1. 从 checklist 提取已确认漏洞
    vuln_details = _render_vuln_details_from_sitemap(task_id)

    # 2. 从 sitemap 提取 FastScanner 孤儿发现
    orphan_section = ""
    try:
        sitemap_path = Path(f"data/tasks/{task_id}-sitemap.json")
        if sitemap_path.exists():
            import json as _json
            data = _json.loads(sitemap_path.read_text(encoding="utf-8"))
            orphans = data.get("_fast_scanner_orphan_findings", []) or []
            if orphans:
                sev_emoji = {
                    "critical": "🔴 严重", "high": "🟠 高危",
                    "medium": "🟡 中危", "low": "🟢 低危", "info": "ℹ️ 信息",
                }
                lines = [
                    "",
                    "## FastScanner 发现（待人工确认）",
                    "",
                    f"共 {len(orphans)} 条，未经危害验证裁决：",
                    "",
                ]
                for i, f in enumerate(orphans, 1):
                    if not isinstance(f, dict):
                        continue
                    sev = (f.get("severity") or "medium").lower()
                    sev_label = sev_emoji.get(sev, sev)
                    vt = f.get("vuln_type", "未知")
                    url = f.get("url", "")
                    method = f.get("method", "")
                    detail = (f.get("detail", "") or "")[:200]
                    payload = (f.get("payload", "") or "")[:150]
                    lines.append(f"{i}. [{sev_label}] {vt} - `{url}` ({method})")
                    if detail:
                        lines.append(f"   - 详情: {detail}")
                    if payload:
                        lines.append(f"   - Payload: `{payload}`")
                    lines.append("")
                orphan_section = "\n".join(lines)
    except Exception:
        pass

    if not vuln_details and not orphan_section:
        return ""

    parts = [
        "> ⚠️ 本节由系统自动从 sitemap.checklist + FastScanner 孤儿发现提取生成",
        "> （LLM 未手写 result.md，系统兜底生成以保证报告可产出）",
        "",
    ]
    if vuln_details:
        parts.append("## 已确认漏洞")
        parts.append("")
        parts.append(vuln_details)
    if orphan_section:
        parts.append(orphan_section)
    return "\n".join(parts)


def _render_vuln_details_from_sitemap(task_id: str) -> str:
    """★ #12: 从 sitemap 自动填充 PT 报告漏洞详情。

    当 LLM 没有手工填充详细漏洞记录时，从 sitemap.checklist 提取
    所有 result=vulnerable 的检查项，按等级分组渲染为标准 PT 报告格式，
    包含完整的请求/响应包、复现步骤、修复建议。

    返回空字符串表示无可用数据（调用方应保留 LLM 原文）。
    """
    try:
        sitemap_path = Path(f"data/tasks/{task_id}-sitemap.json")
        if not sitemap_path.exists():
            return ""
        import json as _json
        data = _json.loads(sitemap_path.read_text(encoding="utf-8"))
        features = data.get("features", {})
    except Exception:
        return ""

    # 收集所有 vulnerable 检查项 + needs_review 疑似项
    # ★ #报告空问题修复：之前只提取 result=vulnerable，当 LLM 把可疑项标 needs_review
    # 而非 vulnerable 时，报告就空了。现在同时纳入 needs_review，标注「疑似/待人工确认」。
    vulns_by_severity: dict[str, list[dict]] = {
        "critical": [], "high": [], "medium": [], "low": [],
    }
    suspected_by_severity: dict[str, list[dict]] = {
        "critical": [], "high": [], "medium": [], "low": [],
    }
    for fp in features.values():
        fp_name = fp.get("name", fp.get("id", ""))
        fp_url = fp.get("page_url", "")
        related_apis = fp.get("related_apis", []) or []
        for check in (fp.get("checklist") or []):
            result = check.get("result", "")
            if result not in ("vulnerable", "needs_review"):
                continue
            sev = (check.get("severity") or "").lower()
            if sev not in vulns_by_severity:
                # 按 feature 优先级兜底
                prio = (fp.get("priority") or "").lower()
                sev = prio if prio in vulns_by_severity else "low"
            item = {
                "feature": fp_name,
                "vuln_type": check.get("vuln_type", ""),
                "url": fp_url,
                "related_apis": related_apis,
                "severity": sev,
                "detail": check.get("detail", ""),
                "reproduce_steps": check.get("reproduce_steps", ""),
                "fix_suggestion": check.get("fix_suggestion", ""),
                "evidence_request": check.get("evidence_request", ""),
                "evidence_response": check.get("evidence_response", ""),
                "evidence_flow_id": check.get("evidence_flow_id", ""),
                "skill_used": check.get("skill_used", ""),
            }
            if result == "vulnerable":
                vulns_by_severity[sev].append(item)
            else:
                # needs_review：疑似漏洞，单独分组
                suspected_by_severity[sev].append(item)

    total_vulns = sum(len(v) for v in vulns_by_severity.values())
    total_suspected = sum(len(v) for v in suspected_by_severity.values())
    if total_vulns == 0 and total_suspected == 0:
        return ""

    sev_labels = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
    }
    sev_order = ["critical", "high", "medium", "low"]

    parts: list[str] = [
        "",
        "> 以下漏洞详情由系统从测试 checklist 自动提取生成（含完整证据包），",
        "> 如 LLM 已在上文手工描述，请以本节为准（数据源自 sitemap.checklist）。",
        "",
    ]
    vuln_idx = 0
    for sev in sev_order:
        vulns = vulns_by_severity[sev]
        if not vulns:
            continue
        parts.append(f"\n### {sev_labels[sev]}漏洞（{len(vulns)} 个）\n")
        for v in vulns:
            vuln_idx += 1
            parts.append(f"#### 5.{vuln_idx} [{v['vuln_type']}] {v['feature']}\n")
            parts.append("| 项目 | 内容 |")
            parts.append("|------|------|")
            parts.append(f"| **等级** | {sev_labels[sev]} |")
            parts.append(f"| **类型** | {v['vuln_type']} |")
            parts.append(f"| **URL** | `{v['url']}` |")
            if v.get("related_apis"):
                apis_str = ", ".join(f"`{a}`" for a in v["related_apis"][:3])
                parts.append(f"| **关联 API** | {apis_str} |")
            if v.get("skill_used"):
                parts.append(f"| **测试方法** | {v['skill_used']} |")
            parts.append("")

            # 影响说明
            if v.get("detail"):
                parts.append(f"**影响说明**: {v['detail']}\n")

            # 复现步骤
            if v.get("reproduce_steps"):
                parts.append("**复现步骤**:\n")
                parts.append(v["reproduce_steps"].strip() + "\n")

            # 请求包
            if v.get("evidence_request"):
                parts.append("**请求**:\n")
                parts.append("```http")
                parts.append(v["evidence_request"].strip())
                parts.append("```\n")

            # 响应包
            if v.get("evidence_response"):
                parts.append("**响应**:\n")
                parts.append("```http")
                parts.append(v["evidence_response"].strip())
                parts.append("```\n")

            # 修复建议
            if v.get("fix_suggestion"):
                parts.append("**修复建议**:\n")
                parts.append(v["fix_suggestion"].strip() + "\n")

            if v.get("evidence_flow_id"):
                parts.append(f"> 证据 flow_id: `{v['evidence_flow_id']}`\n")

            parts.append("---\n")

    # ★ 疑似漏洞分组（needs_review）：单独成节，标注待人工确认
    if total_suspected > 0:
        parts.append("\n### 🟡 疑似漏洞（待人工确认）\n")
        parts.append(
            f"> 共 {total_suspected} 项被标记为 needs_review（多为自动检测命中但未完成危害验证），"
            "建议人工复核以下条目，确认后可升级为已确认漏洞。\n"
        )
        for sev in sev_order:
            suspects = suspected_by_severity[sev]
            if not suspects:
                continue
            parts.append(f"\n**{sev_labels[sev]}（{len(suspects)} 个）**\n")
            for i, s in enumerate(suspects, 1):
                parts.append(f"{i}. [{sev_labels[sev]}] {s['vuln_type']} - {s['feature']}")
                parts.append(f"   - URL: `{s['url']}`")
                if s.get("detail"):
                    detail = s["detail"][:200]
                    parts.append(f"   - 详情: {detail}")
                if s.get("evidence_request"):
                    parts.append(f"   - 请求: `{s['evidence_request'][:150]}`")
                if s.get("evidence_response"):
                    parts.append(f"   - 响应: `{s['evidence_response'][:150]}`")
                parts.append("")

    return "\n".join(parts)


@mcp.tool()
async def report_generate(task_id: str = "default", report_type: str = "src", **kwargs) -> str:
    """生成渗透测试报告（支持追问后增量更新）。

    - task_id: 任务 ID
    - report_type: src（SRC 漏洞报告）/ pt（渗透测试报告）

    行为：
    - 每次调用都会写一份带时间戳的历史快照（审计留痕）
    - 同时覆盖 `{task_id}-{report_type}-latest.md`（最新版，给前端/用户读取）
    - 用内容指纹判断本次是否真的有变化，无变化时仅刷新时间戳
    """
    # 读取 result 笔记
    result_file = NOTE_DIR / f"{task_id}-result.md"
    if not result_file.exists():
        # ★ result.md 缺失时不再拒绝生成报告，而是自动从 sitemap 提取漏洞
        # 之前 LLM 没写 result.md 就直接返回"无法生成报告"，导致用户拿不到任何报告，
        # 即使 sitemap 里已有完整的 vulnerable checklist + FastScanner 孤儿发现。
        # 现在自动生成一份 result 内容，让报告流程继续。
        auto_results = _auto_generate_results_from_sitemap(task_id)
        if not auto_results:
            # ★ 报告空问题修复：最后兜底——尝试读取 default-result.md
            # §12 修复前 worker_agent 没传 task_id，导致子 Agent 笔记写到 default-*.md。
            # 这里读取 default-result.md 挽回历史孤儿漏洞数据，避免报告完全空白。
            default_result = NOTE_DIR / "default-result.md"
            if default_result.exists():
                default_content = default_result.read_text(encoding="utf-8").strip()
                if default_content:
                    auto_results = (
                        "> ⚠️ 本节数据源自历史 default-result.md（task_id 未匹配），\n"
                        "> 可能混入多个任务的记录，请核验归属后人工整理。\n\n"
                        + default_content
                    )
                    log.warning(
                        "report_generate[%s]: result.md 缺失且 sitemap 无漏洞，"
                        "已兜底读取 default-result.md（含历史孤儿数据）", task_id)
        if not auto_results:
            return ("暂无漏洞记录（result 笔记为空，且 sitemap 无已确认漏洞），无法生成报告。"
                    "请确认测试已完成，或手动调用 sitemap_get_coverage 检查测试状态。")
        results = auto_results
        # 同步落盘，让后续增量判断能命中
        try:
            result_file.parent.mkdir(parents=True, exist_ok=True)
            result_file.write_text(results, encoding="utf-8")
        except Exception:
            pass
    else:
        results = result_file.read_text(encoding="utf-8")
        # ★ result.md 存在但为空 → 同样自动补全
        if not results.strip():
            auto_results = _auto_generate_results_from_sitemap(task_id)
            if auto_results:
                results = auto_results
                try:
                    result_file.write_text(results, encoding="utf-8")
                except Exception:
                    pass

    # 读取 info 笔记
    info_file = NOTE_DIR / f"{task_id}-info.md"
    info_content = info_file.read_text(encoding="utf-8") if info_file.exists() else "无"

    # 加载模板（内置模版）
    template_file = TEMPLATE_DIR / f"report-{report_type}.md"
    if template_file.exists():
        template = template_file.read_text(encoding="utf-8")
    else:
        template = _default_template(report_type)

    # 计算内容指纹（不含时间戳，用于"是否真的有变化"判断）
    body_fp = _fingerprint(results + "||" + info_content + "||" + report_type)

    latest_file = _latest_path(task_id, report_type)
    prev_fp = None
    if latest_file.exists():
        for line in latest_file.read_text(encoding="utf-8", errors="ignore").splitlines()[:5]:
            if line.startswith("<!-- fingerprint:"):
                # 形如 "<!-- fingerprint: abc123 -->"
                try:
                    prev_fp = line.split("fingerprint:", 1)[1].split("-->")[0].strip()
                except Exception:
                    prev_fp = None
                break

    # 填充模板
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    report = template.replace("{{TIMESTAMP}}", timestamp)
    report = report.replace("{{TASK_ID}}", task_id)
    report = report.replace("{{ASSET_INFO}}", info_content)
    report = report.replace("{{VULNERABILITIES}}", results)

    # ★ #13: 漏洞等级计数 — 全报告统一数据源，避免摘要表和详情区口径不一致
    vuln_counts = _count_vulns_by_severity(task_id, results)
    report = report.replace("{{CRITICAL_COUNT}}", str(vuln_counts["critical"]))
    report = report.replace("{{HIGH_COUNT}}", str(vuln_counts["high"]))
    report = report.replace("{{MEDIUM_COUNT}}", str(vuln_counts["medium"]))
    report = report.replace("{{LOW_COUNT}}", str(vuln_counts["low"]))
    report = report.replace("{{TOTAL_COUNT}}", str(vuln_counts["total"]))
    # ★ #18: 新增测试覆盖率统计占位符（已测/跳过/待测），区分 skipped 与 completed
    report = report.replace("{{TESTED_COUNT}}", str(vuln_counts["tested"]))
    report = report.replace("{{SKIPPED_COUNT}}", str(vuln_counts["skipped"]))
    report = report.replace("{{PENDING_COUNT}}", str(vuln_counts["pending"]))
    coverage_total = (vuln_counts["tested"]
                      + vuln_counts["skipped"]
                      + vuln_counts["pending"])
    coverage_pct = f"{(vuln_counts['tested'] / coverage_total * 100):.1f}%" if coverage_total else "0.0%"
    report = report.replace("{{COVERAGE_PERCENT}}", coverage_pct)
    report = report.replace("{{DATA_SOURCE}}", vuln_counts["source"])
    # ★ 报告空问题修复：疑似漏洞占位符（避免 needs_review 项被完全忽略）
    # 兼容两种命名：{{SUSPECTED_*_COUNT}}（旧）和 {{SUSPECTED_*}}（新，PT 模板用）
    for _ph_suffix in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL"):
        _val = str(vuln_counts.get(f"suspected_{_ph_suffix.lower()}", 0))
        report = report.replace("{{SUSPECTED_" + _ph_suffix + "_COUNT}}", _val)
        report = report.replace("{{SUSPECTED_" + _ph_suffix + "}}", _val)

    # ★ #12: PT 报告漏洞详情自动填充
    # 当 LLM 仅写了概要、没有按 PT 模板逐条填充漏洞详情时，
    # 从 sitemap.checklist 提取 vulnerable 项，自动生成标准 PT 详情章节。
    # 仅 PT 报告需要（SRC 报告 {{VULNERABILITIES}} 即详情）。
    if report_type == "pt":
        sitemap_vuln_details = _render_vuln_details_from_sitemap(task_id)
        if sitemap_vuln_details:
            # 检查 LLM 是否已手工填充了「5.X」详情章节；若已存在则追加 sitemap 版本作为附录 C
            import re as _re_detail
            has_manual_details = bool(_re_detail.search(r"####?\s*5\.\d+", report))
            if has_manual_details:
                # LLM 已填充 → 在末尾追加 sitemap 提取版作为「附录 C：完整漏洞清单」
                appendix_c = (
                    "\n---\n\n"
                    "## 附录 C：完整漏洞清单（系统自动提取自 sitemap.checklist）\n\n"
                    "> 以下清单为系统从测试 checklist 中自动提取的所有确认漏洞，\n"
                    "> 含完整请求/响应证据包，可作为漏洞总数与详情的权威依据。\n"
                    + sitemap_vuln_details
                )
                # 在报告末尾（修复建议之前）插入
                if "## 6. 安全建议总结" in report:
                    report = report.replace("## 6. 安全建议总结", appendix_c + "\n---\n\n## 6. 安全建议总结")
                else:
                    report = report.rstrip() + appendix_c
            else:
                # LLM 未填充详情 → 直接把 sitemap 提取的详情插入到「## 3. 发现的安全问题」之后
                if "## 3. 发现的安全问题" in report:
                    # 在第 3 节后插入（保留 LLM 的概要 + 追加结构化详情）
                    marker = "## 3. 发现的安全问题"
                    idx = report.find(marker)
                    next_section_idx = report.find("\n## ", idx + len(marker))
                    if next_section_idx > 0:
                        report = (report[:next_section_idx]
                                  + "\n" + sitemap_vuln_details + "\n"
                                  + report[next_section_idx:])
                    else:
                        report = report.rstrip() + "\n" + sitemap_vuln_details
                else:
                    report = report.rstrip() + "\n" + sitemap_vuln_details

    # ★ #14/#19: 在报告末尾追加「跳过项」和「降级项」附录
    skipped_section = _render_skipped_section(vuln_counts["skipped_items"])
    fallback_section = _render_fallback_section(vuln_counts["fallback_notes"])
    # 仅当模板未显式包含这两个占位符时才追加到末尾（保持向后兼容）
    if "{{SKIPPED_SECTION}}" not in template and skipped_section:
        report = report.rstrip() + skipped_section
    else:
        report = report.replace("{{SKIPPED_SECTION}}", skipped_section)
    if "{{FALLBACK_SECTION}}" not in template and fallback_section:
        report = report.rstrip() + fallback_section
    else:
        report = report.replace("{{FALLBACK_SECTION}}", fallback_section)

    # ★ OPT2-P0: 空心化告警 + 真实完成率注入
    # 从 sitemap JSON 计算真实完成率，若检测到空心化则在报告头部插入红色告警
    _rc = _compute_real_completion_from_sitemap(task_id)
    if _rc and _rc["total"] > 0:
        _hollowing_md = _render_hollowing_alert(_rc)
        if _hollowing_md:
            # 空心化告警插入到报告最前面（标题之后）
            _title_end = report.find("\n", report.find("#"))
            if _title_end > 0:
                report = report[:_title_end + 1] + _hollowing_md + report[_title_end + 1:]
            else:
                report = _hollowing_md + report
            log.warning("report_generate[%s]: 检测到空心化 — 真实完成率 %.1f%%, 跳过率 %.1f%%",
                        task_id, _rc["real_rate"], _rc["skip_rate"])

    # ★ 写盘前做一次强制占位符替换（幂等），确保任何路径生成的报告都不会
    # 残留 {{CRITICAL_COUNT}} 等字面占位符。即使上方主替换逻辑因异常跳过
    # 或 LLM 手工拼装了模板文本，这里也能兜底。
    try:
        report = _force_replace_placeholders(
            report, task_id=task_id, results=results,
            info_content=info_content, timestamp=timestamp,
        )
    except Exception as e_ph:
        log.error("report_generate: _force_replace_placeholders 异常: %s", e_ph)
        # 兜底中的兜底：手动替换关键占位符，绝不把 {{XXX}} 写入文件
        for _ph, _val in [
            ("{{TIMESTAMP}}", timestamp), ("{{TASK_ID}}", task_id),
            ("{{ASSET_INFO}}", info_content), ("{{VULNERABILITIES}}", results),
            ("{{DATA_SOURCE}}", "fallback"), ("{{COVERAGE_PERCENT}}", "0.0%"),
        ]:
            report = report.replace(_ph, _val)
        # 用正则清除剩余的所有 {{XXX}} 占位符
        report = _PLACEHOLDER_RE.sub("", report)

    latest_content = f"<!-- fingerprint: {body_fp} -->\n{report}"

    # 保存历史快照（始终新文件，留审计痕迹；用毫秒精度避免同秒覆盖）
    snapshot_path = REPORT_DIR / f"{task_id}-{report_type}-{int(time.time() * 1000)}.md"
    snapshot_path.write_text(report, encoding="utf-8")

    # 覆盖最新版（主报告文件）
    latest_file.write_text(latest_content, encoding="utf-8")

    if prev_fp == body_fp:
        hint = "（内容指纹与上次一致，仅刷新时间戳）"
    elif prev_fp is None:
        hint = "（首次生成）"
    else:
        hint = f"（增量更新：指纹 {prev_fp} → {body_fp}）"

    # ★ 检测返回值中是否还有未替换的占位符，如有则警告 LLM
    leftover_ph = _PLACEHOLDER_RE.findall(report)
    warn_msg = ""
    if leftover_ph:
        unique_leftovers = sorted(set(leftover_ph))
        warn_msg = (
            f"\n\n⚠️ **警告：报告中仍有 {len(leftover_ph)} 个占位符未替换** "
            f"({', '.join(unique_leftovers[:5])})。"
            f" 这通常是 MCP 服务缓存旧代码导致，请重启 MCP 服务后重新调用 "
            f"report_generate，或手动用 note_add 补充内容后重新生成。"
        )
        log.error(
            "report_generate[%s]: 返回值仍有 %d 个未替换占位符 %s",
            task_id, len(leftover_ph), unique_leftovers,
        )

    return (
        f"报告已生成 {hint}\n"
        f"- 最新版（主报告）: {latest_file}\n"
        f"- 历史快照: {snapshot_path}\n\n"
        f"{report[:1000]}..."
        f"{warn_msg}"
    )


def _default_template(report_type: str) -> str:
    if report_type == "src":
        return """# SRC 漏洞报告

- 生成时间: {{TIMESTAMP}}
- 任务 ID: {{TASK_ID}}
- 数据来源: {{DATA_SOURCE}}

## 资产信息

{{ASSET_INFO}}

## 漏洞详情

{{VULNERABILITIES}}

## 漏洞统计

- 严重: {{CRITICAL_COUNT}} 个
- 高危: {{HIGH_COUNT}} 个
- 中危: {{MEDIUM_COUNT}} 个
- 低危: {{LOW_COUNT}} 个
- **合计**: {{TOTAL_COUNT}} 个

测试覆盖率: {{COVERAGE_PERCENT}}（已测 {{TESTED_COUNT}} / 跳过 {{SKIPPED_COUNT}} / 待测 {{PENDING_COUNT}}）

{{SKIPPED_SECTION}}

{{FALLBACK_SECTION}}
"""
    else:
        return """# 渗透测试报告

- 生成时间: {{TIMESTAMP}}
- 任务 ID: {{TASK_ID}}
- 数据来源: {{DATA_SOURCE}}

## 1. 测试范围

{{ASSET_INFO}}

## 2. 发现的安全问题

{{VULNERABILITIES}}

## 3. 风险评级汇总

| 等级 | 数量 |
|------|------|
| 严重 | {{CRITICAL_COUNT}} |
| 高危 | {{HIGH_COUNT}} |
| 中危 | {{MEDIUM_COUNT}} |
| 低危 | {{LOW_COUNT}} |
| **合计** | **{{TOTAL_COUNT}}** |

测试覆盖率: {{COVERAGE_PERCENT}}（已测 {{TESTED_COUNT}} / 跳过 {{SKIPPED_COUNT}} / 待测 {{PENDING_COUNT}}）

## 4. 修复建议

（请根据漏洞详情补充修复建议）

## 5. 结论

（请根据测试结果补充总结）

{{SKIPPED_SECTION}}

{{FALLBACK_SECTION}}
"""


if __name__ == "__main__":
    mcp.run(transport="stdio")
