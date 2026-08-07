"""
报告渲染模块 — Markdown 输出。

职责：
- render_to_markdown: 渲染危害验证结果为报告章节 5
- render_proven_only: 渲染已证明漏洞独立报告（报告 B）
"""

from __future__ import annotations

import json
import re


def _extract_params_from_evidence(evidence: str) -> str:
    """从证据请求包中提取参数名列表，用于漏洞报告「参数」字段。"""
    if not evidence:
        return "-"
    params: list[str] = []
    text = str(evidence)
    # URL query params
    for m in re.finditer(r'[?&](\w+)=', text):
        p = m.group(1)
        if p and p not in params:
            params.append(p)
    # POST body params (non-JSON): key=value
    for m in re.finditer(r'(?:^|\n)(\w+)=', text):
        p = m.group(1)
        if p and p not in params and p not in ("HTTP", "GET", "POST", "PUT", "DELETE"):
            params.append(p)
    # JSON body params
    for m in re.finditer(r'"(\w+)"\s*:', text):
        p = m.group(1)
        if p and p not in params and p not in (
            "Content-Type", "Content-Length", "Host", "User-Agent",
            "Accept", "Cookie", "Authorization", "Connection",
        ):
            params.append(p)
    return " / ".join(params) if params else "-"


def render_to_markdown(hv_result: dict) -> str:
    """渲染危害验证结果为报告章节 5 的 Markdown。"""
    if not hv_result:
        return ""
    status = hv_result.get("status", "")
    if status == "no_vulns":
        return ""  # 没漏洞就不渲染章节
    if status != "ok":
        err = hv_result.get("error", "未知错误")
        return (f"## 5. 漏洞危害验证（SRC/赏金平台标准）\n\n"
                f"> ⚠️ 危害验证未完成 ({status}): {err[:300]}\n\n"
                f"> 主报告漏洞详情仍请以第 3 章为准。\n")

    verdicts = hv_result.get("verdicts", []) or []
    stats = hv_result.get("stats", {}) or {"accepted": 0, "borderline": 0, "rejected": 0}
    summary = hv_result.get("summary", "")

    accepted = [v for v in verdicts if v.get("verdict") == "accepted"]
    borderline = [v for v in verdicts if v.get("verdict") == "borderline"]
    rejected = [v for v in verdicts if v.get("verdict") == "rejected"]

    # 修复优先级分布
    prio_count = {"立即": 0, "上线前": 0, "加固建议": 0, "不必修": 0}
    for vd in verdicts:
        p = vd.get("fix_priority", "加固建议")
        if p in prio_count:
            prio_count[p] += 1

    lines: list[str] = []
    lines.append("## 5. 漏洞危害验证（SRC/赏金平台标准）")
    lines.append("")
    lines.append("> 由专业安全人员视角对前述漏洞做二次研判，按 SRC/赏金平台真实收录")
    lines.append("> 标准过滤【形式漏洞】，只保留有实际危害的漏洞。")
    lines.append("")

    # 5.1 总览
    lines.append("### 5.1 裁决总览")
    lines.append("")
    lines.append("| 状态 | 数量 |")
    lines.append("|------|------|")
    lines.append(f"| ✅ 接受 (达到收录标准) | {stats.get('accepted', 0)} |")
    lines.append(f"| ⚠️ 边缘 (需人工复核) | {stats.get('borderline', 0)} |")
    lines.append(f"| ❌ 拒收 (形式漏洞,无实际危害) | {stats.get('rejected', 0)} |")
    lines.append("")
    lines.append(f"**预估能在赏金平台收录的漏洞: {stats.get('accepted', 0)} 个**")
    lines.append("")
    lines.append("**修复优先级分布**：")
    lines.append("")
    lines.append(f"- 🔴 立即修复: {prio_count['立即']} 个")
    lines.append(f"- 🟠 上线前修复: {prio_count['上线前']} 个")
    lines.append(f"- 🟡 加固建议: {prio_count['加固建议']} 个")
    lines.append(f"- ⚪ 不必修: {prio_count['不必修']} 个")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 5.2 接受的漏洞
    if accepted:
        lines.append("### 5.2 ✅ 接受的漏洞 (达到收录标准)")
        lines.append("")
        for i, vd in enumerate(accepted, 1):
            orig = vd.get("_original", {}) or {}
            level = vd.get("platform_level", "medium").lower()
            level_emoji = {
                "critical": "🔴 严重",
                "high": "🟠 高危",
                "medium": "🟡 中危",
                "low": "🔵 低危",
                "no_value": "⚪",
            }.get(level, "🟡 中危")
            title = orig.get("title", "") or vd.get("vuln_id", "")
            harm_story = vd.get("harm_story", "")
            vtype = orig.get("vuln_type", "") or "未知"
            url = orig.get("url", "") or ""
            detail = (orig.get("detail", "") or "")[:500]
            impact_text = harm_story or detail or "（详见描述）"
            params_str = _extract_params_from_evidence(
                orig.get("evidence_request") or orig.get("payload") or ""
            )
            broken = vd.get("broken_promises", []) or []
            platforms = vd.get("would_be_accepted_by", []) or []

            lines.append(f"#### 5.2.{i} [{vtype}] {title}")
            lines.append("")
            lines.append("| 项目 | 内容 |")
            lines.append("|------|------|")
            lines.append(f"| 等级 | {level_emoji} |")
            lines.append(f"| 类型 | {vtype} |")
            lines.append(f"| URL | `{url}` |")
            lines.append(f"| 参数 | {params_str} |")
            lines.append(f"| 影响 | {impact_text} |")
            lines.append("")

            # 复现步骤
            lines.append("复现步骤:")
            lines.append("")
            repro = orig.get("reproduce_steps") or ""
            poc_note = vd.get("poc_note", "")
            if repro:
                lines.append(str(repro)[:800])
                lines.append("")
            elif poc_note:
                lines.append(str(poc_note)[:800])
                lines.append("")
            else:
                lines.append("（无复现步骤记录）")
                lines.append("")

            # 请求
            lines.append("请求:")
            lines.append("")
            req = orig.get("evidence_request") or orig.get("payload") or ""
            if req:
                lines.append("```http")
                lines.append(str(req)[:1500])
                lines.append("```")
                lines.append("")
            else:
                lines.append("（无请求包）")
                lines.append("")

            # 响应
            lines.append("响应:")
            lines.append("")
            resp = orig.get("evidence_response") or ""
            if resp:
                lines.append("```http")
                lines.append(str(resp)[:1500])
                lines.append("```")
                lines.append("")
            else:
                lines.append("（无响应包）")
                lines.append("")

            # 截图
            lines.append("截图: （如有）")
            lines.append("")

            # 修复建议
            lines.append("修复建议:")
            lines.append("")
            fix_suggestion = orig.get("fix_suggestion", "") or ""
            if fix_suggestion:
                lines.append(str(fix_suggestion)[:1500])
                lines.append("")
            else:
                lines.append("（未提供修复建议）")
                lines.append("")

            # 附加信息（折叠）
            extra_parts = []
            if broken:
                extra_parts.append(f"打破的业务承诺: {', '.join(str(p) for p in broken)}")
            if platforms:
                extra_parts.append(f"估计收录平台: {', '.join(str(p) for p in platforms)}")
            extra_parts.append(f"证据强度: {vd.get('evidence_strength', '')}")
            extra_parts.append(f"修复优先级: {vd.get('fix_priority', '')}")
            extra_parts.append(f"原漏洞 ID: `{vd.get('vuln_id', '')}`")
            # ★ 优化.md 建议6：溯源 ID
            _trace = orig.get("trace_id", "") or vd.get("trace_id", "")
            if _trace:
                extra_parts.append(f"溯源 ID: `{_trace}`")
            if extra_parts:
                lines.append(f"<details><summary>附加信息</summary>\n\n{'  '.join(extra_parts)}\n\n</details>")
                lines.append("")
            lines.append("---")
            lines.append("")

    # 5.3 边缘漏洞
    if borderline:
        lines.append("### 5.3 ⚠️ 边缘漏洞 (需人工复核)")
        lines.append("")
        for i, vd in enumerate(borderline, 1):
            orig = vd.get("_original", {}) or {}
            title = orig.get("title", "") or vd.get("vuln_id", "")
            lines.append(f"#### 漏洞 5.3.{i} {title}")
            lines.append("")
            if vd.get("harm_story"):
                lines.append(f"**审核员意见**: {vd['harm_story']}")
                lines.append("")
            lines.append(f"- 原漏洞 ID: `{vd.get('vuln_id', '')}`")
            lines.append(f"- 漏洞类型: {orig.get('vuln_type', '')}")
            lines.append(f"- 接口: `{orig.get('url', '')}`")
            if vd.get("reject_reason"):
                lines.append(f"- 边缘原因: {vd['reject_reason']}")
            lines.append(f"- 修复优先级: {vd.get('fix_priority', '')}")
            lines.append("")
            lines.append("---")
            lines.append("")

    # 5.4 拒收的漏洞 (透明披露)
    if rejected:
        lines.append("### 5.4 ❌ 拒收的【漏洞】(透明披露)")
        lines.append("")
        lines.append("> 以下条目在主报告漏洞详情中存在,但经审核员判断不符合 SRC/赏金平台收录标准——")
        lines.append("> 多为【防御纵深建议】而非【实际危害】。透明披露,客户可自行判断是否纳入合规整改。")
        lines.append("")
        lines.append("| # | 原漏洞 | 类型 | 拒收理由 | 修复建议 |")
        lines.append("|---|--------|------|---------|---------|")
        for i, vd in enumerate(rejected, 1):
            orig = vd.get("_original", {}) or {}
            title = (orig.get("title", "") or vd.get("vuln_id", "")).replace("|", "\\|")[:60]
            vtype = (orig.get("vuln_type", "") or "").replace("|", "\\|")[:40]
            reason = vd.get("reject_reason", "").replace("|", "\\|")[:200]
            prio = vd.get("fix_priority", "")
            lines.append(f"| {i} | {title} | {vtype} | {reason} | {prio} |")
        lines.append("")
        lines.append("---")
        lines.append("")

    # 5.5 审核员总评
    if summary:
        lines.append("### 5.5 审核员总评")
        lines.append("")
        lines.append(summary)
        lines.append("")

    return "\n".join(lines)


def _get_vulns_from_sitemap(task_id: str) -> list[dict]:
    """★ 从 sitemap 提取 checklist 中 result=vulnerable 的漏洞。

    当 harm_validation 没运行（hv_result 为空）时，proven 报告不应该
    只显示"暂无数据"——checklist 中已经有标记为 vulnerable 的漏洞，
    应该把它们展示出来让用户看到测试发现了什么。

    Returns:
        漏洞字典列表，每项含 vuln_type/severity/url/detail/fix_suggestion/evidence_request/evidence_response
    """
    if not task_id:
        return []
    try:
        import json as _json
        from pathlib import Path as _Path
        sitemap_path = _Path(f"data/tasks/{task_id}-sitemap.json")
        if not sitemap_path.exists():
            return []
        data = _json.loads(sitemap_path.read_text(encoding="utf-8"))
        features = data.get("features", {}) or {}
        if not isinstance(features, dict):
            return []

        vulns = []
        for fp_id, fp in features.items():
            if not isinstance(fp, dict):
                continue
            fp_name = fp.get("name", fp_id) or fp_id
            fp_url = fp.get("page_url", "") or ""
            for c in (fp.get("checklist", []) or []):
                if not isinstance(c, dict):
                    continue
                if c.get("result") != "vulnerable":
                    continue
                vulns.append({
                    "vuln_type": c.get("vuln_type", "") or "未知",
                    "severity": c.get("severity", "medium") or "medium",
                    "feature": fp_name,
                    "url": fp_url,
                    "detail": (c.get("detail", "") or "")[:500],
                    "fix_suggestion": (c.get("fix_suggestion", "") or "")[:500],
                    "evidence_request": (c.get("evidence_request", "") or "")[:800],
                    "evidence_response": (c.get("evidence_response", "") or "")[:800],
                    "reproduce_steps": (c.get("reproduce_steps", "") or "")[:500],
                })
        return vulns
    except Exception:
        return []


def _render_checklist_vulns_block(vulns: list[dict]) -> list[str]:
    """渲染 checklist 漏洞为 Markdown 块（harm_validation 未运行时的兜底展示）。"""
    if not vulns:
        return []

    # 按严重等级排序
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns_sorted = sorted(vulns, key=lambda v: sev_order.get(
        (v.get("severity", "") or "").lower(), 9
    ))

    lines = [
        "---",
        "",
        f"## 🔍 测试发现的漏洞（共 {len(vulns_sorted)} 个，待危害验证）",
        "",
        "> 以下漏洞在功能点测试中被标记为「存在漏洞」，但危害验证（Phase 2.6）尚未运行。",
        "> 请人工复核每条记录的 PoC 和证据，确认实际危害后可纳入已证明漏洞。",
        "",
    ]

    for i, v in enumerate(vulns_sorted, 1):
        vt = v.get("vuln_type", "") or "未知"
        sev = v.get("severity", "") or "medium"
        sev_emoji = {
            "critical": "🔴 严重", "high": "🟠 高危",
            "medium": "🟡 中危", "low": "🔵 低危", "info": "⚪ 信息",
        }.get(sev.lower(), "🟡 中危")
        url = v.get("url", "") or ""
        feature = v.get("feature", "") or ""
        detail = v.get("detail", "") or ""
        evidence_req = v.get("evidence_request", "") or ""
        evidence_resp = v.get("evidence_response", "") or ""
        fix = v.get("fix_suggestion", "") or ""
        repro = v.get("reproduce_steps", "") or ""
        params_str = _extract_params_from_evidence(evidence_req)
        impact_text = detail or f"功能点 {feature} 存在 {vt} 漏洞"

        lines.append(f"### 5.{i} [{vt}] {feature}")
        lines.append("")
        lines.append("| 项目 | 内容 |")
        lines.append("|------|------|")
        lines.append(f"| 等级 | {sev_emoji} |")
        lines.append(f"| 类型 | {vt} |")
        lines.append(f"| URL | `{url}` |")
        lines.append(f"| 参数 | {params_str} |")
        lines.append(f"| 影响 | {impact_text} |")
        # ★ 优化.md 建议5/2：CWE 映射 + 四维定级依据（checklist 兜底展示同样补 CWE）
        from core.cwe_mapping import enrich_finding_with_cwe as _enrich_cwe
        from core.severity_rules import apply_severity as _apply_sev
        _enrich_cwe(v)
        _apply_sev(v)
        cwe_id = v.get("cwe_id", "")
        cwe_name = v.get("cwe_name", "")
        if cwe_id:
            lines.append(f"| CWE | [{cwe_id} {cwe_name}]({v.get('cwe_url', '')}) |")
        sev_rationale = v.get("severity_rationale", "")
        if sev_rationale:
            lines.append(f"| 定级依据 | {sev_rationale} |")
        lines.append("")

        # 复现步骤
        lines.append("复现步骤:")
        lines.append("")
        if repro:
            lines.append(str(repro)[:800])
            lines.append("")
        else:
            lines.append("（未提供复现步骤）")
            lines.append("")

        # 请求
        lines.append("请求:")
        lines.append("")
        if evidence_req:
            lines.append("```http")
            lines.append(evidence_req)
            lines.append("```")
            lines.append("")
        else:
            lines.append("（无请求包）")
            lines.append("")

        # 响应
        lines.append("响应:")
        lines.append("")
        if evidence_resp:
            lines.append("```http")
            lines.append(evidence_resp)
            lines.append("```")
            lines.append("")
        else:
            lines.append("（无响应包）")
            lines.append("")

        # 截图
        lines.append("截图: （如有）")
        lines.append("")

        # 修复建议
        lines.append("修复建议:")
        lines.append("")
        if fix:
            lines.append(str(fix)[:800])
            lines.append("")
        else:
            lines.append("（未提供修复建议）")
            lines.append("")

        lines.append("---")
        lines.append("")

    return lines


def _get_test_summary_from_sitemap(task_id: str) -> list[str]:
    """从 sitemap 文件提取测试覆盖摘要，用于 proven 报告在无漏洞时展示测试结论。

    避免 proven 报告在 no_vulns / 暂无数据 分支只有一句话，用户觉得"报告没内容"。
    """
    if not task_id:
        return []
    try:
        import json as _json
        from pathlib import Path as _Path
        sitemap_path = _Path(f"data/tasks/{task_id}-sitemap.json")
        if not sitemap_path.exists():
            return []
        data = _json.loads(sitemap_path.read_text(encoding="utf-8"))
        features = data.get("features", {}) or {}
        if not isinstance(features, dict):
            return []

        lines = [
            "## 📋 测试覆盖摘要",
            "",
            f"- 目标: `{data.get('target', '') or '未知'}`",
            f"- 功能点总数: {len(features)}",
        ]

        # 统计测试状态
        total_checks = 0
        done_checks = 0
        vuln_count = 0
        review_count = 0
        tested_features = []
        for fp_id, fp in features.items():
            if not isinstance(fp, dict):
                continue
            fp_name = fp.get("name", fp_id) or fp_id
            checklist = fp.get("checklist", []) or []
            if not checklist:
                continue
            fp_done = 0
            fp_vuln = 0
            fp_review = 0
            for c in checklist:
                if not isinstance(c, dict):
                    continue
                total_checks += 1
                result = c.get("result", "")
                if result and result != "pending":
                    done_checks += 1
                    fp_done += 1
                if result == "vulnerable":
                    vuln_count += 1
                    fp_vuln += 1
                elif result == "needs_review":
                    review_count += 1
                    fp_review += 1
            if fp_done > 0:
                status_icon = "🔴" if fp_vuln else ("🟡" if fp_review else "✅")
                tested_features.append((fp_name, status_icon, fp_done, fp_vuln, fp_review))

        coverage_pct = f"{(done_checks / total_checks * 100):.1f}%" if total_checks else "0.0%"
        lines.append(f"- 测试项: {done_checks}/{total_checks} 完成 ({coverage_pct})")
        lines.append(f"- 已确认漏洞: {vuln_count} 个")
        lines.append(f"- 疑似待确认: {review_count} 个")
        lines.append("")

        if tested_features:
            lines.append("### 已测试功能点")
            lines.append("")
            lines.append("| # | 功能点 | 状态 | 测试项 | 漏洞 | 疑似 |")
            lines.append("|---|--------|------|--------|------|------|")
            for i, (name, icon, done, vuln, review) in enumerate(tested_features[:30], 1):
                lines.append(f"| {i} | {name} | {icon} | {done} | {vuln} | {review} |")
            if len(tested_features) > 30:
                lines.append(f"\n> 还有 {len(tested_features) - 30} 个功能点未在此列出。")
            lines.append("")

        return lines
    except Exception:
        return []


def merge_similar_findings(verdicts: list[dict], threshold: int = 3) -> list[dict]:
    """合并同类漏洞（优化.md 建议7）。

    同组（漏洞类型 + 严重度）> threshold 条时，合并为一条带端点清单的发现，
    避免报告中大量同类条目堆叠（如 109 条敏感路径 200 合并为 1 条）。
    合并后保留第一条作为代表，其余 URL 收进 _merged_endpoints 字段。
    """
    if not verdicts:
        return []
    from core.cwe_mapping import normalize_vuln_type

    def _group_key(vd: dict) -> str:
        orig = vd.get("_original", {}) or {}
        vt = normalize_vuln_type(orig.get("vuln_type", "") or vd.get("vuln_id", ""))
        level = (vd.get("platform_level") or "").lower()
        return f"{vt}|{level}"

    groups: dict[str, list[dict]] = {}
    order: list[str] = []
    for vd in verdicts:
        k = _group_key(vd)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(vd)

    result: list[dict] = []
    for k in order:
        grp = groups[k]
        if len(grp) <= threshold:
            result.extend(grp)
            continue
        # 合并：取第一条作为代表
        rep = dict(grp[0])
        endpoints: list[str] = []
        for g in grp:
            orig = g.get("_original", {}) or {}
            url = orig.get("url", "") or g.get("vuln_id", "")
            if url and url not in endpoints:
                endpoints.append(url)
        rep["_merged_endpoints"] = endpoints
        rep["_merged_count"] = len(grp)
        orig = rep.get("_original", {}) or {}
        merged_title = f"{orig.get('vuln_type', '同类漏洞')} ×{len(grp)}（已合并端点清单）"
        orig_merged = dict(orig)
        orig_merged["title"] = merged_title
        rep["_original"] = orig_merged
        result.append(rep)
    return result


def _compliance_footer(target_label: str, scope_label: str) -> list[str]:
    """★ 优化.md 建议3：生成合规章节尾部（测试范围/免责声明/复测建议）。

    可在 render_proven_only 的所有分支中复用，确保无论有无漏洞都包含合规章节。
    """
    return [
        "---",
        "",
        "## 测试范围与局限性",
        "",
        "**测试范围**：",
        f"- 目标: `{target_label}`",
        f"- 测试范围: {scope_label}",
        "- 测试方式: 自动化漏洞扫描 + LLM 危害验证 + 人工研判标准过滤",
        "",
        "**局限性声明**：",
        "- 本报告仅覆盖测试期间可访问的接口和功能点，不保证发现所有潜在漏洞。",
        "- 自动化扫描可能遗漏需要复杂业务逻辑上下文的漏洞（如多步组合利用链）。",
        "- 危害验证基于当前测试环境，实际风险可能因部署配置差异而不同。",
        "- 标记为「边缘」的漏洞需人工进一步复核确认。",
        "",
        "## 免责声明",
        "",
        "本报告由自动化安全测试工具生成，仅供授权方在授权范围内参考使用。",
        "测试人员已尽合理努力确保报告准确性，但不对其完整性作任何担保。",
        "报告接收方应根据自身业务场景进行独立评估，并决定是否采纳修复建议。",
        "",
        "## 复测建议",
        "",
        "1. **修复后复测时间点**：建议在漏洞修复完成后 3 个工作日内安排复测。",
        "2. **复测验证清单**：",
        "   - 逐条验证本报告中列出的每个漏洞是否已修复",
        "   - 对「边缘」漏洞确认是否为真实漏洞并决定是否纳入修复范围",
        "   - 重新运行扫描以确认无新增漏洞",
        "3. **溯源验证**：每条漏洞的「溯源 ID」可在测试日志中检索原始请求/响应证据，",
        "   复测时可对照验证修复效果。",
        "",
    ]


def render_proven_only(
    hv_result: dict,
    target: str = "",
    task_id: str = "",
    orphan_findings: list | None = None,
    tester: str = "",
    scan_scope: str = "",
) -> str:
    """渲染【已证明漏洞】独立报告（报告 B）。

    设计：
    - 只包含 verdict == "accepted" 的条目（边缘和拒收都不要）
    - 优先使用 LLM 实测得到的 poc_request/poc_response（阶段二产物），
      没有时回退到 _original.evidence_request/evidence_response
    - 顶部冠以醒目说明，避免与"完整报告"混淆
    - 无任何已证明漏洞时，返回包含说明的占位报告（不返回空字符串，
      让前端按钮始终能点击查看，避免"按钮无反应"的体验问题）
    - ★ orphan_findings: FastScanner 未匹配功能点的发现。当 harm_validation
      未产出 accepted 时，把它们作为"待人工确认"列出，避免报告永远空、
      用户以为系统没发现任何问题。
    - ★ 优化.md 建议3：补合规章节（封面/执行摘要/范围局限性/免责声明/复测建议）
      tester/scan_scope 由调用方注入，禁止写死测试人员姓名。
    """
    import time as _time

    target_label = target or "（未知目标）"
    task_label = task_id or "default"
    tester_label = tester or "（未指定）"
    scope_label = scan_scope or "由测试配置决定（详见测试覆盖摘要）"
    timestamp = _time.strftime("%Y-%m-%d %H:%M:%S")

    # ★ 优化.md 建议3：合规章节 — 封面
    header = [
        "# 安全测试报告 — 已证明漏洞",
        "",
        f"> 这份报告**只包含被审核员判定为有实际危害、达到 SRC / 赏金平台收录标准**的漏洞。",
        f"> 已剔除：CORS 配置不规范、防御纵深建议、形式合规问题等无实际利用链的条目。",
        f"> 完整测试发现请查看「完整报告」。",
        "",
        "---",
        "",
        "## 封面信息",
        "",
        "| 项目 | 内容 |",
        "|------|------|",
        f"| 测试目标 | `{target_label}` |",
        f"| 测试日期 | {timestamp} |",
        f"| 测试人员 | {tester_label} |",
        f"| 任务 ID | `{task_label}` |",
        f"| 测试范围 | {scope_label} |",
        f"| 授权声明 | 本次测试已在授权范围内执行，所有测试行为基于已获取的合法授权。 |",
        "",
        "---",
        "",
    ]

    if not hv_result:
        orphan_block = _render_orphan_block(orphan_findings)
        test_summary = _get_test_summary_from_sitemap(task_label)
        # ★ harm_validation 没运行时，从 sitemap 提取 checklist 漏洞展示
        # 避免 54 个漏洞的任务 proven 报告只显示"暂无数据"
        checklist_vulns = _get_vulns_from_sitemap(task_label)
        checklist_block = _render_checklist_vulns_block(checklist_vulns)
        _footer = _compliance_footer(target_label, scope_label)
        if orphan_block:
            return "\n".join(header + test_summary + checklist_block + orphan_block + _footer)
        if checklist_block:
            # 有 checklist 漏洞时，说明测试已发现漏洞但危害验证没运行
            return "\n".join(header + test_summary + checklist_block + _footer)
        return "\n".join(header + test_summary + [
            "## 暂无数据",
            "",
            "尚未运行漏洞危害验证（Phase 2.6）。请等待测试结束或在测试完成后查看。",
            "",
        ] + _footer)

    status = hv_result.get("status", "")
    if status == "no_vulns":
        orphan_block = _render_orphan_block(orphan_findings)
        test_summary = _get_test_summary_from_sitemap(task_label)
        if orphan_block:
            return "\n".join(header + test_summary + orphan_block + _compliance_footer(target_label, scope_label))
        return "\n".join(header + test_summary + [
            "## 无已证明的漏洞",
            "",
            "本次测试未发现达到 SRC / 赏金平台收录标准的漏洞。",
            "",
            "> 以上测试覆盖摘要展示了本次测试的覆盖范围和结论。",
            "> 完整的测试详情请查看「完整报告」。",
            "",
        ] + _compliance_footer(target_label, scope_label))
    if status != "ok":
        err = hv_result.get("error", "未知错误")
        # ★ 危害验证失败时也展示 checklist 漏洞，避免报告空
        test_summary = _get_test_summary_from_sitemap(task_label)
        checklist_vulns = _get_vulns_from_sitemap(task_label)
        checklist_block = _render_checklist_vulns_block(checklist_vulns)
        return "\n".join(header + test_summary + [
            f"## ⚠️ 危害验证未完成（状态: {status}）",
            "",
            f"原因: {err[:500]}",
            "",
        ] + checklist_block + [
            "",
            "请查看「完整报告」中的漏洞详情。",
            "",
        ] + _compliance_footer(target_label, scope_label))

    verdicts = hv_result.get("verdicts", []) or []
    accepted = [v for v in verdicts if v.get("verdict") == "accepted"]
    summary = hv_result.get("summary", "")

    def _dedupe_verdicts(items: list[dict]) -> list[dict]:
        from urllib.parse import urlparse
        import re

        def _canon_type(orig: dict) -> str:
            vt = (orig.get("vuln_type", "") or "").lower()
            blob = "\n".join([
                vt,
                (orig.get("detail", "") or "").lower(),
                (orig.get("evidence_request", "") or "").lower(),
                (orig.get("evidence_response", "") or "").lower(),
            ])
            if ("信息泄露" in orig.get("vuln_type", "") or "代码审计" in orig.get("vuln_type", "") or "key" in vt or "secret" in vt) and any(
                marker in blob for marker in ("appsecret", "app_secret", "api_key", "apikey", "appkey", "硬编码密钥", "签名密钥")
            ):
                return "客户端硬编码密钥泄露"
            return orig.get("vuln_type", "") or "未知"

        def _key(vd: dict) -> str:
            orig = vd.get("_original", {}) or {}
            url = orig.get("url", "") or ""
            req = orig.get("evidence_request", "") or ""
            if not url and req:
                m = re.search(r"\b(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)", req)
                if m:
                    url = m.group(1)
            try:
                pu = urlparse(url)
                path = pu.path or url.split("?", 1)[0]
                norm_parts = []
                for part in [p for p in path.split("/") if p]:
                    if part.isdigit() or re.fullmatch(r"[0-9a-fA-F]{16,}", part):
                        norm_parts.append("*")
                    else:
                        norm_parts.append(part)
                norm_path = "/" + "/".join(norm_parts) if norm_parts else path
                host = pu.netloc.lower()
            except Exception:
                host, norm_path = "", url
            return f"{host}{norm_path}|{_canon_type(orig)}"

        seen: set[str] = set()
        result: list[dict] = []
        for item in items:
            k = _key(item)
            if k in seen:
                continue
            seen.add(k)
            result.append(item)
        return result

    accepted = _dedupe_verdicts(accepted)

    # ★ 优化.md 建议5/2/7：补 CWE + 四维定级，并合并同类项
    from core.cwe_mapping import enrich_finding_with_cwe
    from core.severity_rules import apply_severity
    for vd in accepted:
        orig = vd.get("_original")
        if isinstance(orig, dict):
            enrich_finding_with_cwe(orig)
            apply_severity(orig)
    accepted = merge_similar_findings(accepted)

    if not accepted:
        rej_count = sum(1 for v in verdicts if v.get("verdict") == "rejected")
        bord_count = sum(1 for v in verdicts if v.get("verdict") == "borderline")
        body = [
            "## 无已证明的漏洞",
            "",
            f"测试共发现 {len(verdicts)} 个候选漏洞，但**没有一条**通过审核员的危害验证：",
            "",
            f"- ❌ 拒收（无实际利用链）: {rej_count}",
            f"- ⚠️ 边缘（需人工复核）: {bord_count}",
            "",
        ]
        # ★ 当存在 borderline 漏洞时，直接在 proven 报告展示详情，
        # 而非只说"详见完整报告"。之前用户反馈"报告没有内容"——
        # 51 个漏洞全是 borderline 时 proven 报告只有一句话，用户拿不到任何漏洞详情。
        # 现在把 borderline 漏洞的标题、类型、URL、证据、修复建议都列出来，
        # 明确标注"未经危害验证，需人工复核"，不与已证明漏洞混淆。
        borderline = _dedupe_verdicts([v for v in verdicts if v.get("verdict") == "borderline"])
        if borderline:
            body.extend([
                "---",
                "",
                f"## ⚠️ 边缘漏洞详情（共 {len(borderline)} 个，需人工复核）",
                "",
                "> 以下漏洞经测试发现但未通过危害验证裁决（LLM 复现失败或证据不足）。",
                "> 请人工复核每条记录的 PoC 和证据，确认后可升级为已证明漏洞。",
                "",
            ])
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            borderline_sorted = sorted(
                borderline,
                key=lambda v: sev_order.get(
                    (v.get("_original", {}) or {}).get("severity_original", "").lower(), 9
                )
            )
            for i, vd in enumerate(borderline_sorted, 1):
                orig = vd.get("_original", {}) or {}
                vt = orig.get("vuln_type", "") or "未知"
                url = orig.get("url", "") or ""
                sev = orig.get("severity_original", "") or "medium"
                sev_emoji = {
                    "critical": "🔴 严重", "high": "🟠 高危",
                    "medium": "🟡 中危", "low": "🔵 低危", "info": "⚪ 信息",
                }.get(sev.lower(), "🟡 中危")
                detail = (orig.get("detail", "") or "")[:400]
                evidence_req = (orig.get("evidence_request", "") or "")[:500]
                evidence_resp = (orig.get("evidence_response", "") or "")[:500]
                fix = (orig.get("fix_suggestion", "") or "")[:300]
                harm = vd.get("harm_story", "") or ""
                vid = vd.get("vuln_id", "") or ""
                params_str = _extract_params_from_evidence(evidence_req)
                impact_text = harm or detail or "（未经危害验证，需人工复核）"

                body.append(f"### 5.{i} [{vt}] 待人工复核")
                body.append("")
                body.append("| 项目 | 内容 |")
                body.append("|------|------|")
                body.append(f"| 等级 | {sev_emoji} |")
                body.append(f"| 类型 | {vt} |")
                body.append(f"| URL | `{url}` |")
                body.append(f"| 参数 | {params_str} |")
                body.append(f"| 影响 | {impact_text} |")
                body.append("")

                # 复现步骤
                body.append("复现步骤:")
                body.append("")
                repro = (orig.get("reproduce_steps", "") or "")[:500]
                if repro:
                    body.append(repro)
                    body.append("")
                else:
                    body.append("（未提供复现步骤）")
                    body.append("")

                # 请求
                body.append("请求:")
                body.append("")
                if evidence_req:
                    body.append("```http")
                    body.append(evidence_req)
                    body.append("```")
                    body.append("")
                else:
                    body.append("（无请求包）")
                    body.append("")

                # 响应
                body.append("响应:")
                body.append("")
                if evidence_resp:
                    body.append("```http")
                    body.append(evidence_resp)
                    body.append("```")
                    body.append("")
                else:
                    body.append("（无响应包）")
                    body.append("")

                # 截图
                body.append("截图: （如有）")
                body.append("")

                # 修复建议
                body.append("修复建议:")
                body.append("")
                if fix:
                    body.append(fix)
                    body.append("")
                else:
                    body.append("（未提供修复建议）")
                    body.append("")

                if vid:
                    body.append(f"> 漏洞 ID: `{vid}`")
                    body.append("")
                body.append("---")
                body.append("")
        else:
            body.append("详见「完整报告」第 5 章「漏洞危害验证」。")
            body.append("")
        if summary:
            body.extend(["**审核员总评**:", "", summary, ""])
        return "\n".join(header + body + _compliance_footer(target_label, scope_label))

    # 有 accepted 漏洞 → 正式渲染
    lines = list(header)

    # ★ 优化.md 建议3：执行摘要 + 定级说明
    lines.append("## 执行摘要")
    lines.append("")
    lines.append(f"本次安全测试对目标 `{target_label}` 进行了自动化漏洞扫描与危害验证。")
    lines.append(f"经专业安全人员视角二次研判，共发现 **{len(accepted)} 个**达到 SRC/赏金平台收录标准的漏洞。")
    lines.append("")
    lines.append("**定级说明（评级口径）**：")
    lines.append("")
    lines.append("本报告采用四维定级法（数据敏感度 × 可利用性 × 认证要求 × 影响范围）：")
    lines.append("")
    lines.append("| 等级 | 定义 |")
    lines.append("|------|------|")
    lines.append("| 🔴 严重 | 无凭证可直接读写核心敏感数据/执行管理操作 |")
    lines.append("| 🟠 高危 | 存在可利用的漏洞链，需有限条件即可触发 |")
    lines.append("| 🟡 中危 | 需特定条件或认证后方可利用，影响有限 |")
    lines.append("| 🔵 低危 | 信息泄露/配置建议，无直接利用链 |")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append(f"## 📊 总览")
    lines.append("")
    lines.append(f"**已证明的漏洞数: {len(accepted)} 个**")
    lines.append("")

    # 按严重等级分布
    level_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "no_value": 0}
    for vd in accepted:
        lv = (vd.get("platform_level") or "medium").lower()
        if lv in level_count:
            level_count[lv] += 1
        else:
            level_count["medium"] += 1
    lines.append("| 等级 | 数量 |")
    lines.append("|------|------|")
    if level_count["critical"]:
        lines.append(f"| 🔴 严重 | {level_count['critical']} |")
    if level_count["high"]:
        lines.append(f"| 🟠 高危 | {level_count['high']} |")
    if level_count["medium"]:
        lines.append(f"| 🟡 中危 | {level_count['medium']} |")
    if level_count["low"]:
        lines.append(f"| 🔵 低危 | {level_count['low']} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 逐个漏洞详情 — 标准漏洞报告格式
    lines.append("## 漏洞详情")
    lines.append("")
    for i, vd in enumerate(accepted, 1):
        orig = vd.get("_original", {}) or {}
        level = (vd.get("platform_level") or "medium").lower()
        level_emoji = {
            "critical": "🔴 严重",
            "high": "🟠 高危",
            "medium": "🟡 中危",
            "low": "🔵 低危",
            "no_value": "⚪",
        }.get(level, "🟡 中危")
        title = orig.get("title", "") or vd.get("vuln_id", "")
        url = orig.get("url", "") or ""
        vtype = orig.get("vuln_type", "") or "未知"
        vid = vd.get("vuln_id", "")
        harm_story = vd.get("harm_story", "")
        detail = orig.get("detail", "") or ""
        impact_text = harm_story or detail or vtype or "（无描述）"
        evidence_req = orig.get("evidence_request") or ""
        evidence_resp = orig.get("evidence_response") or ""
        poc_req_fallback = vd.get("poc_request") or ""
        poc_resp_fallback = vd.get("poc_response") or ""
        params_str = _extract_params_from_evidence(evidence_req or poc_req_fallback)
        fix_suggestion = orig.get("fix_suggestion", "") or ""

        # 标题行
        lines.append(f"### 5.{i} [{vtype}] {title}")
        lines.append("")

        # 信息表
        lines.append("| 项目 | 内容 |")
        lines.append("|------|------|")
        lines.append(f"| 等级 | {level_emoji} |")
        lines.append(f"| 类型 | {vtype} |")
        lines.append(f"| URL | `{url}` |")
        lines.append(f"| 参数 | {params_str} |")
        lines.append(f"| 影响 | {impact_text} |")
        # ★ 优化.md 建议5/2：CWE 映射 + 四维定级依据
        cwe_id = orig.get("cwe_id", "")
        cwe_name = orig.get("cwe_name", "")
        if cwe_id:
            cwe_url = orig.get("cwe_url", "")
            if cwe_url:
                lines.append(f"| CWE | [{cwe_id} {cwe_name}]({cwe_url}) |")
            else:
                lines.append(f"| CWE | {cwe_id} {cwe_name} |")
        sev_rationale = orig.get("severity_rationale", "")
        if sev_rationale:
            lines.append(f"| 定级依据 | {sev_rationale} |")
        # ★ 优化.md 建议6：溯源 ID（日志→报告溯源）
        trace_id = orig.get("trace_id", "") or vd.get("trace_id", "")
        if trace_id:
            lines.append(f"| 溯源 ID | `{trace_id}` |")
        lines.append("")

        # 复现步骤
        lines.append("复现步骤:")
        lines.append("")
        repro = orig.get("reproduce_steps") or ""
        poc_note = vd.get("poc_note", "")
        if repro:
            lines.append(str(repro)[:3000])
            lines.append("")
        elif poc_note:
            lines.append(str(poc_note)[:1000])
            lines.append("")
        else:
            lines.append("（无复现步骤记录）")
            lines.append("")

        # 请求
        lines.append("请求:")
        lines.append("")
        raw_traces = vd.get("_raw_traces") or []
        full_request = evidence_req
        full_response = evidence_resp
        has_request_shown = False

        if raw_traces:
            for ti, rt in enumerate(raw_traces):
                req_text = rt.get("request", "")
                if req_text:
                    poc_label = f"PoC #{ti + 1}" if len(raw_traces) > 1 else "PoC"
                    lines.append(f"**{poc_label}**:")
                    lines.append("")
                    lines.append("```http")
                    lines.append(str(req_text)[:5000])
                    lines.append("```")
                    lines.append("")
                    has_request_shown = True
        else:
            req_to_show = full_request or poc_req_fallback
            if req_to_show:
                lines.append("```http")
                lines.append(str(req_to_show)[:5000])
                lines.append("```")
                lines.append("")
                has_request_shown = True

        if not has_request_shown:
            lines.append("（无请求包）")
            lines.append("")

        # 响应
        lines.append("响应:")
        lines.append("")
        has_response_shown = False

        if raw_traces:
            for ti, rt in enumerate(raw_traces):
                resp_text = rt.get("response", "")
                if resp_text:
                    poc_label = f"PoC #{ti + 1}" if len(raw_traces) > 1 else "PoC"
                    lines.append(f"**{poc_label}**:")
                    lines.append("")
                    lines.append("```http")
                    lines.append(str(resp_text)[:5000])
                    lines.append("```")
                    lines.append("")
                    has_response_shown = True
        else:
            resp_to_show = full_response or poc_resp_fallback
            if resp_to_show:
                lines.append("```http")
                lines.append(str(resp_to_show)[:5000])
                lines.append("```")
                lines.append("")
                has_response_shown = True

        if not has_response_shown:
            lines.append("（无响应包）")
            lines.append("")

        # 截图
        lines.append("截图: （如有）")
        lines.append("")

        # 修复建议
        lines.append("修复建议:")
        lines.append("")
        if fix_suggestion:
            lines.append(str(fix_suggestion)[:1500])
            lines.append("")
        else:
            lines.append("（未提供修复建议）")
            lines.append("")

        # 附加信息（折叠）
        broken = vd.get("broken_promises", []) or []
        platforms = vd.get("would_be_accepted_by", []) or []
        extra_parts = []
        if broken:
            extra_parts.append(f"打破的业务承诺: {', '.join(str(p) for p in broken)}")
        if platforms:
            extra_parts.append(f"估计收录平台: {', '.join(str(p) for p in platforms)}")
        extra_parts.append(f"证据强度: {vd.get('evidence_strength', '')}")
        extra_parts.append(f"修复优先级: {vd.get('fix_priority', '')}")
        if vid:
            extra_parts.append(f"原漏洞 ID: `{vid}`")
        # ★ 优化.md 建议6：溯源 ID（附加信息中也列出，方便折叠查看）
        if not trace_id:
            trace_id = orig.get("trace_id", "") or vd.get("trace_id", "")
        if trace_id:
            extra_parts.append(f"溯源 ID: `{trace_id}`（可在测试日志中检索对应请求/响应）")
        if extra_parts:
            lines.append(f"<details><summary>附加信息</summary>\n\n{'  '.join(extra_parts)}\n\n</details>")
            lines.append("")

        # ★ 优化.md 建议7：合并端点清单（同类漏洞合并后展示）
        merged_endpoints = vd.get("_merged_endpoints") or []
        merged_count = vd.get("_merged_count", 0)
        if merged_endpoints:
            lines.append(f"<details><summary>已合并端点清单（共 {merged_count} 个同类端点）</summary>\n\n")
            for ep_url in merged_endpoints[:50]:
                lines.append(f"- `{ep_url}`")
            if len(merged_endpoints) > 50:
                lines.append(f"- ... 还有 {len(merged_endpoints) - 50} 个端点未列出")
            lines.append("\n</details>")
            lines.append("")

        lines.append("---")
        lines.append("")

    if summary:
        lines.append("## 审核员总评")
        lines.append("")
        lines.append(summary)
        lines.append("")

    # ★ 优化.md 建议3：测试范围与局限性 / 免责声明 / 复测建议
    lines.extend(_compliance_footer(target_label, scope_label))

    return "\n".join(lines)


def _render_orphan_block(orphan_findings: list | None) -> list[str]:
    """渲染 FastScanner 孤儿发现为"待人工确认"章节。

    当 harm_validation 未产出 accepted 漏洞时，把 FastScanner 发现但未匹配
    功能点的漏洞列出来，避免 proven 报告永远空、用户误以为系统什么都没发现。
    明确标注"未经危害验证"，不与已证明漏洞混淆。
    """
    if not orphan_findings:
        return []
    from urllib.parse import urlparse

    deduped_findings = []
    seen_keys: set[str] = set()
    for f in orphan_findings:
        if not isinstance(f, dict):
            continue
        vt = f.get("vuln_type", "未知")
        blob = "\n".join([
            str(vt).lower(),
            (f.get("detail", "") or "").lower(),
            (f.get("evidence", "") or "").lower(),
        ])
        if ("信息泄露" in str(vt) or "代码审计" in str(vt) or "key" in str(vt).lower()) and any(
            marker in blob for marker in ("appsecret", "app_secret", "api_key", "apikey", "appkey", "硬编码密钥", "签名密钥")
        ):
            vt_key = "客户端硬编码密钥泄露"
        else:
            vt_key = str(vt)
        url = f.get("url", "") or ""
        try:
            pu = urlparse(url)
            url_key = f"{pu.netloc.lower()}{pu.path}".rstrip("/")
        except Exception:
            url_key = url.split("?", 1)[0].rstrip("/")
        key = f"{vt_key}|{url_key}|{f.get('method', '')}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped_findings.append(f)

    sev_emoji = {
        "critical": "🔴 严重", "high": "🟠 高危",
        "medium": "🟡 中危", "low": "🟢 低危", "info": "ℹ️ 信息",
    }
    lines = [
        "## ⚠️ 待人工确认的发现（未经危害验证）",
        "",
        "> 以下漏洞由本地规则引擎（FastScanner）发现，但未匹配到功能点、",
        "> 也未经 Phase 2.6 危害验证裁决。请人工复核是否有实际利用价值。",
        "",
        f"**共 {len(deduped_findings)} 条**",
        "",
    ]
    for i, f in enumerate(deduped_findings, 1):
        sev = (f.get("severity") or "medium").lower()
        sev_label = sev_emoji.get(sev, sev)
        vt = f.get("vuln_type", "未知")
        url = f.get("url", "")
        method = f.get("method", "")
        detail = (f.get("detail", "") or "")[:300]
        payload = (f.get("payload", "") or "")[:200]
        fix = (f.get("fix_suggestion", "") or "")[:200]

        lines.append(f"### {i}. [{sev_label}] {vt}")
        lines.append("")
        if url:
            lines.append(f"- **URL**: `{url}`")
        if method:
            lines.append(f"- **方法**: {method}")
        if payload:
            lines.append(f"- **Payload**: `{payload}`")
        if detail:
            lines.append(f"- **详情**: {detail}")
        if fix:
            lines.append(f"- **修复建议**: {fix}")
        lines.append("")
    lines.append("---")
    lines.append("")
    return lines
