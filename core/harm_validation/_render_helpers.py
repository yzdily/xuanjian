"""
_render_helpers — 从 render.py 机械拆分出的辅助函数。

包含：
- _extract_params_from_evidence: 从证据请求包提取参数名
- _get_vulns_from_sitemap: 从 sitemap 提取 checklist 漏洞
- _render_checklist_vulns_block: 渲染 checklist 漏洞为 Markdown 块
- _get_test_summary_from_sitemap: 从 sitemap 提取测试覆盖摘要
- merge_similar_findings: 合并同类漏洞（公开）
- _compliance_footer: 生成合规章节尾部
- _render_orphan_block: 渲染 FastScanner 孤儿发现

这些函数原位于 core.harm_validation.render，为降低单文件体积而迁出，
逻辑与行为保持完全一致（机械 relocation，无任何改动）。
"""

from __future__ import annotations

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
