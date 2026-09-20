"""
漏洞收集与 LLM 上下文构建模块。

职责：
- 从 sitemap 收集所有漏洞
- 拼装喂给 LLM 的输入上下文
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)


def _safe_str(val, max_len: int = 0) -> str:
    """★ P0-3: 安全转字符串——防止非字符串值（list/dict/slice/int）导致 slice 操作或格式化异常。

    如果 val 不是 str，先转 str 再截断。
    """
    if val is None:
        return ""
    if not isinstance(val, str):
        val = str(val)
    if max_len > 0 and len(val) > max_len:
        val = val[:max_len]
    return val


def _safe_list(val) -> list:
    """★ P0-3: 安全转列表——防止非列表值导致 slice 操作异常。"""
    if isinstance(val, list):
        return val
    return []


# ★ 预编译正则：从 evidence_request 提取真实接口 URL
# 匹配以下格式：
#   1. HTTP 请求行: "GET /api/users HTTP/1.1"  / "POST https://host/path HTTP/1.1"
#   2. curl 命令: curl 'http://host/path'  /  curl -X POST "http://host/path"
#   3. 完整 URL: http://host/path  /  https://host/path
#   4. Host 头: "Host: example.com" 配合请求行中的路径
_HTTP_REQ_LINE_RE = re.compile(
    r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+?)\s+HTTP",
    re.IGNORECASE | re.MULTILINE,
)
_HOST_HEADER_RE = re.compile(
    r"^\s*Host:\s*([^\s\r\n]+)", re.IGNORECASE | re.MULTILINE,
)
_CURL_URL_RE = re.compile(
    r"""curl\s+(?:-[A-Za-z]+\s+\S+\s+)*['"]?(https?://[^\s'"]+)['"]?""",
    re.IGNORECASE,
)
_FULL_URL_RE = re.compile(
    r"(https?://[^\s'\"<>\\]+)",
    re.IGNORECASE,
)


def _extract_url_from_evidence(evidence_request: str) -> str:
    """从 evidence_request 文本中提取真实接口 URL。

    evidence_request 可能是以下格式之一：
    - 原始 HTTP 请求包: "GET /api/users HTTP/1.1\\r\\nHost: example.com"
    - curl 命令: "curl 'http://example.com/api/users'"
    - 完整 URL: "http://example.com/api/users"
    - 摘要文本: "GET http://example.com/api/users ..."

    Returns:
        完整 URL（含 scheme+host+path），提取失败返回空字符串。
    """
    if not evidence_request or not isinstance(evidence_request, str):
        return ""

    text = evidence_request.strip()
    if not text:
        return ""

    # 1. curl 命令 → 直接提取 URL
    m = _CURL_URL_RE.search(text)
    if m:
        return m.group(1)

    # 2. 完整 URL（http/https）→ 取第一个
    m = _FULL_URL_RE.search(text)
    if m:
        return m.group(1)

    # 3. HTTP 请求行 + Host 头组合
    req_line_match = _HTTP_REQ_LINE_RE.search(text)
    if req_line_match:
        path_or_url = req_line_match.group(2)
        # 请求行里可能是完整 URL（代理格式）或纯路径
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        # 纯路径 → 需要找 Host 头
        host_match = _HOST_HEADER_RE.search(text)
        if host_match:
            host = host_match.group(1).strip()
            # 路径可能含 query，保留原样
            return f"https://{host}{path_or_url}"
        # 找不到 Host 头，至少返回路径（比空标题好）
        return path_or_url

    # 4. 兜底：找不到任何 URL 信息
    return ""


def _make_title(vuln_type: str, url: str, evidence_request: str = "") -> str:
    """生成有意义的漏洞标题。

    优先级：
    1. vuln_type + 从 evidence_request 提取的真实 URL（最准）
    2. vuln_type + 传入的 url（可能为空或为页面 URL 而非接口 URL）
    3. 仅 vuln_type

    标题截断到 80 字符，避免过长。
    """
    vt = (vuln_type or "").strip() or "漏洞"

    # 优先从 evidence_request 提取真实接口 URL（比 fp_url 更准）
    real_url = _extract_url_from_evidence(evidence_request)
    if not real_url:
        real_url = (url or "").strip()

    if real_url:
        # 截断超长 URL
        url_display = real_url if len(real_url) <= 60 else real_url[:57] + "..."
        title = f"{vt} - {url_display}"
    else:
        title = vt

    # 总长度兜底
    if len(title) > 80:
        title = title[:77] + "..."
    return title


def _check_api_publicly_called(sitemap: "Sitemap", vuln_url: str) -> str:
    """检查漏洞 URL 对应的 API 是否在前端页面被公开调用。

    Returns:
        空字符串: 无证据表明公开调用
        非空字符串: 描述公开调用的证据
    """
    if not vuln_url:
        return ""

    api_samples = getattr(sitemap, "api_samples", None) or {}
    js_api_calls = getattr(sitemap, "js_api_calls", None) or []

    # 从漏洞 URL 提取路径
    from urllib.parse import urlparse
    try:
        parsed = urlparse(vuln_url)
        vuln_path = parsed.path.rstrip("/")
    except Exception:
        return ""

    evidences: list[str] = []

    # 1. 检查 api_samples: 如果爬虫阶段（前端正常浏览）就采集到了这个 API 的样本，
    #    说明前端页面直接调用了它 → 公开接口
    for key, sample in api_samples.items():
        sample_url = sample.get("url", "") or sample.get("path", "")
        try:
            sp = urlparse(sample_url)
            sample_path = sp.path.rstrip("/")
        except Exception:
            continue
        if sample_path == vuln_path or vuln_path.endswith(sample_path) or sample_path.endswith(vuln_path):
            # 确认是正常浏览时采集的（不是安全测试时发的变形请求）
            status_code = sample.get("status_code", 0)
            # ★ case-insensitive 匹配 Content-Type
            resp_headers = sample.get("response_headers", {}) or {}
            resp_ct = ""
            for hk, hv in resp_headers.items():
                if hk.lower() == "content-type":
                    resp_ct = hv.lower()
                    break
            # 正常 200 + JSON 响应 = 前端正常调用
            if status_code == 200 and "json" in resp_ct:
                evidences.append(
                    f"该接口在爬虫阶段被前端正常调用(api_samples有记录), "
                    f"返回200+JSON, 是面向用户的公开接口"
                )
                break

    # 2. 检查 js_api_calls: JS 代码中直接调用
    if js_api_calls:
        for call in js_api_calls[:50]:
            call_url = call.get("url", "") or call.get("path", "")
            if vuln_path and vuln_path in call_url:
                evidences.append(f"前端JS代码直接调用该接口")
                break

    return "; ".join(evidences)


# 用于从 evidence_response 末尾剥离 FastScanner 注入的 [evidence_quality=xxx] 标记
_EQ_TAG_RE = re.compile(r"\[evidence_quality=([a-z_]+)\]\s*$", re.IGNORECASE)


def _extract_evidence_quality(evidence_response: str) -> tuple[str, str]:
    """从 evidence_response 末尾剥离 [evidence_quality=xxx] 标记。

    FastScanner 在写 sitemap 时把 evidence_quality 追加到 evidence_response 末尾，
    这里剥离出来供 harm_validation 二次裁决使用，避免标记污染展示给 LLM 的证据文本。

    Returns:
        (clean_response, evidence_quality): 清理后的响应文本 + 证据质量等级
    """
    if not evidence_response:
        return "", ""
    m = _EQ_TAG_RE.search(evidence_response)
    if m:
        clean = _EQ_TAG_RE.sub("", evidence_response).rstrip()
        return clean, m.group(1).lower()
    return evidence_response, ""


def collect_vulnerabilities(sitemap: "Sitemap") -> list[dict]:
    """从 sitemap 收集所有标记为漏洞的项,返回统一格式。

    ★ 收集范围：
    - result == "vulnerable"（已确认漏洞）→ candidate_level = "confirmed"
    - result == "needs_review"（疑似漏洞）→ candidate_level = "suspected"
    避免疑似项被静默丢弃，确保每一条疑似都进入 harm_validation 流程。
    """
    vulns: list[dict] = []

    # 1. 普通 checklist 项
    features = getattr(sitemap, "features", None) or {}
    for fp_id, fp in features.items():
        fp_name = getattr(fp, "name", "")
        fp_module = getattr(fp, "module", "")
        fp_url = getattr(fp, "page_url", "") or getattr(fp, "url", "")
        for c in (getattr(fp, "checklist", []) or []):
            r = getattr(c, "result", None)
            r_str = getattr(r, "value", str(r)) if r else ""
            # ★ 同时收集 vulnerable 和 needs_review，避免疑似项被静默丢弃
            if r_str == "vulnerable":
                candidate_level = "confirmed"
            elif r_str == "needs_review":
                candidate_level = "suspected"
            else:
                continue
            vid = f"{fp_id}-{getattr(c, 'id', len(vulns))}"
            severity = getattr(c, "severity", "") or "medium"
            sev_str = getattr(severity, "value", str(severity)) if severity else "medium"

            # ★ 检查该 API 是否在前端被公开调用
            public_evidence = _check_api_publicly_called(sitemap, fp_url)

            vt = getattr(c, "vuln_type", "") or getattr(c, "check_type", "") or "漏洞"
            evidence_req_text = getattr(c, "evidence_request", "") or ""
            # ★ 从 evidence_response 末尾剥离 [evidence_quality=xxx] 标记
            evidence_resp_clean, eq_value = _extract_evidence_quality(
                getattr(c, "evidence_response", "") or "")

            # ★ 标题兜底：优先用 item/description，为空时从 evidence_request
            # 提取真实接口 URL 生成 "vuln_type - url" 标题，避免空标题或纯 "漏洞 @ "
            title = _safe_str(getattr(c, "item", "")) or _safe_str(getattr(c, "description", ""))
            if not title:
                title = _make_title(vt, fp_url, evidence_req_text)

            vulns.append({
                "vuln_id": vid,
                "source": "checklist",
                "title": title,
                "vuln_type": _safe_str(getattr(c, "vuln_type", "")) or _safe_str(getattr(c, "check_type", "")) or "未知",
                "feature": fp_name or "未知功能点",
                "module": fp_module or "未知模块",
                "url": fp_url,
                "severity_original": sev_str,
                "detail": _safe_str(getattr(c, "detail", ""), 1500),
                "evidence_request": _safe_str(evidence_req_text, 2000),
                "evidence_response": _safe_str(evidence_resp_clean, 2000),
                "reproduce_steps": _safe_str(getattr(c, "reproduce_steps", ""), 1500),
                "fix_suggestion": _safe_str(getattr(c, "fix_suggestion", ""), 800),
                "public_api_evidence": public_evidence,
                "candidate_level": candidate_level,
                # ★ 证据质量（header_only=仅响应头/状态码, body_confirmed=响应体已确认含敏感数据,
                #   content_match=敏感路径内容指纹已匹配）
                "evidence_quality": eq_value,
            })

    # 2. XSS findings (status == confirmed / needs_review 都算候选)
    xss_findings = getattr(sitemap, "xss_findings", []) or []
    for f in xss_findings:
        if not isinstance(f, dict):
            continue
        if f.get("status") not in ("confirmed", "needs_review"):
            continue
        vid = f.get("id") or f"V-XSS-{len(vulns)}"
        xss_url = f.get("url", "")
        # ★ XSS 通常针对页面 URL 而非 API，公开调用检查意义不大，但仍然做一下
        public_evidence = _check_api_publicly_called(sitemap, xss_url)
        candidate_level = "confirmed" if f.get("status") == "confirmed" else "suspected"
        xss_vt = f"XSS-{f.get('xss_type', 'reflected')}"
        # ★ 标题兜底：从 evidence/payload 提取真实 URL，避免空标题
        title = f.get("title", "")
        if not title:
            xss_evidence = (f.get("evidence", "") or f.get("payload", "") or "")
            title = _make_title(xss_vt, xss_url, xss_evidence)
        vulns.append({
            "vuln_id": vid,
            "source": "xss_module",
            "title": title,
            "vuln_type": f"XSS-{f.get('xss_type', 'reflected')}",
            "feature": "",
            "module": "",
            "url": xss_url,
            "severity_original": f.get("severity", "medium"),
            "detail": f.get("description", "")[:1500],
            "browser_triggered": f.get("browser_triggered", False),
            "browser_evidence": (f.get("browser_evidence", "") or "")[:600],
            "echo_contexts": f.get("echo_contexts", []),
            "payload": f.get("payload", "")[:500],
            "reproduce_steps": (f.get("reproduce_steps", "") or "")[:1500],
            "fix_suggestion": (f.get("fix_suggestion", "") or "")[:800],
            "judge_reasoning": (f.get("judge_reasoning", "") or "")[:800],
            "public_api_evidence": public_evidence,
            "candidate_level": candidate_level,
        })

    # 3. ★ FastScanner 孤儿发现（未匹配到功能点的漏洞）
    # 之前这里漏收 → FastScanner 发现的漏洞只要没匹配功能点就永远不进 harm_validation，
    # proven 报告永远显示"无已证明的漏洞"，数据完全丢失。
    # 现在统一收集为 suspected 候选，交给 harm_validation 裁决。
    orphan_findings = getattr(sitemap, "_fast_scanner_orphan_findings", None) or []
    for idx, f in enumerate(orphan_findings):
        if not isinstance(f, dict):
            continue
        vuln_url = f.get("url", "") or ""
        public_evidence = _check_api_publicly_called(sitemap, vuln_url)
        vt = f.get("vuln_type", "") or "未知"
        orphan_evidence = (f.get("evidence", "") or f.get("payload", "") or "")
        # ★ 标题：优先从 evidence 提取真实接口 URL，比 vuln_url 更准
        title = _make_title(vt, vuln_url, orphan_evidence)
        vulns.append({
            "vuln_id": f.get("vuln_id", "") or f"V-ORPHAN-{idx}",
            "source": "fast_scanner_orphan",
            "title": title,
            "vuln_type": vt,
            "feature": "（未匹配功能点）",
            "module": "",
            "url": vuln_url,
            "method": f.get("method", ""),
            "severity_original": f.get("severity", "medium"),
            "detail": (f.get("detail", "") or "")[:1500],
            "evidence": (f.get("evidence", "") or "")[:2000],
            "payload": (f.get("payload", "") or "")[:500],
            "fix_suggestion": (f.get("fix_suggestion", "") or "")[:800],
            "public_api_evidence": public_evidence,
            # 孤儿发现未经 LLM 确认，默认疑似，交 harm_validation 裁决
            "candidate_level": "suspected",
            # ★ 证据质量（FastScanner 已标注）
            "evidence_quality": f.get("evidence_quality", "") or "",
            # ★ 优化.md 建议6：溯源 ID + 规则标签（日志→报告溯源）
            "trace_id": f.get("trace_id", "") or "",
            "rule_tag": f.get("rule_tag", "") or "",
        })

    # 4. 脚本广扫发现（统一作为 suspected 候选）
    scripted_findings = getattr(sitemap, "_scripted_scan_findings", None) or []
    for idx, f in enumerate(scripted_findings):
        if not isinstance(f, dict):
            continue
        vuln_url = f.get("url", "") or ""
        public_evidence = _check_api_publicly_called(sitemap, vuln_url)
        vt = f.get("vuln_type", "") or "未知"
        title = f.get("title", "") or _make_title(vt, vuln_url, f.get("evidence_request", "") or "")
        vulns.append({
            "vuln_id": f.get("vuln_id", "") or f"V-SCRIPTED-{idx}",
            "source": "scripted_scan",
            "phase": f.get("phase", ""),
            "owasp_id": f.get("owasp_id", ""),
            "title": title,
            "vuln_type": vt,
            "feature": "（脚本广扫发现）",
            "module": "",
            "url": vuln_url,
            "method": f.get("method", ""),
            "severity_original": f.get("severity_original", "medium"),
            "detail": (f.get("detail", "") or "")[:1500],
            "evidence_request": (f.get("evidence_request", "") or "")[:2000],
            "evidence_response": (f.get("evidence_response", "") or "")[:2000],
            "payload": (f.get("payload", "") or "")[:500],
            "fix_suggestion": (f.get("fix_suggestion", "") or "")[:800],
            "confidence": f.get("confidence", 0),
            "public_api_evidence": public_evidence,
            "candidate_level": "suspected",
            # ★ 优化.md 建议6：溯源 ID + 规则标签（日志→报告溯源）
            "trace_id": f.get("trace_id", "") or "",
            "rule_tag": f.get("rule_tag", "") or "",
        })

    return vulns


def build_context_for_llm(
    sitemap: "Sitemap",
    vulnerabilities: list[dict],
) -> str:
    """拼装上下文: 经验笔记 + 业务理解精简版 + 全部漏洞。"""
    parts: list[str] = []

    # === 经验笔记 (来自 memory.recall，最高优先级) ===
    try:
        from core import memory as _mem
        target_url = ""
        for v in vulnerabilities:
            if v.get("url"):
                target_url = v["url"]
                break
        # ★ SEC-1: 防御非字符串 vuln_type（list/dict/slice 等）导致 set 抛
        # 'unhashable type' 而让 Phase 2.6 整体崩溃。
        _vt_set: set[str] = set()
        for v in vulnerabilities:
            vt = v.get("vuln_type", "")
            if isinstance(vt, str) and vt:
                _vt_set.add(vt)
        vuln_types = " ".join(_vt_set)
        lessons = _mem.recall(target_url=target_url, vuln_type=vuln_types,
                             query="未授权访问 信息泄露 公开信息 漏洞误判", limit=10)
        if lessons:
            lessons_text = _mem.format_for_prompt(lessons)
            if lessons_text:
                parts.append(lessons_text)
                parts.append("")
    except Exception as e:
        log.debug("harm_validation: 注入经验笔记失败（非致命）: %s", e)

    # === 业务理解精简版 (供漏洞裁决参考 promises) ===
    bu = getattr(sitemap, "business_understanding", None) or {} if sitemap else {}
    if bu and bu.get("status") == "ok":
        u = bu.get("understanding") or {}
        parts.append("# 业务上下文 (来自 Phase 0.5 业务理解)")
        parts.append("")
        domain = u.get("domain") or {}
        if isinstance(domain, dict):
            # ★ 空字段兜底：domain.label 为空时显示「未识别」
            domain_label = domain.get("label", "") or "未识别"
            parts.append(f"- **领域**: {domain_label}")
        promises = u.get("promises") or []
        if promises:
            parts.append("- **系统承诺** (核心,用于裁决是否打破业务规则):")
            for p in promises[:20]:
                if isinstance(p, dict):
                    pid = p.get("id", "") or "未命名"
                    prio = p.get("priority", "") or "未定"
                    stmt = (p.get("statement", "") or p.get("promise", "") or "未描述")[:160]
                    parts.append(f"  - [{prio}] {pid}: {stmt}")
        # 关键数据资产
        data_landscape = u.get("data_landscape") or []
        if data_landscape:
            parts.append("- **关键数据资产** (用于裁决危害严重性):")
            for d in data_landscape[:10]:
                if isinstance(d, dict):
                    # ★ 空字段兜底：name/owner 为空时显示「未知」
                    name = d.get("name", "") or "未知资产"
                    owner = d.get("owner", "") or "未知"
                    parts.append(f"  - {name} (所有者: {owner})")
        parts.append("")

    # === 漏洞清单 ===
    # ★ P0-3: 防御 vulnerabilities 非列表或包含非字典项的边界情况
    if not isinstance(vulnerabilities, list):
        vulnerabilities = _safe_list(vulnerabilities)
    parts.append(f"# 待裁决漏洞清单 (共 {len(vulnerabilities)} 个)")
    parts.append("")
    for i, v in enumerate(vulnerabilities, 1):
        if not isinstance(v, dict):
            parts.append(f"## 漏洞 {i}: [数据格式异常]")
            parts.append("")
            continue
        # ★ vuln_id 兜底：避免显示为 "x" 或空值
        vuln_id = _safe_str(v.get("vuln_id", "")) or f"V-{i}"
        title = _safe_str(v.get("title", "")) or "未命名漏洞"
        vuln_type = _safe_str(v.get("vuln_type", "")) or "未知"
        candidate_level = _safe_str(v.get("candidate_level", "")) or "unknown"
        parts.append(f"## 漏洞 {i}: {vuln_id} [{candidate_level}]")
        parts.append("")
        parts.append(f"- **标题**: {title}")
        parts.append(f"- **类型**: {vuln_type}")
        parts.append(f"- **候选级别**: {candidate_level}（confirmed=已确认/suspected=疑似待验证）")
        eq = _safe_str(v.get("evidence_quality", "")) or ""
        if eq:
            eq_desc = {
                "header_only": "仅响应头/状态码证据（最易误报，必须实测复现才能 accepted）",
                "body_confirmed": "响应体已确认含敏感数据",
                "content_match": "敏感路径内容指纹已匹配",
            }.get(eq, eq)
            parts.append(f"- **证据质量**: {eq} — {eq_desc}")
        parts.append(f"- **来源**: {_safe_str(v.get('source', '')) or '未知'}")
        parts.append(f"- **URL**: `{_safe_str(v.get('url', '')) or '未知'}`")
        parts.append(f"- **功能模块**: {_safe_str(v.get('module', '')) or _safe_str(v.get('feature', '')) or '未知'}")
        parts.append(f"- **原始严重等级**: {_safe_str(v.get('severity_original', '')) or 'medium'}")
        if v.get("payload"):
            parts.append(f"- **Payload**: `{_safe_str(v['payload'], 200)}`")
        if v.get("echo_contexts"):
            parts.append(f"- **回显上下文**: {v['echo_contexts']}")
        if v.get("browser_triggered") is not None:
            parts.append(f"- **浏览器实测触发**: {v.get('browser_triggered')}")
            if v.get("browser_evidence"):
                parts.append(f"  证据: {_safe_str(v['browser_evidence'], 300)}")
        if v.get("detail"):
            parts.append(f"- **详细说明**: {_safe_str(v['detail'], 800)}")
        if v.get("evidence_request"):
            parts.append(f"- **请求证据**:")
            parts.append("  ```")
            parts.append(f"  {_safe_str(v['evidence_request'], 600)}")
            parts.append("  ```")
        if v.get("evidence_response"):
            parts.append(f"- **响应证据**:")
            parts.append("  ```")
            parts.append(f"  {_safe_str(v['evidence_response'], 600)}")
            parts.append("  ```")
        if v.get("reproduce_steps"):
            parts.append(f"- **复现步骤**: {_safe_str(v['reproduce_steps'], 400)}")
        if v.get("judge_reasoning"):
            parts.append(f"- **此前研判**: {_safe_str(v['judge_reasoning'], 300)}")
        if v.get("public_api_evidence"):
            parts.append(f"- **⚠️ 公开API证据**: {_safe_str(v['public_api_evidence'])}")
            parts.append(f"  → 如果该接口返回的数据在前端页面已公开可见，这是公开接口不算漏洞，应判 rejected")
        parts.append("")

    parts.append("---")
    parts.append("")
    parts.append("请按提示词要求,对每个漏洞独立裁决,严格输出 JSON 数组 + 100 字总评。")

    return "\n".join(parts)
