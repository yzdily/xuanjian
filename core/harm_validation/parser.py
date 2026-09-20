"""
LLM 响应解析与结果最终化模块。

职责：
- 从 LLM 响应中提取 JSON 数组和审核员总评
- 最终化 harm_validation 结果（合并原漏洞、附加工具轨迹）
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from .tools import format_tool_request

log = logging.getLogger(__name__)


def parse_response(raw_text: str) -> tuple[Optional[list], str]:
    """从 LLM 响应中提取 JSON 数组和审核员总评。

    解析策略（按可靠性排序）：
    0. 先剥离 <think>...</think> 推理块（DeepSeek/QwQ/R1 类模型）
    1. ```json [...] ``` 代码块（贪婪匹配，能容纳嵌套）
    2. ``` [...] ``` 无语言标记代码块
    3. 全文搜第一个 `[` 到平衡匹配的 `]`（支持字符串内 `[` / `]` 转义）
    4. 修复常见错误（尾随逗号、单引号）后再 parse
    """
    if not raw_text:
        return None, ""

    # 0. 剥离 <think>...</think> 推理块，避免推理文本中的伪 JSON 干扰解析
    clean_text = re.sub(r"<think>[\s\S]*?</think>", "", raw_text, flags=re.IGNORECASE).strip()
    if not clean_text:
        clean_text = raw_text  # 全是 think 块时回退原文

    verdicts: Optional[list] = None

    # 1. ```json [...] ``` 代码块（贪婪匹配能容纳整段数组）
    if verdicts is None:
        m = re.search(r"```json\s*(\[[\s\S]+\])\s*```", clean_text)
        if m:
            verdicts = _try_loads_json(m.group(1))

    # 2. 无语言标记的代码块
    if verdicts is None:
        m = re.search(r"```\s*(\[[\s\S]+?\])\s*```", clean_text)
        if m:
            verdicts = _try_loads_json(m.group(1))

    # 3. 全文搜：第一个 `[` 到平衡匹配的 `]`（带字符串感知）
    if verdicts is None:
        verdicts = _extract_balanced_json_array(clean_text)

    # 4. 修复常见 LLM 输出错误后再试一次
    if verdicts is None and "[" in clean_text and "]" in clean_text:
        start = clean_text.find("[")
        end = clean_text.rfind("]")
        if 0 <= start < end:
            candidate = clean_text[start:end + 1]
            # 修尾随逗号 `,]` `,}`
            candidate = re.sub(r",(\s*[\]\}])", r"\1", candidate)
            verdicts = _try_loads_json(candidate)

    # 5. 尝试修复 LLM 常见的 JSON 字符串内未转义引号问题
    if verdicts is None and "[" in clean_text and "]" in clean_text:
        start = clean_text.find("[")
        end = clean_text.rfind("]")
        if 0 <= start < end:
            candidate = clean_text[start:end + 1]
            candidate = _fix_unescaped_quotes(candidate)
            verdicts = _try_loads_json(candidate)

    # 6. 提取审核员总评（也用 clean_text）
    summary = ""
    sum_match = re.search(r"(?:审核员总评|总评|summary)\s*[:：]\s*\n?\s*([\s\S]+?)(?:$|```)",
                          clean_text, re.IGNORECASE)
    if sum_match:
        summary = sum_match.group(1).strip()
        # 去掉可能的 markdown 加粗符号
        summary = re.sub(r"^\*+|\*+$", "", summary).strip()
        summary = summary[:500]

    if verdicts is None:
        return None, summary

    # 校验每个 verdict 的必要字段
    valid: list = []
    for vd in verdicts:
        if not isinstance(vd, dict):
            continue
        if "verdict" not in vd:
            continue
        # 默认值兜底
        vd.setdefault("vuln_id", "")
        vd.setdefault("platform_level", "no_value")
        vd.setdefault("harm_story", "")
        vd.setdefault("evidence_strength", "weak")
        vd.setdefault("broken_promises", [])
        vd.setdefault("would_be_accepted_by", [])
        vd.setdefault("reject_reason", "")
        vd.setdefault("fix_priority", "加固建议")
        valid.append(vd)

    return valid, summary


def _fix_unescaped_quotes(text: str) -> str:
    """尝试修复 JSON 字符串值中未转义的双引号。

    LLM 常见错误模式：
    - "poc_request": "POST /login.php vcode="" (删除vcode参数)"
    - "poc_request": "GET /path?param=\"value\"" (多余转义)

    策略：逐字符扫描，在 JSON 字符串值内部发现未转义的 " 时，
    判断它是否是字段结束符（后跟 , 或 } 或 ]），如果不是则转义它。
    """
    result = []
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]

        # 不在字符串中，直接复制
        if ch == '"':
            # 进入字符串
            result.append(ch)
            i += 1
            # 扫描字符串内容
            while i < n:
                c = text[i]
                if c == '\\' and i + 1 < n:
                    # 已转义字符，直接复制两个
                    result.append(c)
                    result.append(text[i + 1])
                    i += 2
                elif c == '"':
                    # 可能是字符串结束，也可能是未转义的内嵌引号
                    # 判断：如果后面紧跟 JSON 结构字符（: , } ] 或空白+这些），则是真正的结束
                    rest = text[i + 1:].lstrip()
                    if not rest or rest[0] in (',', '}', ']', ':'):
                        # 真正的字符串结束符
                        result.append(c)
                        i += 1
                        break
                    else:
                        # 未转义的内嵌引号 → 转义它
                        result.append('\\')
                        result.append(c)
                        i += 1
                else:
                    result.append(c)
                    i += 1
        else:
            result.append(ch)
            i += 1

    return ''.join(result)


def _try_loads_json(text: str) -> Optional[list]:
    """安全的 json.loads，仅接受 list 类型。"""
    try:
        result = json.loads(text)
        return result if isinstance(result, list) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _extract_balanced_json_array(text: str) -> Optional[list]:
    """从文本中提取第一个平衡的 JSON 数组，正确处理字符串内的方括号和转义。"""
    start = text.find("[")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape_next = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return _try_loads_json(text[start:i + 1])
    return None


def finalize_harm_result(
    raw_text: str,
    vulns: list[dict],
    tool_trace: list[dict],
    elapsed: float,
) -> dict:
    """统一收尾：解析 JSON、合并原漏洞、附加工具调用轨迹。"""
    verdicts, summary = parse_response(raw_text)
    if verdicts is None:
        return {
            "status": "error",
            "error": "with-tools 模式 LLM 输出无法解析为 JSON 数组",
            "raw_response": raw_text[:5000],
            "tool_trace": tool_trace,
            "elapsed": elapsed,
        }

    vuln_by_id = {v["vuln_id"]: v for v in vulns}
    for vd in verdicts:
        vid = vd.get("vuln_id", "")
        if vid in vuln_by_id:
            vd["_original"] = vuln_by_id[vid]

    # ★ 将 tool_trace 中的原始 HTTP 包关联到对应 verdict
    # 策略：proxy_send_request/proxy_replay 的调用参数含 url，
    #        匹配 verdict._original.url（前缀匹配）或 poc_request 中提到的 URL
    has_real_poc = False  # ★ 是否有至少一次真实 PoC 复现
    for tr in tool_trace:
        if tr.get("tool") in ("proxy_send_request", "proxy_replay", "fuzz_exploit"):
            has_real_poc = True
            break

    for vd in verdicts:
        orig = vd.get("_original") or {}
        target_url = orig.get("url", "")
        poc_req_text = vd.get("poc_request", "")
        matched_traces = []
        for tr in tool_trace:
            tool_name = tr.get("tool", "")
            if tool_name not in ("proxy_send_request", "proxy_replay", "fuzz_exploit"):
                continue
            tr_args = tr.get("args") or {}
            tr_url = tr_args.get("url", "") or tr_args.get("target_url", "")
            # 匹配：trace URL 与漏洞 URL 前缀匹配，或 poc_request 文本中提到该 URL
            if (tr_url and target_url and (
                tr_url.startswith(target_url) or target_url.startswith(tr_url)
            )) or (tr_url and tr_url in poc_req_text):
                matched_traces.append({
                    "tool": tool_name,
                    "request": format_tool_request(tr_args, tool_name),
                    "response": tr.get("result_preview", ""),
                })
        if matched_traces:
            vd["_raw_traces"] = matched_traces
            # ★ 用实测结果覆盖 LLM 编造的 poc_request/poc_response
            best = matched_traces[0]
            vd["poc_request"] = best["request"]
            vd["poc_response"] = best["response"][:500]
            vd["poc_note"] = "实测复现（工具调用结果自动注入）"

        # ★ 核心修复 1：仅响应头证据(header_only)的 accepted → 降级为 rejected（优先）
        # 纯响应头/状态码/banner/版本号泄露不构成可被 SRC 收录的漏洞；
        # 只有当 LLM 实测复现(matched_traces 非空)并拿到敏感数据时才保留 accepted。
        orig_eq = (orig.get("evidence_quality", "") or "").lower()
        if (orig_eq == "header_only"
                and vd.get("verdict") == "accepted"
                and not matched_traces):
            log.warning(
                "harm_validation: vuln %s 为 header_only 证据却被 accepted，降级为 rejected",
                vd.get("vuln_id", "?"),
            )
            vd["verdict"] = "rejected"
            old_note = vd.get("poc_note", "")
            vd["poc_note"] = (
                "⛔ 仅响应头/状态码证据(header_only)，无实测复现，"
                "纯响应头信息不构成可被 SRC 收录的漏洞，自动降级为 rejected。"
                + (f" 原说明: {old_note}" if old_note else "")
            )
            vd["reject_reason"] = (
                "仅响应头/状态码证据（header_only），未实测复现敏感数据，"
                "属合规/banner 问题而非可收录漏洞"
            )

        # ★ 核心修复 2：未实际调 proxy_send_request 就判 accepted → 降级为 borderline
        # 但 body_confirmed / content_match 是响应体级强证据（已含敏感数据/指纹匹配），
        # 可不依赖工具实测复现即保留 accepted，避免误降级真实漏洞。
        elif (not matched_traces
                and vd.get("verdict") == "accepted"
                and tool_trace is not None
                and orig_eq not in ("body_confirmed", "content_match")):
            log.warning(
                "harm_validation: vuln %s accepted 但无实测复现且非强证据(%s)，降级为 borderline",
                vd.get("vuln_id", "?"), orig_eq or "无标签",
            )
            vd["verdict"] = "borderline"
            old_note = vd.get("poc_note", "")
            vd["poc_note"] = (
                "⚠️ 未实际调 proxy_send_request 复现 PoC，仅凭旧证据裁决，自动降级为 borderline。"
                + (f" 原说明: {old_note}" if old_note else "")
            )
            # 如果没有真实 PoC 复现，poc_request/poc_response 也应标记为不可信
            if not vd.get("_raw_traces"):
                vd["poc_request"] = vd.get("poc_request", "") + " (⚠️ LLM 自述，非实测)"
                vd["poc_response"] = vd.get("poc_response", "") + " (⚠️ LLM 自述，非实测)"

    stats = {"accepted": 0, "borderline": 0, "rejected": 0}
    for vd in verdicts:
        v = vd.get("verdict", "rejected")
        if v in stats:
            stats[v] += 1

    return {
        "status": "ok",
        "verdicts": verdicts,
        "summary": summary,
        "stats": stats,
        "total_vulns": len(vulns),
        "raw_response": raw_text[:30000],
        "tool_trace": tool_trace,  # 留作审计
        "elapsed": elapsed,
        "mode": "with_tools",
    }
