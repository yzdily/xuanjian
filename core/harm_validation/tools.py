"""
工具 Schema 构建、Exploit Skills 方法论注入、FuzzRouter 桥接。

职责：
- 构建 harm 模式下允许的工具 schema
- 加载 exploit skills 方法论内容
- 执行 fuzz_exploit 工具调用
- 构建救援消息
- 格式化工具请求
"""

from __future__ import annotations

import json
import logging
from typing import Any

log = logging.getLogger(__name__)

# ★ exploit skill 加载
from core.skill_registry import find_exploit_skills_for_vuln
from core.prompts import load_prompt

# 允许 harm_validation LLM 使用的工具子集（只读 + 重发请求，不改 sitemap/不写笔记）
HARM_TOOL_NAMES = {
    "proxy_send_request", "proxy_replay", "proxy_get_traffic",
    "proxy_get_flow_detail", "proxy_diff_responses",
    "fuzz_exploit",  # ★ 调用 FuzzRouter 自动化利用引擎
}


def build_harm_tool_schema() -> list[dict]:
    """从 core.tools 抽出 harm 模式下允许的工具 schema。"""
    try:
        from core.tools import ALL_MAIN_TOOLS
    except Exception:
        return []
    schemas = [t for t in ALL_MAIN_TOOLS
               if t.get("type") == "function"
               and t.get("function", {}).get("name") in HARM_TOOL_NAMES]

    # ★ 追加 fuzz_exploit 工具 schema（不在 ALL_MAIN_TOOLS 中，手动定义）
    fuzz_exploit_schema = {
        "type": "function",
        "function": {
            "name": "fuzz_exploit",
            "description": (
                "调用 Fuzz 引擎（像 Burp Intruder）批量发送请求。"
                "适用场景：1) SQL盲注逐字符提取数据 2) WAF绕过批量fuzz payload变体 3) 竞态条件并发。"
                "引擎会在发现响应差异时自动停止（状态码变化/body长度变化）。"
                "使用方式：先用 proxy_send_request 探路确认注入点，再调用本工具批量执行。"
                "WAF绕过场景：传入 payload_list（你生成的绕过变体列表），引擎会逐个发送并在绕过成功时停止。"
                "SQL盲注场景：传入 working_payload_template（已验证可用的盲注模板），引擎自动提取数据。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {
                        "type": "string",
                        "description": "漏洞/fuzz类型：SQL注入、WAF绕过、竞态条件",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "目标 URL（完整，含 path + query）",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP 方法，默认 GET",
                        "default": "GET",
                    },
                    "param_name": {
                        "type": "string",
                        "description": "注入参数名（如 id、keyword）",
                    },
                    "original_value": {
                        "type": "string",
                        "description": "参数原始值",
                        "default": "",
                    },
                    "headers": {
                        "type": "object",
                        "description": "请求头（含 Cookie/Authorization）",
                        "default": {},
                    },
                    "body": {
                        "type": "string",
                        "description": "请求体（POST 场景）",
                        "default": "",
                    },
                    "working_payload_template": {
                        "type": "string",
                        "description": "已验证可用的 payload 模板。SQL盲注示例：\"1' AND IF(ASCII(SUBSTR(({expr}),{pos},1))>{mid},SLEEP(3),0)-- -\"",
                        "default": "",
                    },
                    "injection_type": {
                        "type": "string",
                        "description": "注入类型提示：error_based/union/blind_time/blind_bool",
                        "default": "",
                    },
                    "payload_list": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "WAF绕过场景：你生成的 payload 变体列表，引擎会逐个发送并在绕过成功时停止",
                        "default": [],
                    },
                    "bypass_notes": {
                        "type": "string",
                        "description": "WAF 绕过方式说明（如 '内联注释绕过'、'双重URL编码'）",
                        "default": "",
                    },
                    "hints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "利用提示",
                        "default": [],
                    },
                },
                "required": ["vuln_type", "target_url", "param_name"],
            },
        },
    }
    # 只有当 fuzz_exploit 不在已有 schema 中时才追加
    if not any(s.get("function", {}).get("name") == "fuzz_exploit" for s in schemas):
        schemas.append(fuzz_exploit_schema)

    return schemas


def build_exploit_methodology(vuln_types: set[str]) -> str:
    """根据漏洞类型集合，加载对应的 exploit skills 方法论内容。

    设计：
    - 每种漏洞类型加载对应的 exploit skill（如 SQL注入 → exploit-sqli）
    - 始终附加 exploit-universal-bypass（通用绕过方法论）
    - 控制总长度，避免上下文爆炸（每个 skill 最多 3000 字符）
    """
    if not vuln_types:
        return ""

    loaded_skills: list[tuple[str, str]] = []
    loaded_names: set[str] = set()

    for vt in vuln_types:
        if not vt:
            continue
        skills = find_exploit_skills_for_vuln(vt)
        for name, content in skills:
            if name not in loaded_names:
                loaded_names.add(name)
                # 截断单个 skill 内容，防止上下文爆炸
                truncated = content[:3000]
                if len(content) > 3000:
                    truncated += "\n\n... (方法论内容已截断，请基于以上策略灵活应用)"
                loaded_skills.append((name, truncated))

    if not loaded_skills:
        log.info("exploit skills 未找到匹配的方法论, vuln_types=%s", vuln_types)
        return ""

    log.info(
        "exploit skills 已加载: %s (vuln_types=%s)",
        [name for name, _ in loaded_skills],
        vuln_types,
    )

    parts = ["\n\n# 🔥 漏洞利用方法论（exploit skills 自动注入）\n"]
    parts.append("> 以下方法论来自 exploit skills，指导你如何绕过防护、深入利用漏洞证明危害。\n")
    parts.append("> 对于需要大量请求的场景（盲注提取、并发竞态），优先使用 `fuzz_exploit` 工具。\n")
    parts.append("> 对于需要灵活构造 payload 的场景（WAF绕过、编码变体），用 `proxy_send_request` 手动构造。\n")

    for name, content in loaded_skills:
        parts.append(f"\n## 📖 {name}\n")
        parts.append(content)

    return "\n".join(parts)


async def execute_fuzz_exploit(args: dict) -> str:
    """执行 fuzz_exploit 工具 — 桥接 FuzzRouter 自动化利用引擎。

    将 LLM 传入的参数转换为 FuzzTask，调用 FuzzRouter 执行，
    返回结构化的利用证据文本。
    """
    from core.fuzz.registry import get_fuzz_router
    from core.fuzz.base import FuzzTask, FuzzResult

    try:
        vuln_type = args.get("vuln_type", "")
        target_url = args.get("target_url", "")
        param_name = args.get("param_name", "")

        if not vuln_type or not target_url:
            return "错误：vuln_type 和 target_url 为必填参数"

        task = FuzzTask(
            vuln_type=vuln_type,
            target_url=target_url,
            method=args.get("method", "GET"),
            param_name=param_name,
            original_value=args.get("original_value", ""),
            headers=args.get("headers") or {},
            body=args.get("body", ""),
            hints=args.get("hints") or [],
            # ★ LLM 可传入已验证的 payload 模板（WAF 绕过/盲注场景）
            working_payload_template=args.get("working_payload_template", ""),
            injection_type=args.get("injection_type", ""),
            bypass_notes=args.get("bypass_notes", ""),
            payload_list=args.get("payload_list") or [],
            timeout=30.0,
            max_requests=100,
        )

        router = get_fuzz_router()
        evidence = await router.fuzz(task)

        if evidence is None:
            return "FuzzRouter 未返回结果（可能不支持该漏洞类型或无匹配策略）"

        if evidence.result == FuzzResult.CONFIRMED:
            parts = [
                "✅ **Fuzz 利用成功！**",
                f"- 结果: {evidence.result.value}",
                f"- 摘要: {evidence.summary}",
            ]
            if evidence.extracted_data:
                parts.append(f"- 提取数据: {json.dumps(evidence.extracted_data, ensure_ascii=False)[:2000]}")
            if evidence.successful_payloads:
                parts.append(f"- 成功 payload: {evidence.successful_payloads[:5]}")
            if evidence.requests_sent:
                parts.append(f"- 发送请求数: {evidence.requests_sent}")
            return "\n".join(parts)
        else:
            parts = [
                f"⚠️ Fuzz 未确认利用成功",
                f"- 结果: {evidence.result.value}",
                f"- 摘要: {evidence.summary}",
            ]
            if evidence.extracted_data:
                parts.append(f"- 部分数据: {json.dumps(evidence.extracted_data, ensure_ascii=False)[:1000]}")
            if evidence.requests_sent:
                parts.append(f"- 发送请求数: {evidence.requests_sent}")
            return "\n".join(parts)

    except Exception as e:
        log.exception("fuzz_exploit 执行异常")
        return f"fuzz_exploit 执行异常: {e}"


def build_rescue_messages(
    vulns: list[dict],
    user_context: str,
    tool_trace: list[dict],
) -> list:
    """构造救援用的最小上下文。

    设计要点：
    - 不携带主循环的 messages（避免工具结果污染注意力）
    - 系统提示极简，只强调"输出 JSON"
    - user 消息把漏洞清单格式化为简表，让 LLM 一眼能扫
    - 简要列出 tool_trace 摘要，告诉 LLM 之前测过什么
    """
    from core.llm import Message
    # 用极简漏洞清单（去掉冗余字段，保留 vuln_id + 类型 + 描述）
    vuln_lines = []
    for v in vulns:
        vid = v.get("vuln_id", "?")
        vtype = v.get("vuln_type", "?")
        fp_name = v.get("feature_name", "?")
        detail = (v.get("detail") or "")[:200].replace("\n", " ")
        vuln_lines.append(f"- {vid} [{vtype}] @ {fp_name}: {detail}")
    vuln_summary = "\n".join(vuln_lines)

    # 简要列出 tool_trace（如有）
    trace_summary = ""
    if tool_trace:
        trace_lines = []
        for t in tool_trace[-5:]:  # 最多 5 条
            tn = t.get("tool", "?")
            args_brief = str(t.get("args", ""))[:80]
            res_brief = str(t.get("result_preview", ""))[:100].replace("\n", " ")
            trace_lines.append(f"- {tn}({args_brief}) → {res_brief}")
        trace_summary = "\n\n## 你刚才调过的工具（最后 5 条）\n" + "\n".join(trace_lines)

    rescue_system = load_prompt("rescue_system")

    rescue_user = (
        f"请对以下 {len(vulns)} 个候选漏洞输出最终裁决 JSON 数组：\n\n"
        f"## 漏洞清单\n{vuln_summary}\n"
        f"{trace_summary}\n\n"
        "## 输出格式（严格遵守）\n"
        "```json\n"
        "[\n"
        "  {\n"
        '    "vuln_id": "fp_X/漏洞类型",\n'
        '    "verdict": "accepted" | "borderline" | "rejected",\n'
        '    "platform_level": "高危" | "中危" | "低危" | "信息",\n'
        '    "harm_story": "一句话说危害",\n'
        '    "evidence_strength": "强/中/弱",\n'
        '    "poc_request": "method url 关键参数",\n'
        '    "poc_response": "状态码 + 关键响应片段",\n'
        '    "poc_note": "一句话怎么验证的"\n'
        "  }\n"
        "]\n"
        "```\n\n"
        "**立即输出 JSON 数组，不要任何其他文字**。"
    )

    return [
        Message(role="system", content=rescue_system),
        Message(role="user", content=rescue_user),
    ]


def generate_placeholder_verdicts(vulns: list[dict]) -> str:
    """救援彻底失败时的兜底：基于原漏洞证据质量生成确定性裁决（优化.md P0-3）。

    设计原则：
    - 哪怕 LLM 完全摆烂，至少给报告生成器一份可解析的数据
    - ★ 确定性降级规则（LLM 不可用时不再一刀切 rejected）：
      * evidence_quality == body_confirmed / content_match（响应体级强证据）
        → borderline（保留待人工复核，避免丢弃真实漏洞）
      * header_only / 未知（仅响应头/状态码弱证据）
        → rejected（弱证据无法人工复核，归入拒收透明披露）
    - 这样 LLM 故障时，有响应体敏感数据证据的漏洞不会被误丢弃。
    """
    # 证据质量 -> 确定性裁决
    _STRONG = ("body_confirmed", "content_match")
    verdicts = []
    for v in vulns:
        eq = (v.get("evidence_quality", "") or "").lower()
        if eq in _STRONG:
            verdicts.append({
                "vuln_id": v.get("vuln_id", "?"),
                "verdict": "borderline",
                "platform_level": "中危",
                "harm_story": f"{v.get('vuln_type', '?')}：危害验证 LLM 调用失败，"
                              f"但存在响应体级强证据({eq})，保留待人工复核",
                "evidence_strength": "中",
                "poc_request": "未生成（LLM 故障）",
                "poc_response": v.get("evidence", "")[:500] or "未生成",
                "poc_note": f"LLM 救援失败，但证据质量={eq}（响应体级），"
                            f"自动保留为 borderline 待人工复核",
            })
        else:
            verdicts.append({
                "vuln_id": v.get("vuln_id", "?"),
                "verdict": "rejected",
                "platform_level": "信息",
                "harm_story": f"{v.get('vuln_type', '?')}：危害验证 LLM 调用失败，无 PoC 数据",
                "evidence_strength": "弱",
                "poc_request": "未生成",
                "poc_response": "未生成",
                "poc_note": "LLM 救援失败 - 无 PoC 数据，危害验证未执行成功",
                "reject_reason": "危害验证 LLM 调用失败，未生成 PoC，无法人工复核",
            })
    return "```json\n" + json.dumps(verdicts, ensure_ascii=False, indent=2) + "\n```"


def format_tool_request(args: dict, tool_name: str) -> str:
    """将 proxy_send_request / proxy_replay / fuzz_exploit 的调用参数格式化为可读的 HTTP 请求摘要。"""
    if tool_name == "proxy_send_request":
        method = args.get("method", "GET")
        url = args.get("url", "")
        headers = args.get("headers") or {}
        body = args.get("body", "")
        drop_auth = args.get("drop_auth", False)
        parts = [f"{method} {url}"]
        if drop_auth:
            parts.append("（已去除认证）")
        for k, v in headers.items():
            parts.append(f"{k}: {v}")
        if body:
            parts.append(f"\n{body}")
        return "\n".join(parts)
    elif tool_name == "proxy_replay":
        flow_id = args.get("flow_id", "")
        mods = args.get("modify", {}) or {}
        drop_auth = args.get("drop_auth", False)
        parts = [f"重放 flow_id={flow_id}"]
        if drop_auth:
            parts.append("（已去除认证）")
        if mods:
            parts.append(f"修改参数: {json.dumps(mods, ensure_ascii=False)[:500]}")
        return "\n".join(parts)
    elif tool_name == "fuzz_exploit":
        vuln_type = args.get("vuln_type", "")
        target_url = args.get("target_url", "")
        method = args.get("method", "GET")
        param_name = args.get("param_name", "")
        parts = [f"FuzzRouter 自动化利用: {vuln_type}"]
        parts.append(f"{method} {target_url}")
        if param_name:
            parts.append(f"参数: {param_name}={args.get('original_value', '')}")
        hints = args.get("hints") or []
        if hints:
            parts.append(f"提示: {', '.join(hints)}")
        return "\n".join(parts)
    return json.dumps(args, ensure_ascii=False)[:500]
