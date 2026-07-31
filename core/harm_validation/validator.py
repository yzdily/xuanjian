"""
危害验证核心逻辑 — 批量裁决（Phase 2.6）。

职责：
- validate_harm: 主入口，对所有漏洞做危害验证
- _validate_harm_with_tools: 带工具的多轮验证循环
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.llm import parse_tool_call_arguments
from .context import collect_vulnerabilities, build_context_for_llm
from .tools import (
    HARM_TOOL_NAMES,
    build_harm_tool_schema,
    build_exploit_methodology,
    execute_fuzz_exploit,
    build_rescue_messages,
    generate_placeholder_verdicts,
)
from .parser import parse_response, finalize_harm_result

if TYPE_CHECKING:
    from core.llm import LLMClient
    from core.sitemap import Sitemap

log = logging.getLogger(__name__)

PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "harm_validation.md"


async def validate_harm(
    sitemap: "Sitemap",
    llm: "LLMClient",
    timeout: float = 120.0,
    tool_executor: Any = None,
    max_rounds: int = 15,
) -> dict:
    """对所有漏洞做危害验证。

    新参数（可选）：
    - tool_executor: 若提供，启用"带工具调用的多轮复现验证"模式，LLM 会真实调用
      proxy_send_request 等工具复现 PoC，拿到实测响应后才出裁决；不提供则走原有的
      纯文本判断模式（向后兼容）。
    - max_rounds: 工具循环最大轮次（仅 with-tools 模式生效）。

    Returns:
        {
            "status": "ok" / "error" / "timeout" / "no_vulns",
            "verdicts": list[dict],  # 每个漏洞的裁决
            "summary": str,           # 审核员总评
            "stats": {accepted, borderline, rejected},
            "raw_response": str,
            "elapsed": float,
        }
    """
    started = time.time()
    if not PROMPT_PATH.exists():
        return {"status": "error", "error": f"提示词缺失: {PROMPT_PATH}",
                "elapsed": 0}

    vulns = collect_vulnerabilities(sitemap)
    if not vulns:
        return {"status": "no_vulns",
                "verdicts": [],
                "summary": "无已发现漏洞,跳过危害验证",
                "stats": {"accepted": 0, "borderline": 0, "rejected": 0},
                "elapsed": time.time() - started}

    try:
        system_prompt = PROMPT_PATH.read_text(encoding="utf-8")
        user_context = build_context_for_llm(sitemap, vulns)
    except Exception as e:
        return {"status": "error", "error": f"上下文拼装失败: {e}",
                "elapsed": time.time() - started}

    # ★ with-tools 模式：让 LLM 真实调用 proxy_send_request 等工具复现 PoC
    if tool_executor is not None:
        try:
            return await asyncio.wait_for(
                _validate_harm_with_tools(
                    sitemap=sitemap,
                    llm=llm,
                    tool_executor=tool_executor,
                    vulns=vulns,
                    system_prompt=system_prompt,
                    user_context=user_context,
                    max_rounds=max_rounds,
                    started=started,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return {"status": "timeout",
                    "error": f"with-tools 模式超过 {timeout}s",
                    "elapsed": time.time() - started}
        except Exception as e:
            log.exception("harm_validation with-tools 模式失败")
            return {"status": "error",
                    "error": f"with-tools 模式失败: {e}",
                    "elapsed": time.time() - started}

    from core.llm import Message
    messages = [
        Message(role="system", content=system_prompt),
        Message(role="user", content=user_context),
    ]

    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(llm.chat, messages, caller="harm_validation"),
            timeout=timeout,
        )
        raw_text = response.content or ""
    except asyncio.TimeoutError:
        return {"status": "timeout",
                "error": f"LLM 调用超过 {timeout}s",
                "elapsed": time.time() - started}
    except Exception as e:
        log.exception("harm_validation LLM call failed")
        return {"status": "error",
                "error": f"LLM 调用失败: {e}",
                "elapsed": time.time() - started}

    elapsed = time.time() - started
    verdicts, summary = parse_response(raw_text)
    if verdicts is None:
        return {"status": "error",
                "error": "无法解析 JSON 数组",
                "raw_response": raw_text[:5000],
                "elapsed": elapsed}

    # 把原漏洞数据合并回 verdict (用于报告渲染时引用原始证据)
    vuln_by_id = {v["vuln_id"]: v for v in vulns}
    for vd in verdicts:
        vid = vd.get("vuln_id", "")
        if vid in vuln_by_id:
            vd["_original"] = vuln_by_id[vid]
        else:
            # ★ 2026-05-25 修复：LLM 可能省略 V- 前缀或格式有变，做模糊匹配 fallback
            for k, v in vuln_by_id.items():
                if k == vid or k.lstrip("V-") == vid or vid.lstrip("V-") == k:
                    vd["_original"] = v
                    break

    # 统计
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
        "elapsed": elapsed,
    }


async def _validate_harm_with_tools(
    sitemap: "Sitemap",
    llm: "LLMClient",
    tool_executor: Any,
    vulns: list[dict],
    system_prompt: str,
    user_context: str,
    max_rounds: int,
    started: float,
) -> dict:
    """让 LLM 真实重发请求复现每个候选漏洞，再产出最终裁决 JSON。

    流程：
    1. system 提示加上"必须先调 proxy_send_request 复现 PoC，再裁决"
    2. 多轮 LLM 调用：
       - LLM 调工具 → 我们执行 → 把结果回喂
       - 直到 LLM 不再调工具，输出最终 JSON 数组
    3. 解析 JSON，把工具调用过程中实测的请求/响应作为 poc_request/poc_response 注入 verdicts
    """
    from core.llm import Message

    # ★ 收集所有漏洞类型，加载对应的 exploit skills 方法论
    vuln_types_set = {v.get("vuln_type", "") for v in vulns if v.get("vuln_type")}
    exploit_methodology = build_exploit_methodology(vuln_types_set)

    # 增强系统提示，要求"先复现，再裁决"
    enhanced_system = (
        system_prompt
        + "\n\n# ⚙️ 工具使用规则（with-tools 模式）\n\n"
        "你拥有 `proxy_send_request` / `proxy_replay` / `proxy_get_flow_detail` 等工具。\n"
        "**对每个候选漏洞，你必须按以下流程执行：**\n\n"
        "1. **复现 PoC**：用 `proxy_send_request` 发起一个能证明危害的请求\n"
        "   - 例如未授权访问 → 不带 Cookie 请求接口\n"
        "   - 例如 IDOR → 把 user_id 改成他人的\n"
        "   - 例如 CORS → 带 Origin: https://evil.com 请求并观察响应头\n"
        "   - 例如 SQL 注入 → 发布注入 payload 看响应差异\n"
        "2. **观察响应**：检查响应是否真包含敏感数据 / 真触发了越权\n"
        "3. **基于实测做裁决**：\n"
        "   - 实测能拿到敏感数据 → accepted\n"
        "   - 实测拿不到任何东西（如反射 Origin 但接口仍 401）→ rejected\n"
        "   - 拿不准 → borderline\n\n"
        "你最多有 " + str(max_rounds) + " 轮工具调用机会。**轮次有限，挑最有可能成立的漏洞优先复现**，"
        "不需要每个都复现（明显是配置不规范、无利用链的可以直接 rejected）。\n\n"
        "⚠️ **关键约束——禁止用 proxy_get_traffic 代替实际复现**：\n"
        "- `proxy_get_traffic` 只是查看历史流量记录，**不能替代 proxy_send_request 做实际 PoC 复现**\n"
        "- 对于\"未授权访问\"类漏洞，**必须**用 `proxy_send_request` 发一个 `drop_auth=true` 的请求，"
        "观察响应中是否包含真实敏感数据（PII/私有资产/内部配置），而不是仅看流量摘要就下结论\n"
        "- 如果漏洞上下文中已有 `⚠️ 公开API证据`，说明该接口在前端已被公开调用，"
        "你只需用 proxy_send_request 确认返回的数据是否确实是公开数据即可——"
        "如果返回的是交易参数、利率、公告等面向公众的信息，**直接 rejected**\n\n"
        "⛔ **致命规则——未实测就判 accepted 会被自动降级**：\n"
        "- 系统会检查你的 tool_trace：如果你输出 `verdict: accepted` 但 tool_trace 中"
        "没有任何 `proxy_send_request` 或 `proxy_replay` 调用匹配到该漏洞，"
        "**该 accepted 会被自动降级为 borderline**，poc_request/poc_response 会被标记为不可信\n"
        "- 因此：**要判 accepted，就必须先用 proxy_send_request 实测复现**；"
        "如果复现不了，就判 borderline 或 rejected\n"
        "- 唯一例外：漏洞类型是\"版本号泄露/banner泄露\"等纯合规问题，直接 rejected 即可，无需实测\n\n"
        "**完成所有调查后**，输出最终 JSON 数组（按提示词原格式），并在每条 verdict 中追加两个字段：\n"
        "- `poc_request`: 你刚刚用 proxy_send_request 发出的实测请求摘要（method + url + 关键 header/body）\n"
        "- `poc_response`: 实测响应的关键片段（状态码 + 关键 header + body 前 500 字，含敏感数据样例）\n"
        "- `poc_note`: 一句话说明你怎么验证的（如 '不带 Cookie 请求返回 200 + 用户列表，确认未授权'）\n\n"
        "如果某条漏洞你没有亲自复现就裁决（例如时间不够），在 `poc_note` 中明确写"
        "'未复现，仅基于子 Agent 留下的证据'，并优先标 borderline。"
    )

    # ★ 注入 exploit skills 方法论（WAF绕过/深入利用策略）
    if exploit_methodology:
        enhanced_system += exploit_methodology

    messages: list = [
        Message(role="system", content=enhanced_system),
        Message(role="user", content=user_context),
    ]
    tools_schema = build_harm_tool_schema()
    if not tools_schema:
        log.warning("harm_validation: 无可用工具 schema，回退纯文本模式")
        # 回退：直接调一次 LLM 不带工具
        response = await asyncio.to_thread(
            llm.chat, messages, caller="harm_validation_no_tool")
        return finalize_harm_result(
            response.content or "", vulns, [], time.time() - started)

    # 工具调用过程中所有实测的 request/response
    tool_trace: list[dict] = []

    raw_text_parts: list[str] = []  # ★ 累积所有轮次的 content
    final_text = ""
    _empty_retry_done = False  # ★ 空响应原地重试标志

    for rd in range(1, max_rounds + 1):
        # ★ 末轮强制收尾：最后一轮不再给工具，逼 LLM 输出 JSON
        is_last_round = (rd == max_rounds)
        if is_last_round:
            messages.append(Message(
                role="user",
                content=(
                    "⛔ **工具调用轮次已用尽**。\n\n"
                    "现在请基于前面所有实测证据，**只输出最终 JSON 数组**（用 ```json ... ``` 包裹），"
                    "不要再调工具，不要任何额外说明文字。\n\n"
                    "数组格式参考系统提示词，每条 verdict 必须包含 `vuln_id`、`verdict`、"
                    "`platform_level`、`harm_story`、`evidence_strength`、"
                    "`poc_request`、`poc_response`、`poc_note` 等字段。"
                )
            ))

        try:
            response = await asyncio.to_thread(
                llm.chat,
                messages,
                None if is_last_round else tools_schema,  # ★ 末轮不带工具
                caller=f"harm_validation_t{rd}"
            )
        except Exception as e:
            log.warning("harm_validation 第 %d 轮 LLM 调用失败: %s", rd, e)
            break

        # 把 assistant 消息（含 tool_calls）回填到对话
        assistant_msg = Message(
            role="assistant",
            content=response.content or "",
            tool_calls=response.tool_calls or [],
        )
        messages.append(assistant_msg)

        if response.content:
            raw_text_parts.append(response.content)
            final_text = response.content  # 保留最后一次（用于 fallback 展示）

        if not response.tool_calls:
            # LLM 不再调工具 → 视为完成
            if not response.content and not _empty_retry_done:
                log.warning(
                    "harm_validation 第 %d 轮 LLM 空响应，尝试原地重试一次",
                    rd,
                )
                _empty_retry_done = True
                messages.append(Message(
                    role="user",
                    content=(
                        "你刚才没有输出任何文本，也没有调用工具。\n"
                        "请基于已有的工具调查结果（如有），继续推理：\n"
                        "  - 还需要调用工具复现别的漏洞 → 继续调工具\n"
                        "  - 已经够了 → 直接输出最终 JSON 数组（用 ```json ... ``` 包裹）\n"
                        "**禁止再次返回空响应**。"
                    )
                ))
                continue
            if not response.content:
                log.warning(
                    "harm_validation 第 %d 轮 LLM 重试后仍空响应，提前退出",
                    rd,
                )

            # ★ 核心修复：危害证明链路强制执行
            has_send_request = any(
                tr.get("tool") in ("proxy_send_request", "proxy_replay", "fuzz_exploit")
                for tr in tool_trace
            )
            # 还有剩余轮次才能拦截（避免死循环）
            if not has_send_request and rd < max_rounds - 2 and not is_last_round:
                log.warning(
                    "harm_validation 第 %d 轮 LLM 未调 proxy_send_request 就想出裁决，"
                    "强制要求先实测复现",
                    rd,
                )
                messages.append(Message(
                    role="user",
                    content=(
                        "⛔ **你还没有用 proxy_send_request 真实复现任何 PoC！**\n\n"
                        "你的危害证明链路不完整——只看了历史流量（proxy_get_traffic）"
                        "或者根本没调工具，这不能作为 accepted 的依据。\n\n"
                        "**现在请：**\n"
                        "1. 对每个想判 accepted 的漏洞，调用 `proxy_send_request` 真实复现\n"
                        "2. 根据实测响应决定裁决（拿到敏感数据 → accepted，"
                        "只拿到 WAF 拦截页/404/公开数据 → rejected）\n"
                        "3. 最后输出完整 JSON 数组\n\n"
                        "⚠️ 不调 proxy_send_request 就判 accepted 会被系统自动降级为 borderline！"
                    )
                ))
                continue

            break

        if is_last_round:
            # 末轮已强制无工具但 LLM 仍尝试 tool_calls → 直接退出
            log.warning("harm_validation 末轮 LLM 仍返回 tool_calls，忽略并退出")
            break

        # 执行工具
        for tc in response.tool_calls:
            func_name = tc["function"]["name"]
            args, _args_failed = parse_tool_call_arguments(
                tc["function"]["arguments"], caller="harm_validator")

            if func_name not in HARM_TOOL_NAMES:
                tool_result = f"工具 {func_name} 在 harm_validation 中不可用"
            elif func_name == "fuzz_exploit":
                # ★ 特殊处理：调用 FuzzRouter 自动化利用引擎
                tool_result = await execute_fuzz_exploit(args)
            else:
                try:
                    tool_result = await tool_executor.execute(func_name, args)
                except Exception as e:
                    tool_result = f"工具 {func_name} 执行失败: {e}"

            # 截断防止上下文爆炸
            tool_result_short = (str(tool_result)[:4000] if tool_result else "")

            tool_trace.append({
                "round": rd,
                "tool": func_name,
                "args": args,
                "result_preview": tool_result_short[:1500],
            })

            messages.append(Message(
                role="tool",
                content=tool_result_short,
                tool_call_id=tc.get("id", ""),
            ))

    # ★ 累积所有轮次的 content，优先用最后一次
    raw_text = final_text or "\n\n".join(raw_text_parts)

    log.info(
        "harm_validation 主循环结束: rounds_done=%d, final_text_len=%d, "
        "raw_text_len=%d, tool_calls=%d",
        rd, len(final_text), len(raw_text), len(tool_trace),
    )

    # ★ 救援：解析失败时再做一次"裸 JSON"调用
    verdicts_check, _ = parse_response(raw_text)
    if verdicts_check is None:
        log.warning(
            "harm_validation: 末轮文本解析失败 (raw_text 长度=%d)，发起裸最小上下文救援",
            len(raw_text),
        )
        try:
            rescue_messages = build_rescue_messages(vulns, user_context, tool_trace)
            rescue_resp = await asyncio.to_thread(
                llm.chat, rescue_messages, None, caller="harm_validation_rescue")
            if rescue_resp.content:
                # ★ 修复：救援返回非空时，先验证是否可解析，不可解析则 fallback
                rescue_check, _ = parse_response(rescue_resp.content)
                if rescue_check is not None:
                    raw_text = rescue_resp.content
                    log.info("harm_validation: 救援调用返回 %d 字符，解析成功", len(rescue_resp.content))
                else:
                    log.warning(
                        "harm_validation: 救援调用返回 %d 字符但仍无法解析，启用 placeholder fallback",
                        len(rescue_resp.content),
                    )
                    raw_text = generate_placeholder_verdicts(vulns)
            else:
                log.warning("harm_validation: 救援调用仍返回空内容，启用 placeholder fallback")
                raw_text = generate_placeholder_verdicts(vulns)
        except Exception as e:
            log.warning("harm_validation 救援调用失败: %s，启用 placeholder fallback", e)
            raw_text = generate_placeholder_verdicts(vulns)

    return finalize_harm_result(raw_text, vulns, tool_trace, time.time() - started)
