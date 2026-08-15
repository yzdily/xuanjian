"""
LLM 研判 — XSS 模块的差异化能力。

工作流：
1. 接收扫描器产出的 XssCandidate 列表
2. 按"context + confidence + 风险等级"分组（减少 LLM 调用次数）
3. 每个候选喂给 LLM，让它判断：
   - 是真 XSS 还是误报（如 WAF echo、已转义、CSP 拦截、JSON 响应等）
   - 严重程度（低/中/高/极高）
   - 修复建议
4. 输出最终 XssFinding 列表

提示词设计：
- 给 LLM 看：payload + 响应片段 + context + 沙化分析 + 是否浏览器触发
- 让 LLM 判断：是否真的能在用户浏览器中执行 JS
- 强调宁可漏报也不要假阳性（误报损害产品可信度）
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Optional

from core.xss.models import (
    ContextType,
    FindingStatus,
    Severity,
    XssCandidate,
    XssFinding,
    XssType,
)
from core.prompts import load_prompt

if TYPE_CHECKING:
    from core.llm import LLMClient

log = logging.getLogger(__name__)


JUDGE_SYSTEM_PROMPT = load_prompt("xss_judge", with_common=True)


def _serialize_candidate_for_llm(cand: XssCandidate, max_resp_len: int = 4000,
                                  csp_summary: str = "") -> dict:
    """把候选裁剪成 LLM 可读的紧凑格式。"""
    target = cand.target
    response_excerpt = ""
    if cand.response_packet:
        # 取所有 marker 出现位置的上下文（前后 200 字符）
        body = cand.response_packet
        excerpts = []
        for m in cand.echo_matches[:5]:
            start = max(0, m.offset - 200)
            end = min(len(body), m.offset + len(cand.marker) + 200)
            excerpts.append(f"[位置 {m.offset}] context={m.context.value}, encoded={m.encoded}:\n  {body[start:end]}")
        response_excerpt = "\n\n".join(excerpts)[:max_resp_len]

    out = {
        "url": target.url,
        "method": target.method,
        "injection_point": target.injection_point.value,
        "param_name": target.param_name,
        "original_value": (target.original_value or "")[:100],
        "payload": cand.payload,
        "marker": cand.marker,
        "response_status": cand.response_status,
        "response_content_type": cand.response_content_type,
        "echo_count": len(cand.echo_matches),
        "echo_contexts": [m.context.value for m in cand.echo_matches[:10]],
        "all_encoded": all(m.encoded for m in cand.echo_matches) if cand.echo_matches else False,
        "any_encoded": any(m.encoded for m in cand.echo_matches),
        "response_excerpt": response_excerpt,
        "browser_triggered": cand.browser_triggered,
        "browser_evidence": cand.browser_evidence,
        "scanner_confidence": cand.confidence,
        "xss_type": cand.xss_type.value,
        "scanner": cand.scanner,
    }
    if csp_summary:
        out["csp_context"] = csp_summary
    return out


def _build_judge_user_message(cands: list[XssCandidate]) -> str:
    """构造 user 消息 — 支持批量研判（节省 token）。"""
    if len(cands) == 1:
        c_data = _serialize_candidate_for_llm(cands[0])
        return (
            "请研判以下 XSS 候选：\n\n"
            f"```json\n{json.dumps(c_data, ensure_ascii=False, indent=2)}\n```\n\n"
            "严格按上述格式输出单个 JSON 对象（不要包数组）。"
        )
    # 批量模式
    cand_data = [_serialize_candidate_for_llm(c, max_resp_len=2000) for c in cands]
    return (
        f"请逐个研判以下 {len(cands)} 个 XSS 候选：\n\n"
        f"```json\n{json.dumps(cand_data, ensure_ascii=False, indent=2)}\n```\n\n"
        "严格输出 JSON 数组，元素顺序与输入一致，每个元素结构同上。"
    )


class XssJudge:
    """LLM 研判器。"""

    def __init__(
        self,
        llm: "LLMClient",
        on_progress: Optional[callable] = None,
        batch_size: int = 5,
        max_concurrent: int = 3,
    ):
        self.llm = llm
        self.on_progress = on_progress
        self.batch_size = batch_size
        self.max_concurrent = max_concurrent
        # 外部注入的 CSP 分析（dict[host] -> CspAnalysis）
        self._csp_analyses: dict = {}

    def _get_csp_summary_for_target(self, target) -> str:
        """根据 target 的 host 找对应 CSP 分析，返回简短摘要。"""
        if not self._csp_analyses:
            return ""
        try:
            from urllib.parse import urlparse
            host = urlparse(target.url).netloc
            analysis = self._csp_analyses.get(host)
            if not analysis:
                return ""
            lvl = getattr(analysis, "mitigation_level", "unknown")
            score = getattr(analysis, "score", 0.0)
            bypass = getattr(analysis, "bypass_paths", []) or []
            summary = f"CSP 强度: {lvl} ({score:.1f}/10)"
            if bypass:
                summary += "; 已知 bypass: " + "; ".join(bypass[:3])
            return summary[:600]
        except Exception:
            return ""

    def _build_judge_user_message_with_context(
        self, cands: list[XssCandidate], csp_summary: str
    ) -> str:
        """带 CSP 上下文的 user 消息。"""
        if len(cands) == 1:
            c_data = _serialize_candidate_for_llm(cands[0], csp_summary=csp_summary)
            return (
                "请研判以下 XSS 候选（请综合 CSP 上下文判断真实可利用性）：\n\n"
                f"```json\n{json.dumps(c_data, ensure_ascii=False, indent=2)}\n```\n\n"
                "严格按上述格式输出单个 JSON 对象（不要包数组）。"
            )
        cand_data = [_serialize_candidate_for_llm(c, max_resp_len=2000,
                                                    csp_summary=csp_summary) for c in cands]
        return (
            f"请逐个研判以下 {len(cands)} 个 XSS 候选：\n\n"
            f"```json\n{json.dumps(cand_data, ensure_ascii=False, indent=2)}\n```\n\n"
            "严格输出 JSON 数组，元素顺序与输入一致，每个元素结构同上。"
        )

    def _report(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    async def judge_all(
        self,
        candidates: list[XssCandidate],
        feature_id_resolver: Optional[callable] = None,
    ) -> list[XssFinding]:
        """对所有候选进行研判。

        Args:
            candidates: 候选列表
            feature_id_resolver: 给定 InjectionTarget 返回相关 feature_id 的函数

        Returns:
            XssFinding 列表
        """
        if not candidates:
            return []

        self._report(f"🧠 LLM 研判启动: {len(candidates)} 个候选")

        # 直接走单个研判（批量模式可能 JSON 解析失败，单个更稳）
        # 高置信度（浏览器已触发）的可以跳过 LLM 直接 confirmed
        findings: list[XssFinding] = []
        to_judge: list[XssCandidate] = []
        for cand in candidates:
            if cand.browser_triggered:
                # 浏览器已实测，直接 confirmed（仍调 LLM 生成描述/严重等级）
                to_judge.append(cand)
            elif cand.confidence >= 0.3:
                to_judge.append(cand)
            else:
                # 置信度过低，直接标 false_positive
                findings.append(self._make_finding(
                    cand, FindingStatus.FALSE_POSITIVE, Severity.INFO,
                    title=f"低置信度候选 - {cand.target.url[:50]}",
                    description="置信度过低（< 0.3），扫描器自动排除",
                    reasoning="scanner_confidence < 0.3",
                    judge_confidence=0.9,
                    feature_id_resolver=feature_id_resolver,
                ))

        if not to_judge:
            return findings

        # 并发研判
        sem = asyncio.Semaphore(self.max_concurrent)
        results = [None] * len(to_judge)
        completed = [0]

        async def _judge_one(idx: int, cand: XssCandidate):
            async with sem:
                try:
                    finding = await self._judge_single(cand, feature_id_resolver)
                    results[idx] = finding
                    completed[0] += 1
                    if completed[0] % 5 == 0:
                        self._report(f"  研判进度: {completed[0]}/{len(to_judge)}")
                except Exception as e:
                    self._report(f"  ⚠️ 研判失败 #{idx}: {str(e)[:80]}")
                    # fallback：保留为 needs_review
                    results[idx] = self._make_finding(
                        cand, FindingStatus.NEEDS_REVIEW,
                        Severity.MEDIUM if cand.confidence > 0.5 else Severity.LOW,
                        title=f"研判失败 - {cand.target.url[:50]}",
                        description=f"LLM 调用失败: {str(e)[:100]}",
                        reasoning="llm_error",
                        judge_confidence=0.0,
                        feature_id_resolver=feature_id_resolver,
                    )

        await asyncio.gather(*[_judge_one(i, c) for i, c in enumerate(to_judge)])
        findings.extend([r for r in results if r is not None])

        # 统计
        confirmed = sum(1 for f in findings if f.status == FindingStatus.CONFIRMED)
        fp = sum(1 for f in findings if f.status == FindingStatus.FALSE_POSITIVE)
        review = sum(1 for f in findings if f.status == FindingStatus.NEEDS_REVIEW)
        self._report(
            f"✅ LLM 研判完成: 确认 {confirmed}, 误报 {fp}, 待复核 {review} (共 {len(findings)})"
        )
        return findings

    async def _judge_single(
        self,
        cand: XssCandidate,
        feature_id_resolver: Optional[callable],
    ) -> XssFinding:
        """对单个候选进行 LLM 研判。"""
        from core.llm import Message

        # 查找该 target 所在 host 的 CSP 分析，作为研判上下文
        csp_summary = self._get_csp_summary_for_target(cand.target)
        user_msg = self._build_judge_user_message_with_context([cand], csp_summary)
        messages = [
            Message(role="system", content=JUDGE_SYSTEM_PROMPT),
            Message(role="user", content=user_msg),
        ]
        try:
            response = await asyncio.to_thread(
                self.llm.chat, messages, caller="xss_judge",
            )
            text = response.content or ""
        except Exception as e:
            log.warning("xss_judge LLM call failed: %s", e)
            raise

        # 提取 JSON
        verdict = self._extract_json(text)
        if not verdict:
            return self._make_finding(
                cand, FindingStatus.NEEDS_REVIEW,
                Severity.MEDIUM if cand.confidence > 0.5 else Severity.LOW,
                title=f"研判 JSON 解析失败 - {cand.target.url[:50]}",
                description="LLM 返回内容无法解析为 JSON",
                reasoning=text[:300],
                judge_confidence=0.3,
                feature_id_resolver=feature_id_resolver,
            )

        # 映射 status / severity
        status_str = (verdict.get("status") or "needs_review").lower()
        status = {
            "confirmed": FindingStatus.CONFIRMED,
            "false_positive": FindingStatus.FALSE_POSITIVE,
            "needs_review": FindingStatus.NEEDS_REVIEW,
        }.get(status_str, FindingStatus.NEEDS_REVIEW)

        sev_str = (verdict.get("severity") or "medium").lower()
        sev = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
        }.get(sev_str, Severity.MEDIUM)

        return self._make_finding(
            cand,
            status,
            sev,
            title=verdict.get("title", "")[:200],
            description=verdict.get("description", "")[:1000],
            reasoning=verdict.get("reasoning", "")[:1500],
            judge_confidence=float(verdict.get("confidence", 0.5)),
            reproduce_steps=verdict.get("reproduce_steps", "")[:2000],
            fix_suggestion=verdict.get("fix_suggestion", "")[:1000],
            feature_id_resolver=feature_id_resolver,
        )

    @staticmethod
    def _extract_json(text: str) -> Optional[dict]:
        """从 LLM 返回中提取 JSON 对象。"""
        import re
        if not text:
            return None
        # 尝试 ```json ... ```
        m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except (json.JSONDecodeError, ValueError):
                pass
        # 尝试直接解析（找第一个 { 到最后一个 }）
        first = text.find("{")
        last = text.rfind("}")
        if first >= 0 and last > first:
            try:
                return json.loads(text[first:last + 1])
            except (json.JSONDecodeError, ValueError):
                pass
        return None

    def _make_finding(
        self,
        cand: XssCandidate,
        status: FindingStatus,
        severity: Severity,
        *,
        title: str = "",
        description: str = "",
        reasoning: str = "",
        judge_confidence: float = 0.5,
        reproduce_steps: str = "",
        fix_suggestion: str = "",
        feature_id_resolver: Optional[callable] = None,
    ) -> XssFinding:
        fid = f"xss_{uuid.uuid4().hex[:10]}"
        feature_id = ""
        if feature_id_resolver:
            try:
                feature_id = feature_id_resolver(cand.target) or ""
            except Exception:
                pass

        if not title:
            title = f"{cand.xss_type.value.title()} XSS - {cand.target.method} {cand.target.url[:60]}"
        if not fix_suggestion and status == FindingStatus.CONFIRMED:
            fix_suggestion = (
                "1. 对所有用户输入进行 HTML 实体编码后再输出到 HTML 上下文；\n"
                "2. JS 字符串上下文使用 JSON.stringify 序列化；\n"
                "3. 添加 Content-Security-Policy 头限制 inline-script 执行；\n"
                "4. 框架层面（Vue/React）禁止使用 v-html / dangerouslySetInnerHTML 渲染未净化内容。"
            )

        return XssFinding(
            id=fid,
            candidate=cand,
            status=status,
            severity=severity,
            title=title,
            description=description,
            reproduce_steps=reproduce_steps,
            fix_suggestion=fix_suggestion,
            judge_reasoning=reasoning,
            judge_confidence=judge_confidence,
            feature_id=feature_id,
            judged_at=time.time(),
        )
