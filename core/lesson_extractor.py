"""
Lesson Extractor — 从用户消息中识别"纠正性反馈"并提取经验

只在用户消息进入 session 时触发一次轻量 LLM 调用：
- 判断用户是否在纠正/批评 Agent 的某个判断
- 如果是，提取出 (scope, scope_value, lesson, trigger) 让 memory.record()

这是 Hermes 风格反馈学习的入口。
"""

from __future__ import annotations

import asyncio
import json
import re

from core.llm import LLMClient, Message
from core.log import get_logger
from core.prompts import load_prompt

log = get_logger("lesson_extractor")


# 一些显式的纠正口吻关键词（命中其一就值得让 LLM 进一步分析）
_CORRECTION_HINTS = [
    "不对", "错了", "不是", "其实", "实际上", "应该", "不应该",
    "你错", "判断错", "误报", "记住", "下次", "以后", "永远",
    "wrong", "incorrect", "false positive", "remember", "should",
]


def looks_like_correction(text: str) -> bool:
    if not text:
        return False
    s = text.lower()
    return any(h in s for h in _CORRECTION_HINTS)


_EXTRACT_PROMPT = load_prompt("lesson_extract")


async def maybe_extract_lesson(
    llm: LLMClient,
    user_message: str,
    last_assistant_text: str = "",
    target_url: str = "",
) -> dict | None:
    """对用户消息做纠正分类。返回 {"is_correction":true,...} 或 None（非纠正/出错）。

    优化：用 _CORRECTION_HINTS 做前置过滤，避免每条普通消息都打 LLM。
    """
    if not user_message or not user_message.strip():
        return None
    # 短消息(< 6 字)且不含纠正词 → 跳过
    if len(user_message.strip()) < 6 and not looks_like_correction(user_message):
        return None
    # 不像纠正口吻 → 跳过
    if not looks_like_correction(user_message):
        return None

    context_block = ""
    if last_assistant_text:
        snippet = last_assistant_text[:1500]
        context_block = f"\n## Agent 最近的输出（被用户回复的上下文）\n{snippet}\n"

    user_block = f"## 用户最新消息\n{user_message[:1000]}"
    target_block = f"\n## 当前测试目标\n{target_url}" if target_url else ""

    messages = [
        Message(role="system", content=_EXTRACT_PROMPT),
        Message(role="user", content=context_block + target_block + "\n" + user_block),
    ]

    try:
        resp = await asyncio.to_thread(
            llm.chat, messages, None, 0.1, 600, "lesson_extract"
        )
        text = (resp.content or "").strip()
        # 容错：去掉 ```json 围栏
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
        # 抓第一个 {...}
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        data = json.loads(m.group(0))
        if not data.get("is_correction"):
            return None
        # 校验
        scope = data.get("scope", "global")
        if scope not in ("global", "host", "path", "vuln_type"):
            scope = "global"
        lesson = (data.get("lesson") or "").strip()
        if not lesson:
            return None
        return {
            "is_correction": True,
            "scope": scope,
            "scope_value": (data.get("scope_value") or "").strip(),
            "lesson": lesson,
            "trigger": (data.get("trigger") or "").strip(),
            "confidence": float(data.get("confidence", 0.5)),
        }
    except Exception as e:
        log.warning("lesson_extractor 解析失败: %s", e)
        return None
