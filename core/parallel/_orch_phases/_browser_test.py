# 浏览器特征测试函数（原样搬迁自 orchestrator.py）。

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import AsyncGenerator, TYPE_CHECKING

import httpx as _httpx

from core.config import (
    MAX_WORKERS, WORKER_EVENT_TIMEOUT, WORKER_STUCK_TIMEOUT,
    FAST_SCAN_MAX_WORKERS, LLM_SCAN_MAX_WORKERS,
    SKIP_META_ANALYSIS, SKIP_BUSINESS_UNDERSTANDING,
    FAST_MODE_TIMEOUTS,
)
from core.prompts.phases import PHASE_TEST_PROMPT, PHASE_REPORT_PROMPT
from core.sitemap import TestStatus, CheckResult
from core.log import get_logger, bind_context, metrics

if TYPE_CHECKING:
    from core.session import AgentSession

log = get_logger("parallel.orchestrator")


from core.parallel._orchestrator_helpers import (
    _check_mitmproxy_health,
    _try_restart_mitmproxy,
    _check_stuck_workers,
    _run_fast_scanner_core,
    _write_fast_scanner_results,
    _apply_skill_routing,
    _run_scripted_scan_core,
    _write_scripted_scan_results,
    _run_llm_preparation,
)
from ._report_phase import _enter_report_phase

async def start_browser_feature_test(session: "AgentSession") -> AsyncGenerator[str, None]:
    """主 Agent 串行测试浏览器专属 checklist 项。"""
    if not session.sitemap:
        return

    from core.config import VULN_TO_SKILL

    queue = getattr(session, "_browser_test_queue", [])

    while queue:
        fp = queue.pop(0)
        browser_pending = fp.get_browser_pending()
        if not browser_pending:
            continue

        session.current_feature_id = fp.id
        session.tool_executor.current_feature_id = fp.id
        bind_context(feature_id=fp.id)
        if fp.test_status == TestStatus.NOT_TESTED:
            session.sitemap.start_test(fp.id)

        yield session._event("feature_start",
            f"🌐 主 Agent 浏览器测试: {fp.name} ({len(browser_pending)} 项)")

        session.current_context = session._new_context_for_phase(PHASE_TEST_PROMPT)

        # 自动注入浏览器测试项对应的 SKILL 方法论
        injected_skills: set[str] = set()
        skills_dir = Path("skills_my")
        for c in browser_pending:
            skill_name = VULN_TO_SKILL.get(c.vuln_type, "")
            if skill_name and skill_name not in injected_skills:
                for skill_md in skills_dir.rglob("SKILL.md"):
                    if skill_md.parent.name == skill_name:
                        content = skill_md.read_text(encoding="utf-8")
                        if len(content) > 4000:
                            content = content[:4000] + "\n\n... (方法论截断，按以上步骤执行)"
                        session.current_context.add_system(
                            f"## 方法论：{c.vuln_type}\n"
                            f"**必须按此步骤执行**：\n\n{content}"
                        )
                        injected_skills.add(skill_name)
                        log.info("主 Agent 注入 SKILL: %s → %s", c.vuln_type, skill_name)
                        break

        from core.test_templates import generate_browser_test_steps

        browser_checklist_lines = []
        for c in browser_pending:
            browser_checklist_lines.append(f"⬜ **{c.vuln_type}**")
            steps = generate_browser_test_steps(
                vuln_type=c.vuln_type,
                page_url=fp.page_url,
                feature_id=fp.id,
            )
            browser_checklist_lines.append(steps)
            browser_checklist_lines.append("")
        browser_checklist = "\n".join(browser_checklist_lines)

        session.current_context.add_user(
            f"## 浏览器专属测试: {fp.name}\n\n"
            f"- 页面: {fp.page_url}\n"
            f"- 优先级: {fp.priority.value}\n\n"
            f"### 待测项（浏览器专属，含具体操作步骤）\n\n{browser_checklist}\n\n"
            f"## 工作流程\n\n"
            f"1. 用 `browser_goto` 访问页面\n"
            f"2. **按上面每个待测项的 Step 执行**\n"
            f"3. 每测完一项调用 `checklist_mark` 记录结论\n"
            f"4. 全部测完后调用 `phase_complete`\n\n"
            f"⛔ 只测上面列出的浏览器项，HTTP 项已由子 Agent 完成。\n"
            f"⛔ **严格按步骤执行**，不要自由发挥。"
        )
        return

    # 所有浏览器项测完
    async for evt in _enter_report_phase(session):
        yield evt


