"""
漏洞危害验证模块 — 在 Phase 2.5 之后、Phase 3 报告生成之前对所有发现的
漏洞做"专业安全人员视角"的二次研判,过滤"形式漏洞",输出 SRC/赏金平台收录裁决。

拆分后的包结构：
- context.py: 漏洞收集与 LLM 上下文构建
- tools.py: 工具 Schema、Exploit Skills、FuzzRouter 桥接
- parser.py: LLM 响应解析与结果最终化
- validator.py: 批量裁决主入口（validate_harm）
- exploit.py: 单目标漏洞利用（exploit_single_target）
- render.py: 报告渲染（Markdown 输出）
"""

from pathlib import Path

# 提示词路径（供外部引用）
PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "harm_validation.md"

# ============================================================
# 公开 API — 保持与旧 core.harm_validation 完全兼容的导出
# ============================================================

from .context import (
    collect_vulnerabilities,
    build_context_for_llm,
)

from .tools import (
    HARM_TOOL_NAMES as _HARM_TOOL_NAMES,
    build_harm_tool_schema as _build_harm_tool_schema,
    build_exploit_methodology as _build_exploit_methodology,
    execute_fuzz_exploit as _execute_fuzz_exploit,
    build_rescue_messages as _build_rescue_messages,
    generate_placeholder_verdicts as _generate_placeholder_verdicts,
    format_tool_request as _format_tool_request,
)

from .parser import (
    parse_response as _parse_response,
    finalize_harm_result as _finalize_harm_result,
)

from .validator import validate_harm

from .exploit import exploit_single_target

from .render import (
    render_to_markdown,
    render_proven_only,
)

# exploit skill 加载（保持旧导入兼容）
from core.skill_registry import find_exploit_skills_for_vuln

__all__ = [
    "PROMPT_PATH",
    "collect_vulnerabilities",
    "build_context_for_llm",
    "validate_harm",
    "exploit_single_target",
    "render_to_markdown",
    "render_proven_only",
    # 内部函数（测试用，保持兼容）
    "_parse_response",
    "_HARM_TOOL_NAMES",
    "_build_harm_tool_schema",
    "_build_exploit_methodology",
    "_execute_fuzz_exploit",
    "_build_rescue_messages",
    "_generate_placeholder_verdicts",
    "_format_tool_request",
    "_finalize_harm_result",
    "find_exploit_skills_for_vuln",
]
