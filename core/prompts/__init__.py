"""core.prompts — 提示词模块（单源加载器）。

所有 LLM 系统提示词以 ``.md`` 形式存放于本目录，通过 :func:`load_prompt` 统一加载，
避免在 ``.py`` 中内联大段提示词（散落、易漂移、不可审计）。

``_common.md`` 为全 Agent 共享的「铁律」前导（漏洞验证多因子、LLM 可用性前置检查、
同根因合并、证据质量标记等）。安全分析类提示词应 ``with_common=True`` 前置它；
纯工具型提示词（压缩、意图解析、经验提炼）用 ``with_common=False`` 保持原语义。

目录成员：
  _common.md                  — 共享铁律单源
  solver.md / browse_sop.md   — Solver / 浏览器 SOP
  business_understanding.md / business_reconcile.md / harm_validation.md
  phases.py / phase1_user.py  — 阶段提示词常量与用户消息构造器
  以及从各模块外置的 *_prompt.md（见 load_prompt 调用点）
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_PROMPTS_DIR: Path = Path(__file__).resolve().parent


@lru_cache(maxsize=None)
def _read(name: str) -> str:
    """读取并缓存提示词文件原文（UTF-8）。文件不存在则抛 FileNotFoundError。"""
    path = _PROMPTS_DIR / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"提示词文件不存在: {path}")
    return path.read_text(encoding="utf-8")


def load_common() -> str:
    """加载共享铁律前导（``_common.md``）。"""
    return _read("_common")


def load_prompt(name: str, *, with_common: bool = False) -> str:
    """加载提示词。

    Args:
        name: 提示词文件名（不含 ``.md``），如 ``"intent_parse"``。
        with_common: 是否前置 ``_common.md`` 铁律。默认 ``False`` 以保持各提示词原语义；
            安全分析 / 漏洞研判类提示词应传 ``True``。

    Returns:
        提示词文本。``with_common=True`` 时在正文前以分隔线拼接铁律前导。
    """
    body = _read(name)
    if with_common:
        return load_common().rstrip() + "\n\n---\n\n" + body
    return body


def load_template(name: str, *, with_common: bool = False, **fields: object) -> str:
    """加载含 ``{placeholder}`` 占位符的提示词模板并用 ``str.format`` 填充。

    模板中的字面花括号（如 JSON 示例）须按 ``{{ }}`` 转义。
    """
    return load_prompt(name, with_common=with_common).format(**fields)


def prompts_dir() -> Path:
    """返回提示词目录路径（供需要直接拼路径的旧调用方过渡使用）。"""
    return _PROMPTS_DIR


__all__ = [
    "load_common",
    "load_prompt",
    "load_template",
    "prompts_dir",
]
