"""
Fuzz — 批量 Fuzz 执行引擎

核心定位：
- LLM 的"批量执行引擎"，像 Burp Intruder 一样工作
- 负责需要大量请求的场景：SQL 盲注提取、WAF 绕过 fuzz、竞态条件并发
- LLM 负责策略（制定 payload 模板、分析结果），Fuzz 负责执行

设计原则：
- 响应差异检测 → 自动停止（body 长度/状态码变化就刹车）
- LLM 可传入已验证的 payload 模板（working_payload_template）
- 每个 Fuzzer 有明确的最大请求数限制

架构：
  LLM（策略制定）→ FuzzRouter（路由）→ 专项 Fuzzer（批量执行）→ FuzzEvidence（结果）

支持的 Fuzz 场景：
  1. SQL 盲注提取 — 逐字符/逐位提取数据库信息
  2. WAF 绕过 fuzz — 批量发送 payload 变体，找到能过防护的那个
  3. 竞态条件验证 — 并发发送请求触发竞态
"""

from core.fuzz.base import (
    BaseFuzzer,
    FuzzTask,
    FuzzEvidence,
    FuzzResult,
)
from core.fuzz.registry import FuzzRouter, get_fuzz_router

__all__ = [
    "BaseFuzzer",
    "FuzzTask",
    "FuzzEvidence",
    "FuzzResult",
    "FuzzRouter",
    "get_fuzz_router",
]
