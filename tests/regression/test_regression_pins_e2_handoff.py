"""回归钉（阶段 5-E2 上下文接力）—— 防回退。

阶段 5-E2 的本质：阶段边界切换上下文时，把**未完成项 + 关键证据引用**带过去。

为什么必须钉住：
1. `_new_context_for_phase()` 每个阶段会**创建全新 ContextManager**（丢弃历史）。
   原实现只在 `phase == "test"` 注入 sitemap 摘要，其它阶段什么都不带 →
   新阶段不知道上阶段做到哪、还有什么没测。
2. `compress()` 原先摘要只取 user/assistant 的 content[:500]，**tool 消息（测试样本结论）
   完全不进摘要** → 丢弃即不可恢复（实测 M4b：30 轮丢 23 条 / 60 轮丢 53 条）。

接力物的权威数据源是 **sitemap**（结构化 + 持久化），不依赖 LLM 摘要。
"""
from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]

from core.context import ContextManager  # noqa: E402
from core.llm import Message  # noqa: E402
from core.session.phase_handoff import build_handoff  # noqa: E402
from core.sitemap.models import CheckItem, CheckResult, FeaturePoint, Priority  # noqa: E402
# 别名导入：TestStatus 以 "Test" 开头，直接 import 会被 pytest 误认为测试类并告警
from core.sitemap.models import TestStatus as TStatus  # noqa: E402
from core.sitemap.sitemap import Sitemap  # noqa: E402


def _mk_sitemap(with_vuln: bool = True) -> Sitemap:
    sp = Sitemap(target="http://t.local", task_id="test_e2_handoff")
    sp.features["f1"] = FeaturePoint(
        id="f1", name="订单查询", related_apis=["GET http://t.local/api/orders"],
        priority=Priority.CRITICAL, test_status=TStatus.IN_PROGRESS,
        checklist=[
            CheckItem(vuln_type="IDOR", result=CheckResult.PENDING, needs_browser=False),
            CheckItem(vuln_type="越权-水平", result=CheckResult.PENDING, needs_browser=True),
        ],
    )
    sp.features["f2"] = FeaturePoint(
        id="f2", name="用户资料", related_apis=["GET http://t.local/api/profile"],
        priority=Priority.HIGH, test_status=TStatus.NOT_TESTED,
        checklist=[CheckItem(vuln_type="敏感信息泄露", result=CheckResult.PENDING)],
    )
    if with_vuln:
        sp.features["f3"] = FeaturePoint(
            id="f3", name="文件下载", priority=Priority.HIGH,
            test_status=TStatus.VULN_FOUND,
            checklist=[CheckItem(
                vuln_type="任意文件读取", result=CheckResult.VULNERABLE, severity="high",
                detail="未校验 path 参数，可读取 /etc/passwd",
                evidence_flow_id="flow_abc123",
                # 以下两项是"报文全文"，**绝不能**进接力物
                evidence_request="GET /download?path=/etc/passwd\nCookie: SECRET_COOKIE_VALUE",
                evidence_response="root:x:0:0:root:/root:/bin/bash",
            )],
        )
    sp.features["f4"] = FeaturePoint(
        id="f4", name="数据看板", priority=Priority.MEDIUM,
        test_status=TStatus.NOT_TESTED, deferred=True, description="需登录后台才能激活",
        checklist=[],
    )
    return sp


# ---------------------------------------------------------------- 接力物内容

def test_handoff_empty_sitemap_returns_empty():
    assert build_handoff(None, to_phase="test") == ("", build_handoff(None, to_phase="test")[1])
    text, stats = build_handoff(None, to_phase="test")
    assert text == "" and stats.features_total == 0


def test_handoff_lists_pending_features_by_priority():
    """未完成项必须列出，且优先级高的在前。"""
    text, stats = build_handoff(_mk_sitemap(), to_phase="test", from_phase="analyze")

    assert "阶段交接（analyze → test）" in text
    assert "订单查询" in text and "用户资料" in text
    assert stats.features_pending == 2, f"未完成项数不对: {stats.features_pending}"
    # critical 的订单查询应出现在 high 的用户资料之前
    assert text.index("订单查询") < text.index("用户资料"), "未按优先级排序"
    # 待测类型与 HTTP/浏览器 分流数
    assert "IDOR" in text and "越权-水平" in text
    assert "HTTP 1 / 浏览器 1" in text, "未标注 HTTP / 浏览器 分流"


def test_handoff_includes_evidence_reference_only():
    """★ 核心：证据只给 flow 引用，绝不带报文全文。"""
    text, stats = build_handoff(_mk_sitemap(), to_phase="test")

    assert "flow_abc123" in text, "缺少证据 flow 引用"
    assert "flow_abc123" in stats.evidence_refs
    # 全文必须被排除
    assert "SECRET_COOKIE_VALUE" not in text, "接力物泄漏了请求报文（含凭证明文）"
    assert "root:x:0:0" not in text, "接力物泄漏了响应报文全文"
    assert "任意文件读取" in text, "缺少漏洞类型"


def test_handoff_includes_deferred_features():
    text, _ = build_handoff(_mk_sitemap(), to_phase="test")
    assert "待激活" in text and "数据看板" in text, "未列出待激活功能点"


def test_handoff_truncates_and_says_so():
    """超预算必须截断并显式标注（否则模型会误以为就这么多）。"""
    text, stats = build_handoff(_mk_sitemap(), to_phase="test", budget_chars=200)
    assert stats.truncated is True
    assert "已按上下文预算截断" in text, "截断未显式标注"
    assert len(text) < 600, "截断后仍过长"


# ---------------------------------------------------------------- 接线（源码级）

def test_new_context_injects_handoff_for_all_phases():
    """★ 所有阶段边界都要注入接力物（不能只注入 phase == 'test'）。"""
    src = (PROJECT_ROOT / "core" / "session" / "base.py").read_text(encoding="utf-8")
    assert "_inject_phase_handoff" in src, "未接入阶段接力"
    # 旧的"只在 test 注入"写法必须已移除
    assert 'if self.phase == "test" and self.sitemap:' not in src, \
        "仍在用「仅 test 阶段注入」的旧实现"


def test_handoff_respects_context_budget():
    """接力物要与 budget_allows_injection 联动（预算紧时收紧体量）。"""
    src = (PROJECT_ROOT / "core" / "session" / "base.py").read_text(encoding="utf-8")
    assert "budget_allows_injection" in src, "接力物未与上下文预算联动"


# ---------------------------------------------------------------- compress 修复

class _CapturingLLM:
    def __init__(self) -> None:
        self.seen = ""

    def chat(self, messages, temperature=0.1, max_tokens=4096):
        import types
        self.seen = "\n".join(m.content or "" for m in messages)
        return types.SimpleNamespace(content="【摘要】")


def _long_context(turns: int, tool_chars: int = 400) -> ContextManager:
    cm = ContextManager(llm=None)
    cm.add_system("sys")
    for i in range(1, turns + 1):
        cm.add_user(f"第 {i} 步：测试 /api/v{i}/orders")
        cm.add_assistant(Message(
            role="assistant", content=f"调用 /api/v{i}/orders",
            tool_calls=[{"id": f"call_{i}", "type": "function",
                         "function": {"name": "browser_goto", "arguments": "{}"}}],
        ))
        cm.add_tool_result(f"call_{i}", f'HTTP 200 {{"vuln":"IDOR","endpoint":"/api/v{i}/orders","m":"{"X" * tool_chars}"}}')
    return cm


def test_compress_includes_tool_samples_in_summary():
    """★ 核心修复：被压缩的 tool 消息（样本结论）必须进摘要，否则丢弃不可恢复。"""
    cm = _long_context(30)
    dropped = [m for m in cm.history if m.role == "tool"]
    cap = _CapturingLLM()
    cm.llm = cap
    cm.compress()

    assert cm.last_compress_stats["compressed"] is True
    assert cm.last_compress_stats["dropped_tool_samples"] > 0, "未发生样本移除，测试前提不成立"
    assert cm.last_compress_stats["tool_samples_in_summary"] > 0, "tool 样本未进摘要"
    # 首条被移除样本的特征串应出现在投喂给摘要 LLM 的文本里
    assert dropped[0].content[:40] in cap.seen, "样本结论未进入摘要输入"
    assert "[tool结果]" in cap.seen, "摘要输入未标注 tool 结果段"


def test_compress_stats_are_reported():
    """压缩统计必须完整上报（供 ContextGauge 打点）。"""
    cm = _long_context(30)
    cm.llm = _CapturingLLM()
    cm.compress()
    for key in ("compressed", "dropped_messages", "dropped_tool_samples",
                "kept_messages", "tool_samples_in_summary", "before_tokens", "after_tokens"):
        assert key in cm.last_compress_stats, f"缺少统计字段 {key}"
    s = cm.last_compress_stats
    assert s["before_tokens"] > s["after_tokens"], "压缩后 token 未下降"


def test_keep_recent_is_configurable():
    """保留窗口必须可配置（原先是硬编码 20）。"""
    src = (PROJECT_ROOT / "core" / "context.py").read_text(encoding="utf-8")
    assert "KEEP_RECENT_MESSAGES" in src, "保留窗口未可配置化"
    assert "keep_count = 20" not in src, "仍存在硬编码 keep_count = 20"
